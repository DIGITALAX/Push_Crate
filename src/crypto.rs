use crate::{push_api::Version, user::AdditionalMeta};
use aes::cipher::generic_array::GenericArray;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use base64::{engine::general_purpose, Engine as _};
use ethers::signers::{LocalWallet, Signer};
use hex::{decode, encode};
use hkdf::Hkdf;
use rand::{rngs::OsRng, Rng};
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::error::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AesGcmEncrypted {
    pub ciphertext: Vec<u8>,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedPrivateKey {
    pub ciphertext: String,
    pub salt: String,
    pub nonce: String,
    pub version: String,
    pub pre_key: String,
}

pub fn generate_key_pair() -> KeyPair {
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate private key");
    let public_key = RsaPublicKey::from(&private_key);
    KeyPair {
        private_key: general_purpose::STANDARD.encode(
            private_key
                .to_pkcs1_der()
                .expect("Failed to encode private key")
                .as_bytes(),
        ),
        public_key: general_purpose::STANDARD.encode(
            public_key
                .to_pkcs1_der()
                .expect("Failed to encode public key")
                .as_ref(),
        ),
    }
}

pub fn prepare_pgp_public_key(
    encryption_type: &Version,
    public_key: &str,
) -> Result<String, &'static str> {
    match encryption_type {
        Version::EncTypeV1 => Ok(public_key.to_string()),
        Version::EncTypeV2 | Version::EncTypeV3 | Version::EncTypeV4 => {
            let prepared_key = json!({
                "key": public_key,
                "signature": "DEPRECATED"
            });
            Ok(prepared_key.to_string())
        }
    }
}

pub fn encrypt_private_key(
    encryption_type: &Version,
    private_key: &str,
    secret: &[u8],
    additional_meta: Option<AdditionalMeta>,
) -> Result<EncryptedPrivateKey, &'static str> {
    match encryption_type {
        Version::EncTypeV1 => {
            let encrypted = aes_gcm_encrypt(private_key.as_bytes(), secret)?;
            Ok(EncryptedPrivateKey {
                ciphertext: encode(encrypted.ciphertext),
                salt: encode(encrypted.salt),
                nonce: encode(encrypted.nonce),
                version: Version::EncTypeV1.as_str().to_string(),
                pre_key: "".to_string(),
            })
        }
        Version::EncTypeV2 | Version::EncTypeV3 | Version::EncTypeV4 => {
            if *encryption_type == Version::EncTypeV4 && additional_meta.is_none() {
                return Err("Password is required for ENC_TYPE_V4");
            }
            let secret_key = match encryption_type {
                Version::EncTypeV2 => secret.to_vec(),
                Version::EncTypeV3 | Version::EncTypeV4 => {
                    let password = additional_meta
                        .ok_or("Missing password")?
                        .nftpgp_v1
                        .ok_or("Missing NFTPGP_V1 in additional_meta")?
                        .password
                        .clone();

                    let password_bytes = password.as_bytes();
                    hkdf_generate(password_bytes, 32)
                }
                _ => return Err("Unsupported Encryption Type"),
            };

            let encrypted = aes_gcm_encrypt(private_key.as_bytes(), &secret_key)?;

            Ok(EncryptedPrivateKey {
                ciphertext: encode(encrypted.ciphertext),
                salt: encode(encrypted.salt.clone()),
                nonce: encode(encrypted.nonce),
                version: encryption_type.as_str().to_string(),
                pre_key: String::from_utf8_lossy(&encrypted.salt).to_string(),
            })
        }
    }
}

pub fn aes_gcm_encrypt(data: &[u8], secret: &[u8]) -> Result<AesGcmEncrypted, &'static str> {
    let mut rng = rand::thread_rng();

    let salt: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    let nonce: Vec<u8> = (0..12).map(|_| rng.gen()).collect();

    let hk = Hkdf::<Sha256>::new(Some(&salt), secret);
    let mut key = [0u8; 32];
    hk.expand(b"", &mut key)
        .map_err(|_| "Failed to expand HKDF key")?;

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let ciphertext = cipher
        .encrypt(GenericArray::from_slice(&nonce), data)
        .map_err(|_| "Encryption failed")?;

    Ok(AesGcmEncrypted {
        ciphertext,
        salt,
        nonce,
    })
}

pub fn hkdf_generate(secret: &[u8], length: usize) -> Vec<u8> {
    let salt: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let hk = Hkdf::<Sha256>::new(Some(&salt), secret);
    let mut okm = vec![0u8; length];
    hk.expand(b"", &mut okm).expect("HKDF failed");
    okm
}
pub async fn decrypt_pgp_key(
    encrypted_pgp_private_key: &str,
    signer: &LocalWallet,
    version: &Version,
    additional_meta: Option<AdditionalMeta>,
) -> Result<String, Box<dyn Error>> {
    let parsed_key: Value = serde_json::from_str(encrypted_pgp_private_key)?;

    match version {
        Version::EncTypeV1 => {
            let decrypted = decrypt_v1(&parsed_key, signer).await?;
            Ok(decrypted)
        }
        Version::EncTypeV2 => {
            let pre_key = parsed_key["preKey"]
                .as_str()
                .ok_or("Missing preKey in encrypted PGP key")?;
            let enable_profile_message = format!("Enable Push Chat Profile \n{}", pre_key);

            let secret = get_eip712_signature(&enable_profile_message, signer).await?;
            let decrypted = decrypt_v2(&parsed_key, &decode(secret)?)?;
            Ok(String::from_utf8(decrypted)?)
        }
        Version::EncTypeV3 => {
            let pre_key = parsed_key["preKey"]
                .as_str()
                .ok_or("Missing preKey in encrypted PGP key")?;
            let enable_profile_message = format!("Enable Push Profile \n{}", pre_key);

            let secret = get_eip191_signature(&enable_profile_message, signer).await?;
            let decrypted = decrypt_v2(&parsed_key, &decode(secret)?)?;
            Ok(String::from_utf8(decrypted)?)
        }
        Version::EncTypeV4 => {
            let password = if let Some(meta) = additional_meta {
                meta.nftpgp_v1
                    .as_ref()
                    .ok_or("Missing NFTPGP_V1 in additional_meta")?
                    .password
                    .clone()
            } else {
                return Err("Password required for ENC_TYPE_V4".into());
            };

            let decrypted = decrypt_v2(&parsed_key, &decode(password)?)?;
            Ok(String::from_utf8(decrypted)?)
        }
    }
}

async fn decrypt_v1(parsed_key: &Value, wallet: &LocalWallet) -> Result<String, Box<dyn Error>> {
    let encrypted_data = parsed_key["encryptedData"]
        .as_str()
        .ok_or("Missing encrypted data in ENC_TYPE_V1")?;
    let private_key = wallet.sign_message(encrypted_data.as_bytes()).await?;
    Ok(private_key.to_string())
}

fn decrypt_v2(parsed_key: &Value, secret: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let encrypted_data = decode(
        parsed_key["encryptedData"]
            .as_str()
            .ok_or("Missing encrypted data in ENC_TYPE_V2")?,
    )?;
    let nonce = decode(
        parsed_key["nonce"]
            .as_str()
            .ok_or("Missing nonce in ENC_TYPE_V2")?,
    )?;

    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, secret)
        .expand(&[], &mut key)
        .map_err(|_| "Failed to expand HKDF key")?;

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));

    let nonce = GenericArray::from_slice(&nonce);
    let decrypted_data = cipher
        .decrypt(nonce, &encrypted_data[..])
        .map_err(|_| "Decryption failed")?;
    Ok(decrypted_data)
}

async fn get_eip712_signature(
    message: &str,
    wallet: &LocalWallet,
) -> Result<String, Box<dyn Error>> {
    let signature = wallet.sign_message(message.as_bytes()).await?;
    Ok(encode(signature.to_vec()))
}

async fn get_eip191_signature(
    message: &str,
    wallet: &LocalWallet,
) -> Result<String, Box<dyn Error>> {
    let signature = wallet.sign_message(message.as_bytes()).await?;
    Ok(encode(signature.to_vec()))
}
