use crate::{config::get_version, push_api::Version, user::AdditionalMeta};
use aes::cipher::generic_array::GenericArray;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use base64::{engine::general_purpose::STANDARD, Engine};
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
use std::{
    error::Error,
    time::{SystemTime, UNIX_EPOCH},
};

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

pub fn generate_key_pair() -> Result<KeyPair, Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_key_der = private_key.to_pkcs1_der()?;
    let private_key_encrypted = private_key_der.as_bytes().to_vec();
    let public_key_der = public_key.to_pkcs1_der()?.as_ref().to_vec();
    let creation_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
    let public_key_packet = format_openpgp_public_key(&public_key_der, "", creation_time)?;
    let private_key_packet = format_openpgp_private_key(&private_key_encrypted, "")?;
    Ok(KeyPair {
        public_key: public_key_packet,
        private_key: STANDARD.encode(private_key_packet),
    })
}

fn format_openpgp_public_key(
    public_key: &[u8],
    user_id: &str,
    creation_time: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut packet = vec![];

    packet.push(0x99);
    let key_len = public_key.len() + 6;
    packet.extend_from_slice(&(key_len as u16).to_be_bytes());
    packet.push(0x04);
    packet.extend_from_slice(&creation_time.to_be_bytes());
    packet.push(0x01);
    packet.extend_from_slice(public_key);

    if !user_id.is_empty() {
        packet.push(0xb4);
        packet.extend_from_slice(&(user_id.len() as u16).to_be_bytes());
        packet.extend_from_slice(user_id.as_bytes());
    }

    let base64_key = STANDARD.encode(packet);
    let formatted_key = format!(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n{}\n-----END PGP PUBLIC KEY BLOCK-----",
        base64_key
    );

    Ok(formatted_key)
}

fn format_openpgp_private_key(
    private_key: &[u8],
    user_id: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut packet = vec![];
    packet.extend_from_slice(&[0x95]);
    packet.extend_from_slice(&(private_key.len() as u16).to_be_bytes());
    packet.extend_from_slice(private_key);

    packet.extend_from_slice(user_id.as_bytes());

    Ok(packet)
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

pub async fn encrypt_private_key(
    wallet: &LocalWallet,
    encryption_type: &Version,
    private_key: &str,
    secret: &[u8],
    additional_meta: Option<AdditionalMeta>,
) -> Result<EncryptedPrivateKey, &'static str> {
    match encryption_type {
        Version::EncTypeV1 => {
            let (salt, nonce) = generate_salt_and_nonce();
            let encrypted = aes_gcm_encrypt(private_key.as_bytes(), secret, &salt, &nonce)?;
            Ok(EncryptedPrivateKey {
                ciphertext: encode(encrypted.ciphertext),
                salt: encode(salt),
                nonce: encode(nonce),
                version: get_version(encryption_type).unwrap().to_string(),
                pre_key: "".to_string(),
            })
        }
        Version::EncTypeV2 => {
            let input = generate_pre_key(32)?;

            let enable_profile_message = format!("Enable Push Chat Profile \n{}", input);

            let verification_proof = get_eip712_signature(wallet, &enable_profile_message)
                .await
                .map_err(|_| "Failed to get EIP712 signature")?;

            let trimmed_proof = if verification_proof.starts_with("0x") {
                &verification_proof[2..]
            } else {
                &verification_proof
            };

            if !trimmed_proof.chars().all(|c| c.is_digit(16)) {
                return Err("Verification proof is not valid hexadecimal");
            }

            let secret_key =
                decode(trimmed_proof).map_err(|_| "Failed to decode verification proof")?;

            let (salt, nonce) = generate_salt_and_nonce();

            let encrypted = aes_gcm_encrypt(private_key.as_bytes(), &secret_key, &salt, &nonce)?;

            Ok(EncryptedPrivateKey {
                ciphertext: encode(encrypted.ciphertext),
                salt: encode(salt),
                nonce: encode(nonce),
                version: get_version(encryption_type).unwrap().to_string(),
                pre_key: input,
            })
        }

        Version::EncTypeV3 => {
            let input = generate_pre_key(32)?;

            let enable_profile_message = format!("Enable Push Profile \n{}", input);

            let verification_proof =
                get_eip191_signature(wallet, &enable_profile_message, &Version::EncTypeV1)
                    .await
                    .map_err(|_| "Failed to get EIP191 signature")?;

            let trimmed_proof = if verification_proof.starts_with("eip191:") {
                &verification_proof[7..]
            } else {
                &verification_proof
            };

            let trimmed_proof = if trimmed_proof.starts_with("0x") {
                &trimmed_proof[2..]
            } else {
                trimmed_proof
            };

            if !trimmed_proof.chars().all(|c| c.is_digit(16)) {
                return Err("Verification proof is not valid hexadecimal");
            }

            let secret_key =
                decode(trimmed_proof).map_err(|_| "Failed to decode verification proof")?;

            let (salt, nonce) = generate_salt_and_nonce();

            let encrypted = aes_gcm_encrypt(private_key.as_bytes(), &secret_key, &salt, &nonce)?;

            Ok(EncryptedPrivateKey {
                ciphertext: encode(encrypted.ciphertext),
                salt: encode(salt),
                nonce: encode(nonce),
                version: get_version(encryption_type).unwrap().to_string(),
                pre_key: input,
            })
        }

        Version::EncTypeV4 => {
            let password = additional_meta
                .ok_or("Missing additional metadata")?
                .nftpgp_v1
                .ok_or("Password is required in NFTPGP_V1")?
                .password;

            let input = generate_pre_key(32)?;

            let password_hex = encode(password);
            let secret_key =
                decode(password_hex).map_err(|_| "Failed to decode password to hex")?;

            let (salt, nonce) = generate_salt_and_nonce();

            let encrypted = aes_gcm_encrypt(private_key.as_bytes(), &secret_key, &salt, &nonce)?;

            Ok(EncryptedPrivateKey {
                ciphertext: encode(encrypted.ciphertext),
                salt: encode(salt),
                nonce: encode(nonce),
                version: get_version(encryption_type).unwrap().to_string(),
                pre_key: input,
            })
        }
    }
}

fn aes_gcm_encrypt(
    data: &[u8],
    secret: &[u8],
    salt: &[u8],
    nonce: &[u8],
) -> Result<AesGcmEncrypted, &'static str> {
    let hk = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut key = [0u8; 32];
    hk.expand(b"", &mut key)
        .map_err(|_| "Failed to expand HKDF key")?;

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let ciphertext = cipher
        .encrypt(GenericArray::from_slice(nonce), data)
        .map_err(|_| "Encryption failed")?;

    Ok(AesGcmEncrypted {
        ciphertext,
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
    })
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

            let secret = get_eip712_signature(signer, &enable_profile_message).await?;
            let decrypted = decrypt_v2(&parsed_key, &decode(secret)?)?;
            Ok(String::from_utf8(decrypted)?)
        }
        Version::EncTypeV3 => {
            let pre_key = parsed_key["preKey"]
                .as_str()
                .ok_or("Missing preKey in encrypted PGP key")?;
            let enable_profile_message = format!("Enable Push Profile \n{}", pre_key);

            let secret =
                get_eip191_signature(signer, &enable_profile_message, &Version::EncTypeV1).await?;
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

fn generate_salt_and_nonce() -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let salt: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    let nonce: Vec<u8> = (0..12).map(|_| rng.gen()).collect();
    (salt, nonce)
}

fn generate_pre_key(length: usize) -> Result<String, &'static str> {
    let mut rng = rand::thread_rng();
    let mut buffer = vec![0u8; length];
    rng.fill(buffer.as_mut_slice());
    Ok(buffer.iter().map(|byte| format!("{:02x}", byte)).collect())
}

async fn get_eip712_signature(wallet: &LocalWallet, message: &str) -> Result<String, &'static str> {
    let signed_message = wallet
        .sign_message(message)
        .await
        .map_err(|_| "Failed to sign EIP712 message")?;
    Ok(format!("0x{}", encode(signed_message.to_vec())))
}

pub async fn get_eip191_signature(
    wallet: &LocalWallet,
    message: &String,
    version: &Version,
) -> Result<String, Box<dyn Error>> {

    let signature = wallet.sign_message(message.clone()).await?;
    let sig_type = if *version == Version::EncTypeV1 {
        "eip191"
    } else {
        "eip191v2"
    };

    let signed = format!(
        "{}:{}",
        sig_type,
        
        format!("0x{}", encode(signature.to_vec()))
    );
    Ok(signed)
}
