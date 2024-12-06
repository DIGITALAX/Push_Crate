use crate::{config::get_version, push_api::Version, user::AdditionalMeta};
use aes::cipher::generic_array::GenericArray;
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ethers::{
    middleware::SignerMiddleware,
    providers::{Http, Provider},
    signers::{LocalWallet, Signer},
};

use hex::{decode, encode};
use hkdf::Hkdf;
use rand::{rngs::OsRng, thread_rng, Rng, RngCore};
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{
    error::Error,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Keys {
    pub private_key: String,
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AesGcmEncrypted {
    pub ciphertext: String,
    pub salt: String,
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedPrivateKey {
    pub ciphertext: String,
    pub salt: String,
    pub nonce: String,
    pub version: String,
    pub pre_key: String,
}

pub async fn generate_key_pair() -> Result<Keys, Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    

    let private_key = RsaPrivateKey::new(&mut rng, 4096)?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_key_der = private_key.to_pkcs1_der()?;
    let public_key_der = public_key.to_pkcs1_der()?.as_ref().to_vec();

    let creation_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;

    let public_key_packet = format_openpgp_public_key(&public_key_der, "", creation_time)?;
    let clean_public_key = public_key_packet.replace("\\n", "\n");

    let private_key_packet = format_openpgp_private_key(&private_key_der.as_bytes(), "")?;
    let private_key_base64 = STANDARD.encode(private_key_packet);

    Ok(Keys {
        public_key: clean_public_key,
        private_key: private_key_base64,
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

    let base64_key = segment_base64(&STANDARD.encode(&packet));

    let formatted_key = format!(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n{}\n-----END PGP PUBLIC KEY BLOCK-----",
        base64_key
    );

    Ok(formatted_key)
}

fn segment_base64(base64_str: &str) -> String {
    base64_str
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<&str>>()
        .join("\n")
}

fn format_openpgp_private_key(
    private_key: &[u8],
    user_id: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut packet = vec![];

    packet.push(0x95);
    let key_len = private_key.len() + user_id.len();
    packet.extend_from_slice(&(key_len as u16).to_be_bytes());
    packet.extend_from_slice(private_key);

    if !user_id.is_empty() {
        packet.extend_from_slice(user_id.as_bytes());
    }

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
    wallet: &SignerMiddleware<Arc<Provider<Http>>, LocalWallet>,
    encryption_type: &Version,
    private_key: &str,
    additional_meta: Option<AdditionalMeta>,
) -> Result<EncryptedPrivateKey, &'static str> {
    match encryption_type {
        Version::EncTypeV1 => {
            return Err("V1 Not Supported for Private Key Encryption".into());
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

            let encrypted = aes_gcm_encrypt_v2(private_key.as_bytes(), &secret_key, None)?;

            Ok(EncryptedPrivateKey {
                ciphertext: encrypted.ciphertext,
                salt: encrypted.salt,
                nonce: encrypted.nonce,
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

            let trimmed_proof = verification_proof
                .strip_prefix("eip191:")
                .unwrap_or(&verification_proof)
                .strip_prefix("0x")
                .unwrap_or(&verification_proof);

            if !trimmed_proof.chars().all(|c| c.is_digit(16)) {
                return Err("Verification proof is not valid hexadecimal");
            }

            let secret_key =
                decode(trimmed_proof).map_err(|_| "Failed to decode verification proof")?;

            let encrypted = aes_gcm_encrypt_v2(private_key.as_bytes(), &secret_key, None)?;

            Ok(EncryptedPrivateKey {
                ciphertext: encrypted.ciphertext,
                salt: encrypted.salt,
                nonce: encrypted.nonce,
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

            let encrypted = aes_gcm_encrypt_v2(private_key.as_bytes(), &secret_key, None)?;

            Ok(EncryptedPrivateKey {
                ciphertext: encrypted.ciphertext,
                salt: encrypted.salt,
                nonce: encrypted.nonce,
                version: get_version(encryption_type).unwrap().to_string(),
                pre_key: input,
            })
        }
    }
}

fn aes_gcm_encrypt_v2(
    data: &[u8],
    secret: &[u8],
    additional_data: Option<&[u8]>,
) -> Result<AesGcmEncrypted, &'static str> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    thread_rng().fill_bytes(&mut salt);
    thread_rng().fill_bytes(&mut nonce);

    let hk = Hkdf::<Sha256>::new(Some(&salt), secret);
    let mut key = [0u8; 32];
    hk.expand(b"", &mut key)
        .map_err(|_| "Failed to expand HKDF key")?;

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "Failed to create cipher")?;

    let payload = match additional_data {
        Some(aad) => Payload { msg: data, aad },
        None => Payload {
            msg: data,
            aad: &[],
        },
    };

    let ciphertext = cipher
        .encrypt(GenericArray::from_slice(&nonce), payload)
        .map_err(|_| "Encryption failed")?;

    Ok(AesGcmEncrypted {
        ciphertext: encode(ciphertext),
        salt: encode(salt),
        nonce: encode(nonce),
    })
}

pub async fn decrypt_pgp_key(
    encrypted_pgp_private_key: &str,
    signer: &SignerMiddleware<Arc<Provider<Http>>, LocalWallet>,
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

async fn decrypt_v1(
    parsed_key: &Value,
    wallet: &SignerMiddleware<Arc<Provider<Http>>, LocalWallet>,
) -> Result<String, Box<dyn Error>> {
    let encrypted_data = parsed_key["encryptedData"]
        .as_str()
        .ok_or("Missing encrypted data in ENC_TYPE_V1")?;
    let private_key = wallet
        .signer()
        .sign_message(encrypted_data.as_bytes())
        .await?;
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

fn generate_pre_key(length: usize) -> Result<String, &'static str> {
    let mut rng = rand::thread_rng();
    let mut buffer = vec![0u8; length];
    rng.fill(buffer.as_mut_slice());
    Ok(buffer.iter().map(|byte| format!("{:02x}", byte)).collect())
}

async fn get_eip712_signature(
    wallet: &SignerMiddleware<Arc<Provider<Http>>, LocalWallet>,
    message: &str,
) -> Result<String, &'static str> {
    let signed_message = wallet
        .signer()
        .sign_message(message)
        .await
        .map_err(|_| "Failed to sign EIP712 message")?;
    Ok(format!("0x{}", encode(signed_message.to_vec())))
}

pub async fn get_eip191_signature(
    wallet: &SignerMiddleware<Arc<Provider<Http>>, LocalWallet>,
    message: &String,
    version: &Version,
) -> Result<String, Box<dyn Error>> {
    let signature = wallet.signer().sign_message(message.clone()).await?;
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
