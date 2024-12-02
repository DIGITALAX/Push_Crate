use ethers::signers::{LocalWallet, Signer};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, to_string, Value};
use std::{
    error::Error,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    crypto::{decrypt_pgp_key, encrypt_private_key, generate_key_pair, prepare_pgp_public_key},
    push_api::Version,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    public_key: Option<String>,
    encrypted_private_key: Option<String>,
    decrypted_private_key: Option<String>,
    did: Option<String>,
    wallets: Option<String>,
    verification_proof: Option<String>,
    msg_sent: Option<u64>,
    max_msg_persisted: Option<u64>,
    profile: Option<Profile>,
    origin: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Profile {
    name: Option<String>,
    desc: Option<String>,
    picture: Option<String>,
    profile_verification_proof: Option<String>,
    blocked_users_list: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct AdditionalMeta {
    pub nftpgp_v1: Option<NFTPGP>,
}

#[derive(Debug, Clone)]
pub struct NFTPGP {
    pub password: String,
}

impl User {
    pub fn new() -> Self {
        User {
            public_key: None,
            encrypted_private_key: None,
            decrypted_private_key: None,
            did: None,
            wallets: None,
            verification_proof: None,
            msg_sent: None,
            max_msg_persisted: None,
            profile: None,
            origin: None,
        }
    }

    pub async fn get(
        &self,
        signer: &LocalWallet,
        api_base_url: &str,
        decrypted_pgp_pvt_key: Option<String>,
        pgp_public_key: Option<String>,
        version: &Version,
        additional_metadata: Option<AdditionalMeta>,
    ) -> Result<Self, Box<dyn Error>> {
        let caip10_account = wallet_to_pcaip10(&signer.address().to_string());

        let request_url = format!("{}/v2/users/?caip10={}", api_base_url, caip10_account);

        let client = Client::new();

        let user_response = client.get(&request_url).send().await?;
        if user_response.status().is_success() {
            let data = user_response.json::<User>().await?;
            if data.encrypted_private_key.is_some() {
                let decrypted_private_key = match decrypted_pgp_pvt_key {
                    Some(key) => key,
                    None => {
                        decrypt_pgp_key(
                            &data.encrypted_private_key.clone().unwrap(),
                            signer,
                            version,
                            additional_metadata,
                        )
                        .await?
                    }
                };

                let public_key = match pgp_public_key {
                    Some(key) => Some(key),
                    None => data.public_key,
                };

                return Ok(User {
                    public_key,
                    encrypted_private_key: data.encrypted_private_key,
                    decrypted_private_key: Some(decrypted_private_key),
                    did: data.did,
                    wallets: data.wallets,
                    verification_proof: data.verification_proof,
                    msg_sent: data.msg_sent,
                    max_msg_persisted: data.max_msg_persisted,
                    profile: data.profile,
                    origin: data.origin,
                });
            } else {
                return Err("User data invalid".into());
            }
        } else {
            Err(format!(
                "User not found: {} - {}",
                user_response.status(),
                user_response.text().await?
            )
            .into())
        }
    }

    pub async fn create(
        &mut self,
        signer: &LocalWallet,
        api_base_url: &str,
        version: &Version,
    ) -> Result<Self, Box<dyn Error>> {
        let client = Client::new();
        let create_url = format!("{}/v2/users/", api_base_url);
        let additional_meta = get_additional_meta();
        let secret = get_secret(&version, signer).await?;

        let key_pair = generate_key_pair();
        let public_key = key_pair.public_key;
        let private_key = key_pair.private_key;

        let prepared_public_key = prepare_pgp_public_key(&version, &public_key)?;
        let encrypted_private_key = to_string(&encrypt_private_key(
            &version,
            &private_key,
            &secret,
            additional_meta,
        )?)
        .map_err(|_| "Failed to serialize encryptedPrivateKey")?;

        let caip10 = wallet_to_pcaip10(&signer.address().to_string());

        let user = if is_valid_nft_caip(&caip10) {
            let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if caip10.split(':').count() != 6 {
                format!("{}:{}", caip10, epoch)
            } else {
                caip10.clone()
            }
        } else {
            caip10.clone()
        };

        let data_to_sign = json!({
            "caip10": user,
            "did": user,
            "publicKey": prepared_public_key,
            "encryptedPrivateKey": encrypted_private_key,
        });

        let verification_proof =
            get_eip191_signature(signer, &to_string(&data_to_sign)?, &version).await?;

        let mut payload = json!({
            "caip10": user,
            "did": user,
            "publicKey": prepared_public_key,
            "encryptedPrivateKey": encrypted_private_key,
            "origin": "push_crate",
        });
        let create_payload = payload.as_object_mut().unwrap();
        create_payload.extend(verification_proof.as_object().unwrap().clone());

        println!("{:?}", create_payload);

        let create_response = client
            .post(&create_url)
            .json(&create_payload)
            .send()
            .await?;
        if create_response.status().is_success() {
            let data = create_response.json::<User>().await?;
            Ok(User {
                public_key: Some(prepared_public_key),
                encrypted_private_key: data.encrypted_private_key,
                decrypted_private_key: Some(private_key),
                did: data.did,
                wallets: data.wallets,
                verification_proof: data.verification_proof,
                msg_sent: data.msg_sent,
                max_msg_persisted: data.max_msg_persisted,
                profile: data.profile,
                origin: data.origin,
            })
        } else {
            Err(format!(
                "Failed to create user: {} - {}",
                create_response.status(),
                create_response.text().await?
            )
            .into())
        }
    }
}

fn wallet_to_pcaip10(account: &str) -> String {
    if account.contains("eip155:") {
        account.to_lowercase()
    } else {
        format!("eip155:{}", account.to_lowercase())
    }
}

fn generate_random_secret(length: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

async fn get_secret(version: &Version, wallet: &LocalWallet) -> Result<Vec<u8>, Box<dyn Error>> {
    match version {
        Version::EncTypeV1 => {
            let public_key = wallet.address().as_bytes().to_vec();
            Ok(public_key)
        }
        Version::EncTypeV2 => {
            let input = generate_random_secret(32);
            let enable_message = format!("Enable Push Chat Profile \n{}", input);
            let signature = wallet.sign_message(enable_message.as_bytes()).await?;
            Ok(signature.to_vec())
        }
        Version::EncTypeV3 => {
            let input = generate_random_secret(32);
            let enable_message = format!("Enable Push Profile \n{}", input);
            let signature = wallet.sign_message(enable_message.as_bytes()).await?;
            Ok(signature.to_vec())
        }
        Version::EncTypeV4 => Err("ENC_TYPE_V4 requires additional_meta with password".into()),
    }
}

fn get_additional_meta() -> Option<AdditionalMeta> {
    Some(AdditionalMeta {
        nftpgp_v1: Some(NFTPGP {
            password: format!("$0Pc{}", generate_random_secret(10)),
        }),
    })
}

fn is_valid_nft_caip(wallet: &str) -> bool {
    let wallet_component: Vec<&str> = wallet.split(':').collect();

    if wallet_component.len() != 5 && wallet_component.len() != 6 {
        return false;
    }

    if wallet_component[0].to_lowercase() != "nft" {
        return false;
    }

    if wallet_component[1] != "eip155" {
        return false;
    }

    if wallet_component[2].parse::<u64>().is_err()
        || wallet_component[2].parse::<u64>().unwrap() <= 0
    {
        return false;
    }

    if wallet_component[4].parse::<u64>().is_err()
        || wallet_component[4].parse::<u64>().unwrap() <= 0
    {
        return false;
    }

    if !is_valid_evm_address(wallet_component[3]) {
        return false;
    }

    true
}

fn is_valid_evm_address(address: &str) -> bool {
    if address.len() != 42 || !address.starts_with("0x") {
        return false;
    }

    address[2..].chars().all(|c| c.is_digit(16))
}

async fn get_eip191_signature(
    wallet: &LocalWallet,
    message: &String,
    version: &Version,
) -> Result<Value, Box<dyn Error>> {
    let signature = wallet.sign_message(message).await?;

    let sig_type = if *version == Version::EncTypeV1 {
        "eip191"
    } else {
        "eip191v2"
    };

    let verification_proof = format!(
        "{}:{}",
        sig_type,
        format!("0x{}", hex::encode(signature.to_vec()))
    );

    Ok(json!({ "verificationProof": verification_proof }))
}
