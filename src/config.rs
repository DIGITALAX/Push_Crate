use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::push_api::Version;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Env {
    Prod,
    Staging,
    Dev,
}

impl Env {
    pub fn as_str(&self) -> &'static str {
        match self {
            Env::Prod => "prod",
            Env::Staging => "staging",
            Env::Dev => "dev",
        }
    }
}

const API_BASE_URL: &[(Env, &str)] = &[
    (Env::Prod, "https://backend.epns.io/apis"),
    (Env::Staging, "https://backend.epns.io/apis"),
    (Env::Dev, "https://backend.epns.io/apis"),
];

const COMMUNICATOR_CONTRACT: &[(Env, &str)] = &[
    (Env::Prod, "0xb3971BCef2D791bc4027BbfedFb47319A4AAaaAa"),
    (Env::Staging, "0xb3971BCef2D791bc4027BbfedFb47319A4AAaaAa"),
    (Env::Dev, "0x9cb3bd7550b5c92baa056fc0f08132f49508145f"),
];

const BLOCKCHAIN_NETWORK: &[(&str, &str)] = &[
    ("ETH_MAINNET", "eip155:1"),
    ("POLYGON_MAINNET", "eip155:137"),
    ("POLYGON_AMOY", "eip155:80002"),
];

 const VERSIONS: &[(Version, &str)] = &[
    (Version::EncTypeV1, "x25519-xsalsa20-poly1305"),
    (Version::EncTypeV2, "aes256GcmHkdfSha256"),
    (Version::EncTypeV3, "eip191-aes256-gcm-hkdf-sha256"),
    (Version::EncTypeV4, "pgpv1:nft"),
];

const ETH_CHAIN_ID: &[(Env, u32)] = &[
    (Env::Prod, 1),
    (Env::Staging, 11155111),
    (Env::Dev, 11155111),
];

const MIN_TOKEN_BALANCE: &[(Env, u32)] = &[(Env::Prod, 50), (Env::Staging, 50), (Env::Dev, 50)];

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub network: String,
    pub api_base_url: String,
    pub communicator_contract: String,
}

impl NetworkConfig {
    pub fn new(network: &str, api_base_url: &str, communicator_contract: &str) -> Self {
        Self {
            network: network.to_string(),
            api_base_url: api_base_url.to_string(),
            communicator_contract: communicator_contract.to_string(),
        }
    }
}

pub fn get_version(version: &Version) -> Option<&'static str> {
    VERSIONS
        .iter()
        .find(|(v, _)| v == version)
        .map(|(_, url)| *url)
}


pub fn get_api_base_url(env: &Env) -> Option<&'static str> {
    API_BASE_URL
        .iter()
        .find(|(e, _)| e == env)
        .map(|(_, url)| *url)
}

pub fn get_communicator_contract(env: &Env) -> Option<&'static str> {
    COMMUNICATOR_CONTRACT
        .iter()
        .find(|(e, _)| e == env)
        .map(|(_, url)| *url)
}

pub fn get_network_config(env: &Env) -> HashMap<&'static str, NetworkConfig> {
    let api_base_url = get_api_base_url(env).unwrap_or_default();
    let communicator_contract = get_communicator_contract(env).unwrap_or_default();

    let mut configs = HashMap::new();
    configs.insert(
        "ETH_MAINNET",
        NetworkConfig::new("mainnet", api_base_url, communicator_contract),
    );
    configs.insert(
        "POLYGON_MAINNET",
        NetworkConfig::new("polygon", api_base_url, communicator_contract),
    );
    configs.insert(
        "POLYGON_AMOY",
        NetworkConfig::new("amoy", api_base_url, communicator_contract),
    );
    configs
}
