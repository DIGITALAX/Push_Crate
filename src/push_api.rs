use crate::{
    config::{get_api_base_url, Env},
    user::{AdditionalMeta, User},
};
use ethers::{prelude::*, signers::Signer};
use std::error::Error;

#[derive(Debug)]
pub struct PushAPI {
    pub signer: Option<LocalWallet>,
    pub account: Option<String>,
    pub version: Option<Version>,
    pub env: Env,
    pub user: Option<User>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Version {
    EncTypeV1,
    EncTypeV2,
    EncTypeV3,
    EncTypeV4,
}

impl Version {
    pub fn as_str(&self) -> &'static str {
        match self {
            Version::EncTypeV1 => "ENC_TYPE_V1",
            Version::EncTypeV2 => "ENC_TYPE_V2",
            Version::EncTypeV3 => "ENC_TYPE_V3",
            Version::EncTypeV4 => "ENC_TYPE_V4",
        }
    }
}

impl PushAPI {
    pub fn new(
        env: Env,
        signer: Option<LocalWallet>,
        account: Option<String>,
        version: Option<Version>,
    ) -> Self {
        PushAPI {
            env,
            account,
            signer,
            version,
            user: None,
        }
    }

    pub async fn initialize(
        &mut self,
        create: bool,
        decrypted_pgp_pvt_key: Option<String>,
        pgp_public_key: Option<String>,
        additional_metadata: Option<AdditionalMeta>,
    ) -> Result<(), Box<dyn Error>> {
        if self.account.is_none() && self.signer.is_none() {
            return Err("Must provide either an account or a signer".into());
        }

        if self.account.is_none() {
            let signer_address = format!("{:?}", self.signer.clone().unwrap().address());
            self.account = Some(signer_address);
        }

        let version = self.version.clone().unwrap_or_else(|| Version::EncTypeV3);
        self.version = Some(version.clone());
        let api_base_url = get_api_base_url(&self.env).ok_or("API Base URL not found")?;

        let mut user = User::new();

        if !create {
            user.get(
                &self.signer.clone().unwrap(),
                &api_base_url,
                decrypted_pgp_pvt_key,
                pgp_public_key,
                &version,
                additional_metadata,
            )
            .await?;
        } else if create && self.signer.is_some() {
            user.create(
                &self.signer.clone().unwrap(),
                &api_base_url,
                &version,
            )
            .await?;
        }

        self.user = Some(user);

        Ok(())
    }
}
