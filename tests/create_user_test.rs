#[cfg(test)]
mod tests {
    use ethers::signers::LocalWallet;
    use push_crate::{config::Env, push_api::PushAPI};
    use std::{error::Error, str::FromStr, sync::Once};

    static INIT: Once = Once::new();

    fn setup_logging() {
        INIT.call_once(|| {
            env_logger::init();
        });
    }

    #[tokio::test]
    async fn test_initialize_in_staging() {
        setup_logging();

        let signer = LocalWallet::from_str(
            "",
        )
        .expect("Failed to create LocalWallet");

        let options = PushAPIInitializeProps {
            env: Env::Staging,
            version: Some("ENC_TYPE_V3".to_string()),
            origin: None,
            decrypted_pgp_private_key: None,
        };

        let result: Result<PushAPI, Box<dyn Error>> =
            PushAPI::initialize(Some(signer), options).await;

        assert!(result.is_ok(), "Initialization failed: {:?}", result);

        let push_api = result.unwrap();

        assert_eq!(push_api.env, Env::Staging, "Environment mismatch");
        assert!(
            push_api.account.starts_with("0x"),
            "Account should start with 0x"
        );
        assert!(!push_api.read_mode, "Read mode should be false");
        assert!(
            push_api.pgp_public_key.is_some(),
            "PGP public key should not be None"
        );
        assert!(
            push_api.decrypted_pgp_pvt_key.is_some(),
            "Decrypted PGP private key should not be None"
        );

        println!(
            "PushAPI initialized successfully with account: {}",
            push_api.account
        );
    }
}
