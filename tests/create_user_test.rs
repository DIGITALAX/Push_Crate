#[cfg(test)]
mod tests {
    use dotenv::dotenv;
    use ethers::signers::LocalWallet;
    use push_crate::{
        config::Env,
        push_api::{PushAPI, Version},
    };
    use rand::rngs::OsRng;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn setup_logging() {
        INIT.call_once(|| {
            env_logger::init();
        });
    }

    #[tokio::test]
    async fn test_initialize_in_staging() {
        dotenv().ok();
        setup_logging();

        // let signer =
        //     LocalWallet::from_str(&env::var("SIGNER").expect("SIGNER must be set in .env file"))
        //         .expect("Failed to create LocalWallet");
        let mut rng = OsRng;
        let signer = LocalWallet::new(&mut rng);

        let mut push = PushAPI::new(Env::Staging, Some(signer), None, Some(Version::EncTypeV3));
        let result = push.initialize(true, None, None, None).await;

        assert!(result.is_ok(), "Initialization failed: {:?}", result);
    }
}
