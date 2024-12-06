#[cfg(test)]
mod tests {
    use dotenv::dotenv;
    use ethers::{
        middleware::SignerMiddleware,
        providers::{Http, Provider},
        signers::{LocalWallet, Signer},
        types::Chain,
    };
    use push_crate::{
        config::Env,
        push_api::{PushAPI, Version},
    };
    use rand::thread_rng;
    use std::sync::{Arc, Once};

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

        let provider = Arc::new(Provider::<Http>::try_from("https://eth-sepolia.g.alchemy.com/v2/demo").unwrap());

        let wallet = LocalWallet::new(&mut thread_rng()).with_chain_id(Chain::Sepolia);

        let signer = SignerMiddleware::new(provider.clone(), wallet);
  
        let mut push = PushAPI::new(Env::Prod, Some(signer), None, Some(Version::EncTypeV3));
        let result = push.initialize(true, None, None, None).await;

        assert!(result.is_ok(), "Initialization failed: {:?}", result);
    }
}
