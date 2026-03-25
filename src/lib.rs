pub mod config;
pub mod error;
pub mod exchange;
pub mod github;
pub mod oidc;
pub mod signer;
pub mod trust_policy;

pub fn init_tracing() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}
