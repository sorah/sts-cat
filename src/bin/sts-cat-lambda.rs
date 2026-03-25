#[cfg(feature = "aws-lambda")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    use clap::Parser as _;
    let config = sts_cat::config::Config::parse();

    let signer = config.build_signer().await?;
    let github =
        sts_cat::github::GitHubClient::new(&config.github_api_url, config.github_app_id, signer);
    let oidc = sts_cat::oidc::OidcVerifier::new();

    let policy_cache = moka::future::Cache::builder()
        .max_capacity(200)
        .time_to_live(std::time::Duration::from_secs(300))
        .build();

    let installation_cache = moka::future::Cache::builder().max_capacity(200).build();

    let state = std::sync::Arc::new(sts_cat::exchange::AppState {
        config,
        github,
        oidc,
        policy_cache,
        installation_cache,
    });

    let router = sts_cat::exchange::build_router(state);
    lambda_http::run(router)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    Ok(())
}

#[cfg(not(feature = "aws-lambda"))]
fn main() {
    eprintln!("sts-cat-lambda requires the 'aws-lambda' feature");
    std::process::exit(1);
}
