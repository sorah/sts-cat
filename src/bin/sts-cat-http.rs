#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // HOST/PORT fallback: set STS_CAT_HOST/STS_CAT_PORT from HOST/PORT
    // if the STS_CAT_ prefixed versions are not set
    if std::env::var("STS_CAT_HOST").is_err()
        && let Ok(host) = std::env::var("HOST")
    {
        unsafe { std::env::set_var("STS_CAT_HOST", host) };
    }
    if std::env::var("STS_CAT_PORT").is_err()
        && let Ok(port) = std::env::var("PORT")
    {
        unsafe { std::env::set_var("STS_CAT_PORT", port) };
    }

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
        config: config.clone(),
        github,
        oidc,
        policy_cache,
        installation_cache,
    });

    let router = sts_cat::exchange::build_router(state);
    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(addr = %addr, "sts-cat HTTP server listening");
    axum::serve(listener, router).await?;

    Ok(())
}
