#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser as _;
    let config = sts_cat::config::Config::parse();
    sts_cat::init_tracing(config.log_json);
    let addr = format!("{}:{}", config.host, config.port);

    let state = sts_cat::exchange::AppState::build(config).await?;
    let router = sts_cat::exchange::build_router(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(addr = %addr, "sts-cat HTTP server listening");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}
