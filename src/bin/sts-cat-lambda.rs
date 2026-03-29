#[cfg(feature = "aws-lambda")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser as _;
    let config = sts_cat::config::Config::parse();
    sts_cat::init_tracing(config.log_json);

    let state = sts_cat::exchange::AppState::build(config).await?;
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
