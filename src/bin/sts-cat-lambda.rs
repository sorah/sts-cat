#[cfg(feature = "aws-lambda")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser as _;

    let config = sts_cat::config::Config::parse();
    if config.log_json {
        // SAFETY: called before any other threads are spawned (prior to
        // lambda_http::run and tracing init).
        unsafe { std::env::set_var("AWS_LAMBDA_LOG_FORMAT", "JSON") };
    }
    lambda_http::tracing::init_default_subscriber();

    let state = sts_cat::exchange::AppState::build(config).await?;
    let router =
        sts_cat::exchange::build_router(state).layer(axum::middleware::from_fn(inject_source_ip));

    lambda_http::run(router)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    Ok(())
}

#[cfg(feature = "aws-lambda")]
async fn inject_source_ip(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use lambda_http::RequestExt as _;

    let source_ip = match req.request_context_ref() {
        Some(lambda_http::request::RequestContext::ApiGatewayV2(ctx)) => ctx.http.source_ip.clone(),
        Some(lambda_http::request::RequestContext::ApiGatewayV1(ctx)) => {
            ctx.identity.source_ip.clone()
        }
        Some(lambda_http::request::RequestContext::Alb(_)) => req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned()),
        _ => None,
    };
    if let Some(ip) = source_ip
        && let Ok(val) = axum::http::HeaderValue::from_str(&ip)
    {
        req.headers_mut().insert("x-forwarded-for", val);
    }
    next.run(req).await
}

#[cfg(feature = "aws-lambda")]
#[cfg(test)]
mod tests {
    use super::*;

    async fn echo_xff(headers: axum::http::HeaderMap) -> String {
        headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned()
    }

    fn build_test_router() -> axum::Router {
        axum::Router::new()
            .route("/test", axum::routing::get(echo_xff))
            .layer(axum::middleware::from_fn(inject_source_ip))
    }

    fn apigw_v2_context(source_ip: &str) -> lambda_http::request::RequestContext {
        use lambda_http::aws_lambda_events::apigw::*;
        lambda_http::request::RequestContext::ApiGatewayV2(ApiGatewayV2httpRequestContext {
            http: ApiGatewayV2httpRequestContextHttpDescription {
                source_ip: Some(source_ip.to_owned()),
                ..Default::default()
            },
            ..Default::default()
        })
    }

    fn apigw_v1_context(source_ip: &str) -> lambda_http::request::RequestContext {
        use lambda_http::aws_lambda_events::apigw::*;
        lambda_http::request::RequestContext::ApiGatewayV1(ApiGatewayProxyRequestContext {
            identity: ApiGatewayRequestIdentity {
                source_ip: Some(source_ip.to_owned()),
                ..Default::default()
            },
            ..Default::default()
        })
    }

    fn alb_context() -> lambda_http::request::RequestContext {
        use lambda_http::aws_lambda_events::alb::*;
        lambda_http::request::RequestContext::Alb(AlbTargetGroupRequestContext {
            elb: ElbContext {
                target_group_arn: None,
            },
        })
    }

    #[tokio::test]
    async fn test_inject_source_ip_apigw_v2() {
        use axum::body::Body;
        use lambda_http::http::Request;
        use lambda_http::tower::ServiceExt as _;

        let mut req = Request::get("/test").body(Body::empty()).unwrap();
        req.extensions_mut().insert(apigw_v2_context("1.2.3.4"));

        let resp = build_test_router().oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "1.2.3.4");
    }

    #[tokio::test]
    async fn test_inject_source_ip_apigw_v1() {
        use axum::body::Body;
        use lambda_http::http::Request;
        use lambda_http::tower::ServiceExt as _;

        let mut req = Request::get("/test").body(Body::empty()).unwrap();
        req.extensions_mut().insert(apigw_v1_context("5.6.7.8"));

        let resp = build_test_router().oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "5.6.7.8");
    }

    #[tokio::test]
    async fn test_inject_source_ip_alb() {
        use axum::body::Body;
        use lambda_http::http::Request;
        use lambda_http::tower::ServiceExt as _;

        let mut req = Request::get("/test")
            .header("x-forwarded-for", "9.10.11.12")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(alb_context());

        let resp = build_test_router().oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "9.10.11.12");
    }

    #[tokio::test]
    async fn test_inject_source_ip_no_context() {
        use axum::body::Body;
        use lambda_http::http::Request;
        use lambda_http::tower::ServiceExt as _;

        let req = Request::get("/test").body(Body::empty()).unwrap();

        let resp = build_test_router().oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "");
    }
}

#[cfg(not(feature = "aws-lambda"))]
fn main() {
    eprintln!("sts-cat-lambda requires the 'aws-lambda' feature");
    std::process::exit(1);
}
