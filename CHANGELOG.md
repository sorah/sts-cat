## 0.2.0 (2026-03-29)

### Enhancements

- Tracing
    - Log `remote_addr` and `xff` (X-Forwarded-For) on all exchange events (`exchange_denied`, `exchange_authorized`, `exchange_success`)
    - Add `tower_http::trace::TraceLayer` with request span logging at INFO level, including `method`, `uri`, `remote_addr`, and `xff`
    - Add `#[tracing::instrument]` spans to internal I/O methods (OIDC discovery, JWKS fetch, GitHub API calls, KMS signing)
    - Lambda binary: use `lambda_http::tracing` subscriber instead of custom `init_tracing`; set `AWS_LAMBDA_LOG_FORMAT=JSON` when `--log-json` is given
    - Lambda binary: inject `source_ip` from Lambda request context (API Gateway V2/V1, ALB) into `X-Forwarded-For` header

## 0.1.0 (2026-03-29)

- Initial release.
