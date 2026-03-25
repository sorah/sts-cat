#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthenticated: {0}")]
    Unauthenticated(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("rate limited")]
    RateLimited,

    #[error("GitHub API error")]
    GitHubApi(#[source] reqwest::Error),

    #[error("OIDC discovery error")]
    OidcDiscovery(#[source] reqwest::Error),

    #[error("OIDC HTTP error: {0}")]
    OidcHttpError(u16),

    #[error("JWT verification failed")]
    JwtVerification(#[from] jsonwebtoken::errors::Error),

    #[error("trust policy parse error")]
    PolicyParse(#[from] toml::de::Error),

    #[error("regex compilation error")]
    RegexCompile(#[from] regex::Error),

    #[error("internal error: {0}")]
    Internal(Box<dyn std::error::Error + Send + Sync>),
}

impl axum::response::IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match &self {
            Error::BadRequest(_) => (axum::http::StatusCode::BAD_REQUEST, "bad request"),
            Error::Unauthenticated(_) => (
                axum::http::StatusCode::UNAUTHORIZED,
                "unable to verify bearer token",
            ),
            Error::PermissionDenied(_) => (axum::http::StatusCode::FORBIDDEN, "permission denied"),
            Error::NotFound(_) => (axum::http::StatusCode::NOT_FOUND, "not found"),
            Error::RateLimited => (axum::http::StatusCode::TOO_MANY_REQUESTS, "rate limited"),
            Error::GitHubApi(e) => {
                tracing::error!(error = %e, "GitHub API error");
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error",
                )
            }
            Error::OidcDiscovery(e) => {
                tracing::error!(error = %e, "OIDC discovery error");
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error",
                )
            }
            Error::OidcHttpError(code) => {
                tracing::debug!(status = code, "OIDC HTTP error");
                (
                    axum::http::StatusCode::UNAUTHORIZED,
                    "unable to verify bearer token",
                )
            }
            Error::JwtVerification(_) => (
                axum::http::StatusCode::UNAUTHORIZED,
                "unable to verify bearer token",
            ),
            Error::PolicyParse(e) => {
                tracing::debug!(error = %e, "trust policy parse error");
                (axum::http::StatusCode::NOT_FOUND, "not found")
            }
            Error::RegexCompile(e) => {
                tracing::debug!(error = %e, "regex compilation error in trust policy");
                (axum::http::StatusCode::NOT_FOUND, "not found")
            }
            Error::Internal(e) => {
                tracing::error!(error = %e, "internal error");
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error",
                )
            }
        };

        // Log 4xx at debug, 5xx already logged above
        match &self {
            Error::BadRequest(msg) => tracing::debug!(error = %msg, "bad request"),
            Error::Unauthenticated(msg) => tracing::debug!(error = %msg, "unauthenticated"),
            Error::PermissionDenied(msg) => tracing::debug!(error = %msg, "permission denied"),
            Error::NotFound(msg) => tracing::debug!(error = %msg, "not found"),
            Error::JwtVerification(e) => tracing::debug!(error = %e, "JWT verification failed"),
            _ => {}
        }

        let body = serde_json::json!({"error": message});
        (status, axum::Json(body)).into_response()
    }
}
