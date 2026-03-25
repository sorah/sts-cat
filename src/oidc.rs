use crate::error::Error;

const MAX_RESPONSE_SIZE: usize = 100 * 1024; // 100 KiB

static PATH_CHAR_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"^[a-zA-Z0-9\-._~/]+$").unwrap());

pub fn validate_issuer(issuer: &str) -> Result<(), Error> {
    if issuer.is_empty() || issuer.chars().count() > 255 {
        return Err(Error::Unauthenticated(
            "issuer empty or exceeds 255 characters".into(),
        ));
    }

    let parsed = url::Url::parse(issuer)
        .map_err(|_| Error::Unauthenticated("issuer is not a valid URL".into()))?;

    match parsed.scheme() {
        "https" => {}
        "http" => match parsed.host() {
            Some(url::Host::Domain("localhost")) => {}
            Some(url::Host::Ipv4(ip)) if ip == std::net::Ipv4Addr::LOCALHOST => {}
            Some(url::Host::Ipv6(ip)) if ip == std::net::Ipv6Addr::LOCALHOST => {}
            _ => {
                return Err(Error::Unauthenticated("issuer must use HTTPS".into()));
            }
        },
        _ => {
            return Err(Error::Unauthenticated("issuer must use HTTPS".into()));
        }
    }

    // Check both parsed and raw: url::Url may normalize away certain encodings
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(Error::Unauthenticated(
            "issuer must not contain query or fragment".into(),
        ));
    }
    if issuer.contains('?') || issuer.contains('#') {
        return Err(Error::Unauthenticated(
            "issuer must not contain query or fragment".into(),
        ));
    }

    if parsed.host_str().is_none() || parsed.host_str() == Some("") {
        return Err(Error::Unauthenticated("issuer must have a host".into()));
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::Unauthenticated(
            "issuer must not contain userinfo".into(),
        ));
    }

    // ASCII-only hostname — check the raw input string because url::Url
    // converts IDN to punycode (e.g. exämple.com → xn--exmple-cua.com)
    let raw_host = {
        let after_scheme = issuer
            .strip_prefix(parsed.scheme())
            .and_then(|s| s.strip_prefix("://"))
            .unwrap_or("");
        let host_part = if let Some(pos) = after_scheme.find('/') {
            &after_scheme[..pos]
        } else {
            after_scheme
        };
        if host_part.starts_with('[') {
            // IPv6: take everything including brackets
            host_part.to_owned()
        } else if let Some(pos) = host_part.rfind(':') {
            host_part[..pos].to_owned()
        } else {
            host_part.to_owned()
        }
    };
    for ch in raw_host.chars() {
        if ch as u32 > 127 {
            return Err(Error::Unauthenticated(
                "issuer hostname must be ASCII-only".into(),
            ));
        }
        if ch.is_control() || ch.is_whitespace() {
            return Err(Error::Unauthenticated(
                "issuer hostname contains invalid characters".into(),
            ));
        }
    }

    // Path validation — use the raw issuer string to extract the path,
    // since url::Url normalizes away `.` and `..` segments.
    let raw_path = issuer
        .strip_prefix(parsed.scheme())
        .and_then(|s| s.strip_prefix("://"))
        .and_then(|s| s.find('/').map(|pos| &s[pos..]))
        .unwrap_or("");
    let path = if raw_path.is_empty() {
        parsed.path()
    } else {
        raw_path
    };
    if !path.is_empty() && path != "/" {
        if !path.starts_with('/') {
            return Err(Error::Unauthenticated(
                "issuer path must start with /".into(),
            ));
        }
        if path.contains("..") {
            return Err(Error::Unauthenticated(
                "issuer path must not contain ..".into(),
            ));
        }
        if path.contains("//") {
            return Err(Error::Unauthenticated(
                "issuer path must not contain //".into(),
            ));
        }
        if path.contains("~~") {
            return Err(Error::Unauthenticated(
                "issuer path must not contain ~~".into(),
            ));
        }
        if path.ends_with('~') {
            return Err(Error::Unauthenticated(
                "issuer path must not end with ~".into(),
            ));
        }

        if !PATH_CHAR_RE.is_match(path) {
            return Err(Error::Unauthenticated(
                "issuer path contains invalid characters".into(),
            ));
        }

        for segment in path.split('/') {
            if segment.is_empty() {
                continue;
            }
            if segment == "." || segment == ".." || segment == "~" {
                return Err(Error::Unauthenticated(
                    "issuer path contains invalid segment".into(),
                ));
            }
            if segment.len() > 150 {
                return Err(Error::Unauthenticated(
                    "issuer path segment exceeds 150 characters".into(),
                ));
            }
        }
    }

    Ok(())
}

const SUBJECT_REJECT_CHARS: &str = "\"'`\\<>;&$(){}[]";
const AUDIENCE_REJECT_CHARS: &str = "\"'`\\<>;|&$(){}[]@";

pub fn validate_subject(value: &str) -> Result<(), Error> {
    validate_claim_string(value, SUBJECT_REJECT_CHARS, "subject")
}

pub fn validate_audience(value: &str) -> Result<(), Error> {
    validate_claim_string(value, AUDIENCE_REJECT_CHARS, "audience")
}

fn validate_claim_string(value: &str, reject_chars: &str, field: &str) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::Unauthenticated(format!("{field} must not be empty")));
    }
    if value.chars().count() > 255 {
        return Err(Error::Unauthenticated(format!(
            "{field} exceeds 255 characters"
        )));
    }
    for ch in value.chars() {
        if (ch as u32) <= 0x1f {
            return Err(Error::Unauthenticated(format!(
                "{field} contains control characters"
            )));
        }
        if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
            return Err(Error::Unauthenticated(format!(
                "{field} contains whitespace"
            )));
        }
        if reject_chars.contains(ch) {
            return Err(Error::Unauthenticated(format!(
                "{field} contains invalid character"
            )));
        }
        if !ch.is_alphanumeric() && !ch.is_ascii_punctuation() && ch as u32 > 127 {
            // Approximate Go's unicode.IsPrint (categories L, M, N, P, S, Zs)
            if !is_printable(ch) {
                return Err(Error::Unauthenticated(format!(
                    "{field} contains non-printable character"
                )));
            }
        }
    }
    Ok(())
}

fn is_printable(ch: char) -> bool {
    !ch.is_control() && ch as u32 != 0xFFFD
}

#[derive(Debug, serde::Deserialize)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub jwks_uri: String,
}

#[derive(Debug, Clone)]
pub struct OidcProvider {
    pub issuer: String,
    pub jwks: jsonwebtoken::jwk::JwkSet,
}

pub struct OidcVerifier {
    http: reqwest::Client,
    cache: moka::future::Cache<String, std::sync::Arc<OidcProvider>>,
}

impl Default for OidcVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct TokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: OneOrMany,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        let slice: &[String] = match self {
            OneOrMany::One(s) => std::slice::from_ref(s),
            OneOrMany::Many(v) => v.as_slice(),
        };
        slice.iter().map(|s| s.as_str())
    }
}

impl OidcVerifier {
    pub fn new() -> Self {
        let redirect_policy = reqwest::redirect::Policy::custom(|attempt| {
            let url_str = attempt.url().to_string();
            if validate_issuer(&url_str).is_err() {
                attempt.error(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("redirect to invalid issuer URL: {url_str}"),
                ))
            } else {
                attempt.follow()
            }
        });

        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .redirect(redirect_policy)
            .user_agent(format!("sts-cat/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("failed to build OIDC HTTP client");

        let cache = moka::future::Cache::builder().max_capacity(100).build();

        Self { http, cache }
    }

    async fn discover(&self, issuer: &str) -> Result<std::sync::Arc<OidcProvider>, Error> {
        if let Some(provider) = self.cache.get(issuer).await {
            return Ok(provider);
        }

        let provider = self.discover_with_retry(issuer).await?;
        let provider = std::sync::Arc::new(provider);
        self.cache.insert(issuer.to_owned(), provider.clone()).await;
        Ok(provider)
    }

    async fn discover_with_retry(&self, issuer: &str) -> Result<OidcProvider, Error> {
        use backon::Retryable as _;

        let discover_fn = || async { self.discover_once(issuer).await };

        discover_fn
            .retry(
                backon::ExponentialBuilder::default()
                    .with_min_delay(std::time::Duration::from_secs(1))
                    .with_max_delay(std::time::Duration::from_secs(30))
                    .with_factor(2.0)
                    .with_jitter()
                    .with_max_times(6),
            )
            .when(|e| !is_permanent_error(e))
            .await
    }

    async fn discover_once(&self, issuer: &str) -> Result<OidcProvider, Error> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );

        let resp = self
            .http
            .get(&discovery_url)
            .send()
            .await
            .map_err(Error::OidcDiscovery)?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OidcHttpError(status.as_u16()));
        }

        let body = read_limited_body(resp, MAX_RESPONSE_SIZE, Error::OidcDiscovery).await?;
        let doc: OidcDiscoveryDocument =
            serde_json::from_slice(&body).map_err(|e| Error::Internal(Box::new(e)))?;

        let jwks_resp = self
            .http
            .get(&doc.jwks_uri)
            .send()
            .await
            .map_err(Error::OidcDiscovery)?;

        if !jwks_resp.status().is_success() {
            return Err(Error::OidcHttpError(jwks_resp.status().as_u16()));
        }

        let jwks_body =
            read_limited_body(jwks_resp, MAX_RESPONSE_SIZE, Error::OidcDiscovery).await?;
        let jwks: jsonwebtoken::jwk::JwkSet =
            serde_json::from_slice(&jwks_body).map_err(|e| Error::Internal(Box::new(e)))?;

        Ok(OidcProvider {
            issuer: doc.issuer,
            jwks,
        })
    }

    pub async fn verify(&self, token: &str) -> Result<TokenClaims, Error> {
        let header = jsonwebtoken::decode_header(token)?;

        // Extract issuer without signature verification to discover the OIDC provider
        let mut validation = jsonwebtoken::Validation::default();
        validation.insecure_disable_signature_validation();
        validation.validate_aud = false;
        validation.validate_exp = false;

        let unverified: jsonwebtoken::TokenData<TokenClaims> = jsonwebtoken::decode(
            token,
            &jsonwebtoken::DecodingKey::from_secret(&[]),
            &validation,
        )?;

        let issuer = &unverified.claims.iss;

        validate_issuer(issuer)?;
        let provider = self.discover(issuer).await?;

        let kid = header.kid.as_deref();
        let decoding_key = find_decoding_key(&provider.jwks, kid, &header.alg)?;

        let mut verification = jsonwebtoken::Validation::new(header.alg);
        verification.validate_aud = false; // Audience checked later by trust policy
        verification.set_issuer(&[issuer]);

        let token_data: jsonwebtoken::TokenData<TokenClaims> =
            jsonwebtoken::decode(token, &decoding_key, &verification)?;

        Ok(token_data.claims)
    }
}

fn find_decoding_key(
    jwks: &jsonwebtoken::jwk::JwkSet,
    kid: Option<&str>,
    alg: &jsonwebtoken::Algorithm,
) -> Result<jsonwebtoken::DecodingKey, Error> {
    let jwk = if let Some(kid) = kid {
        jwks.find(kid).ok_or_else(|| {
            Error::Unauthenticated(format!("no matching key found for kid: {kid}"))
        })?
    } else {
        let alg_str = format!("{alg:?}");
        jwks.keys
            .iter()
            .find(|k| {
                k.common
                    .key_algorithm
                    .is_some_and(|ka| format!("{ka:?}") == alg_str)
            })
            .or_else(|| jwks.keys.first())
            .ok_or_else(|| Error::Unauthenticated("no keys in JWKS".into()))?
    };

    jsonwebtoken::DecodingKey::from_jwk(jwk)
        .map_err(|e| Error::Unauthenticated(format!("invalid JWK: {e}")))
}

fn is_permanent_error(e: &Error) -> bool {
    match e {
        // HTTP 4xx (except 408, 429) and 501 are permanent
        Error::OidcHttpError(code) => matches!(
            code,
            400 | 401 | 403 | 404 | 405 | 406 | 410 | 415 | 422 | 501
        ),
        Error::OidcDiscovery(_) => false, // Network errors are transient
        _ => true,                        // Parse errors etc. are permanent
    }
}

pub(crate) async fn read_limited_body(
    resp: reqwest::Response,
    limit: usize,
    map_err: impl Fn(reqwest::Error) -> Error,
) -> Result<Vec<u8>, Error> {
    if let Some(len) = resp.content_length()
        && len as usize > limit
    {
        return Err(Error::Unauthenticated(format!(
            "response too large: {len} bytes (limit: {limit})"
        )));
    }

    use futures_util::StreamExt as _;
    let mut stream = resp.bytes_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(&map_err)?;
        if buf.len() + chunk.len() > limit {
            return Err(Error::Unauthenticated(format!(
                "response too large (limit: {limit})"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_issuer_valid() {
        assert!(validate_issuer("https://accounts.google.com").is_ok());
        assert!(validate_issuer("https://token.actions.githubusercontent.com").is_ok());
        assert!(validate_issuer("https://example.com/path/to/issuer").is_ok());
        assert!(validate_issuer("http://localhost").is_ok());
        assert!(validate_issuer("http://127.0.0.1").is_ok());
        assert!(validate_issuer("http://[::1]").is_ok());
    }

    #[test]
    fn test_validate_issuer_rejects_http_non_localhost() {
        assert!(validate_issuer("http://example.com").is_err());
    }

    #[test]
    fn test_validate_issuer_rejects_query_fragment() {
        assert!(validate_issuer("https://example.com?foo=bar").is_err());
        assert!(validate_issuer("https://example.com#frag").is_err());
    }

    #[test]
    fn test_validate_issuer_rejects_userinfo() {
        assert!(validate_issuer("https://user:pass@example.com").is_err());
    }

    #[test]
    fn test_validate_issuer_rejects_path_traversal() {
        assert!(validate_issuer("https://example.com/..").is_err());
        assert!(validate_issuer("https://example.com/a/../b").is_err());
    }

    #[test]
    fn test_validate_issuer_rejects_double_slash() {
        assert!(validate_issuer("https://example.com//path").is_err());
    }

    #[test]
    fn test_validate_issuer_rejects_tilde_issues() {
        assert!(validate_issuer("https://example.com/path~").is_err());
        assert!(validate_issuer("https://example.com/~~path").is_err());
        assert!(validate_issuer("https://example.com/~").is_err());
    }

    #[test]
    fn test_validate_issuer_rejects_dot_segment() {
        assert!(validate_issuer("https://example.com/.").is_err());
    }

    #[test]
    fn test_validate_issuer_rejects_long_segment() {
        let long_segment = "a".repeat(151);
        assert!(validate_issuer(&format!("https://example.com/{long_segment}")).is_err());
    }

    #[test]
    fn test_validate_issuer_rejects_non_ascii_host() {
        assert!(validate_issuer("https://exämple.com").is_err());
    }

    #[test]
    fn test_validate_subject_valid() {
        assert!(validate_subject("repo:org/repo:ref:refs/heads/main").is_ok());
        assert!(validate_subject("user@example.com").is_ok());
        assert!(validate_subject("simple-subject").is_ok());
        assert!(validate_subject("pipe|separated").is_ok());
    }

    #[test]
    fn test_validate_subject_rejects() {
        assert!(validate_subject("").is_err());
        assert!(validate_subject("has space").is_err());
        assert!(validate_subject("has\"quote").is_err());
        assert!(validate_subject("has'quote").is_err());
        assert!(validate_subject("has\\backslash").is_err());
        assert!(validate_subject("has<bracket").is_err());
        assert!(validate_subject("has[bracket]").is_err());
    }

    #[test]
    fn test_validate_audience_valid() {
        assert!(validate_audience("https://example.com").is_ok());
        assert!(validate_audience("my-audience").is_ok());
    }

    #[test]
    fn test_validate_audience_more_restrictive_than_subject() {
        // Subject allows these, audience rejects them
        assert!(validate_subject("user@example.com").is_ok());
        assert!(validate_audience("user@example.com").is_err());

        assert!(validate_subject("pipe|value").is_ok());
        assert!(validate_audience("pipe|value").is_err());

        assert!(validate_subject("has[bracket]").is_err()); // subject also rejects []
        assert!(validate_audience("has[bracket]").is_err());
    }
}
