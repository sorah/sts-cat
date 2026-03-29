use crate::error::Error;

const MAX_PAGES: u32 = 50;
const PER_PAGE: u32 = 100;
const MAX_RESPONSE_SIZE: usize = 100 * 1024; // 100 KiB

/// Percent-encoding set for URL path segments (RFC 3986 unreserved chars preserved).
const PATH_SEGMENT_ENCODE_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

pub struct GitHubClient {
    http: reqwest::Client,
    base_url: String,
    app_id: String,
    signer: std::sync::Arc<dyn crate::signer::Signer>,
}

impl GitHubClient {
    pub fn new(
        base_url: &str,
        app_id: &str,
        signer: std::sync::Arc<dyn crate::signer::Signer>,
    ) -> Self {
        use reqwest::header;

        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            "X-GitHub-Api-Version",
            header::HeaderValue::from_static("2026-03-10"),
        );

        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(format!("sts-cat/{}", env!("CARGO_PKG_VERSION")))
            .default_headers(headers)
            .build()
            .expect("failed to build GitHub HTTP client");

        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_owned(),
            app_id: app_id.to_owned(),
            signer,
        }
    }

    async fn app_jwt(&self) -> Result<secrecy::SecretString, Error> {
        use base64::Engine as _;
        use secrecy::ExposeSecret as _;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Error::Internal(Box::new(e)))?
            .as_secs();

        let header = JwtHeader {
            alg: "RS256",
            typ: "JWT",
        };
        let claims = JwtClaims {
            iss: self.app_id.clone(),
            iat: now - 60,  // 60s clock skew allowance
            exp: now + 540, // 10 minutes total (GitHub's max)
        };

        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header_b64 = engine.encode(serde_json::to_vec(&header).unwrap());
        let claims_b64 = engine.encode(serde_json::to_vec(&claims).unwrap());
        let message = format!("{header_b64}.{claims_b64}");

        let signature = self.signer.sign(message.as_bytes()).await?;
        let signature_b64 = engine.encode(signature.expose_secret());

        Ok(secrecy::SecretString::from(format!(
            "{message}.{signature_b64}"
        )))
    }

    pub async fn get_installation_id(&self, owner: &str) -> Result<u64, Error> {
        use secrecy::ExposeSecret as _;
        let jwt = self.app_jwt().await?;

        for page in 1..=MAX_PAGES {
            let url = format!(
                "{}/app/installations?per_page={PER_PAGE}&page={page}",
                self.base_url
            );

            let resp = self
                .http
                .get(&url)
                .bearer_auth(jwt.expose_secret())
                .send()
                .await
                .map_err(Error::GitHubApi)?;

            if !resp.status().is_success() {
                return Err(handle_github_error(resp).await);
            }

            let installations: Vec<Installation> = resp.json().await.map_err(Error::GitHubApi)?;

            if let Some(inst) = installations.iter().find(|i| {
                i.account
                    .as_ref()
                    .is_some_and(|a| a.login.eq_ignore_ascii_case(owner))
            }) {
                return Ok(inst.id);
            }

            // If fewer results than per_page, no more pages
            if (installations.len() as u32) < PER_PAGE {
                break;
            }
        }

        Err(Error::NotFound(format!(
            "no installation found for owner: {owner}"
        )))
    }

    pub async fn get_trust_policy_content(
        &self,
        installation_id: u64,
        owner: &str,
        repo: &str,
        path: &str,
    ) -> Result<String, Error> {
        use secrecy::ExposeSecret as _;

        let read_permissions = crate::trust_policy::Permissions {
            inner: [("contents".into(), "read".into())].into(),
        };
        let read_token = self
            .create_installation_token_raw(installation_id, &read_permissions, &[repo.to_owned()])
            .await?;

        // Encode each path segment individually to preserve `/` separators.
        let encoded_path = path
            .split('/')
            .map(|seg| {
                percent_encoding::utf8_percent_encode(seg, PATH_SEGMENT_ENCODE_SET).to_string()
            })
            .collect::<Vec<_>>()
            .join("/");
        let url = format!(
            "{}/repos/{}/{}/contents/{encoded_path}",
            self.base_url,
            percent_encoding::utf8_percent_encode(owner, PATH_SEGMENT_ENCODE_SET),
            percent_encoding::utf8_percent_encode(repo, PATH_SEGMENT_ENCODE_SET),
        );

        let resp = self
            .http
            .get(&url)
            .bearer_auth(read_token.expose_secret().as_str())
            .send()
            .await
            .map_err(Error::GitHubApi)?;

        let fetch_result = if !resp.status().is_success() {
            let status = resp.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                Err(Error::NotFound(format!("trust policy not found: {path}")))
            } else {
                Err(handle_github_error(resp).await)
            }
        } else {
            let body_bytes =
                crate::oidc::read_limited_body(resp, MAX_RESPONSE_SIZE, Error::GitHubApi).await?;
            let file_resp: FileContent =
                serde_json::from_slice(&body_bytes).map_err(|e| Error::Internal(Box::new(e)))?;
            decode_content(&file_resp.content)
        };

        self.revoke_token(&read_token).await;

        fetch_result
    }

    pub async fn create_installation_token(
        &self,
        installation_id: u64,
        permissions: &crate::trust_policy::Permissions,
        repositories: &[String],
    ) -> Result<crate::exchange::GitHubToken, Error> {
        self.create_installation_token_raw(installation_id, permissions, repositories)
            .await
    }

    async fn create_installation_token_raw(
        &self,
        installation_id: u64,
        permissions: &crate::trust_policy::Permissions,
        repositories: &[String],
    ) -> Result<crate::exchange::GitHubToken, Error> {
        use secrecy::ExposeSecret as _;
        let jwt = self.app_jwt().await?;

        let url = format!(
            "{}/app/installations/{installation_id}/access_tokens",
            self.base_url
        );

        let body = CreateTokenRequest {
            permissions,
            repositories,
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(jwt.expose_secret())
            .json(&body)
            .send()
            .await
            .map_err(Error::GitHubApi)?;

        let status = resp.status();
        if !status.is_success() {
            return match status.as_u16() {
                422 => {
                    let body = resp.text().await.unwrap_or_default();
                    tracing::debug!(body = %body, "GitHub API 422 creating installation token");
                    Err(Error::PermissionDenied(
                        "invalid permission combination".into(),
                    ))
                }
                403 | 429 => Err(Error::RateLimited),
                _ => {
                    let body = resp.text().await.unwrap_or_default();
                    tracing::debug!(
                        status = %status,
                        body = %body,
                        "GitHub API error creating installation token"
                    );
                    Err(Error::Internal(
                        format!("GitHub API error: HTTP {status}").into(),
                    ))
                }
            };
        }

        let token_resp: TokenResponse = resp.json().await.map_err(Error::GitHubApi)?;

        Ok(secrecy::SecretBox::new(Box::new(token_resp.token)))
    }

    async fn revoke_token(&self, token: &crate::exchange::GitHubToken) {
        use secrecy::ExposeSecret as _;
        let resp = self
            .http
            .delete(format!("{}/installation/token", self.base_url))
            .bearer_auth(token.expose_secret().as_str())
            .send()
            .await;

        match resp {
            Ok(r) if r.status() == reqwest::StatusCode::NO_CONTENT => {}
            Ok(r) => {
                tracing::warn!(
                    status = %r.status(),
                    "failed to revoke installation token"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to revoke installation token");
            }
        }
    }
}

async fn handle_github_error(resp: reqwest::Response) -> Error {
    let status = resp.status();
    match status.as_u16() {
        403 | 429 => Error::RateLimited,
        _ => {
            let body = resp.text().await.unwrap_or_default();
            tracing::debug!(status = %status, body = %body, "GitHub API error");
            Error::Internal(format!("GitHub API error: HTTP {status}").into())
        }
    }
}

fn decode_content(encoded: &str) -> Result<String, Error> {
    use base64::Engine as _;
    // GitHub returns base64-encoded content with newlines
    let cleaned: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .map_err(|e| Error::Internal(Box::new(e)))?;
    String::from_utf8(bytes).map_err(|e| Error::Internal(Box::new(e)))
}

#[derive(serde::Serialize)]
struct JwtHeader {
    alg: &'static str,
    typ: &'static str,
}

#[derive(serde::Serialize)]
struct JwtClaims {
    iss: String,
    iat: u64,
    exp: u64,
}

#[derive(serde::Serialize)]
struct CreateTokenRequest<'a> {
    permissions: &'a crate::trust_policy::Permissions,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    repositories: &'a [String],
}

#[derive(serde::Deserialize)]
struct Installation {
    id: u64,
    account: Option<Account>,
}

#[derive(serde::Deserialize)]
struct Account {
    login: String,
}

#[derive(serde::Deserialize)]
struct FileContent {
    content: String,
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    token: crate::exchange::GitHubTokenInner,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::Signer as _;

    // RSA-2048 test key from RFC 9500
    const TEST_RSA_PEM: &[u8] = b"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsPnoGUOnrpiSqt4XynxA+HRP7S+BSObI6qJ7fQAVSPtRkqso
tWxQYLEYzNEx5ZSHTGypibVsJylvCfuToDTfMul8b/CZjP2Ob0LdpYrNH6l5hvFE
89FU1nZQF15oVLOpUgA7wGiHuEVawrGfey92UE68mOyUVXGweJIVDdxqdMoPvNNU
l86BU02vlBiESxOuox+dWmuVV7vfYZ79Toh/LUK43YvJh+rhv4nKuF7iHjVjBd9s
B6iDjj70HFldzOQ9r8SRI+9NirupPTkF5AKNe6kUhKJ1luB7S27ZkvB3tSTT3P59
3VVJvnzOjaA1z6Cz+4+eRvcysqhrRgFlwI9TEwIDAQABAoIBAEEYiyDP29vCzx/+
dS3LqnI5BjUuJhXUnc6AWX/PCgVAO+8A+gZRgvct7PtZb0sM6P9ZcLrweomlGezI
FrL0/6xQaa8bBr/ve/a8155OgcjFo6fZEw3Dz7ra5fbSiPmu4/b/kvrg+Br1l77J
aun6uUAs1f5B9wW+vbR7tzbT/mxaUeDiBzKpe15GwcvbJtdIVMa2YErtRjc1/5B2
BGVXyvlJv0SIlcIEMsHgnAFOp1ZgQ08aDzvilLq8XVMOahAhP1O2A3X8hKdXPyrx
IVWE9bS9ptTo+eF6eNl+d7htpKGEZHUxinoQpWEBTv+iOoHsVunkEJ3vjLP3lyI/
fY0NQ1ECgYEA3RBXAjgvIys2gfU3keImF8e/TprLge1I2vbWmV2j6rZCg5r/AS0u
pii5CvJ5/T5vfJPNgPBy8B/yRDs+6PJO1GmnlhOkG9JAIPkv0RBZvR0PMBtbp6nT
Y3yo1lwamBVBfY6rc0sLTzosZh2aGoLzrHNMQFMGaauORzBFpY5lU50CgYEAzPHl
u5DI6Xgep1vr8QvCUuEesCOgJg8Yh1UqVoY/SmQh6MYAv1I9bLGwrb3WW/7kqIoD
fj0aQV5buVZI2loMomtU9KY5SFIsPV+JuUpy7/+VE01ZQM5FdY8wiYCQiVZYju9X
Wz5LxMNoz+gT7pwlLCsC4N+R8aoBk404aF1gum8CgYAJ7VTq7Zj4TFV7Soa/T1eE
k9y8a+kdoYk3BASpCHJ29M5R2KEA7YV9wrBklHTz8VzSTFTbKHEQ5W5csAhoL5Fo
qoHzFFi3Qx7MHESQb9qHyolHEMNx6QdsHUn7rlEnaTTyrXh3ifQtD6C0yTmFXUIS
CW9wKApOrnyKJ9nI0HcuZQKBgQCMtoV6e9VGX4AEfpuHvAAnMYQFgeBiYTkBKltQ
XwozhH63uMMomUmtSG87Sz1TmrXadjAhy8gsG6I0pWaN7QgBuFnzQ/HOkwTm+qKw
AsrZt4zeXNwsH7QXHEJCFnCmqw9QzEoZTrNtHJHpNboBuVnYcoueZEJrP8OnUG3r
UjmopwKBgAqB2KYYMUqAOvYcBnEfLDmyZv9BTVNHbR2lKkMYqv5LlvDaBxVfilE0
2riO4p6BaAdvzXjKeRrGNEKoHNBpOSfYCOM16NjL8hIZB1CaV3WbT5oY+jp7Mzd5
7d56RZOE+ERK2uz/7JX9VSsM/LbH9pJibd4e8mikDS9ntciqOH/3
-----END RSA PRIVATE KEY-----";

    fn test_signer() -> std::sync::Arc<dyn crate::signer::Signer> {
        std::sync::Arc::new(crate::signer::raw::RawSigner::from_pem(TEST_RSA_PEM).unwrap())
    }

    #[tokio::test]
    async fn test_app_jwt_structure() {
        use base64::Engine as _;
        use secrecy::ExposeSecret as _;

        let client = GitHubClient::new("https://api.github.com", "12345", test_signer());
        let jwt = client.app_jwt().await.unwrap();
        let jwt_str = jwt.expose_secret();

        let parts: Vec<&str> = jwt_str.split('.').collect();
        assert_eq!(parts.len(), 3);

        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header_bytes = engine.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["typ"], "JWT");

        let claims_bytes = engine.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();
        assert_eq!(claims["iss"], "12345");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let iat = claims["iat"].as_u64().unwrap();
        let exp = claims["exp"].as_u64().unwrap();

        // iat should be ~60s before now
        assert!(now - iat <= 62 && now - iat >= 58);
        // exp should be ~540s after now
        assert!(exp - now <= 542 && exp - now >= 538);
    }

    fn test_public_key_pem() -> Vec<u8> {
        use rsa::pkcs1::DecodeRsaPrivateKey as _;
        use rsa::pkcs8::EncodePublicKey as _;
        let private_key =
            rsa::RsaPrivateKey::from_pkcs1_pem(std::str::from_utf8(TEST_RSA_PEM).unwrap()).unwrap();
        let public_key = private_key.to_public_key();
        public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .into_bytes()
    }

    #[tokio::test]
    async fn test_app_jwt_verifiable() {
        use secrecy::ExposeSecret as _;

        let client = GitHubClient::new("https://api.github.com", "99999", test_signer());
        let jwt = client.app_jwt().await.unwrap();

        let pub_pem = test_public_key_pem();
        let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(&pub_pem).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&["99999"]);
        validation.validate_aud = false;

        let token_data = jsonwebtoken::decode::<serde_json::Value>(
            jwt.expose_secret(),
            &decoding_key,
            &validation,
        )
        .unwrap();

        assert_eq!(token_data.claims["iss"], "99999");
    }

    #[tokio::test]
    async fn test_raw_signer_produces_valid_rs256() {
        use base64::Engine as _;
        use secrecy::ExposeSecret as _;
        let signer = crate::signer::raw::RawSigner::from_pem(TEST_RSA_PEM).unwrap();

        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = engine.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let payload = engine.encode(b"{\"sub\":\"test\"}");
        let msg = format!("{header}.{payload}");

        let sig = signer.sign(msg.as_bytes()).await.unwrap();
        assert!(!sig.expose_secret().is_empty());

        let sig_b64 = engine.encode(sig.expose_secret());
        let token = format!("{msg}.{sig_b64}");

        let pub_pem = test_public_key_pem();
        let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(&pub_pem).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_aud = false;
        validation.validate_exp = false;
        validation.required_spec_claims.clear();

        let result = jsonwebtoken::decode::<serde_json::Value>(&token, &decoding_key, &validation);
        assert!(result.is_ok(), "JWT verification failed: {result:?}");
    }
}
