use crate::error::Error;

#[derive(serde::Deserialize)]
pub struct ExchangeRequest {
    pub scope: String,
    pub identity: String,
}

#[derive(serde::Serialize)]
pub struct ExchangeResponse {
    pub token: String,
}

pub struct AppState {
    pub config: crate::config::Config,
    pub github: crate::github::GitHubClient,
    pub oidc: crate::oidc::OidcVerifier,
    pub policy_cache: moka::future::Cache<(String, String, String), String>,
    pub installation_cache: moka::future::Cache<String, u64>,
}

pub async fn handle_exchange(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<AppState>>,
    bearer: Result<
        axum_extra::TypedHeader<headers::Authorization<headers::authorization::Bearer>>,
        axum_extra::typed_header::TypedHeaderRejection,
    >,
    axum::Json(req): axum::Json<ExchangeRequest>,
) -> Result<axum::Json<ExchangeResponse>, Error> {
    let axum_extra::TypedHeader(authorization) = bearer
        .map_err(|_| Error::Unauthenticated("missing or invalid Authorization header".into()))?;
    let bearer_token = authorization.token();

    if req.scope.is_empty() {
        return Err(Error::BadRequest("scope must not be empty".into()));
    }
    if req.identity.is_empty() {
        return Err(Error::BadRequest("identity must not be empty".into()));
    }

    let (owner, repo, is_org_level) = parse_scope(&req.scope)?;
    let claims = state.oidc.verify(bearer_token).await?;

    let installation_id = if let Some(id) = state.installation_cache.get(&owner).await {
        id
    } else {
        let id = state.github.get_installation_id(&owner).await?;
        state.installation_cache.insert(owner.clone(), id).await;
        id
    };

    let policy_path = format!(
        "{}/{}{}",
        state.config.policy_path_prefix, req.identity, state.config.policy_file_extension
    );

    let cache_key = (owner.clone(), repo.clone(), req.identity.clone());
    let policy_toml = if let Some(cached) = state.policy_cache.get(&cache_key).await {
        cached
    } else {
        let content = state
            .github
            .get_trust_policy_content(installation_id, &owner, &repo, &policy_path)
            .await?;
        state.policy_cache.insert(cache_key, content.clone()).await;
        content
    };

    let policy = crate::trust_policy::TrustPolicy::parse(&policy_toml)?;
    let compiled = policy.compile(is_org_level)?;

    let actor = match compiled.check_token(&claims, &state.config.domain) {
        Ok(actor) => actor,
        Err(e) => {
            tracing::warn!(
                event = "exchange_denied",
                scope = %req.scope,
                identity = %req.identity,
                issuer = %claims.iss,
                subject = %claims.sub,
                reason = %e,
            );
            return Err(e);
        }
    };

    tracing::info!(
        event = "exchange_authorized",
        scope = %req.scope,
        identity = %req.identity,
        issuer = %actor.issuer,
        subject = %actor.subject,
        installation_id = installation_id,
        policy_path = %policy_path,
    );

    let repositories = if is_org_level {
        compiled.repositories.clone().unwrap_or_default()
    } else {
        vec![repo.clone()]
    };

    let token = state
        .github
        .create_installation_token(installation_id, &compiled.permissions, &repositories)
        .await?;

    use sha2::Digest as _;
    let token_hash = hex::encode(sha2::Sha256::digest(token.as_bytes()));
    tracing::info!(
        event = "exchange_success",
        scope = %req.scope,
        identity = %req.identity,
        issuer = %actor.issuer,
        subject = %actor.subject,
        installation_id = installation_id,
        token_sha256 = %token_hash,
    );

    Ok(axum::Json(ExchangeResponse { token }))
}

#[derive(serde::Serialize)]
pub struct HealthResponse {
    ok: bool,
}

pub async fn handle_healthz() -> axum::Json<HealthResponse> {
    axum::Json(HealthResponse { ok: true })
}

fn parse_scope(scope: &str) -> Result<(String, String, bool), Error> {
    if let Some((owner, repo)) = scope.split_once('/') {
        if owner.is_empty() || repo.is_empty() {
            return Err(Error::BadRequest("invalid scope format".into()));
        }
        let is_org_level = repo == ".github";
        Ok((owner.to_owned(), repo.to_owned(), is_org_level))
    } else {
        // Org-level scope: "org" → reads from ".github" repo
        if scope.is_empty() {
            return Err(Error::BadRequest("invalid scope format".into()));
        }
        Ok((scope.to_owned(), ".github".to_owned(), true))
    }
}

pub fn build_router(state: std::sync::Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route("/token", axum::routing::post(handle_exchange))
        .route("/healthz", axum::routing::get(handle_healthz))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scope_repo() {
        let (owner, repo, is_org) = parse_scope("myorg/myrepo").unwrap();
        assert_eq!(owner, "myorg");
        assert_eq!(repo, "myrepo");
        assert!(!is_org);
    }

    #[test]
    fn test_parse_scope_org() {
        let (owner, repo, is_org) = parse_scope("myorg").unwrap();
        assert_eq!(owner, "myorg");
        assert_eq!(repo, ".github");
        assert!(is_org);
    }

    #[test]
    fn test_parse_scope_org_dotgithub() {
        let (owner, repo, is_org) = parse_scope("myorg/.github").unwrap();
        assert_eq!(owner, "myorg");
        assert_eq!(repo, ".github");
        assert!(is_org);
    }

    #[test]
    fn test_parse_scope_empty() {
        assert!(parse_scope("").is_err());
        assert!(parse_scope("/repo").is_err());
        assert!(parse_scope("owner/").is_err());
    }
}
