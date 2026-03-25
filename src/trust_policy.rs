use crate::error::Error;
use serde::de::Error as _;

#[derive(Debug, serde::Deserialize)]
pub struct TrustPolicy {
    pub issuer: Option<String>,
    pub issuer_pattern: Option<String>,
    pub subject: Option<String>,
    pub subject_pattern: Option<String>,
    pub audience: Option<String>,
    pub audience_pattern: Option<String>,
    pub claim_pattern: Option<std::collections::HashMap<String, String>>,
    pub permissions: Permissions,
    pub repositories: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Permissions {
    #[serde(flatten)]
    pub inner: std::collections::HashMap<String, String>,
}

pub struct CompiledTrustPolicy {
    issuer: IssuerMatch,
    subject: SubjectMatch,
    audience: AudienceMatch,
    claim_patterns: Vec<(String, regex::Regex)>,
    pub permissions: Permissions,
    pub repositories: Option<Vec<String>>,
}

enum IssuerMatch {
    Exact(String),
    Pattern(regex::Regex),
}

enum SubjectMatch {
    Exact(String),
    Pattern(regex::Regex),
}

enum AudienceMatch {
    Exact(String),
    Pattern(regex::Regex),
    Domain,
}

pub struct Actor {
    pub issuer: String,
    pub subject: String,
    pub matched_claims: Vec<(String, String)>,
}

impl TrustPolicy {
    pub fn parse(toml_str: &str) -> Result<Self, Error> {
        let policy: TrustPolicy = toml::from_str(toml_str)?;
        Ok(policy)
    }

    pub fn compile(self, is_org_level: bool) -> Result<CompiledTrustPolicy, Error> {
        // Reject repositories field on repo-level policies
        if !is_org_level && self.repositories.is_some() {
            return Err(Error::PermissionDenied(
                "repositories field is not allowed in repository-level trust policies".into(),
            ));
        }

        // Exactly one of issuer or issuer_pattern
        let issuer = match (self.issuer, self.issuer_pattern) {
            (Some(exact), None) => IssuerMatch::Exact(exact),
            (None, Some(pattern)) => {
                let re = regex::Regex::new(&format!("^{pattern}$"))?;
                IssuerMatch::Pattern(re)
            }
            (Some(_), Some(_)) => {
                return Err(Error::PolicyParse(toml::de::Error::custom(
                    "cannot specify both issuer and issuer_pattern",
                )));
            }
            (None, None) => {
                return Err(Error::PolicyParse(toml::de::Error::custom(
                    "must specify either issuer or issuer_pattern",
                )));
            }
        };

        // Exactly one of subject or subject_pattern
        let subject = match (self.subject, self.subject_pattern) {
            (Some(exact), None) => SubjectMatch::Exact(exact),
            (None, Some(pattern)) => {
                let re = regex::Regex::new(&format!("^{pattern}$"))?;
                SubjectMatch::Pattern(re)
            }
            (Some(_), Some(_)) => {
                return Err(Error::PolicyParse(toml::de::Error::custom(
                    "cannot specify both subject and subject_pattern",
                )));
            }
            (None, None) => {
                return Err(Error::PolicyParse(toml::de::Error::custom(
                    "must specify either subject or subject_pattern",
                )));
            }
        };

        // At most one of audience or audience_pattern; if neither, use Domain
        let audience = match (self.audience, self.audience_pattern) {
            (Some(exact), None) => AudienceMatch::Exact(exact),
            (None, Some(pattern)) => {
                let re = regex::Regex::new(&format!("^{pattern}$"))?;
                AudienceMatch::Pattern(re)
            }
            (None, None) => AudienceMatch::Domain,
            (Some(_), Some(_)) => {
                return Err(Error::PolicyParse(toml::de::Error::custom(
                    "cannot specify both audience and audience_pattern",
                )));
            }
        };

        // Compile claim patterns
        let claim_patterns = if let Some(patterns) = self.claim_pattern {
            let mut compiled = Vec::with_capacity(patterns.len());
            for (name, pattern) in patterns {
                let re = regex::Regex::new(&format!("^{pattern}$"))?;
                compiled.push((name, re));
            }
            compiled
        } else {
            Vec::new()
        };

        Ok(CompiledTrustPolicy {
            issuer,
            subject,
            audience,
            claim_patterns,
            permissions: self.permissions,
            repositories: self.repositories,
        })
    }
}

impl CompiledTrustPolicy {
    pub fn check_token(
        &self,
        claims: &crate::oidc::TokenClaims,
        domain: &str,
    ) -> Result<Actor, Error> {
        // Defense-in-depth: validate all claim format strings before matching
        crate::oidc::validate_issuer(&claims.iss)?;
        crate::oidc::validate_subject(&claims.sub)?;
        for aud in claims.aud.as_slice() {
            crate::oidc::validate_audience(aud)?;
        }

        // Match issuer
        match &self.issuer {
            IssuerMatch::Exact(expected) => {
                if claims.iss != *expected {
                    return Err(Error::PermissionDenied("issuer did not match".into()));
                }
            }
            IssuerMatch::Pattern(re) => {
                if !re.is_match(&claims.iss) {
                    return Err(Error::PermissionDenied(
                        "issuer did not match pattern".into(),
                    ));
                }
            }
        }

        // Match subject
        match &self.subject {
            SubjectMatch::Exact(expected) => {
                if claims.sub != *expected {
                    return Err(Error::PermissionDenied("subject did not match".into()));
                }
            }
            SubjectMatch::Pattern(re) => {
                if !re.is_match(&claims.sub) {
                    return Err(Error::PermissionDenied(
                        "subject did not match pattern".into(),
                    ));
                }
            }
        }

        // Match audience
        let audiences = claims.aud.as_slice();
        match &self.audience {
            AudienceMatch::Exact(expected) => {
                if !audiences.iter().any(|a| *a == *expected) {
                    return Err(Error::PermissionDenied("audience did not match".into()));
                }
            }
            AudienceMatch::Pattern(re) => {
                if !audiences.iter().any(|a| re.is_match(a)) {
                    return Err(Error::PermissionDenied(
                        "audience did not match pattern".into(),
                    ));
                }
            }
            AudienceMatch::Domain => {
                if !audiences.contains(&domain) {
                    return Err(Error::PermissionDenied(
                        "audience did not match domain".into(),
                    ));
                }
            }
        }

        // Match claim patterns
        let mut matched_claims = Vec::new();
        for (claim_name, pattern) in &self.claim_patterns {
            let value = claims.extra.get(claim_name).ok_or_else(|| {
                Error::PermissionDenied(format!("required claim '{claim_name}' not present"))
            })?;

            let string_value = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => {
                    return Err(Error::PermissionDenied(format!(
                        "claim '{claim_name}' is not a string or boolean"
                    )));
                }
            };

            if !pattern.is_match(&string_value) {
                return Err(Error::PermissionDenied(format!(
                    "claim '{claim_name}' did not match pattern"
                )));
            }

            matched_claims.push((claim_name.clone(), string_value));
        }

        Ok(Actor {
            issuer: claims.iss.clone(),
            subject: claims.sub.clone(),
            matched_claims,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_policy() {
        let toml = r#"
            issuer = "https://token.actions.githubusercontent.com"
            subject = "repo:myorg/myrepo:ref:refs/heads/main"

            [permissions]
            contents = "read"
        "#;
        let policy = TrustPolicy::parse(toml).unwrap();
        assert_eq!(
            policy.issuer.as_deref(),
            Some("https://token.actions.githubusercontent.com")
        );
        assert!(policy.issuer_pattern.is_none());
    }

    #[test]
    fn test_parse_pattern_policy() {
        let toml = r#"
            issuer = "https://token.actions.githubusercontent.com"
            subject_pattern = "repo:myorg/.*:ref:refs/heads/main"
            repositories = ["repo-a", "repo-b"]

            [permissions]
            contents = "read"
        "#;
        let policy = TrustPolicy::parse(toml).unwrap();
        assert!(policy.subject_pattern.is_some());
        assert!(policy.repositories.is_some());
    }

    #[test]
    fn test_compile_rejects_both_issuer_and_pattern() {
        let toml = r#"
            issuer = "https://example.com"
            issuer_pattern = "https://.*"
            subject = "sub"

            [permissions]
            contents = "read"
        "#;
        let policy = TrustPolicy::parse(toml).unwrap();
        assert!(policy.compile(false).is_err());
    }

    #[test]
    fn test_compile_rejects_neither_issuer() {
        let toml = r#"
            subject = "sub"

            [permissions]
            contents = "read"
        "#;
        let policy = TrustPolicy::parse(toml).unwrap();
        assert!(policy.compile(false).is_err());
    }

    #[test]
    fn test_compile_rejects_repositories_on_repo_level() {
        let toml = r#"
            issuer = "https://example.com"
            subject = "sub"
            repositories = ["repo-a"]

            [permissions]
            contents = "read"
        "#;
        let policy = TrustPolicy::parse(toml).unwrap();
        assert!(policy.compile(false).is_err());
        // But org-level should be fine
        let policy2 = TrustPolicy::parse(toml).unwrap();
        assert!(policy2.compile(true).is_ok());
    }

    #[test]
    fn test_compile_audience_fallback_to_domain() {
        let toml = r#"
            issuer = "https://example.com"
            subject = "sub"

            [permissions]
            contents = "read"
        "#;
        let policy = TrustPolicy::parse(toml).unwrap();
        let compiled = policy.compile(false).unwrap();
        assert!(matches!(compiled.audience, AudienceMatch::Domain));
    }

    #[test]
    fn test_check_token_exact_match() {
        let toml = r#"
            issuer = "https://token.actions.githubusercontent.com"
            subject = "repo:myorg/myrepo:ref:refs/heads/main"

            [permissions]
            contents = "read"
        "#;
        let policy = TrustPolicy::parse(toml).unwrap();
        let compiled = policy.compile(false).unwrap();

        let claims = crate::oidc::TokenClaims {
            iss: "https://token.actions.githubusercontent.com".into(),
            sub: "repo:myorg/myrepo:ref:refs/heads/main".into(),
            aud: crate::oidc::OneOrMany::One("sts.example.com".into()),
            extra: std::collections::HashMap::new(),
        };

        let actor = compiled.check_token(&claims, "sts.example.com").unwrap();
        assert_eq!(actor.issuer, "https://token.actions.githubusercontent.com");
        assert_eq!(actor.subject, "repo:myorg/myrepo:ref:refs/heads/main");
    }

    #[test]
    fn test_check_token_pattern_match() {
        let toml = r#"
            issuer = "https://token.actions.githubusercontent.com"
            subject_pattern = "repo:myorg/.*:ref:refs/heads/main"

            [permissions]
            contents = "read"
        "#;
        let policy = TrustPolicy::parse(toml).unwrap();
        let compiled = policy.compile(true).unwrap();

        let claims = crate::oidc::TokenClaims {
            iss: "https://token.actions.githubusercontent.com".into(),
            sub: "repo:myorg/some-repo:ref:refs/heads/main".into(),
            aud: crate::oidc::OneOrMany::One("sts.example.com".into()),
            extra: std::collections::HashMap::new(),
        };

        assert!(compiled.check_token(&claims, "sts.example.com").is_ok());
    }

    #[test]
    fn test_check_token_subject_mismatch() {
        let toml = r#"
            issuer = "https://token.actions.githubusercontent.com"
            subject = "repo:myorg/myrepo:ref:refs/heads/main"

            [permissions]
            contents = "read"
        "#;
        let policy = TrustPolicy::parse(toml).unwrap();
        let compiled = policy.compile(false).unwrap();

        let claims = crate::oidc::TokenClaims {
            iss: "https://token.actions.githubusercontent.com".into(),
            sub: "repo:myorg/other-repo:ref:refs/heads/main".into(),
            aud: crate::oidc::OneOrMany::One("sts.example.com".into()),
            extra: std::collections::HashMap::new(),
        };

        assert!(compiled.check_token(&claims, "sts.example.com").is_err());
    }

    #[test]
    fn test_check_token_audience_domain_fallback() {
        let toml = r#"
            issuer = "https://example.com"
            subject = "sub"

            [permissions]
            contents = "read"
        "#;
        let policy = TrustPolicy::parse(toml).unwrap();
        let compiled = policy.compile(false).unwrap();

        // Matching domain
        let claims = crate::oidc::TokenClaims {
            iss: "https://example.com".into(),
            sub: "sub".into(),
            aud: crate::oidc::OneOrMany::One("sts.example.com".into()),
            extra: std::collections::HashMap::new(),
        };
        assert!(compiled.check_token(&claims, "sts.example.com").is_ok());

        // Non-matching domain
        let claims2 = crate::oidc::TokenClaims {
            iss: "https://example.com".into(),
            sub: "sub".into(),
            aud: crate::oidc::OneOrMany::One("other.example.com".into()),
            extra: std::collections::HashMap::new(),
        };
        assert!(compiled.check_token(&claims2, "sts.example.com").is_err());
    }

    #[test]
    fn test_check_token_claim_pattern_bool_coercion() {
        let toml = r#"
            issuer = "https://example.com"
            subject = "sub"

            [permissions]
            contents = "read"

            [claim_pattern]
            email_verified = "true"
        "#;
        let policy = TrustPolicy::parse(toml).unwrap();
        let compiled = policy.compile(false).unwrap();

        let mut extra = std::collections::HashMap::new();
        extra.insert("email_verified".into(), serde_json::Value::Bool(true));

        let claims = crate::oidc::TokenClaims {
            iss: "https://example.com".into(),
            sub: "sub".into(),
            aud: crate::oidc::OneOrMany::One("sts.example.com".into()),
            extra,
        };

        assert!(compiled.check_token(&claims, "sts.example.com").is_ok());
    }

    #[test]
    fn test_check_token_rejects_numeric_claim() {
        let toml = r#"
            issuer = "https://example.com"
            subject = "sub"

            [permissions]
            contents = "read"

            [claim_pattern]
            some_number = "42"
        "#;
        let policy = TrustPolicy::parse(toml).unwrap();
        let compiled = policy.compile(false).unwrap();

        let mut extra = std::collections::HashMap::new();
        extra.insert("some_number".into(), serde_json::Value::Number(42.into()));

        let claims = crate::oidc::TokenClaims {
            iss: "https://example.com".into(),
            sub: "sub".into(),
            aud: crate::oidc::OneOrMany::One("sts.example.com".into()),
            extra,
        };

        assert!(compiled.check_token(&claims, "sts.example.com").is_err());
    }

    #[test]
    fn test_check_token_audience_multi() {
        let toml = r#"
            issuer = "https://example.com"
            subject = "sub"
            audience = "my-audience"

            [permissions]
            contents = "read"
        "#;
        let policy = TrustPolicy::parse(toml).unwrap();
        let compiled = policy.compile(false).unwrap();

        let claims = crate::oidc::TokenClaims {
            iss: "https://example.com".into(),
            sub: "sub".into(),
            aud: crate::oidc::OneOrMany::Many(vec!["other-aud".into(), "my-audience".into()]),
            extra: std::collections::HashMap::new(),
        };

        assert!(compiled.check_token(&claims, "sts.example.com").is_ok());
    }
}
