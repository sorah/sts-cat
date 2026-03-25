use crate::error::Error;

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
    issuer: StringMatcher,
    subject: StringMatcher,
    audience: AudienceMatch,
    claim_patterns: Vec<(String, regex::Regex)>,
    pub permissions: Permissions,
    pub repositories: Option<Vec<String>>,
}

enum StringMatcher {
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

impl StringMatcher {
    fn compile(
        exact: Option<String>,
        pattern: Option<String>,
        field_name: &str,
    ) -> Result<Self, Error> {
        use serde::de::Error as _;
        match (exact, pattern) {
            (Some(exact), None) => Ok(StringMatcher::Exact(exact)),
            (None, Some(pattern)) => {
                let re = compile_anchored_regex(&pattern)?;
                Ok(StringMatcher::Pattern(re))
            }
            (Some(_), Some(_)) => Err(Error::PolicyParse(toml::de::Error::custom(format!(
                "cannot specify both {field_name} and {field_name}_pattern"
            )))),
            (None, None) => Err(Error::PolicyParse(toml::de::Error::custom(format!(
                "must specify either {field_name} or {field_name}_pattern"
            )))),
        }
    }

    fn check(&self, value: &str, field_name: &str) -> Result<(), Error> {
        match self {
            StringMatcher::Exact(expected) => {
                if value != expected {
                    return Err(Error::PermissionDenied(format!(
                        "{field_name} did not match"
                    )));
                }
            }
            StringMatcher::Pattern(re) => {
                if !re.is_match(value) {
                    return Err(Error::PermissionDenied(format!(
                        "{field_name} did not match pattern"
                    )));
                }
            }
        }
        Ok(())
    }
}

impl AudienceMatch {
    fn compile(exact: Option<String>, pattern: Option<String>) -> Result<Self, Error> {
        use serde::de::Error as _;
        match (exact, pattern) {
            (Some(exact), None) => Ok(AudienceMatch::Exact(exact)),
            (None, Some(pattern)) => {
                let re = compile_anchored_regex(&pattern)?;
                Ok(AudienceMatch::Pattern(re))
            }
            (None, None) => Ok(AudienceMatch::Domain),
            (Some(_), Some(_)) => Err(Error::PolicyParse(toml::de::Error::custom(
                "cannot specify both audience and audience_pattern",
            ))),
        }
    }

    fn check<'a>(
        &self,
        audiences: impl Iterator<Item = &'a str>,
        domain: &str,
    ) -> Result<(), Error> {
        match self {
            AudienceMatch::Exact(expected) => {
                if !audiences.into_iter().any(|a| a == expected) {
                    return Err(Error::PermissionDenied("audience did not match".into()));
                }
            }
            AudienceMatch::Pattern(re) => {
                if !audiences.into_iter().any(|a| re.is_match(a)) {
                    return Err(Error::PermissionDenied(
                        "audience did not match pattern".into(),
                    ));
                }
            }
            AudienceMatch::Domain => {
                if !audiences.into_iter().any(|a| a == domain) {
                    return Err(Error::PermissionDenied(
                        "audience did not match domain".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn compile_anchored_regex(pattern: &str) -> Result<regex::Regex, Error> {
    Ok(regex::Regex::new(&format!("^(?:{pattern})$"))?)
}

fn compile_claim_patterns(
    patterns: Option<std::collections::HashMap<String, String>>,
) -> Result<Vec<(String, regex::Regex)>, Error> {
    let Some(patterns) = patterns else {
        return Ok(Vec::new());
    };
    let mut compiled = Vec::with_capacity(patterns.len());
    for (name, pattern) in patterns {
        let re = compile_anchored_regex(&pattern)?;
        compiled.push((name, re));
    }
    Ok(compiled)
}

impl TrustPolicy {
    pub fn parse(toml_str: &str) -> Result<Self, Error> {
        let policy: TrustPolicy = toml::from_str(toml_str)?;
        Ok(policy)
    }

    pub fn compile(self, is_org_level: bool) -> Result<CompiledTrustPolicy, Error> {
        if !is_org_level && self.repositories.is_some() {
            return Err(Error::PermissionDenied(
                "repositories field is not allowed in repository-level trust policies".into(),
            ));
        }

        Ok(CompiledTrustPolicy {
            issuer: StringMatcher::compile(self.issuer, self.issuer_pattern, "issuer")?,
            subject: StringMatcher::compile(self.subject, self.subject_pattern, "subject")?,
            audience: AudienceMatch::compile(self.audience, self.audience_pattern)?,
            claim_patterns: compile_claim_patterns(self.claim_pattern)?,
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
        // Defense-in-depth: validate claim format strings before pattern matching
        crate::oidc::validate_issuer(&claims.iss)?;
        crate::oidc::validate_subject(&claims.sub)?;
        for aud in claims.aud.iter() {
            crate::oidc::validate_audience(aud)?;
        }

        self.issuer.check(&claims.iss, "issuer")?;
        self.subject.check(&claims.sub, "subject")?;
        self.audience.check(claims.aud.iter(), domain)?;
        let matched_claims = self.check_claim_patterns(claims)?;

        Ok(Actor {
            issuer: claims.iss.clone(),
            subject: claims.sub.clone(),
            matched_claims,
        })
    }

    fn check_claim_patterns(
        &self,
        claims: &crate::oidc::TokenClaims,
    ) -> Result<Vec<(String, String)>, Error> {
        let mut matched = Vec::new();
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

            matched.push((claim_name.clone(), string_value));
        }
        Ok(matched)
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

        let claims = crate::oidc::TokenClaims {
            iss: "https://example.com".into(),
            sub: "sub".into(),
            aud: crate::oidc::OneOrMany::One("sts.example.com".into()),
            extra: std::collections::HashMap::new(),
        };
        assert!(compiled.check_token(&claims, "sts.example.com").is_ok());

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

    #[test]
    fn test_pattern_alternation_fully_anchored() {
        let toml = r#"
            issuer = "https://token.actions.githubusercontent.com"
            subject_pattern = "repo:myorg/a|repo:myorg/b"

            [permissions]
            contents = "read"
        "#;
        let policy = TrustPolicy::parse(toml).unwrap();
        let compiled = policy.compile(false).unwrap();

        let make_claims = |sub: &str| crate::oidc::TokenClaims {
            iss: "https://token.actions.githubusercontent.com".into(),
            sub: sub.into(),
            aud: crate::oidc::OneOrMany::One("sts.example.com".into()),
            extra: std::collections::HashMap::new(),
        };

        assert!(
            compiled
                .check_token(&make_claims("repo:myorg/a"), "sts.example.com")
                .is_ok()
        );
        assert!(
            compiled
                .check_token(&make_claims("repo:myorg/b"), "sts.example.com")
                .is_ok()
        );
        // Must not match partial strings
        assert!(
            compiled
                .check_token(&make_claims("repo:myorg/a-extra"), "sts.example.com")
                .is_err()
        );
        assert!(
            compiled
                .check_token(&make_claims("prefix-repo:myorg/b"), "sts.example.com")
                .is_err()
        );
    }
}
