#[derive(Debug, Clone, clap::Parser)]
pub struct Config {
    #[arg(long, env = "STS_CAT_GITHUB_APP_ID")]
    pub github_app_id: String,

    #[arg(
        long,
        default_value = "https://api.github.com",
        env = "STS_CAT_GITHUB_API_URL"
    )]
    pub github_api_url: String,

    #[arg(long, env = "STS_CAT_IDENTIFIER")]
    pub identifier: String,

    #[arg(long, default_value = "0.0.0.0", env = "HOST")]
    pub host: String,

    #[arg(long, default_value_t = 8080, env = "PORT")]
    pub port: u16,

    #[arg(long, env = "STS_CAT_LOG_JSON")]
    pub log_json: bool,

    #[arg(long, env = "STS_CAT_KEY_SOURCE")]
    pub key_source: KeySource,

    #[arg(long, env = "STS_CAT_KEY_FILE", required_if_eq("key_source", "file"))]
    pub key_file: Option<std::path::PathBuf>,

    #[arg(long, env = "STS_CAT_KEY_ENV", required_if_eq("key_source", "env"))]
    pub key_env: Option<String>,

    #[cfg(feature = "aws-kms")]
    #[arg(
        long,
        env = "STS_CAT_AWS_KMS_KEY_ARN",
        required_if_eq("key_source", "aws-kms")
    )]
    pub aws_kms_key_arn: Option<String>,

    #[arg(
        long,
        default_value = ".github/sts-cat",
        env = "STS_CAT_POLICY_PATH_PREFIX"
    )]
    pub policy_path_prefix: String,

    #[arg(
        long,
        default_value = ".sts.toml",
        env = "STS_CAT_POLICY_FILE_EXTENSION"
    )]
    pub policy_file_extension: String,

    #[arg(long, env = "STS_CAT_ALLOWED_ISSUER_URLS", value_delimiter = ',')]
    pub allowed_issuer_urls: Option<Vec<String>>,

    #[arg(long, env = "STS_CAT_ORG_REPO", value_delimiter = ',')]
    pub org_repo: Option<Vec<String>>,

    #[arg(long, env = "STS_CAT_ALLOWED_ORGS", value_delimiter = ',')]
    pub allowed_orgs: Option<Vec<String>>,

    #[arg(long, env = "STS_CAT_POLICY_IGNORED_REPOS", value_delimiter = ',')]
    pub policy_ignored_repos: Option<Vec<String>>,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum KeySource {
    File,
    Env,
    #[cfg(feature = "aws-kms")]
    AwsKms,
}

impl Config {
    pub fn parse_org_repos(
        &self,
    ) -> Result<std::collections::HashMap<String, String>, anyhow::Error> {
        let mut map = std::collections::HashMap::new();
        if let Some(ref entries) = self.org_repo {
            for entry in entries {
                let (org, repo) = entry.split_once('/').ok_or_else(|| {
                    anyhow::anyhow!(
                        "invalid --org-repo value '{entry}': expected format 'org/repo'"
                    )
                })?;
                if org.is_empty() || repo.is_empty() {
                    anyhow::bail!(
                        "invalid --org-repo value '{entry}': org and repo must not be empty"
                    );
                }
                map.insert(org.to_ascii_lowercase(), repo.to_owned());
            }
        }
        Ok(map)
    }

    pub fn parse_policy_ignored_repos(
        &self,
    ) -> Result<std::collections::HashSet<(String, String)>, anyhow::Error> {
        let mut set = std::collections::HashSet::new();
        if let Some(ref entries) = self.policy_ignored_repos {
            for entry in entries {
                let (org, repo) = entry.split_once('/').ok_or_else(|| {
                    anyhow::anyhow!(
                        "invalid --policy-ignored-repos value '{entry}': expected format 'org/repo'"
                    )
                })?;
                if org.is_empty() || repo.is_empty() {
                    anyhow::bail!(
                        "invalid --policy-ignored-repos value '{entry}': org and repo must not be empty"
                    );
                }
                set.insert((org.to_ascii_lowercase(), repo.to_ascii_lowercase()));
            }
        }
        Ok(set)
    }

    pub async fn build_signer(
        &self,
    ) -> Result<std::sync::Arc<dyn crate::signer::Signer>, anyhow::Error> {
        match &self.key_source {
            KeySource::File => {
                let path = self.key_file.as_ref().unwrap();
                let pem = std::fs::read(path)?;
                Ok(std::sync::Arc::new(
                    crate::signer::raw::RawSigner::from_pem(&pem)?,
                ))
            }
            KeySource::Env => {
                let env_name = self.key_env.as_ref().unwrap();
                let pem = std::env::var(env_name)
                    .map_err(|_| anyhow::anyhow!("env var {env_name} not set"))?;
                Ok(std::sync::Arc::new(
                    crate::signer::raw::RawSigner::from_pem(pem.as_bytes())?,
                ))
            }
            #[cfg(feature = "aws-kms")]
            KeySource::AwsKms => {
                let arn = self.aws_kms_key_arn.as_ref().unwrap();
                Ok(std::sync::Arc::new(
                    crate::signer::aws_kms::AwsKmsSigner::new(arn.clone()).await?,
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_org_repo(org_repo: Option<Vec<String>>) -> Config {
        Config {
            github_app_id: "123".into(),
            github_api_url: "https://api.github.com".into(),
            identifier: "example.com".into(),
            host: "0.0.0.0".into(),
            port: 8080,
            log_json: false,
            key_source: KeySource::File,
            key_file: Some("/dev/null".into()),
            key_env: None,
            #[cfg(feature = "aws-kms")]
            aws_kms_key_arn: None,
            policy_path_prefix: ".github/sts-cat".into(),
            policy_file_extension: ".sts.toml".into(),
            allowed_issuer_urls: None,
            org_repo,
            allowed_orgs: None,
            policy_ignored_repos: None,
        }
    }

    #[test]
    fn test_parse_org_repos_none() {
        let config = config_with_org_repo(None);
        let map = config.parse_org_repos().unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_org_repos_single() {
        let config = config_with_org_repo(Some(vec!["myorg/policies".into()]));
        let map = config.parse_org_repos().unwrap();
        assert_eq!(map.get("myorg").unwrap(), "policies");
    }

    #[test]
    fn test_parse_org_repos_multiple() {
        let config =
            config_with_org_repo(Some(vec!["myorg/policies".into(), "other/infra".into()]));
        let map = config.parse_org_repos().unwrap();
        assert_eq!(map.get("myorg").unwrap(), "policies");
        assert_eq!(map.get("other").unwrap(), "infra");
    }

    #[test]
    fn test_parse_org_repos_lowercases_org() {
        let config = config_with_org_repo(Some(vec!["MyOrg/policies".into()]));
        let map = config.parse_org_repos().unwrap();
        assert_eq!(map.get("myorg").unwrap(), "policies");
        assert!(map.get("MyOrg").is_none());
    }

    #[test]
    fn test_parse_org_repos_rejects_no_slash() {
        let config = config_with_org_repo(Some(vec!["myorg".into()]));
        assert!(config.parse_org_repos().is_err());
    }

    fn config_with_policy_ignored_repos(policy_ignored_repos: Option<Vec<String>>) -> Config {
        Config {
            policy_ignored_repos,
            ..config_with_org_repo(None)
        }
    }

    #[test]
    fn test_parse_policy_ignored_repos_none() {
        let config = config_with_policy_ignored_repos(None);
        let set = config.parse_policy_ignored_repos().unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn test_parse_policy_ignored_repos_single() {
        let config = config_with_policy_ignored_repos(Some(vec!["myorg/myrepo".into()]));
        let set = config.parse_policy_ignored_repos().unwrap();
        assert!(set.contains(&("myorg".into(), "myrepo".into())));
    }

    #[test]
    fn test_parse_policy_ignored_repos_multiple() {
        let config = config_with_policy_ignored_repos(Some(vec![
            "myorg/repo1".into(),
            "other/repo2".into(),
        ]));
        let set = config.parse_policy_ignored_repos().unwrap();
        assert!(set.contains(&("myorg".into(), "repo1".into())));
        assert!(set.contains(&("other".into(), "repo2".into())));
    }

    #[test]
    fn test_parse_policy_ignored_repos_lowercases() {
        let config = config_with_policy_ignored_repos(Some(vec!["MyOrg/MyRepo".into()]));
        let set = config.parse_policy_ignored_repos().unwrap();
        assert!(set.contains(&("myorg".into(), "myrepo".into())));
    }

    #[test]
    fn test_parse_policy_ignored_repos_rejects_no_slash() {
        let config = config_with_policy_ignored_repos(Some(vec!["myorg".into()]));
        assert!(config.parse_policy_ignored_repos().is_err());
    }

    #[test]
    fn test_parse_policy_ignored_repos_rejects_empty_parts() {
        let config = config_with_policy_ignored_repos(Some(vec!["/repo".into()]));
        assert!(config.parse_policy_ignored_repos().is_err());

        let config = config_with_policy_ignored_repos(Some(vec!["org/".into()]));
        assert!(config.parse_policy_ignored_repos().is_err());
    }

    #[test]
    fn test_parse_org_repos_rejects_empty_parts() {
        let config = config_with_org_repo(Some(vec!["/repo".into()]));
        assert!(config.parse_org_repos().is_err());

        let config = config_with_org_repo(Some(vec!["org/".into()]));
        assert!(config.parse_org_repos().is_err());
    }
}
