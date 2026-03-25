#[derive(Debug, Clone, clap::Parser)]
pub struct Config {
    #[arg(long, env = "STS_CAT_GITHUB_APP_ID")]
    pub github_app_id: u64,

    #[arg(
        long,
        default_value = "https://api.github.com",
        env = "STS_CAT_GITHUB_API_URL"
    )]
    pub github_api_url: String,

    #[arg(long, env = "STS_CAT_DOMAIN")]
    pub domain: String,

    #[arg(long, default_value = "0.0.0.0", env = "HOST")]
    pub host: String,

    #[arg(long, default_value_t = 8080, env = "PORT")]
    pub port: u16,

    #[arg(long, env = "STS_CAT_KEY_SOURCE")]
    pub key_source: KeySource,

    #[arg(long, env = "STS_CAT_KEY_FILE", required_if_eq("key_source", "file"))]
    pub key_file: Option<std::path::PathBuf>,

    #[arg(long, env = "STS_CAT_KEY_ENV", required_if_eq("key_source", "env"))]
    pub key_env: Option<String>,

    #[cfg(feature = "aws-kms")]
    #[arg(long, env = "STS_CAT_KMS_KEY_ARN", required_if_eq("key_source", "kms"))]
    pub kms_key_arn: Option<String>,

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
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum KeySource {
    File,
    Env,
    #[cfg(feature = "aws-kms")]
    Kms,
}

impl Config {
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
            KeySource::Kms => {
                let arn = self.kms_key_arn.as_ref().unwrap();
                Ok(std::sync::Arc::new(
                    crate::signer::aws_kms::AwsKmsSigner::new(arn.clone()).await?,
                ))
            }
        }
    }
}
