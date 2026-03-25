pub mod raw;

#[cfg(feature = "aws-kms")]
pub mod kms;

#[async_trait::async_trait]
pub trait Signer: Send + Sync {
    async fn sign(
        &self,
        message: &[u8],
    ) -> Result<secrecy::SecretBox<Vec<u8>>, crate::error::Error>;
}
