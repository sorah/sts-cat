#[cfg(feature = "aws-kms")]
pub struct AwsKmsSigner {
    client: aws_sdk_kms::Client,
    key_id: String,
}

#[cfg(feature = "aws-kms")]
impl AwsKmsSigner {
    pub async fn new(key_arn: String) -> Result<Self, anyhow::Error> {
        let config = aws_sdk_kms::config::Builder::from(
            &aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await,
        )
        .build();
        let client = aws_sdk_kms::Client::from_conf(config);
        Ok(Self {
            client,
            key_id: key_arn,
        })
    }

    pub fn from_client(client: aws_sdk_kms::Client, key_id: String) -> Self {
        Self { client, key_id }
    }
}

#[cfg(feature = "aws-kms")]
#[async_trait::async_trait]
impl crate::signer::Signer for AwsKmsSigner {
    #[tracing::instrument(skip_all)]
    async fn sign(
        &self,
        message: &[u8],
    ) -> Result<secrecy::SecretBox<Vec<u8>>, crate::error::Error> {
        let resp = self
            .client
            .sign()
            .key_id(&self.key_id)
            .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::RsassaPkcs1V15Sha256)
            .message_type(aws_sdk_kms::types::MessageType::Raw)
            .message(aws_sdk_kms::primitives::Blob::new(message))
            .send()
            .await
            .map_err(|e| crate::error::Error::Internal(Box::new(e)))?;

        let signature = resp.signature().ok_or_else(|| {
            crate::error::Error::Internal("KMS Sign response missing signature".into())
        })?;

        Ok(secrecy::SecretBox::new(Box::new(
            signature.as_ref().to_vec(),
        )))
    }
}

#[cfg(test)]
#[cfg(feature = "aws-kms")]
mod tests {
    use super::*;
    use crate::signer::Signer as _;
    use aws_smithy_mocks::mock;

    #[tokio::test]
    async fn test_kms_sign_success() {
        let expected_signature = b"mock-signature-bytes";
        let rule = mock!(aws_sdk_kms::Client::sign).then_output(|| {
            aws_sdk_kms::operation::sign::SignOutput::builder()
                .signature(aws_sdk_kms::primitives::Blob::new(
                    expected_signature.as_slice(),
                ))
                .key_id("arn:aws:kms:us-east-1:123456789012:key/test-key-id")
                .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::RsassaPkcs1V15Sha256)
                .build()
        });

        let client = aws_smithy_mocks::mock_client!(aws_sdk_kms, [&rule]);
        let signer = AwsKmsSigner::from_client(
            client,
            "arn:aws:kms:us-east-1:123456789012:key/test-key-id".into(),
        );

        use secrecy::ExposeSecret as _;
        let result = signer.sign(b"test message").await.unwrap();
        assert_eq!(result.expose_secret().as_slice(), expected_signature);
        assert_eq!(rule.num_calls(), 1);
    }

    #[tokio::test]
    async fn test_kms_sign_error() {
        let rule = mock!(aws_sdk_kms::Client::sign).then_error(|| {
            aws_sdk_kms::operation::sign::SignError::NotFoundException(
                aws_sdk_kms::types::error::NotFoundException::builder()
                    .message("key not found")
                    .build(),
            )
        });

        let client = aws_smithy_mocks::mock_client!(aws_sdk_kms, [&rule]);
        let signer = AwsKmsSigner::from_client(
            client,
            "arn:aws:kms:us-east-1:123456789012:key/nonexistent".into(),
        );

        let result = signer.sign(b"test message").await;
        assert!(result.is_err());
    }
}
