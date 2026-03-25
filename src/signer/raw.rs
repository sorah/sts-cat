pub struct RawSigner {
    encoding_key: jsonwebtoken::EncodingKey,
}

impl RawSigner {
    pub fn from_pem(pem_data: &[u8]) -> Result<Self, anyhow::Error> {
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(pem_data)?;
        Ok(Self { encoding_key })
    }
}

#[async_trait::async_trait]
impl crate::signer::Signer for RawSigner {
    async fn sign(
        &self,
        message: &[u8],
    ) -> Result<secrecy::SecretBox<Vec<u8>>, crate::error::Error> {
        // jsonwebtoken::crypto::sign returns a base64url-encoded string;
        // decode it back to raw bytes for the Signer trait contract.
        use base64::Engine as _;
        let b64 =
            jsonwebtoken::crypto::sign(message, &self.encoding_key, jsonwebtoken::Algorithm::RS256)
                .map_err(crate::error::Error::JwtVerification)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| crate::error::Error::Internal(Box::new(e)))?;
        Ok(secrecy::SecretBox::new(Box::new(bytes)))
    }
}
