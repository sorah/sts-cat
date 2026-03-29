variable "function_name" {
  type        = string
  description = "Lambda function name"
}

variable "source_url" {
  type        = string
  description = "URL to download the Lambda function zip package"
}

variable "source_sha512" {
  type        = string
  description = "SHA-512 checksum of the zip file. When provided, validated via postcondition"
  default     = null
}

variable "iam_role_arn" {
  type        = string
  description = "IAM role ARN for the Lambda function execution"
}

variable "github_app_id" {
  type        = string
  description = "GitHub App ID (STS_CAT_GITHUB_APP_ID)"
}

variable "domain" {
  type        = string
  description = "Domain name used as default audience (STS_CAT_DOMAIN)"
}

variable "aws_kms_key_arn" {
  type        = string
  description = "ARN (or alias ARN) of the AWS KMS asymmetric signing key for the GitHub App"
}

variable "architecture" {
  type        = string
  description = "Lambda function architecture"
  default     = "arm64"
}

variable "memory_size" {
  type        = number
  description = "Lambda function memory in MB"
  default     = 256
}

variable "timeout" {
  type        = number
  description = "Lambda function timeout in seconds"
  default     = 30
}

variable "policy_path_prefix" {
  type        = string
  description = "Override trust policy path prefix (STS_CAT_POLICY_PATH_PREFIX)"
  default     = null
}

variable "policy_file_extension" {
  type        = string
  description = "Override trust policy file extension (STS_CAT_POLICY_FILE_EXTENSION)"
  default     = null
}

variable "allowed_issuer_urls" {
  type        = list(string)
  description = "Allowed OIDC issuer URLs (STS_CAT_ALLOWED_ISSUER_URLS)"
  default     = null
}

variable "org_repo" {
  type        = list(string)
  description = "Org-level policy repository overrides (STS_CAT_ORG_REPO), e.g. [\"myorg/policies\"]"
  default     = null
}

variable "environment_variables" {
  type        = map(string)
  description = "Additional environment variables. Merged with module-managed variables; user values take precedence on collision"
  default     = {}
}
