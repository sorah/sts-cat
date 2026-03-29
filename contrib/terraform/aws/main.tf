locals {
  source_hash = sha256("${var.source_url}${var.source_sha512}")

  module_env_vars = merge(
    {
      STS_CAT_GITHUB_APP_ID  = var.github_app_id
      STS_CAT_DOMAIN         = var.domain
      STS_CAT_KEY_SOURCE     = "aws-kms"
      STS_CAT_AWS_KMS_KEY_ARN = var.aws_kms_key_arn
      STS_CAT_LOG_JSON       = "true"
    },
    var.policy_path_prefix != null ? {
      STS_CAT_POLICY_PATH_PREFIX = var.policy_path_prefix
    } : {},
    var.policy_file_extension != null ? {
      STS_CAT_POLICY_FILE_EXTENSION = var.policy_file_extension
    } : {},
    var.allowed_issuer_urls != null ? {
      STS_CAT_ALLOWED_ISSUER_URLS = join(",", var.allowed_issuer_urls)
    } : {},
    var.org_repo != null ? {
      STS_CAT_ORG_REPO = join(",", var.org_repo)
    } : {},
  )
}

data "http" "source" {
  url = var.source_url

  lifecycle {
    postcondition {
      condition     = var.source_sha512 == null || sha512(self.response_body_base64) == var.source_sha512
      error_message = "SHA-512 checksum mismatch for source zip"
    }
  }
}

resource "local_file" "source" {
  filename       = "${path.module}/.terraform/source-${local.source_hash}.zip"
  content_base64 = sensitive(data.http.source.response_body_base64)
}

resource "aws_lambda_function" "this" {
  function_name    = var.function_name
  filename         = local_file.source.filename
  source_code_hash = local_file.source.content_sha256

  runtime       = "provided.al2023"
  handler       = "bootstrap"
  architectures = [var.architecture]
  role          = var.iam_role_arn
  memory_size   = var.memory_size
  timeout       = var.timeout

  environment {
    variables = merge(local.module_env_vars, var.environment_variables)
  }
}

resource "aws_lambda_function_url" "this" {
  function_name      = aws_lambda_function.this.function_name
  authorization_type = "NONE"
}
