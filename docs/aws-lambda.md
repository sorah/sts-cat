# Deploying sts-cat on AWS Lambda

This guide covers deploying sts-cat as an AWS Lambda function with a function URL, using the provided Terraform module. You can also build the Lambda package yourself with:

```bash
cargo lambda build --release
```

## Prerequisites

- A [GitHub App](https://docs.github.com/en/apps/creating-github-apps) with the permissions you want to vend (e.g., `contents:read`)
- An AWS KMS asymmetric signing key (RSA_2048, SIGN_VERIFY usage) containing the GitHub App's private key
  - Use `contrib/aws-kms-import-pem.rb` to import an existing PEM key into KMS
- An IAM role for the Lambda function
- Terraform >= 1.0

## KMS Key

Create an external KMS key for importing the GitHub App's RSA private key:

```hcl
resource "aws_kms_external_key" "sts_cat" {
  description = "sts-cat key"
  key_spec    = "RSA_2048"
  policy      = data.aws_iam_policy_document.sts_cat_kms.json
  key_usage   = "SIGN_VERIFY"
}

data "aws_iam_policy_document" "sts_cat_kms" {
  statement {
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_kms_alias" "sts_cat" {
  name          = "alias/sts-cat"
  target_key_id = aws_kms_external_key.sts_cat.id
}
```

Then import the GitHub App's PEM private key into the KMS key:

```bash
ruby contrib/aws-kms-import-pem.rb <kms-key-arn> <path-to-private-key.pem>
```

## IAM Role

The Lambda execution role needs the following in addition to the basic Lambda policies:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "kms:Sign",
      "Resource": "<your-kms-key-arn>"
    }
  ]
}
```

## Terraform Module

The module is available at `contrib/terraform/aws` in this repository, or as a tarball attached to each [GitHub release](https://github.com/sorah/sts-cat/releases).

### Usage

```hcl
module "sts_cat" {
  source = "github.com/sorah/sts-cat//contrib/terraform/aws"

  function_name   = "sts-cat"
  iam_role_arn    = aws_iam_role.sts_cat.arn
  github_app_id   = "12345"
  identifier      = "https://sts.example.com"
  aws_kms_key_arn = aws_kms_key.sts_cat.arn
  architecture    = "arm64"

  # Find source_url and source_sha512 in the GitHub release description
  source_url    = "https://github.com/sorah/sts-cat/releases/download/v0.1.0/sts-cat-lambda.arm64.zip"
  source_sha512 = "..."
}
```

### Inputs

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `function_name` | Lambda function name | yes | |
| `source_url` | URL to the Lambda zip from a GitHub release | yes | |
| `source_sha512` | SHA-512 checksum (see release description) | no | |
| `iam_role_arn` | IAM execution role ARN | yes | |
| `github_app_id` | GitHub App ID | yes | |
| `identifier` | Default audience identifier (`STS_CAT_IDENTIFIER`) | yes | |
| `aws_kms_key_arn` | KMS key ARN for GitHub App signing | yes | |
| `architecture` | `arm64` or `x86_64` | no | `arm64` |
| `memory_size` | Memory in MB | no | `256` |
| `timeout` | Timeout in seconds | no | `30` |
| `policy_path_prefix` | Override policy path prefix | no | |
| `policy_file_extension` | Override policy file extension | no | |
| `allowed_issuer_urls` | Restrict allowed OIDC issuers | no | |
| `org_repo` | Org-level policy repo overrides | no | |
| `allowed_orgs` | Restrict to specific org names | no | |
| `environment_variables` | Additional env vars (merged, user wins) | no | `{}` |

### Outputs

| Name | Description |
|------|-------------|
| `function_arn` | ARN of the deployed Lambda function |
| `function_url` | Lambda function URL endpoint |

## Install the GitHub App

After deploying, install the GitHub App on each organization or repository where you want sts-cat to vend tokens. The app needs at least `metadata:read` plus whatever permissions your trust policies will grant.

## Trust Policies

Create trust policy files in target repositories at `.github/sts-cat/<identity>.sts.toml`:

```toml
issuer = "https://token.actions.githubusercontent.com"
subject = "repo:myorg/myrepo:ref:refs/heads/main"

[permissions]
contents = "read"
```

See the [README](../README.md) for the full trust policy reference.

## Testing

```bash
# Health check
curl https://<function-url>/healthz

# Exchange token (example with GitHub Actions OIDC)
curl -X POST https://<function-url>/token \
  -H "Authorization: Bearer <oidc-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"scope": "myorg/myrepo", "identity": "deploy"}'
```
