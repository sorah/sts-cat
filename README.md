# sts-cat

OIDC-to-GitHub-token exchange service. A Rust reimplementation of [octo-sts](https://github.com/octo-sts/app) designed for easy self-hosting on AWS (Lambda, ECS) or any environment with a TCP socket.

sts-cat accepts OIDC JWT tokens from any identity provider, validates them against trust policies stored in GitHub repositories, and returns scoped GitHub installation access tokens.

## Setup

### Prerequisites

- A [GitHub App](https://docs.github.com/en/apps/creating-github-apps) with the desired permissions
- The GitHub App's private key (PEM file) or an AWS KMS asymmetric signing key

### Configuration

All configuration is via environment variables:

| Variable | Required | Description |
|---|---|---|
| `STS_CAT_GITHUB_APP_ID` | Yes | GitHub App ID |
| `STS_CAT_IDENTIFIER` | Yes | Identifier used as default audience (e.g. `https://sts.example.com`) |
| `STS_CAT_GITHUB_API_URL` | No | GitHub API base URL (default: `https://api.github.com`) |
| `HOST` | No | Listen host (default: `0.0.0.0`). Ignored in Lambda mode. |
| `PORT` | No | Listen port (default: `8080`). Ignored in Lambda mode. |
| `STS_CAT_LOG_JSON` | No | Enable JSON-formatted logging |
| `STS_CAT_KEY_SOURCE` | Yes | Signing key source: `file`, `env`, or `aws-kms` |
| `STS_CAT_KEY_FILE` | When `file` | Path to the GitHub App PEM private key |
| `STS_CAT_KEY_ENV` | When `env` | Name of env var containing the PEM private key |
| `STS_CAT_AWS_KMS_KEY_ARN` | When `aws-kms` | ARN of the AWS KMS asymmetric signing key |
| `STS_CAT_POLICY_PATH_PREFIX` | No | Path prefix within repos for trust policy files (default: `.github/sts-cat`) |
| `STS_CAT_POLICY_FILE_EXTENSION` | No | File extension for trust policy files (default: `.sts.toml`) |
| `STS_CAT_ALLOWED_ISSUER_URLS` | No | Comma-separated list of allowed OIDC issuer URLs |
| `STS_CAT_ORG_REPO` | No | Comma-separated `org/repo` pairs to override org-level policy repository |

### Running

```bash
# HTTP server mode
STS_CAT_GITHUB_APP_ID=12345 \
STS_CAT_IDENTIFIER=https://sts.example.com \
STS_CAT_KEY_SOURCE=file \
STS_CAT_KEY_FILE=/path/to/private-key.pem \
sts-cat-http

# Docker
docker run \
  -e STS_CAT_GITHUB_APP_ID=12345 \
  -e STS_CAT_IDENTIFIER=https://sts.example.com \
  -e STS_CAT_KEY_SOURCE=file \
  -e STS_CAT_KEY_FILE=/app/private-key.pem \
  -v /path/to/private-key.pem:/app/private-key.pem:ro \
  sts-cat
```

### Lambda Deployment

Build with the `aws-lambda` feature:

```bash
cargo lambda build --release
```

Deploy the `sts-cat-lambda` binary as a Lambda function with Function URL (`AuthType=NONE`).

## API

### Token Exchange

```
POST /token HTTP/1.1
Authorization: Bearer <oidc-jwt>
Content-Type: application/json

{"scope": "org/repo", "identity": "my-policy"}
```

Response:

```json
{"token": "ghs_xxx..."}
```

- `scope`: `"org/repo"` for repository-level, or `"org"` for organization-level policies
- `identity`: Name of the trust policy file (without extension)

### Health Check

```
GET /healthz
```

Returns `{"ok": true}` with HTTP 200.

### Usage from GitHub Actions

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - name: Get token from sts-cat
        uses: actions/github-script@v7
        id: sts-cat
        with:
          script: |
            const idToken = await core.getIDToken('https://sts.example.com');
            const resp = await fetch('https://sts.example.com/token', {
              method: 'POST',
              headers: {
                'Authorization': `Bearer ${idToken}`,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                scope: '${{ github.repository }}',
                identity: 'deploy',
              }),
            });
            if (!resp.ok) {
              throw new Error(`sts-cat returned ${resp.status}: ${await resp.text()}`);
            }
            const { token } = await resp.json();
            core.setSecret(token);
            core.setOutput('github_token', token);
          result-encoding: string

      - name: Use the token
        env:
          GITHUB_TOKEN: ${{ steps.sts-cat.outputs.github_token }}
        run: |
          gh api repos/myorg/myrepo/pulls
```

The audience passed to `core.getIDToken()` must match the `STS_CAT_IDENTIFIER` value (or the `audience` field in the trust policy).

## Trust Policies

Trust policies are TOML files stored at `{policy_path_prefix}/{identity}{policy_file_extension}` in the target repository (or the `.github` repo for org-level policies).

### Repository-level example

`.github/sts-cat/deploy.sts.toml`:

```toml
issuer = "https://token.actions.githubusercontent.com"
subject = "repo:myorg/myrepo:ref:refs/heads/main"

[permissions]
contents = "read"
pull_requests = "write"
```

### Organization-level example

In the `.github` repo, `.github/sts-cat/ci.sts.toml`:

```toml
issuer = "https://token.actions.githubusercontent.com"
subject_pattern = "repo:myorg/.*:ref:refs/heads/main"
repositories = ["repo-a", "repo-b"]

[permissions]
contents = "read"
```

### Trust Policy Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `issuer` | string | One of `issuer`/`issuer_pattern` | Exact match for the OIDC token issuer |
| `issuer_pattern` | string | | Regex pattern for issuer |
| `subject` | string | One of `subject`/`subject_pattern` | Exact match for the OIDC token subject |
| `subject_pattern` | string | | Regex pattern for subject |
| `audience` | string | Optional | Exact match for at least one token audience |
| `audience_pattern` | string | | Regex pattern for audience |
| `claim_pattern` | table | Optional | Map of claim names to regex patterns |
| `max_token_lifetime` | integer | Optional | Max allowed token lifetime in seconds (`exp - nbf` or `exp - iat`) |
| `permissions` | table | Required | GitHub permission keys and access levels |
| `repositories` | array | Org-level only | Scoped list of repositories |

All regex patterns use Rust `regex` crate syntax and are automatically anchored with `^...$`.

## Building

```bash
# Default (includes both aws-kms and aws-lambda)
cargo build --release

# HTTP server only (no AWS KMS or Lambda support)
cargo build --release --no-default-features

# Lambda binary via cargo-lambda
cargo lambda build --release
```

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `aws-kms` | On | Enables AWS KMS signer |
| `aws-lambda` | On | Enables `sts-cat-lambda` binary |

## License

(c) Sorah Fukumori https://sorah.jp/

Apache 2.0 License unless otherwise noted.

- Code snippets in this README are licensed under CC0-1.0 universal. https://spdx.org/licenses/CC0-1.0.html
