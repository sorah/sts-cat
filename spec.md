# sts-cat design doc

## Summary

sts-cat is a Rust reimplementation of [octo-sts](https://github.com/octo-sts/app), an OIDC-to-GitHub-token exchange service. It accepts OIDC JWT tokens from any identity provider, validates them against trust policies stored in GitHub repositories, and returns scoped GitHub installation access tokens. Designed for easy self-hosting on AWS (Lambda, ECS) or any environment with a TCP socket, without Google Cloud dependencies.

## Motivation

octo-sts lacks sufficient documentation and tooling for self-hosting. Its implementation is deeply coupled with Google Cloud services (Cloud KMS, Cloud Run, Secret Manager, CloudEvents). For teams on AWS who want to use OIDC federation for GitHub token exchange (e.g., from GitHub Actions, CI/CD systems, or other OIDC-capable workloads), there is no straightforward path to deploy octo-sts.

sts-cat addresses this by:
- Rewriting in Rust for a single static binary with minimal runtime dependencies
- Supporting AWS KMS for private key operations instead of Google Cloud KMS
- Running as an AWS Lambda function (via Function URL) or a standalone HTTP server
- Using environment variables for configuration instead of GCP-specific secret management
- Using TOML for trust policies instead of YAML

## Explanation

### HTTP API

sts-cat exposes a single REST endpoint for token exchange:

```
POST /token HTTP/1.1
Authorization: Bearer <oidc-jwt>
Content-Type: application/json

{"scope": "org/repo", "identity": "my-policy"}
```

Response on success:

```
HTTP/1.1 200 OK
Content-Type: application/json

{"token": "ghs_xxx..."}
```

- `scope`: Target GitHub scope. `"org/repo"` for a specific repository, or `"org"` for organization-level policies (reads from the `.github` repo).
- `identity`: Name of the trust policy file (without extension).
- `Authorization`: OIDC JWT bearer token from the requesting workload.

### Server Configuration

All server configuration is provided via environment variables:

| Variable | Required | Description |
|---|---|---|
| `STS_CAT_GITHUB_APP_ID` | Yes | GitHub App ID |
| `STS_CAT_DOMAIN` | Yes | Domain name used as default audience (e.g. `sts.example.com`) |
| `STS_CAT_HOST` / `HOST` | No | Listen host (default: `0.0.0.0`). Ignored in Lambda mode. |
| `STS_CAT_PORT` / `PORT` | No | Listen port (default: `8080`). Ignored in Lambda mode. |
| `STS_CAT_KEY_SOURCE` | Yes | Signing key source: `file`, `env`, or `kms` |
| `STS_CAT_KEY_FILE` | When `file` | Path to the GitHub App PEM private key |
| `STS_CAT_KEY_ENV` | When `env` | Name of env var containing the PEM private key |
| `STS_CAT_KMS_KEY_ARN` | When `kms` | ARN of the AWS KMS asymmetric signing key |
| `STS_CAT_ALLOWED_ISSUER_URLS` | No | Comma-separated list of allowed OIDC issuer URLs. When set, only tokens from these issuers are accepted. |

### Trust Policies

Trust policies are TOML files stored in GitHub repositories at a configurable path prefix. The default path is `.github/sts-cat/{name}.sts.toml`.

| Variable | Required | Description |
|---|---|---|
| `STS_CAT_POLICY_PATH_PREFIX` | No | Path prefix within repos for trust policy files (default: `.github/sts-cat`) |
| `STS_CAT_POLICY_FILE_EXTENSION` | No | File extension for trust policy files (default: `.sts.toml`) |

#### Trust Policy TOML Schema

Trust policies are TOML files with the following fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `issuer` | string | Exactly one of `issuer` or `issuer_pattern` | Exact match for the OIDC token issuer |
| `issuer_pattern` | string | | Regex pattern for issuer (auto-wrapped with `^...$`) |
| `subject` | string | Exactly one of `subject` or `subject_pattern` | Exact match for the OIDC token subject |
| `subject_pattern` | string | | Regex pattern for subject (auto-wrapped with `^...$`) |
| `audience` | string | Optional (at most one of `audience`/`audience_pattern`) | Exact match for at least one token audience |
| `audience_pattern` | string | | Regex pattern for audience (auto-wrapped with `^...$`) |
| `claim_pattern` | table | Optional | Map of claim names to regex patterns. All must match. Boolean claims are coerced to `"true"`/`"false"`. |
| `permissions` | table | Required | GitHub installation permission keys and their access levels (`"read"` or `"write"`) |
| `repositories` | array of strings | Org-level only | Scoped list of repositories. Only valid in policies read from the `.github` repo. |

If neither `audience` nor `audience_pattern` is set, the token's audience must contain `STS_CAT_DOMAIN`.

All regex patterns use Rust `regex` crate syntax and are automatically anchored with `^` and `$`.

**Repository-level policy example** (`.github/sts-cat/deploy.sts.toml`):

```toml
issuer = "https://token.actions.githubusercontent.com"
subject = "repo:myorg/myrepo:ref:refs/heads/main"

[permissions]
contents = "read"
pull_requests = "write"
```

**Organization-level policy example** (in `.github` repo, `.github/sts-cat/ci.sts.toml`):

```toml
issuer = "https://token.actions.githubusercontent.com"
subject_pattern = "repo:myorg/.*:ref:refs/heads/main"
repositories = ["repo-a", "repo-b"]

[permissions]
contents = "read"
```


### Error Responses

Errors are returned as JSON with an appropriate HTTP status code:

```json
{"error": "unable to verify bearer token"}
```

| HTTP Status | Meaning |
|---|---|
| 400 | Invalid request (missing fields, bad token format) |
| 401 | Bearer token verification failed |
| 403 | Token does not match trust policy |
| 404 | Trust policy not found |
| 429 | GitHub API rate limit exceeded |
| 500 | Internal error (token exchange failure) |

## Drawbacks

- **Not a drop-in replacement for octo-sts.** Different API endpoint (`POST /token` vs gRPC), different trust policy format (TOML vs YAML), different file path (`.github/sts-cat/` vs `.github/chainguard/`). Existing octo-sts users must migrate policies.
- **Single GitHub App only.** No round-robin across multiple apps, which limits throughput for very large organizations hitting GitHub API rate limits.

## Considered Alternatives

- **Fork and patch octo-sts.** Rejected because octo-sts is deeply coupled with Chainguard's SDK, gRPC framework, and Google Cloud services. Decoupling would be more work than a focused rewrite.
- **Use octo-sts with a GCP compatibility shim.** Rejected because it would require emulating GCP KMS and Secret Manager APIs, adding complexity without simplifying the deployment.

## Prior Art

- [octo-sts](https://github.com/octo-sts/app) — the original Go implementation. Source code available at `~/git/github.com/octo-sts/app`.

## Security and Privacy Considerations

- **OIDC issuer validation**: Strict validation rules (HTTPS, no path traversal, ASCII-only, etc.) prevent SSRF and token confusion attacks. Operators can further restrict accepted issuers via `STS_CAT_ALLOWED_ISSUER_URLS`.
- **OIDC discovery issuer verification**: The `issuer` field returned in the OIDC discovery document is verified to match the requested issuer, preventing token confusion via compromised discovery endpoints.
- **Default branch only**: Trust policies are always read from the repository's default branch, preventing branch-based policy injection.
- **Token revocation**: Temporary read-only installation tokens used to fetch policies are revoked immediately after use.
- **No internal error leakage**: Client-facing error messages are generic. Internal details (GitHub API errors, stack traces) are only logged via tracing at debug level.
- **Response size limits**: All external fetches (OIDC discovery, JWKS, trust policy) are capped at 100 KiB.
- **Token not logged**: The issued GitHub installation token is never logged. Only its SHA-256 hash is recorded for audit purposes.
- **Least privilege**: Temporary tokens for policy fetching are scoped to read-only contents on the specific repository. Issued tokens are scoped to the exact permissions declared in the trust policy.
- **Regex anchoring**: All trust policy patterns are automatically wrapped with `^...$` to prevent partial matches.
- **OIDC redirect validation**: Redirect destinations during OIDC discovery are validated with the same issuer rules, preventing SSRF via open redirects.
- **Claim type strictness**: Only string and boolean claim values are accepted. Booleans are coerced to `"true"`/`"false"`. All other types (numbers, arrays, objects) are rejected.
- **Repositories field enforcement**: The `repositories` field in trust policies is rejected at parse time for repository-level scopes, preventing privilege escalation.
- **HTTP timeouts**: All outbound HTTP requests (OIDC, GitHub API) use explicit connect and response timeouts to prevent hanging connections.
- **Org-level policy scope**: Organization-level trust policies that omit the `repositories` field grant the declared permissions across **all repositories** the GitHub App is installed on within that organization. This matches octo-sts behavior and is by design — the GitHub App's installation scope (which repositories it is installed on) is the access control boundary. Operators should scope GitHub App installations to only the repositories that need token exchange.

## Comparison with octo-sts: Gap Analysis

This section documents a systematic comparison between sts-cat's design and the octo-sts source code, identifying gaps, oversights, and intentional divergences. Each finding includes a resolution.

### Module Structure Mapping

| octo-sts (Go) | sts-cat (Rust) | Notes |
|---|---|---|
| **Binaries** | | |
| `cmd/app/main.go` | `src/bin/sts-cat-http.rs` | gRPC+HTTP gateway → plain axum HTTP server |
| `cmd/webhook/main.go` | _(dropped)_ | Webhook validation out of scope |
| `cmd/prober/main.go` | _(dropped)_ | Health prober — not needed, `GET /healthz` built-in |
| `cmd/negative-prober/main.go` | _(dropped)_ | Negative test prober — not needed |
| `cmd/schemagen/main.go` | _(dropped)_ | JSON schema generator for trust policy — not needed |
| _(N/A)_ | `src/bin/sts-cat-lambda.rs` | New: Lambda Function URL entry point |
| **Core exchange logic** | | |
| `pkg/octosts/octosts.go` | `src/exchange.rs` | Exchange handler, request validation, flow orchestration |
| `pkg/octosts/trust_policy.go` | `src/trust_policy.rs` | Policy parsing, compilation, token matching |
| `pkg/octosts/event.go` | _(inlined)_ | Actor/Event structs → inlined in `exchange.rs` as tracing fields |
| `pkg/octosts/revoke.go` | `src/github.rs` | Revocation → method on `GitHubClient` |
| **OIDC** | | |
| `pkg/oidcvalidate/validate.go` | `src/oidc.rs` | `validate_issuer`, `validate_subject`, `validate_audience` |
| `pkg/provider/provider.go` | `src/oidc.rs` | OIDC discovery, JWKS fetch, provider cache, retry logic — merged into `OidcVerifier` |
| `pkg/maxsize/maxsize.go` | `src/oidc.rs` | Response size limiting — applied via `reqwest` response body read limit in `OidcVerifier` |
| **GitHub integration** | | |
| `pkg/ghinstall/ghinstall.go` | `src/github.rs` | Installation lookup — merged into `GitHubClient::get_installation_id` |
| `pkg/ghtransport/ghtransport.go` | `src/github.rs` + `src/signer/` | Transport creation → JWT construction in `GitHubClient::app_jwt` + `Signer` trait |
| **Signing** | | |
| `pkg/gcpkms/gcpkms.go` | `src/signer/kms.rs` | GCP KMS → AWS KMS (`AwsKmsSigner`) |
| _(env var / file in ghtransport)_ | `src/signer/raw.rs` | PEM key loading — extracted into dedicated `RawSigner` |
| **Configuration** | | |
| `pkg/envconfig/envconfig.go` | `src/config.rs` | Env config → clap derive with env support |
| **Webhooks** | | |
| `pkg/webhook/webhook.go` | _(dropped)_ | Webhook validation entirely out of scope |
| **Probing** | | |
| `pkg/prober/prober.go` | _(dropped)_ | GCP-specific OIDC prober — not applicable |
| **Shared** | | |
| _(N/A)_ | `src/error.rs` | New: centralized error type with `IntoResponse` |
| _(N/A)_ | `src/lib.rs` | New: crate root tying modules together |

**Key differences in structure:**

- **Fewer modules by design.** octo-sts has 10 packages under `pkg/` because Go encourages small packages. sts-cat merges related concerns: `provider` + `oidcvalidate` + `maxsize` → `oidc.rs`; `ghinstall` + `ghtransport` + `revoke` → `github.rs`.
- **No separate event type.** octo-sts has `event.go` with `Event`, `Actor`, `Claim` structs for CloudEvents serialization. sts-cat logs via tracing structured fields — the `Actor` struct lives in `trust_policy.rs`, event fields are ad-hoc in `exchange.rs`.
- **Signer extracted as a first-class module.** octo-sts embeds key source selection in `ghtransport.go` with the signing delegated to `ghinstallation.AppsTransport`. sts-cat builds JWTs itself and delegates only the raw signing operation to the `Signer` trait, making `signer/` a standalone module with `raw.rs` and `kms.rs`.
- **No round-robin manager.** octo-sts has `Manager` interface + `roundRobin` struct in `ghinstall`. sts-cat supports a single app, so installation lookup is a direct method on `GitHubClient`.

### Critical Gaps (security-relevant)

#### 1. OIDC Redirect Validation During Discovery

**octo-sts behavior**: When fetching OIDC discovery metadata, the HTTP client validates every redirect destination with `IsValidIssuer()` (`pkg/provider/provider.go:49-55`). This prevents SSRF attacks where a malicious issuer redirects discovery to an internal service.

**Gap in spec**: The spec mentioned OIDC discovery but did not specify redirect handling.

**Resolution**: The `reqwest::Client` used for OIDC discovery must have a custom redirect policy that validates each redirect URL with `validate_issuer()`. Added to `OidcVerifier` construction.

#### 2. Subject vs Audience Validation Have Different Character Sets

**octo-sts behavior**: `IsValidSubject()` and `IsValidAudience()` reject different character sets (`pkg/oidcvalidate/validate.go`):
- Subject rejects: `"'` `` ` `` `\<>;&$(){}[]` — but allows `@`, `|`, `:`, `/`
- Audience rejects: `"'` `` ` `` `\<>;|&$(){}[]@` — note: also rejects `@`, `|`, `[]`
- Both reject control chars (0x00-0x1f), whitespace, and non-printable Unicode

**Gap in spec**: The spec said "validated for control characters and injection characters" without distinguishing the two.

**Resolution**: Implement separate `validate_subject()` and `validate_audience()` functions with the exact character sets above. The `validate_string_claim()` in `src/oidc.rs` must be split into two functions.

#### 3. Issuer Validation: Missing Path-Level Detail

**octo-sts behavior** (`pkg/oidcvalidate/validate.go:74-118`) enforces rules not fully enumerated in the spec:
- Path character strict whitelist: `[a-zA-Z0-9\-._~/]+` — only these characters allowed
- Single-dot segments (`.`) rejected — not just `..`
- Double-tilde (`~~`) rejected
- Per-segment max length: 150 characters
- Tilde-only segments (`~`) rejected

**Gap in spec**: The spec listed some rules but missed the strict whitelist, single-dot segments, double-tilde, tilde segments, and per-segment length limit.

**Resolution**: All rules now enumerated in the OIDC Token Validation section.

#### 4. Token Claims Validated INSIDE CheckToken, Before Policy Matching

**octo-sts behavior**: `CheckToken()` (`trust_policy.go:131-142`) validates the token's issuer, subject, and every audience string with `IsValidIssuer()`, `IsValidSubject()`, and `IsValidAudience()` BEFORE attempting any policy matching. This is defense-in-depth: even if the JWT verification library doesn't reject malformed claims, the policy matcher will.

**Gap in spec**: The verification flow listed "Validate issuer, subject, audience format strings" as step 7, after OIDC verification but separately from `check_token`. In reality this must happen inside `CompiledTrustPolicy::check_token()` as the first operation, before any pattern matching.

**Resolution**: `CompiledTrustPolicy::check_token()` must validate all claim format strings as its first step.

#### 5. Repositories Field Enforcement for Repo-Level Policies

**octo-sts behavior**: Uses two separate Go types — `TrustPolicy` (no `repositories` field) and `OrgTrustPolicy` (embeds `TrustPolicy` + `repositories`). For repo-level scopes, the YAML is parsed via `yaml.UnmarshalStrict()` into `TrustPolicy`, which means any `repositories` key in the file causes a parse error. This prevents a repo-level policy from attempting to scope to other repositories.

**Gap in spec**: sts-cat uses a single `TrustPolicy` struct with `repositories: Option<Vec<String>>`. A repo-level policy file with `repositories = [...]` would parse without error, and the field would be silently ignored (overridden by the implicit `[repo]` scoping). This is a security weakness — a repo-level policy should not be allowed to contain `repositories`.

**Resolution**: Two approaches:
- **(A) Strict parsing with `#[serde(deny_unknown_fields)]`-like approach**: Parse repo-level policies with a struct that has no `repositories` field, org-level with one that does. Reject unknown fields.
- **(B) Post-parse validation**: Parse with the single struct, then reject if `repositories` is `Some` for a repo-level scope.

Adopt approach **(B)**: after parsing and before compilation, `compile()` takes an `is_org_level: bool` parameter. If `!is_org_level && repositories.is_some()`, return error.

#### 6. Claim Type Handling: Numeric Values Rejected

**octo-sts behavior**: In `CheckToken()` (`trust_policy.go:218-228`), claim values are processed as follows:
1. If `bool` → coerce to `"true"` or `"false"` string
2. If `string` → use as-is
3. Otherwise → reject with `PermissionDenied` ("expected claim not a string")

Numeric claims, arrays, nested objects are all rejected.

**Gap in spec**: The spec mentioned boolean coercion but didn't explicitly state that non-string, non-bool claims are rejected.

**Resolution**: `CompiledTrustPolicy::check_token()` must match exactly: `serde_json::Value::String` → use, `serde_json::Value::Bool` → coerce, all other types → reject.

### Medium Gaps (correctness / robustness)

#### 7. OIDC Provider Discovery Retry Logic

**octo-sts behavior** (`pkg/provider/provider.go:71-101`): OIDC provider creation uses exponential backoff retry:
- Initial interval: 1s, max 30s, multiplier 2.0, jitter ±10%
- Permanent errors (no retry): HTTP 400, 401, 403, 404, 405, 406, 410, 415, 422, 501
- All other errors (including 5xx): retried

**Gap in spec**: The spec did not mention retry logic for OIDC discovery.

**Resolution**: Implement retry with exponential backoff for OIDC discovery using `backon` crate or manual implementation. Classify HTTP 4xx (except 408, 429) and 501 as permanent; retry on 5xx, timeouts, and network errors. This is especially important since OIDC providers can have transient failures.

#### 8. GitHub API HTTP 422 Special Handling

**octo-sts behavior** (`octosts.go:191-214`): When GitHub returns HTTP 422 during token creation, the response body (which contains a useful error message about invalid permission combinations) is logged at debug level, and a generic `PermissionDenied` is returned to the client. For other errors, the full response is dumped at debug level with a generic `Internal` error to the client.

**Gap in spec**: The spec's error handling section didn't distinguish 422 from other GitHub errors.

**Resolution**: `GitHubClient::create_installation_token()` must:
- On 422: log body at debug, return `Error::PermissionDenied`
- On 403/429: return `Error::RateLimited`
- On other errors: log at debug, return `Error::Internal`

#### 9. GitHub API Rate Limit: Both 403 and 429

**octo-sts behavior** (`octosts.go:311-316`): Both HTTP 403 (which GitHub uses for secondary rate limits) and HTTP 429 are treated as rate limit errors, mapped to `codes.ResourceExhausted`.

**Gap in spec**: The error response table shows 429 for rate limiting but doesn't mention that GitHub's 403 can also be a rate limit.

**Resolution**: Map both GitHub 403 and 429 responses to `Error::RateLimited` (HTTP 429 to client).

#### 10. Token Revocation: Expected Response Code

**octo-sts behavior** (`revoke.go:26`): Expects HTTP 204 No Content from the revocation endpoint. Any other status is an error.

**Gap in spec**: The spec says "revoke via DELETE" but doesn't specify expected response or error handling.

**Resolution**: `revoke_token()` must expect HTTP 204. Log warning on failure but do not propagate — revocation failure should not fail the exchange. The token will expire on its own.

#### 11. HTTP Client Configuration

**octo-sts behavior**: Uses separate HTTP clients for different purposes:
- OIDC discovery: custom client with size limiter + redirect validator + metrics
- GitHub API: uses `ghinstallation` transport (handles JWT auth)
- Revocation: `http.DefaultClient` (no customization)

**Gap in spec**: No mention of:
- Connection timeouts for outbound HTTP
- User-Agent header
- Redirect policy per client
- Separate clients for OIDC vs GitHub

**Resolution**: Configure `reqwest::Client` instances with:
- Connect timeout: 10s
- Response timeout: 30s
- User-Agent: `sts-cat/<version>`
- OIDC client: custom redirect policy (validate with `validate_issuer`), response size limiter
- GitHub client: no redirects (API shouldn't redirect), `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2026-03-10`

#### 12. Installation Lookup Pagination

**octo-sts behavior** (`ghinstall.go`): Walks all pages (100 per page) of `GET /app/installations` until finding the matching owner. No upper bound on pages.

**Gap in spec**: No mention of pagination handling or limits.

**Resolution**: Implement pagination (100 per page). Add a reasonable upper bound (e.g., 50 pages = 5000 installations) to prevent unbounded API calls. Log a warning if the limit is hit.

### Low Gaps (minor / intentional divergences)

#### 13. Compile Idempotency Guard

**octo-sts**: `TrustPolicy.Compile()` has an `isCompiled` flag — calling `Compile()` twice returns an error.

**Resolution**: In Rust, this is naturally handled by the type system: `TrustPolicy::compile(self)` consumes `self` and returns `CompiledTrustPolicy`. Double-compilation is impossible. No gap.

#### 14. OIDC Provider Cache Has No TTL

Both octo-sts and sts-cat use LRU cache with no TTL for OIDC providers. A compromised signing key would persist in cache until evicted by LRU pressure.

**Accepted risk**: Same as octo-sts. OIDC providers rotate keys infrequently. JWKS endpoints include key IDs — if a key is rotated, JWT verification will fail because the kid won't match cached keys, forcing a cache miss and re-fetch on the next request with a new token.

#### 15. Audit Event: Trust Policy Content in Logs

**octo-sts**: Includes the full `OrgTrustPolicy` in the audit event. This means permissions and repositories lists are logged.

**Resolution**: sts-cat already logs scope, identity, issuer, subject, and matched claims. The trust policy content (permissions, repositories) is in the git-versioned policy file itself, so logging it is optional. Log `policy_path` (e.g., `.github/sts-cat/deploy.sts.toml`) instead of the full policy body.

#### 16. Legacy Scope Handling

**octo-sts**: Supports a deprecated `GetScope()` fallback for old clients.

**Resolution**: Not needed. sts-cat is a new project with no legacy clients. Dropped intentionally.

## Mission Scope

### In scope

This list is non exhaustive. Key highlights that the author wants to have.

- __Rust.__ Rewrite in Rust.
- __Bare GitHub App private key support.__ via file or environment variable.
- __AWS KMS support.__ instead of Google Cloud equivalent one. Delegate private key operation to KMS.
  - worth to have Signer trait for abstraction between raw key vs cloud-stored key.
- __HTTP servers.__ Support various HTTP serving mode. Straightforward -- listen TCP socket for HTTP1, or serve as a Lambda function for a Lambda Function URL event.
- __Feature flags.__ Cloud provider specific or runtime specific modes must be disabled with feature flag when building.
- __Logging.__ Use `tracing`, `tracing_subscriber` for logging, including audit logs.

### Out of scope

- __Webhooks.__ octo-sts provides webhooks to validate trust policies as GitHub Checks, but this is not needed for the initial release.
- __YAML configuration.__ Trust policies use TOML instead of YAML.
- __Google Cloud support.__ No GCP KMS, no Cloud Run, no GCP-specific features.
- __GitHub Action.__ No bundled Action for calling the API. Users call it directly with curl or custom scripts. Can be added as a separate project later.
- __Multi-app support.__ Only a single GitHub App is supported. octo-sts's round-robin multi-app feature is not included.
- __CloudEvents / external event sink.__ Audit logging is via structured tracing logs only, not CloudEvents.

### Expected Outcomes

- `sts-cat-http` binary — standalone TCP HTTP server
- `sts-cat-lambda` binary — Lambda Function URL handler (built with `aws-lambda` feature)
- `Dockerfile` — container image for HTTP server mode
- `README.md` — setup guide, configuration reference, usage examples

## Implementation Plan

### HTTP Framework

Use `axum` for the HTTP server. Lambda integration via the `lambda_http` crate, which adapts Lambda Function URL events to standard `http::Request`/`http::Response` types compatible with axum's tower-based architecture.

### Signer Trait and Key Sources

A `Signer` trait abstracts over different private key sources for signing GitHub App JWTs (RS256):

```rust
#[async_trait]
pub trait Signer: Send + Sync {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
}
```

Three implementations, selected by `STS_CAT_KEY_SOURCE`:

1. **`file`** — Reads PEM private key from `STS_CAT_KEY_FILE`. Signs in-process using `jsonwebtoken`'s `aws_lc_rs` backend.
2. **`env`** — Reads PEM private key from the env var named in `STS_CAT_KEY_ENV`. Signs in-process using `jsonwebtoken`'s `aws_lc_rs` backend.
3. **`kms`** — Delegates signing to AWS KMS. Key must be `RSA_2048` with `SIGN_VERIFY` usage. Calls KMS `Sign` API with `RSASSA_PKCS1_V1_5_SHA_256` algorithm. JWT RS256 uses RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 §3.3), which is directly compatible with this KMS algorithm.

### GitHub App Integration

sts-cat supports a single GitHub App. The app ID is configured via `STS_CAT_GITHUB_APP_ID`.

The server constructs GitHub App JWTs itself (no `ghinstallation` Go library equivalent needed — just build the JWT claims and sign with the Signer trait). It then uses the GitHub REST API to:

1. Look up the installation ID for a given organization/owner.
2. Fetch trust policy files from repositories.
3. Create scoped installation access tokens.

### Caching

Use the `moka` crate for async-aware, TTL-supporting caches:

| Cache | Max Entries | TTL | Key | Value |
|---|---|---|---|---|
| OIDC Providers | 100 | None (evict on LRU) | Issuer URL | OIDC provider metadata + JWKS |
| Trust Policies | 200 | 5 minutes | `(owner, repo, identity)` | Raw TOML string |
| Installation IDs | 200 | None (evict on LRU) | Owner name | Installation ID |

### Key Crate Dependencies

| Crate | Purpose |
|---|---|
| `clap` | CLI argument and env var parsing (with `derive` and `env` features) |
| `axum` | HTTP framework |
| `tokio` | Async runtime |
| `reqwest` | HTTP client for OIDC discovery, JWKS fetching, and GitHub API calls |
| `jsonwebtoken` | JWT verification (OIDC tokens) and construction (GitHub App JWTs). Use `aws_lc_rs` crypto backend. |
| `serde`, `serde_json` | Serialization |
| `toml` | Trust policy parsing |
| `regex` | Pattern matching in trust policies |
| `moka` | Async LRU caches with TTL |
| `tracing`, `tracing-subscriber` | Structured logging |
| `url` | URL parsing for issuer validation |
| `backon` | Retry with exponential backoff for OIDC discovery |
| `async_trait` | Async trait support for `Signer` trait (dyn dispatch) |
| `thiserror` | Error enum derive |
| `sha2` | SHA-256 hashing for token audit logging |
| `aws-sdk-kms` | AWS KMS signing (behind `aws-kms` feature) |
| `aws-smithy-mocks` | Mock AWS SDK responses for `AwsKmsSigner` tests (dev-dependency, behind `aws-kms` feature) |
| `lambda_http` | Lambda Function URL adapter (behind `aws-lambda` feature) |

### GitHub API Client

Direct REST API calls via `reqwest` — no GitHub SDK. Only four endpoints are needed:

1. `GET /app/installations` — find installation ID for an owner (paginated, 100 per page)
2. `GET /repos/{owner}/{repo}/contents/{path}` — fetch trust policy file (default branch only, no `?ref=` parameter — this is a security feature preventing branch-based policy injection)
3. `POST /app/installations/{id}/access_tokens` — create scoped installation token
4. `DELETE /installation/token` — revoke temporary read-only token after policy fetch

All GitHub API calls use a GitHub App JWT in the `Authorization: Bearer` header. The JWT is constructed with `iss` (app ID), `iat` (now - 60s for clock skew), `exp` (now + 540s, totaling 10 minutes — GitHub's maximum), signed with RS256 using the configured Signer.

### OIDC Token Validation

Replicate octo-sts's strict validation rules.

#### Issuer Validation (`validate_issuer`)

- **Max 255 characters** (rune count)
- **Valid URL** parseable by `url::Url`
- **HTTPS required** (except `localhost`, `127.0.0.1`, `::1` which allow HTTP)
- **No query string or fragment** (check both parsed and raw `?`/`#` presence)
- **Host required**, **no userinfo** (`user:pass@host` rejected)
- **ASCII-only hostnames** (reject any rune > 127 — prevents homograph attacks)
- **No control characters or whitespace** in hostname
- **Path rules** (when path is present):
  - Must start with `/`
  - No `..` (path traversal)
  - No `//` (double slash)
  - No `~~` (double tilde)
  - No trailing `~`
  - Strict character whitelist: `[a-zA-Z0-9\-._~/]+` only
  - Per-segment: reject `.`, `..`, `~` as standalone segments
  - Per-segment: max 150 characters

#### Subject Validation (`validate_subject`)

- **Non-empty**, **max 255 characters**
- **Reject** control chars (`0x00-0x1f`), whitespace (` \t\n\r`)
- **Reject** injection chars: `"'` `` ` `` `\<>;&$(){}[]`
- **Allow** chars commonly used by OIDC providers: `|:/@-._+=`
- **All characters must be printable** (`char::is_alphanumeric` or other printable)

#### Audience Validation (`validate_audience`)

- **Non-empty**, **max 255 characters**
- **Reject** control chars, whitespace (same as subject)
- **Reject** injection chars: `"'` `` ` `` `\<>;|&$(){}[]@` — **more restrictive than subject** (also rejects `@`, `|`, `[]`)
- **All characters must be printable**

All external fetches (OIDC discovery, JWKS, trust policy files from GitHub) are limited to 100 KiB response size to prevent abuse.

Token verification flow:
1. Extract bearer token from `Authorization` header
2. Validate request fields (scope non-empty, identity non-empty) — fail fast on bad requests
3. Decode JWT header to extract issuer (without verifying signature yet)
4. Validate issuer format (`validate_issuer`)
5. Fetch OIDC provider metadata from `{issuer}/.well-known/openid-configuration` (cached, with retry)
6. Fetch JWKS from the provider's `jwks_uri` (cached with provider)
7. Verify JWT signature, expiry; skip audience check (verified later by trust policy)
8. Look up installation ID and trust policy
9. `check_token`: validate issuer/subject/audience format strings (defense-in-depth), then match against policy rules

### Scope Parsing

Scope is parsed the same way as octo-sts:

| Input scope | Owner | Repo | Policy level |
|---|---|---|---|
| `org/repo` | `org` | `repo` | Repository-level — token scoped to `[repo]` |
| `org` | `org` | `.github` | Organization-level — token scoped to `repositories` list or all repos |
| `org/.github` | `org` | `.github` | Organization-level (same as above) |

For repository-level policies, the `repositories` field is implicitly set to `[repo]`. The `repositories` field in the trust policy TOML is only valid in organization-level policies (read from the `.github` repo).

### Startup Configuration Validation

All configuration is validated at startup via `clap::Parser`. Required fields and conditional requirements (`required_if_eq`) are enforced by clap before the application starts. Additional validation runs after parsing:

- Key file readable (for `file` mode)
- PEM key parseable (for `file` and `env` modes)
- KMS key ARN format valid (for `kms` mode)

If any validation fails, sts-cat exits immediately with a clear error message. The server does not start listening until configuration is fully validated.

### Token Revocation

After fetching a trust policy from GitHub, the temporary read-only installation token is revoked via `DELETE https://api.github.com/installation/token`. This minimizes the exposure window for the short-lived token.

### Error Handling

Define `crate::error::Error` as a `thiserror` enum in `src/error.rs`. Each variant maps to an HTTP status code via an `IntoResponse` implementation. Internal details are logged via tracing; only generic messages are sent to clients.

Use `thiserror` features (`#[from]`, `#[source]`, `transparent`, etc.) to preserve full error chains and avoid data loss. Wrap underlying errors from libraries (reqwest, jsonwebtoken, toml, regex, etc.) in appropriate variants rather than converting to strings prematurely.

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bad request: {0}")]
    BadRequest(String),                          // 400

    #[error("unauthenticated: {0}")]
    Unauthenticated(String),                     // 401

    #[error("permission denied: {0}")]
    PermissionDenied(String),                    // 403

    #[error("not found: {0}")]
    NotFound(String),                            // 404

    #[error("rate limited")]
    RateLimited,                                 // 429

    #[error("GitHub API error")]
    GitHubApi(#[source] reqwest::Error),         // 500

    #[error("OIDC discovery error")]
    OidcDiscovery(#[source] reqwest::Error),     // 500

    #[error("JWT verification failed")]
    JwtVerification(#[from] jsonwebtoken::errors::Error), // 401

    #[error("trust policy parse error")]
    PolicyParse(#[from] toml::de::Error),        // 404 (treat as not found)

    #[error("regex compilation error")]
    RegexCompile(#[from] regex::Error),          // 404 (invalid policy)

    #[error("internal error: {0}")]
    Internal(Box<dyn std::error::Error + Send + Sync>), // 500
}
```

The `IntoResponse` implementation maps each variant to an HTTP status code and a generic client-facing message. The full error chain (including `#[source]`) is logged via `tracing` at appropriate levels (debug for 4xx, error for 5xx) but never exposed to the client.

`anyhow` is reserved for CLI/startup error wrapping only — not used in request handling paths.

### Audit Logging

Use `tracing` with `tracing_subscriber` in JSON format for structured logging. All exchange events are logged with structured fields:

**Authorization passed** (INFO level, logged after trust policy check, before token creation):
```json
{"level":"INFO","event":"exchange_authorized","scope":"org/repo","identity":"deploy",
 "issuer":"https://token.actions.githubusercontent.com",
 "subject":"repo:org/repo:ref:refs/heads/main",
 "installation_id":12345,"policy_path":".github/sts-cat/deploy.sts.toml"}
```

**Success** (INFO level, logged after installation token created):
```json
{"level":"INFO","event":"exchange_success","scope":"org/repo","identity":"deploy",
 "issuer":"https://token.actions.githubusercontent.com",
 "subject":"repo:org/repo:ref:refs/heads/main",
 "installation_id":12345,"token_sha256":"abcd1234..."}
```

**Denial** (WARN level):
```json
{"level":"WARN","event":"exchange_denied","scope":"org/repo","identity":"deploy",
 "issuer":"https://...","subject":"repo:org/repo:...",
 "reason":"subject did not match pattern"}
```

**Sensitive data**: The GitHub installation token is never logged. Only its SHA-256 hash is recorded. Debug-level logs may include more detail (e.g. GitHub API error bodies) but are off by default.

### Health Check

`GET /healthz` returns HTTP 200 with `{"ok":true}`. Available in both server and Lambda modes for ALB/ECS/Kubernetes health checks.

### Lambda Deployment

When built with the `aws-lambda` feature, sts-cat runs as a Lambda function behind a Lambda Function URL with `AuthType=NONE`. sts-cat handles all authentication internally via OIDC token verification — no IAM auth at the Function URL layer.

### Crate and Binary Structure

Single binary crate with multiple binary targets for different runtime modes:

```
sts-cat/
├── Cargo.toml
└── src/
    ├── bin/
    │   ├── sts-cat-http.rs    # TCP HTTP server (default)
    │   └── sts-cat-lambda.rs    # Lambda Function URL handler
    ├── lib.rs                   # Shared core logic
    ├── config.rs
    ├── exchange.rs
    ├── trust_policy.rs
    ├── signer/
    │   ├── mod.rs               # Signer trait
    │   ├── raw.rs              # PEM file/env signer
    │   └── kms.rs               # AWS KMS signer (behind `aws-kms` feature)
    ├── github.rs                # GitHub API client, JWT generation
    └── oidc.rs                  # OIDC discovery, validation, verification
```

`sts-cat-http` is the default binary (TCP socket). `sts-cat-lambda` is built when the `aws-lambda` feature is enabled.

### Detailed Rust Structures

#### `src/config.rs` — Configuration

Uses `clap` derive with `env` feature for environment variable parsing. Each field specifies `env` names; `HOST`/`PORT` use multiple env aliases to support the de-facto convention.

```rust
#[derive(Debug, Clone, clap::Parser)]
pub struct Config {
    #[arg(long, env = "STS_CAT_GITHUB_APP_ID")]
    pub github_app_id: u64,

    #[arg(long, env = "STS_CAT_DOMAIN")]
    pub domain: String,

    /// Listen host. Accepts STS_CAT_HOST or HOST.
    #[arg(long, default_value = "0.0.0.0", env = "STS_CAT_HOST")]
    pub host: String,

    /// Listen port. Accepts STS_CAT_PORT or PORT.
    #[arg(long, default_value_t = 8080, env = "STS_CAT_PORT")]
    pub port: u16,

    #[arg(long, env = "STS_CAT_KEY_SOURCE")]
    pub key_source: KeySource,

    #[arg(long, env = "STS_CAT_KEY_FILE", required_if_eq("key_source", "file"))]
    pub key_file: Option<PathBuf>,

    #[arg(long, env = "STS_CAT_KEY_ENV", required_if_eq("key_source", "env"))]
    pub key_env: Option<String>,

    #[cfg(feature = "aws-kms")]
    #[arg(long, env = "STS_CAT_KMS_KEY_ARN", required_if_eq("key_source", "kms"))]
    pub kms_key_arn: Option<String>,

    #[arg(long, default_value = ".github/sts-cat", env = "STS_CAT_POLICY_PATH_PREFIX")]
    pub policy_path_prefix: String,

    #[arg(long, default_value = ".sts.toml", env = "STS_CAT_POLICY_FILE_EXTENSION")]
    pub policy_file_extension: String,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum KeySource {
    File,
    Env,
    #[cfg(feature = "aws-kms")]
    Kms,
}
```

The `sts-cat-http` binary also accepts de-facto `HOST` and `PORT` env vars as fallbacks. Precedence: CLI arg > `STS_CAT_HOST`/`STS_CAT_PORT` > `HOST`/`PORT` > default. The `HOST`/`PORT` fallback is handled in the binary entrypoint since clap's `env` only supports a single env name per field.

#### `src/error.rs` — Error Types

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthenticated: {0}")]
    Unauthenticated(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("rate limited")]
    RateLimited,
    #[error("GitHub API error")]
    GitHubApi(#[source] reqwest::Error),
    #[error("OIDC discovery error")]
    OidcDiscovery(#[source] reqwest::Error),
    #[error("JWT verification failed")]
    JwtVerification(#[from] jsonwebtoken::errors::Error),
    #[error("trust policy parse error")]
    PolicyParse(#[from] toml::de::Error),
    #[error("regex compilation error")]
    RegexCompile(#[from] regex::Error),
    #[error("internal error: {0}")]
    Internal(Box<dyn std::error::Error + Send + Sync>),
}

impl axum::response::IntoResponse for Error {
    fn into_response(self) -> axum::response::Response;
    // Maps variants to HTTP status + generic message.
    // Full error chain logged via tracing, never exposed to client.
}
```

#### `src/signer/mod.rs` — Signer Trait

```rust
#[async_trait::async_trait]
pub trait Signer: Send + Sync {
    /// Sign the given message with RS256 and return the raw signature bytes.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
}

pub mod raw;     // RawSigner: PEM from file or env var
#[cfg(feature = "aws-kms")]
pub mod kms;     // AwsKmsSigner: AWS KMS
```

#### `src/signer/raw.rs`

```rust
pub struct RawSigner {
    encoding_key: jsonwebtoken::EncodingKey,
}

impl RawSigner {
    pub fn from_pem(pem_data: &[u8]) -> Result<Self, anyhow::Error>;
}
```

#### `src/signer/kms.rs`

```rust
#[cfg(feature = "aws-kms")]
pub struct AwsKmsSigner {
    client: aws_sdk_kms::Client,
    key_id: String,
}

#[cfg(feature = "aws-kms")]
impl AwsKmsSigner {
    pub async fn new(key_arn: String) -> Result<Self, anyhow::Error>;
}

// Tests use aws-smithy-mocks to mock KMS Sign API responses.
#[cfg(test)]
#[cfg(feature = "aws-kms")]
mod tests {
    // Test successful signing via mocked KMS Sign response
    // Test KMS error handling (key not found, invalid key state, etc.)
}
```

#### `src/github.rs` — GitHub API Client

```rust
pub struct GitHubClient {
    http: reqwest::Client,  // no redirects, Accept: application/vnd.github+json,
                            // X-GitHub-Api-Version: 2026-03-10, User-Agent: sts-cat/<ver>,
                            // connect timeout: 10s, response timeout: 30s
    app_id: u64,
    signer: Arc<dyn Signer>,
}

impl GitHubClient {
    pub fn new(app_id: u64, signer: Arc<dyn Signer>) -> Self;

    /// Build and sign a GitHub App JWT (RS256, 10-min expiry).
    async fn app_jwt(&self) -> Result<String, Error>;

    /// Find the installation ID for the given owner.
    /// Uses the app JWT to call GET /app/installations.
    /// Paginates (100 per page, max 50 pages).
    pub async fn get_installation_id(&self, owner: &str) -> Result<u64, Error>;

    /// Fetch a file's content from a repository (default branch).
    /// Creates a scoped read-only installation token, fetches the file,
    /// then revokes the token. Revocation failure is logged but does not
    /// fail the operation.
    pub async fn get_trust_policy_content(
        &self,
        installation_id: u64,
        owner: &str,
        repo: &str,
        path: &str,
    ) -> Result<String, Error>;

    /// Create a scoped installation access token with the given permissions and repos.
    /// Error handling:
    /// - HTTP 422: log body at debug, return PermissionDenied
    /// - HTTP 403/429: return RateLimited
    /// - Other errors: log at debug, return Internal
    pub async fn create_installation_token(
        &self,
        installation_id: u64,
        permissions: &Permissions,
        repositories: &[String],
    ) -> Result<String, Error>;

    /// Revoke an installation token. Expects HTTP 204 No Content.
    /// Logs warning on failure but does not propagate error.
    async fn revoke_token(&self, token: &str);
}

/// GitHub installation permissions (subset of GitHub's full permission set).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permissions {
    #[serde(flatten)]
    pub inner: HashMap<String, String>,  // e.g. {"contents": "read", "issues": "write"}
}
```

#### `src/oidc.rs` — OIDC Discovery and Validation

```rust
pub struct OidcProvider {
    pub issuer: String,
    pub jwks: jsonwebtoken::jwk::JwkSet,
}

pub struct OidcVerifier {
    http: reqwest::Client,  // with custom redirect policy: validate_issuer on each redirect
    cache: moka::future::Cache<String, Arc<OidcProvider>>,
}

impl OidcVerifier {
    /// Construct with a reqwest::Client configured for OIDC:
    /// - redirect policy that validates each destination with validate_issuer()
    /// - connect timeout: 10s, response timeout: 30s
    /// - response size limit: 100 KiB
    pub fn new() -> Self;

    /// Discover OIDC provider (with exponential backoff retry) and verify a JWT.
    /// Returns the verified token claims.
    /// Retry: 1s → 2s → 4s → 8s → 16s → 30s max, with jitter.
    /// Permanent errors (no retry): HTTP 400, 401, 403, 404, 405, 406, 410, 415, 422, 501.
    pub async fn verify(&self, token: &str) -> Result<TokenClaims, Error>;
}

#[derive(Debug, Deserialize)]
pub struct TokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: OneOrMany<String>,   // JWT aud can be string or array
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Validate issuer URL format (strict octo-sts rules).
pub fn validate_issuer(issuer: &str) -> Result<(), Error>;

/// Validate subject string (allows @, |, :, / — used by GitHub Actions, Okta, etc.).
pub fn validate_subject(value: &str) -> Result<(), Error>;

/// Validate audience string (more restrictive than subject — also rejects @, |, []).
pub fn validate_audience(value: &str) -> Result<(), Error>;
```

#### `src/trust_policy.rs` — Trust Policy

```rust
#[derive(Debug, Deserialize)]
pub struct TrustPolicy {
    pub issuer: Option<String>,
    pub issuer_pattern: Option<String>,
    pub subject: Option<String>,
    pub subject_pattern: Option<String>,
    pub audience: Option<String>,
    pub audience_pattern: Option<String>,
    pub claim_pattern: Option<HashMap<String, String>>,
    pub permissions: Permissions,
    pub repositories: Option<Vec<String>>,  // org-level only
}

/// Compiled trust policy with pre-built regex patterns, ready for matching.
pub struct CompiledTrustPolicy {
    issuer: IssuerMatch,      // Exact(String) | Pattern(Regex)
    subject: SubjectMatch,    // Exact(String) | Pattern(Regex)
    audience: AudienceMatch,  // Exact(String) | Pattern(Regex) | Domain
    claim_patterns: Vec<(String, Regex)>,
    pub permissions: Permissions,
    pub repositories: Option<Vec<String>>,
}

enum IssuerMatch {
    Exact(String),
    Pattern(regex::Regex),
}

enum SubjectMatch {
    Exact(String),
    Pattern(regex::Regex),
}

enum AudienceMatch {
    Exact(String),
    Pattern(regex::Regex),
    Domain,  // fall back to STS_CAT_DOMAIN
}

impl TrustPolicy {
    /// Parse from TOML string.
    pub fn parse(toml_str: &str) -> Result<Self, Error>;

    /// Validate and compile into a CompiledTrustPolicy.
    /// `is_org_level`: if false and `repositories` is set, returns error
    /// (repo-level policies must not specify repositories).
    pub fn compile(self, is_org_level: bool) -> Result<CompiledTrustPolicy, Error>;
}

impl CompiledTrustPolicy {
    /// Check a verified token's claims against this policy.
    /// First validates all token claim strings (issuer, subject, audience)
    /// with validate_issuer/validate_subject/validate_audience — defense-in-depth.
    /// Then matches against policy rules.
    /// Claim values must be String or Bool (coerced to "true"/"false").
    /// All other types (numbers, arrays, objects) are rejected.
    /// Returns actor info on success.
    pub fn check_token(&self, claims: &TokenClaims, domain: &str) -> Result<Actor, Error>;
}

pub struct Actor {
    pub issuer: String,
    pub subject: String,
    pub matched_claims: Vec<(String, String)>,
}
```

#### `src/exchange.rs` — Exchange Handler

```rust
#[derive(Deserialize)]
pub struct ExchangeRequest {
    pub scope: String,
    pub identity: String,
}

#[derive(Serialize)]
pub struct ExchangeResponse {
    pub token: String,
}

/// Shared application state passed to axum handlers.
pub struct AppState {
    pub config: Config,
    pub github: GitHubClient,
    pub oidc: OidcVerifier,
    pub policy_cache: moka::future::Cache<(String, String, String), String>,
    pub installation_cache: moka::future::Cache<String, u64>,
}

/// POST /token handler.
pub async fn handle_exchange(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ExchangeRequest>,
) -> Result<Json<ExchangeResponse>, Error>;

/// Parse scope into (owner, repo, is_org_level).
fn parse_scope(scope: &str) -> Result<(String, String, bool), Error>;
```

#### `src/bin/sts-cat-http.rs`

```rust
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing (JSON format)

    // HOST/PORT fallback: set STS_CAT_HOST/STS_CAT_PORT from HOST/PORT
    // if the STS_CAT_ prefixed versions are not set
    if std::env::var("STS_CAT_HOST").is_err() {
        if let Ok(host) = std::env::var("HOST") {
            std::env::set_var("STS_CAT_HOST", host);
        }
    }
    if std::env::var("STS_CAT_PORT").is_err() {
        if let Ok(port) = std::env::var("PORT") {
            std::env::set_var("STS_CAT_PORT", port);
        }
    }

    let config = Config::parse();
    // Build Signer, GitHubClient, OidcVerifier, AppState
    // Build axum Router with /token and /healthz
    // Bind to (config.host, config.port) and serve
}
```

#### `src/bin/sts-cat-lambda.rs`

```rust
#[cfg(feature = "aws-lambda")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing (JSON format)
    // Parse Config::from_env()
    // Build Signer, GitHubClient, OidcVerifier, AppState
    // Build axum Router with /token and /healthz
    // Run via lambda_http::run(router)
}
```

### Feature Flags (Cargo Features)

| Feature | Default | Description |
|---|---|---|
| `aws-kms` | Off | Enables AWS KMS signer (pulls in AWS SDK dependencies) |
| `aws-lambda` | Off | Enables `sts-cat-lambda` binary (pulls in `lambda_http`). Enabled via `Cargo.toml` metadata for `cargo lambda build`. |

### Rate Limiting

No built-in rate limiting. sts-cat passes through GitHub API rate limit errors (403/429) as HTTP 429 to callers. Operators should add rate limiting at the infrastructure layer (ALB, API Gateway, CloudFront) as needed.

### Testing Strategy

- **Trust policy parsing/compilation**: Unit tests for valid TOML, invalid TOML, missing required fields, conflicting fields (both `issuer` and `issuer_pattern`), regex compilation errors.
- **Trust policy matching**: Unit tests with mock OIDC token claims — valid matches, denied on issuer/subject/audience/claim mismatch, audience fallback to domain.
- **OIDC validation**: Unit tests for issuer validation rules (HTTPS, path traversal, ASCII, etc.).
- **JWT construction**: Unit tests verifying correct JWT header/claims/signature using an in-memory test key.
- **Exchange handler**: Integration-style tests with a mock GitHub API client. Test the full flow from HTTP request to token response and error cases.

### Deployment Artifacts

**Dockerfile** (for HTTP server mode):
```dockerfile
FROM public.ecr.aws/docker/library/rust:<ver>-slim-trixie AS builder
# ... cargo build --release
FROM public.ecr.aws/docker/library/debian:trixie-slim
COPY --from=builder target/release/sts-cat-http /usr/local/bin/
CMD ["sts-cat-http"]
```

**Lambda**: Use `cargo lambda build --release` with `aws-lambda` feature enabled via `Cargo.toml` metadata. Produces a bootstrap binary suitable for Lambda's `provided.al2023` runtime.

## Current Status

Implementation complete.

### Implementation Checklist

- [x] `Cargo.toml` — dependencies, features, binary targets
- [x] `src/lib.rs` — crate root, module declarations
- [x] `src/error.rs` — `Error` enum with `thiserror` and `IntoResponse`
- [x] `src/config.rs` — `Config` struct with clap derive, startup validation
- [x] `src/signer/mod.rs` — `Signer` trait
- [x] `src/signer/raw.rs` — `RawSigner` (PEM from file or env var)
- [x] `src/signer/kms.rs` — `AwsKmsSigner` (AWS KMS, behind `aws-kms` feature)
- [x] `src/oidc.rs` — OIDC discovery (with redirect validation and retry), JWKS cache, JWT verification
- [x] `src/oidc.rs` — `validate_issuer`, `validate_subject`, `validate_audience` (separate functions, different char sets)
- [x] `src/trust_policy.rs` — TOML parsing, `compile(is_org_level)`, `check_token` with defense-in-depth validation
- [x] `src/trust_policy.rs` — claim type handling: String/Bool only, reject numbers/arrays/objects
- [x] `src/github.rs` — GitHub API client with proper headers (`Accept`, `X-GitHub-Api-Version`, `User-Agent`)
- [x] `src/github.rs` — App JWT construction, installation lookup (paginated, max 50 pages)
- [x] `src/github.rs` — installation token creation with 422/403/429 error handling
- [x] `src/github.rs` — token revocation (expect 204, warn on failure, don't propagate)
- [x] `src/exchange.rs` — `AppState`, `handle_exchange`, scope parsing
- [x] `src/bin/sts-cat-http.rs` — TCP HTTP server entry point
- [x] `src/bin/sts-cat-lambda.rs` — Lambda entry point (behind `aws-lambda` feature)
- [x] `Dockerfile`
- [x] Unit tests: trust policy parsing, compilation (including `repositories` rejection on repo-level)
- [x] Unit tests: trust policy matching (issuer, subject, audience, claim types, audience fallback)
- [x] Unit tests: OIDC validation (`validate_issuer` full rules, `validate_subject`, `validate_audience` different char sets)
- [x] Unit tests: JWT construction and signing
- [ ] Integration-style tests: exchange handler with mock GitHub API
- [x] `README.md` — setup guide, configuration reference, usage examples

### Discrepancies

- **D1: `error.rs` — `GitHubApi` and `OidcDiscovery` map to 500, spec says 502** — Spec comment says `// 502 or mapped per status` for `GitHubApi` and `// 502` for `OidcDiscovery`, but impl maps both to 500. Resolution: **spec updated** — 500 is correct, clients shouldn't distinguish upstream failures
- **D2: `error.rs` — logging levels** — Logging levels match intent (debug for 4xx, error for 5xx). Minor: `RateLimited` (429) has no logging at all. Resolution: **accepted** — no action needed
- **D3: `signer/mod.rs` — submodule named `raw` not `file`** — Spec pseudocode says `pub mod file;`, impl uses `pub mod raw;`. Resolution: **spec updated** — `raw` is better since it covers both file and env sources
- **D4: `signer/kms.rs` — tests are TODO stub** — Spec describes KMS tests with aws-smithy-mocks. Impl has only `// TODO`. Resolution: **fixed** — added `test_kms_sign_success` and `test_kms_sign_error` tests using aws-smithy-mocks with `from_client` constructor
- **D5: `oidc.rs` — `is_permanent_error` uses string matching** — Fragile string matching on error messages for retry classification. Resolution: **fixed** — added `OidcHttpError(u16)` variant, `is_permanent_error` now uses typed status code matching
- **D6: `oidc.rs` — retry jitter is full jitter not ±10%** — `backon::with_jitter()` uses full jitter, spec says ±10%. Resolution: **accepted** — full jitter is standard practice
- **D7: `exchange.rs` — extra `exchange_authorized` log event** — Impl logs both `exchange_authorized` and `exchange_success`. Resolution: **spec updated** — useful to know authorization passed even if token creation later fails
- **D8: `exchange.rs` — no structured denial audit log** — No `exchange_denied` event with scope/identity/issuer/subject/reason. Resolution: **fixed** — added WARN-level `exchange_denied` log with scope/identity/issuer/subject/reason fields when `check_token` fails
- **D9: `github.rs` — no 100 KiB limit on trust policy fetch** — OIDC uses `read_limited_body` but GitHub contents fetch has no size limit. Resolution: **fixed** — added `read_limited_body` (made `pub(crate)`) call in `get_trust_policy_content`
- **D10: `github.rs` — passes `owner/repo` instead of repo ID to installation token API** — GitHub expects repo names without owner prefix, or numeric IDs. Resolution: **fixed** — changed to pass just repo name
- **D11: `oidc.rs` — `read_limited_body` doesn't stream-limit** — Reads entire body then checks size; doesn't protect during reading. Resolution: **fixed** — now uses `bytes_stream()` with chunk-by-chunk size tracking via `futures-util::StreamExt`
- **D12: `exchange.rs` — request field validation before OIDC verification** — Spec has validation after OIDC; impl validates early. Resolution: **spec updated** — fail fast on bad requests is better
- **D13: `config.rs` — startup validation in `build_signer` not `config.rs`** — Validation happens at startup but in binary entrypoints. Resolution: **fixed** — moved `build_signer` to `Config::build_signer()` method in `config.rs`
- **D14: `build_signer` duplicated between binaries** — Identical code in both binaries. Resolution: **fixed** — both binaries now call `config.build_signer()`

- **D15: `sts-cat-lambda.rs` — compilation error with `aws-lambda` feature** — `lambda_http::run()` returns `Result<_, Box<dyn Error + Send + Sync>>` which can't convert to `anyhow::Error` via `?` in Rust 2024 edition. Resolution: **fixed** — added `.map_err(|e| anyhow::anyhow!(e))`
- **D16: `exchange.rs` — spec pseudocode not updated for TypedHeader** — Spec shows `headers: HeaderMap`, impl uses `TypedHeader<Authorization<Bearer>>` (commit b7ccd84). Resolution: **deferred** — spec update skipped per user decision
- **D17: `config.rs` — `github_api_url` / `STS_CAT_GITHUB_API_URL` not in spec** — Added in commit a072a9b, not reflected in spec Config struct or env var table. Resolution: **deferred** — spec update skipped per user decision
- **D18: `oidc.rs` — `read_limited_body` error type misattributed in GitHub context** — Chunk read errors hardcoded as `Error::OidcDiscovery`, incorrect when called from `github.rs`. Resolution: **fixed** — parameterized `read_limited_body` with error mapping function; callers pass `Error::OidcDiscovery` or `Error::GitHubApi`
- **D19: `trust_policy.rs` — `use serde::de::Error as _` at module scope** — Trait import should be scoped per sorah-guides:rust. Resolution: **fixed** — moved inside `compile()` method
- **D20: `oidc.rs` — regex recompiled on every `validate_issuer` call** — `Regex::new()` in hot path. Resolution: **fixed** — replaced with `std::sync::LazyLock<regex::Regex>` static
- **D21: `github.rs` — missing blank line between top-level items** — No blank line between `PATH_SEGMENT_ENCODE_SET` const and `pub struct GitHubClient`. Resolution: **fixed**
- **D22: Narrating comments throughout codebase** — ~38 comments across 4 files violated sorah-guides:coding ("do not narrate what the code is doing"). Resolution: **fixed** — removed all narrating comments; kept ~17 comments that explain WHY, document assumptions, or provide external context

### Updates

- 2026-03-26: Initial implementation complete. All core modules implemented per spec. 34 unit tests passing (OIDC validation, trust policy parsing/compilation/matching, scope parsing, claim type handling, JWT construction and signature verification using RFC 9500 test key). Zero clippy warnings. Integration-style exchange handler tests deferred — require mock GitHub API server.
- 2026-03-26: Validation started. 14 discrepancies identified. 5 resolved as spec updates (D1, D3, D6, D7, D12), 1 accepted (D2), 8 require implementation fixes (D4, D5, D8, D9, D10, D11, D13, D14).
- 2026-03-26: All 8 implementation fixes completed (D4, D5, D8, D9, D10, D11, D13, D14). 36 tests passing with `aws-kms` feature (34 base + 2 KMS). Zero clippy warnings. Zero fmt issues.
- 2026-03-26: Second validation pass (code quality focus). 8 new discrepancies (D15-D22). 6 fixed (D15, D18-D22), 2 deferred spec updates (D16-D17). 36 tests passing with all features. Zero clippy warnings. Zero fmt issues.
