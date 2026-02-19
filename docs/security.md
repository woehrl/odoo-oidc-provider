# Security & Best Practices

## PKCE

Enforced for public clients; strongly recommended for confidential clients too.
`S256` (SHA-256) is required by default — configurable via system parameter
`odoo_oidc.pkce_require_s256` (default `True`). When enabled, `plain` is rejected at
both the authorization endpoint and is omitted from the discovery document's
`code_challenge_methods_supported`.

## Redirect URIs

Exact-match validation only. No wildcards. Prefer HTTPS URIs.
An error from the authorization endpoint is redirected back to `redirect_uri` (with
`error=` / `error_description=` / `state=` query parameters) whenever the redirect URI
has already been validated — per RFC 6749 §4.1.2.1.

## Client Authentication

Confidential clients must present `client_secret` via HTTP Basic auth
(`Authorization: Basic …`) or as a POST parameter (`client_secret`). Public clients
must not send a secret. Client authentication is validated on token, introspect, and
revoke endpoints.

## Scopes

Limit scopes per client via `allowed_scopes`; the authorization endpoint silently
filters requested scopes to the allowed set. When a client has no scopes configured,
all requests are denied unless `odoo_oidc.allow_all_scopes_when_unset` is explicitly
enabled (not recommended).

## Consent

Stored in `auth_oidc.consent`; prompt is forced if consent is missing, outdated (scopes
expanded), or `prompt=consent` is passed. The `auto_consent` flag on a client skips the
prompt (useful for first-party clients). Consent POST uses Odoo CSRF protection.

## CORS

Discovery endpoints (`/.well-known/openid-configuration`, `/.well-known/jwks.json`)
use `Access-Control-Allow-Origin: *` — they are intentionally public and must be
reachable from any browser. No credentials are involved.

Credentialed endpoints (token, userinfo, introspect, revoke) use origin-based CORS:
the `Origin` header is matched against all active clients' redirect URI domains. Only
matching origins receive `Access-Control-Allow-Origin` with
`Access-Control-Allow-Credentials: true`. No changes to `odoo.conf` are needed.

## Keys / JWKS

Manage signing keys in `auth_oidc.key`. Store private keys restricted to
`base.group_system`. Prefer RS256 with at least 2048-bit RSA keys. Rotate keys
regularly; the JWKS endpoint automatically skips inactive or expired keys, allowing
zero-downtime rotation when a new key is added before the old one is expired.
HS256 is supported but requires the secret to remain in the database, which is less
desirable than asymmetric keys.

## Tokens

Access tokens: 1-hour TTL. Refresh tokens: 30-day TTL, rotated on every use (old token
deleted on rotation). Both token types are stored as SHA-256 hashes at rest; raw values
are returned only at issuance. Consider adding IP/device binding if required by your
threat model.

## Rate Limiting

Built-in per-IP/client buckets for authorize, token, userinfo, introspect, and revoke
endpoints. Defaults (configurable via system parameters
`odoo_oidc.rate_limit.<bucket>.limit` / `.window`):

| Bucket | Limit | Window |
|---|---|---|
| authorize | 30 | 60 s |
| token | 60 | 60 s |
| userinfo | 120 | 60 s |
| introspect | 60 | 60 s |
| revoke | 60 | 60 s |

Use a reverse proxy or WAF for additional protection.

## Logging / Audit

`auth_oidc.event` records code issuance, token issuance/rotation, introspection,
revocation, and consent denial — with IP address and User-Agent. Monitor this table
for anomalies.

## Error Handling

RFC-compliant error codes: `invalid_request`, `invalid_client`, `invalid_grant`,
`unsupported_grant_type`, `access_denied`. Errors that occur after a valid redirect URI
is established are returned as redirects (not direct JSON), per the OAuth2 spec.

## Transport

Serve all endpoints over HTTPS; set Strict-Transport-Security on the reverse proxy.
`odoo_oidc.require_https` (default `True`) rejects plain HTTP requests at the
application level. Odoo must be run behind a proxy that sets `X-Forwarded-Proto: https`
with `proxy_mode = True` in `odoo.conf`.

## Hardening TODOs

- Add replay protection for authorization codes (code replay is partially mitigated by
  the one-time-use flag, but consider binding codes to the client IP).
- Consider PKCE enforcement for confidential clients as well (currently optional).
- Add anti-phishing UX to the consent page (e.g., display client logo/description).
- Consider peppering token hashes and adding DB row-level access control.
- Consider `id_token_hint` validation on `/oauth/end_session`.
