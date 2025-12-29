# Security & Best Practices (Skeleton)

- **PKCE**: Enforced for public clients; recommended for confidential clients too. Use `S256` code challenges (configurable via `odoo_oidc.pkce_require_s256`, default True).
- **Redirect URIs**: Exact-match validation. Avoid wildcards; prefer HTTPS only.
- **Client auth**: Confidential clients must present client_secret (or migrate to mTLS/private_key_jwt). Public clients cannot send secrets.
- **Scopes**: Limit scopes per client via `allowed_scopes`; authorization endpoint filters requested scopes to the allowed set. When a client has no scopes configured, requests are denied unless `odoo_oidc.allow_all_scopes_when_unset` is explicitly enabled.
- **Consent**: Stored in `auth_oidc.consent`; prompt is forced if missing, outdated, or `prompt=consent` is passed. Consent POST uses Odoo CSRF token; keep the route csrf-enabled.
- **Keys / JWKS**: Manage signing keys in `auth_oidc.key`. Store private keys with restricted groups (`base.group_system`). Rotate keys regularly; publish public JWK. Prefer RS256 with adequate key length; HS signing requires stored secret material (ID Tokens are blocked otherwise). JWKS skips inactive/expired keys.
- **Tokens**: Access tokens are short-lived; refresh tokens are hashed at rest and rotated (`rotate_refresh_token`). Implement IP/device binding and revocation lists if required.
- **Rate limiting**: Built-in per-IP/client buckets for authorize/token/userinfo/introspect/revoke (defaults in `controllers/main.py`). Override via system params `odoo_oidc.rate_limit.<bucket>.limit` / `.window`; use a reverse proxy/WAF when available.
- **Logging/Audit**: Minimal event log (`auth_oidc.event`) is written for code issuance, token issuance/rotation, introspection, revocation, and consent denial; includes IP/User-Agent. Extend with correlation IDs and IP/user agent recording.
- **Error handling**: Respond with RFC-compliant errors (`invalid_request`, `invalid_client`, `invalid_grant`, `unsupported_grant_type`). Avoid leaking secrets in error messages.
- **Transport**: Serve endpoints over HTTPS only; set secure cookies; enable HSTS on your reverse proxy. Enforce via `odoo_oidc.require_https` (default True).
- **Hardening TODOs**: Add replay protection for codes/tokens, PKCE enforcement for all clients, anti-phishing UX on consent, and consider token hashing peppering + DB row-level access control.
