# Security & Best Practices

## Configuration Settings

All OIDC Provider security settings can be configured through the Odoo UI at **Settings > OIDC Provider > Settings**. On fresh installation, all security options default to **enabled** for maximum protection.

### Available Security Settings

#### 1. Require HTTPS for OIDC endpoints
- **Config Parameter**: `odoo_oidc.require_https`
- **Default**: True (enabled)
- **Description**: Enforces HTTPS for all OpenID Connect endpoints as recommended by OIDC Core 1.0
- **Best Practice**: Always keep enabled in production. Only disable for local development/testing.
- **Additional Steps**: Enable HSTS (HTTP Strict Transport Security) on your reverse proxy for added protection.

#### 2. Require PKCE for public clients
- **Config Parameter**: `odoo_oidc.require_pkce_public`
- **Default**: True (enabled)
- **Description**: Enforces PKCE (Proof Key for Code Exchange, RFC 7636) for public (non-confidential) clients during authorization code flow
- **Best Practice**: Keep enabled. PKCE prevents authorization code interception attacks, especially critical for mobile and SPA applications that cannot securely store client secrets.
- **Recommendation**: Consider requiring PKCE for confidential clients as well for defense in depth.

#### 3. Require PKCE S256
- **Config Parameter**: `odoo_oidc.pkce_require_s256`
- **Default**: True (enabled)
- **Description**: Disallows PKCE plain challenge method; requires S256 (SHA-256) as recommended by RFC 7636
- **Best Practice**: Keep enabled. The S256 method provides cryptographic protection whereas plain method offers minimal security benefit.

#### 4. Require nonce for OIDC
- **Config Parameter**: `odoo_oidc.require_nonce`
- **Default**: True (enabled)
- **Description**: Requires the nonce parameter on OpenID Connect (openid scope) authorization requests to prevent replay attacks (OIDC Core 3.1.2.1)
- **Best Practice**: Keep enabled for all OIDC flows. The nonce binds the ID token to the client's session and prevents token replay.

#### 5. Allow external redirect URIs
- **Config Parameter**: `odoo_oidc.allow_external_redirects`
- **Default**: True (enabled)
- **Description**: Allows redirects to registered external callback hosts (per OIDC Core 3.1.2.5). When disabled, restricts redirects to local host only.
- **Best Practice**: Keep enabled for production use with external applications. Redirect URIs are still validated against the exact registered list for each client.
- **When to Disable**: Only disable if all OAuth clients are on the same host as your Odoo instance.

## Additional Security Measures

- **Redirect URIs**: Exact-match validation. Avoid wildcards; prefer HTTPS only. Register each redirect URI explicitly in the client configuration.
- **Client Authentication**: Confidential clients must present `client_secret` (or migrate to mTLS/private_key_jwt). Public clients cannot send secrets and must use PKCE.
- **Scopes**: Limit scopes per client via `allowed_scopes`; the authorization endpoint filters requested scopes to the allowed set.
- **Consent**: Stored in `auth_oidc.consent`; prompt is forced if missing, outdated, or `prompt=consent` is passed. Consent POST uses Odoo CSRF token; keep the route CSRF-enabled.
- **Keys / JWKS**: Manage signing keys in `auth_oidc.key`. Store private keys with restricted groups (`base.group_system`). Rotate keys regularly; publish public JWK. Prefer RS256 with adequate key length (2048+ bits). JWKS endpoint skips inactive/expired keys.
- **Tokens**: Access tokens are short-lived; refresh tokens can be rotated (`rotate_refresh_token`). Implement IP/device binding and revocation lists if required for high-security scenarios.
- **Logging/Audit**: Minimal event log (`auth_oidc.event`) is written for code issuance, token issuance/rotation, introspection, revocation, and consent denial; includes IP/User-Agent. Extend with correlation IDs and additional metadata as needed.
- **Error Handling**: Respond with RFC-compliant errors (`invalid_request`, `invalid_client`, `invalid_grant`, `unsupported_grant_type`). Avoid leaking secrets or internal details in error messages.

## Settings Storage

Settings are stored in `ir.config_parameter` as follows:
- **True values**: Stored as string `'True'`
- **False values**: Stored as string `'False'`
- **Uninstall**: All OIDC config parameters are automatically removed via the uninstall hook

On fresh installation, a `post_init_hook` automatically initializes all security settings to their secure defaults (True).

## Hardening Recommendations

- **Rate Limiting**: Implement rate limits on authorization and token endpoints to prevent brute force attacks
- **Replay Protection**: Add stricter replay protection for authorization codes and tokens beyond expiration
- **PKCE for All Clients**: Consider requiring PKCE even for confidential clients as defense in depth
- **Anti-Phishing UX**: Enhance consent screen with clear client identification and branding
- **IP Binding**: Track and validate IP addresses for token usage in high-security scenarios
- **Device Fingerprinting**: Implement device fingerprinting for additional session validation
