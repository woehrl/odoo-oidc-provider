# OIDC Provider Architecture

## Components

- **Controllers** (`controllers/main.py`): Implements all OIDC / OAuth2 endpoints.
  Enforces HTTPS (configurable), PKCE S256 (configurable), rate limiting, and CORS.
- **Models**:
  - `auth_oidc.client`: Registered OAuth/OIDC clients with redirect URIs, allowed scopes,
    confidentiality flag, auto-consent, and per-client consent CSS.
  - `auth_oidc.scope`: Declares scopes available to clients and tokens (seeded: openid,
    profile, email, address, phone, org, groups, preferences).
  - `auth_oidc.authorization_code`: Durable authorization codes with PKCE metadata,
    nonce, expiry, and one-time-use flag; cleanup cron every 30 min.
  - `auth_oidc.token`: Access/refresh tokens with expiry and scopes; token values hashed
    (SHA-256) at rest; cleanup cron every 30 min.
  - `auth_oidc.consent`: Records per-user/client consents for specific scopes; prompt is
    forced when consent is missing, outdated, or `prompt=consent` is passed.
  - `auth_oidc.key`: Signing keys (JWK metadata + private key PEM) exposed via JWKS.
    RSA key pairs can be generated in the UI; private key restricted to System group.
  - `auth_oidc.event`: Audit log for code/token issuance, rotation, introspection,
    revocation, consent decisions — includes IP and User-Agent.
  - `auth_oidc.rate_limit`: Per-bucket (IP + optional client) rate limiting for all
    public endpoints (authorize/token/userinfo/introspect/revoke).
  - `auth_oidc.dashboard`: Transient model powering the admin overview.
  - `res.config.settings` (extension): OIDC system settings (HTTPS, PKCE, rate limits,
    consent CSS, scope defaults).
- **Views**: Consent page (`views/consent_templates.xml`) with CSRF protection and
  optional per-client / global CSS. Admin UI in `views/oidc_views.xml`.
- **Data**: Seed scopes (`data/oauth_scopes.xml`); cleanup crons (`data/cron.xml`).

## Endpoints

| Endpoint | Methods | Auth | Description |
|---|---|---|---|
| `/.well-known/openid-configuration` | GET, OPTIONS | public | RFC 8414 / OIDC Discovery |
| `/.well-known/jwks.json` | GET, OPTIONS | public | Public signing keys (JWK Set) |
| `/oauth/authorize` | GET, POST | user (Odoo session) | Authorization Code + PKCE |
| `/oauth/token` | POST, OPTIONS | public (client auth) | Token issuance and refresh |
| `/oauth/userinfo` | GET, OPTIONS | public (Bearer token) | User claims |
| `/oauth/revoke` | POST, OPTIONS | public (client auth) | RFC 7009 token revocation |
| `/oauth/introspect` | POST, OPTIONS | public (client auth) | RFC 7662 token introspection |
| `/oauth/end_session` | GET, POST | public | Session logout |

## CORS Strategy

Discovery endpoints (`/.well-known/*`) return `Access-Control-Allow-Origin: *` —
they are public documents that any relying party must be able to fetch from a browser.

Credentialed endpoints (token, userinfo, introspect, revoke) use origin-based CORS:
the request `Origin` header is matched against all active clients' registered redirect
URI domains. Only matching origins receive `Access-Control-Allow-Origin` plus
`Access-Control-Allow-Credentials: true`. All these endpoints handle OPTIONS preflight.

No changes to `odoo.conf` (the `cors =` setting) are needed.

## Authorization Code + PKCE Flow

1. Client redirects user to `/oauth/authorize` with `code_challenge` (S256 recommended,
   required for public clients).
2. If consent is needed, the consent page is shown; user approves or denies.
   - Denial redirects back to `redirect_uri` with `error=access_denied`.
3. On approval, an `auth_oidc.authorization_code` is created (10-min TTL, one-time use).
4. User is redirected to `redirect_uri?code=…&state=…`.
5. Client POSTs `code` + `code_verifier` to `/oauth/token`.
6. Server verifies PKCE, issues access token + refresh token.
7. If `openid` scope was granted, an ID Token (JWT, signed RS256) is also returned.

## ID Token & JWKS

ID Tokens are JWTs signed with the active `auth_oidc.key` (preferred: RS256).
The public JWK is auto-derived from the private key PEM and exposed at
`/.well-known/jwks.json`. Inactive or expired keys are excluded from the JWKS response.

Standard claims always present: `iss`, `sub`, `aud`, `iat`, `exp`, `auth_time`, `azp`,
`user_type`. Optional: `nonce` (if provided in authorize request), `at_hash`.
Scope-based claims: see `docs/scopes.md`.

## Userinfo

`/oauth/userinfo` accepts a Bearer access token and returns JSON claims based on the
token's granted scopes. See `docs/scopes.md` for the full claim matrix.

## Token Security

- Access tokens: short-lived (1 hour), random 32-byte URL-safe values, stored hashed
  (SHA-256) at rest.
- Refresh tokens: long-lived (30 days), also hashed at rest. Rotated on every use —
  old token deleted, new pair (access + refresh) issued.
- Introspection and revocation require client authentication and are scoped to the
  requesting client's own tokens.

## Extensibility Notes

- Replace seed scopes with custom ones; map them to custom claims in `_build_id_token`
  and the userinfo endpoint.
- Add custom consent page styling globally (Settings) or per client.
- Extend `auth_oidc.event` for correlation IDs and alerting.
- Add IP/device binding or token peppered hashing as needed.

## Scopes and Claims

See `docs/scopes.md` for the full claim matrix per scope and the filtering rules
based on client Allowed Scopes.
