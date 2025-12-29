# OIDC Provider Architecture (Skeleton)

## Components
- **Controllers** (`odoo_oidc_provider/controllers/main.py`): Implements discovery, authorize, token, userinfo, JWKS, introspection, revocation; enforces HTTPS (configurable) and PKCE S256 (configurable).
- **Models**:
  - `auth_oidc.client`: Registered OAuth/OIDC clients with redirect URIs, allowed scopes, confidentiality flag.
  - `auth_oidc.scope`: Declares scopes available to clients and tokens.
  - `auth_oidc.authorization_code`: Durable authorization codes with PKCE metadata, nonce, expiry, used-flag; cleanup cron.
  - `auth_oidc.token`: Access/refresh tokens with expiry and scopes; token values hashed at rest; cleanup cron.
  - `auth_oidc.consent`: Records per-user/client consents for specific scopes.
  - `auth_oidc.key`: Signing keys (JWK metadata + private key PEM) exposed via JWKS.
  - `auth_oidc.event`: Minimal event log for issued/revoked tokens and consents with IP/User-Agent.
  - `auth_oidc.rate_limit`: Simple per-bucket counters for abuse protection on public endpoints.
- **Views**: Minimal consent form (`views/consent_templates.xml`) with CSRF token on POST.
- **Data**: Seed scopes (`data/oauth_scopes.xml`); cleanup crons (`data/cron.xml`).

## Flows (simplified)
- **Authorization Code + PKCE**: `/oauth/authorize` validates client + redirect, enforces PKCE for public clients, prompts consent when needed, issues durable auth code with challenge + nonce. `/oauth/token` checks code + PKCE verifier, issues access/refresh + optional ID Token.
- **ID Token & JWKS**: ID Token signed with active key (`auth_oidc.key`); public keys exposed at `/.well-known/jwks.json` (inactive/expired keys excluded).
- **Userinfo**: `/oauth/userinfo` returns profile/email claims based on scopes.
- **Revocation / Introspection**: `/oauth/revoke` deletes tokens; `/oauth/introspect` returns token metadata for authenticated clients.

## Extensibility notes
- Replace in-memory JWT signing dependency handling with a proper module dependency and key rotation cron/UI for RSA key generation + publishing JWKs.
- Add audit/event logging and rate limiting; integrate consent UI styling with your theme.
- Add validation hooks for redirect URI, scope policies, and IP/device restrictions as needed.
