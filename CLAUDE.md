# Odoo OIDC Provider — AI Agent Guide

This file provides a structured overview for AI agents working on this codebase.

## Module Overview

Odoo 18.0 module (`odoo_oidc_provider`) implementing a full **OpenID Connect (OIDC) and OAuth2 Identity Provider** for Odoo. Enables Odoo to act as an IdP for external applications — users authenticate with Odoo credentials to access third-party apps.

- **Python dependencies**: `PyJWT >=2.8.0`, `cryptography >=42.0.0`
- **Odoo dependencies**: `base`, `web`, `auth_signup`
- **License**: LGPL-3

## Key Files

| File | Purpose |
|------|---------|
| `__manifest__.py` | Module metadata and dependencies |
| `controllers/main.py` | All OIDC/OAuth2 HTTP endpoints (the bulk of the logic) |
| `models/oauth_client.py` | `auth_oidc.client` — registered OAuth2 applications |
| `models/oauth_token.py` | `auth_oidc.scope`, `auth_oidc.token` — scopes and hashed tokens |
| `models/oauth_authorization.py` | `auth_oidc.key`, `auth_oidc.authorization_code`, `auth_oidc.consent`, `auth_oidc.event` |
| `models/rate_limit.py` | `auth_oidc.rate_limit` — per-IP/endpoint sliding window buckets |
| `models/settings.py` | `res.config.settings` extension — all OIDC system parameters |
| `models/dashboard.py` | `auth_oidc.dashboard` — transient admin overview model |
| `views/oidc_views.xml` | Admin UI: all forms, lists, menus, actions |
| `views/consent_templates.xml` | User-facing consent page (QWeb template) |
| `data/oauth_scopes.xml` | Seed data: 8 default scopes (openid, profile, email, ...) |
| `data/cron.xml` | Cleanup crons (run every 30 min) |
| `security/ir.model.access.csv` | Access control — all OIDC models require `base.group_system` |
| `docs/architecture.md` | Architecture overview and flow diagrams |
| `docs/security.md` | Security best practices |
| `docs/scopes.md` | Scope-to-claim mapping reference |
| `tests/test_oidc_flow.py` | Test suite |

## Data Models

### `auth_oidc.client` — OAuth Applications
Key fields: `name`, `client_id` (unique, public), `client_secret` (system only, hashed in display), `redirect_uris` (text, one per line, exact match), `allowed_scopes` (m2m → scope), `is_confidential`, `allow_public_spa`, `auto_consent`, `active`, `consent_css`.

Constraint: `is_confidential=True` requires `client_secret`; `allow_public_spa=True` forbids `is_confidential=True`.

### `auth_oidc.scope` — OAuth Scopes
Fields: `name` (unique), `description`, `active`. Seeded: `openid`, `profile`, `email`, `address`, `phone`, `org`, `groups`, `preferences`.

### `auth_oidc.token` — Access/Refresh Tokens
Tokens stored as SHA-256 hashes (`token` field). Raw value available only in-memory via `token_value` computed field (context-injected at creation). Fields: `token_type` (access/refresh), `token` (hash), `client_id`, `user_id`, `expires_at`, `scope_ids`.

### `auth_oidc.authorization_code` — PKCE Auth Codes
One-time use, 10-min TTL. Fields: `code`, `client_id`, `user_id`, `redirect_uri`, `scope`, `nonce`, `code_challenge`, `code_challenge_method` (plain/S256), `expires_at`, `used`.

### `auth_oidc.key` — JWT Signing Keys
Fields: `name`, `kid` (unique, published in JWKS), `alg` (RS256), `kty` (RSA), `use` (sig), `public_jwk` (auto-derived from private key), `private_key_pem` (system group only), `active`, `expires_at`.

### `auth_oidc.consent` — User Consent Records
Unique per `(user_id, client_id)`. Fields: `user_id`, `client_id`, `scope_ids`, `granted`, `granted_at`. `covers_scopes()` checks if saved consent covers all requested scopes.

### `auth_oidc.event` — Audit Log
Immutable records. `_order = "create_date desc"`. Fields: `event_type`, `description`, `client_id`, `user_id`, `ip_address`, `user_agent`.
Event types: `authorization_code`, `token_issued`, `token_rotated`, `token_revoked`, `token_revoke_failed`, `token_introspected`, `token_introspection_failed`, `consent_denied`, `userinfo`, `client_revoked`.

### `auth_oidc.rate_limit` — Rate Limiting
Fields: `key` (endpoint:ip[:client_id]), `window_start`, `count`. `register_hit()` returns `(allowed, retry_after_seconds)`.

### `res.config.settings` Extension
System parameters set via `ir.config_parameter`:
- `odoo_oidc.require_https` (default True)
- `odoo_oidc.pkce_require_s256` (default True)
- `odoo_oidc.allow_all_scopes_when_unset` (default False)
- `odoo_oidc.consent_css` (global consent page CSS)
- `odoo_oidc.rate_limit.<endpoint>.limit` / `.window` (authorize/token/userinfo/introspect/revoke)

## OIDC Endpoints (controllers/main.py)

| Path | Methods | Auth | Description |
|------|---------|------|-------------|
| `/.well-known/openid-configuration` | GET, OPTIONS | public | RFC 8414 discovery document |
| `/.well-known/jwks.json` | GET, OPTIONS | public | Public signing keys (CORS: `*`) |
| `/oauth/authorize` | GET, POST | Odoo session | Authorization Code + PKCE flow |
| `/oauth/token` | POST, OPTIONS | client auth | Token exchange and refresh |
| `/oauth/userinfo` | GET, OPTIONS | Bearer token | User claims |
| `/oauth/revoke` | POST, OPTIONS | client auth | RFC 7009 token revocation |
| `/oauth/introspect` | POST, OPTIONS | client auth | RFC 7662 token introspection |
| `/oauth/end_session` | GET, POST | public | Session logout |

### CORS Strategy
- Discovery (`/.well-known/*`): `Access-Control-Allow-Origin: *`
- Credentialed endpoints (token, userinfo, introspect, revoke): origin-based CORS matched against registered client redirect URI domains

## Development Conventions

- **Odoo version**: 18.0 — use modern XML view attributes (`invisible=`, `required=`, `readonly=` with Python expressions) not `modifiers=` JSON
- **Access control**: All OIDC models require `base.group_system`. Sensitive fields use additional `groups="base.group_system"` attribute
- **Token security**: Never log or display raw token values. SHA-256 hashed at rest via `_hash_token()`
- **Scopes**: Default-deny — clients must have explicit `allowed_scopes`, or `odoo_oidc.allow_all_scopes_when_unset` must be True
- **PKCE**: Always required for public clients. For confidential clients, configurable via `odoo_oidc.pkce_require_s256`
- **CORS**: No changes to `odoo.conf` needed — handled entirely in the controller
- **Rate limiting**: `_rate_limit(endpoint, ip, client_id)` helper in the controller; returns 429 response if exceeded

## Common Development Tasks

### Add a new claim to an existing scope
1. Edit `_build_id_token()` in `controllers/main.py` — add the claim under the relevant scope check
2. Edit the userinfo handler in the same file for the `/oauth/userinfo` endpoint
3. Update `docs/scopes.md` to document the new claim

### Add a new scope
1. Add record to `data/oauth_scopes.xml`
2. Handle claims in `_build_id_token()` and userinfo handler in `controllers/main.py`
3. Update `docs/scopes.md`

### Key rotation (zero-downtime)
1. Generate a new key (Configuration → Keys → New → Generate RSA Keypair)
2. Set `expires_at` on the old key to near future
3. After all tokens signed with old key expire, deactivate old key

### Testing
```
odoo-bin -c odoo.conf -u odoo_oidc_provider --test-enable --stop-after-init
```
Test file: `tests/test_oidc_flow.py`

### Monitor audit events
Query `auth_oidc.event` (Security → Events in admin UI) — all operations are logged with IP and User-Agent.

## Authorization Code + PKCE Flow

1. Client → `GET /oauth/authorize` with `code_challenge` (S256)
2. Odoo shows consent page (or skips if `auto_consent=True` or prior consent exists)
3. User approves → `auth_oidc.authorization_code` created (10-min TTL, one-time)
4. User redirected to `redirect_uri?code=…&state=…`
5. Client → `POST /oauth/token` with `code` + `code_verifier`
6. Server verifies PKCE → issues access token (1h) + refresh token (30d)
7. If `openid` scope granted → ID Token (JWT, RS256) also returned

## Error Handling Pattern

RFC-compliant error codes returned as JSON: `invalid_request`, `invalid_client`, `invalid_grant`, `unsupported_grant_type`, `access_denied`. Errors after a valid redirect URI is established are returned as redirects per OAuth2 spec (RFC 6749 §4.1.2.1).
