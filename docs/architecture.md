# OIDC Provider Architecture

## Components

### Controllers
`odoo_oidc_provider/controllers/main.py` implements the following endpoints:
- **Discovery**: `/.well-known/openid-configuration`
- **JWKS**: `/.well-known/jwks.json`
- **Authorization**: `/oauth/authorize`
- **Token**: `/oauth/token`
- **Userinfo**: `/oauth/userinfo`
- **Introspection**: `/oauth/introspect`
- **Revocation**: `/oauth/revoke`

All endpoints respect the configurable security settings (HTTPS enforcement, PKCE requirements, nonce validation, redirect URI restrictions).

### Models

#### Core OAuth/OIDC Models
- **`auth_oidc.client`**: Registered OAuth/OIDC clients with redirect URIs, allowed scopes, confidentiality flag
- **`auth_oidc.scope`**: Declares scopes available to clients and tokens (openid, profile, email, etc.)
- **`auth_oidc.authorization_code`**: Durable authorization codes with PKCE metadata, nonce, expiry, used-flag; cleanup cron
- **`auth_oidc.token`**: Access/refresh tokens with expiry and scopes; cleanup cron
- **`auth_oidc.consent`**: Records per-user/client consents for specific scopes
- **`auth_oidc.key`**: Signing keys (JWK metadata + private key PEM) exposed via JWKS
- **`auth_oidc.event`**: Minimal event log for issued/revoked tokens and consents with IP/User-Agent

#### Settings Model
- **`res.config.settings`** (inherited): Extends Odoo's configuration settings with OIDC-specific options
  - Located in `models/config_settings.py`
  - Provides UI-configurable security settings accessible at Settings > OIDC Provider > Settings
  - Stores settings in `ir.config_parameter` as string values ('True'/'False')
  - Implements `get_values()` and `set_values()` for proper persistence with secure defaults
  - All settings default to enabled (True) on fresh installation via `post_init_hook`

### Views
- **Consent Form** (`views/consent_templates.xml`): Minimal consent UI with CSRF token on POST
- **Settings View** (`views/res_config_settings_view.xml`): Configuration interface for security options
  - Extends `base_setup.res_config_settings_view_form`
  - Uses standard Odoo checkbox fields for boolean settings
  - Organized in `o_setting_box` layout with labels and help text

### Data Files
- **Seed Scopes** (`data/oauth_scopes.xml`): Initial scope definitions (openid, profile, email)
- **Cleanup Crons** (`data/cron.xml`): Automated cleanup of expired tokens and authorization codes (runs every 30 minutes)

## Flows (simplified)
- **Authorization Code + PKCE**: `/oauth/authorize` validates client + redirect, enforces PKCE for public clients (configurable), prompts consent when needed, issues durable auth code with challenge + nonce (required for `openid`, configurable). `/oauth/token` checks code + PKCE verifier, issues access/refresh + optional ID Token.
- **ID Token & JWKS**: ID Token signed with active key (`auth_oidc.key`); public keys exposed at `/.well-known/jwks.json` (inactive/expired keys excluded).
- **Userinfo**: `/oauth/userinfo` returns profile/email claims based on scopes.
- **Revocation / Introspection**: `/oauth/revoke` deletes tokens; `/oauth/introspect` returns token metadata for authenticated clients.

## Module Lifecycle Hooks

### `post_init_hook` (`__init__.py`)
Executed automatically after module installation:
- Initializes all security settings to their secure defaults (True)
- Sets config parameters: `odoo_oidc.require_https`, `odoo_oidc.require_pkce_public`, `odoo_oidc.pkce_require_s256`, `odoo_oidc.require_nonce`, `odoo_oidc.allow_external_redirects`
- Only sets parameters if they don't already exist (preserves existing configurations on upgrade)

### `uninstall_hook` (`__init__.py`)
Executed automatically during module uninstallation:
- Removes all OIDC-related config parameters from `ir.config_parameter`
- Cleans up: `odoo_oidc.require_https`, `odoo_oidc.require_pkce_public`, `odoo_oidc.pkce_require_s256`, `odoo_oidc.require_nonce`, `odoo_oidc.allow_external_redirects`
- Database records (clients, keys, tokens, etc.) are handled by Odoo's standard uninstall process

## Configuration Storage

Settings are persisted in `ir.config_parameter`:
- Boolean values stored as strings: `'True'` or `'False'`
- Missing parameters trigger secure defaults via `get_values()` helper function
- This approach allows distinguishing between "not configured" vs "explicitly disabled"

## Extensibility Notes

- **Key Rotation**: Consider adding automated key rotation cron and UI for RSA key generation lifecycle
- **Audit Logging**: Extend the `auth_oidc.event` model with additional fields (correlation IDs, detailed metadata)
- **Rate Limiting**: Add rate limiting middleware for authorization and token endpoints
- **Consent UI**: Integrate consent screen styling with your Odoo theme
- **Validation Hooks**: Add custom validation logic for redirect URIs, scope policies, and IP/device restrictions
- **Advanced Auth Methods**: Migrate from client_secret to mTLS or private_key_jwt for confidential clients
