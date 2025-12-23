# Odoo OIDC Provider

Turn your Odoo 18+ instance into an OpenID Connect / OAuth2 Identity Provider.

**Full documentation**: See `README.rst` for complete installation and configuration guide.

## Quick Start

### Installation
- **Self-hosted**: Clone into addons path, install requirements.txt, restart Odoo
- **Odoo.sh**: Add as Git submodule or custom addon, enable requirements.txt
- **Enterprise**: Compatible with both Community and Enterprise editions

### Configuration
Navigate to **Settings > OIDC Provider > Settings** to configure:
- ✓ Require HTTPS (default: enabled)
- ✓ Require PKCE for public clients (default: enabled)
- ✓ Require PKCE S256 (default: enabled)
- ✓ Require nonce for OIDC (default: enabled)
- ✓ Allow external redirect URIs (default: enabled)

All security settings default to **enabled** on fresh installation for maximum protection.

### Initial Setup
1. Configure security settings (Settings > OIDC Provider > Settings)
2. Create signing key (Settings > Technical > Auth OIDC Keys)
3. Register OAuth clients (Auth OIDC Clients)
4. Define redirect URIs and allowed scopes per client

## Production Checklist
- ✓ Enforce HTTPS and enable HSTS on reverse proxy
- ✓ Configure RSA signing keys with valid public JWK
- ✓ Keep PKCE S256 required for all public clients
- ✓ Use exact redirect URI matching (no wildcards)
- ✓ Public clients must not have client secrets
- ✓ Verify cron cleanup is active (every 30 minutes)
- ✓ Review audit logs via `auth_oidc.event` model
- ✓ Plan RSA key rotation strategy

## Endpoints
- Discovery: `/.well-known/openid-configuration`
- JWKS: `/.well-known/jwks.json`
- Authorization: `/oauth/authorize`
- Token: `/oauth/token`
- Userinfo: `/oauth/userinfo`
- Revocation: `/oauth/revoke`
- Introspection: `/oauth/introspect`

## Known Issues

### Developer Mode + Enterprise Edition
When using Odoo Enterprise with developer mode enabled, you may see an error about the `enable_ocn` field. This is caused by the Enterprise `mail_mobile` module (push notifications).

**Solution**: Install the mail_mobile module or disable developer mode. See README.rst "Known Issues" section for details.

## Documentation
- **Full Guide**: `README.rst` (installation, configuration, examples)
- **Architecture**: `docs/architecture.md` (components, flows, extensibility)
- **Security**: `docs/security.md` (settings details, best practices, hardening)

## Support
[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://www.paypal.me/FWoehrl)
