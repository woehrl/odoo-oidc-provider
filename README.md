# Odoo OIDC Provider

This README has moved to `README.rst` for proper rendering in Odoo. Please see that file for full documentation.

## Production checklist
- Enforce HTTPS (`odoo_oidc.require_https` True) and enable HSTS on the reverse proxy.
- Configure RSA keys with a valid public JWK; define a rotation plan and restrict private keys to System users.
- Keep PKCE S256 required (`odoo_oidc.pkce_require_s256` True); public clients must not send secrets.
- Keep clients and redirect URIs exact; populate allowed scopes per client (default-deny when unset).
- Enable built-in rate limits via `odoo_oidc.rate_limit.<bucket>.limit` / `.window` if no external gateway is present.
- Tokens are hashed at rest; still lock down DB access and plan refresh-token revocation/rotation.
- Ensure cron cleanup is active; review logging/audit via `auth_oidc.event`.

## Documentation
- Architecture: `docs/architecture.md`
- Security / Best Practices: `docs/security.md`

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://www.paypal.me/FWoehrl)
