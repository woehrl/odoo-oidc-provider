# Odoo OIDC Provider

This README has moved to `README.rst` for proper rendering in Odoo. Please see that file for full documentation.

## Production checklist
- Enforce HTTPS (`odoo_oidc.require_https` True) and enable HSTS on the reverse proxy.
- Configure RSA keys with a valid public JWK; define a rotation plan.
- Keep PKCE S256 required (`odoo_oidc.pkce_require_s256` True).
- Keep clients and redirect URIs exact; public clients should not have secrets.
- Ensure cron cleanup is active; review logging/audit via `auth_oidc.event`.

## Documentation
- Architecture: `docs/architecture.md`
- Security / Best Practices: `docs/security.md`

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://www.paypal.me/FWoehrl)
