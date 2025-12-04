from odoo import api, fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    oidc_require_https = fields.Boolean(
        string="Require HTTPS for OIDC endpoints",
        config_parameter="odoo_oidc.require_https",
        default=True,
        help="Serve OIDC endpoints only over HTTPS (recommended by OpenID Connect Core 1.0).",
    )
    oidc_require_pkce_public = fields.Boolean(
        string="Require PKCE for public clients",
        config_parameter="odoo_oidc.require_pkce_public",
        default=True,
        help="Enforce PKCE (RFC 7636) for public (non-confidential) clients during the authorization code flow.",
    )
    oidc_pkce_require_s256 = fields.Boolean(
        string="Require PKCE S256",
        config_parameter="odoo_oidc.pkce_require_s256",
        default=True,
        help="Disallow PKCE plain challenges; require S256 as recommended by RFC 7636.",
    )
    oidc_require_nonce = fields.Boolean(
        string="Require nonce for OIDC",
        config_parameter="odoo_oidc.require_nonce",
        default=True,
        help="Require the nonce parameter on OpenID Connect (openid) authorization requests to prevent replay (OIDC Core 3.1.2.1).",
    )
    oidc_allow_external_redirects = fields.Boolean(
        string="Allow external redirect URIs",
        config_parameter="odoo_oidc.allow_external_redirects",
        default=True,
        help="Allow redirects to registered external callback hosts (per OIDC Core 3.1.2.5). If disabled, redirects are restricted to the local host.",
    )

    def name_get(self):
        # Use a stable label in breadcrumbs instead of "New"
        return [(rec.id, "OIDC Settings") for rec in self]
