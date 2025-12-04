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

    @api.model
    def get_values(self):
        res = super().get_values()
        params = self.env["ir.config_parameter"].sudo()
        res.update(
            oidc_require_https=params.get_param("odoo_oidc.require_https", "True") == "True",
            oidc_require_pkce_public=params.get_param(
                "odoo_oidc.require_pkce_public", "True"
            )
            == "True",
            oidc_pkce_require_s256=params.get_param(
                "odoo_oidc.pkce_require_s256", "True"
            )
            == "True",
            oidc_require_nonce=params.get_param("odoo_oidc.require_nonce", "True")
            == "True",
            oidc_allow_external_redirects=params.get_param(
                "odoo_oidc.allow_external_redirects", "True"
            )
            == "True",
        )
        return res

    def set_values(self):
        super().set_values()
        params = self.env["ir.config_parameter"].sudo()
        for rec in self:
            params.set_param("odoo_oidc.require_https", bool(rec.oidc_require_https))
            params.set_param("odoo_oidc.require_pkce_public", bool(rec.oidc_require_pkce_public))
            params.set_param("odoo_oidc.pkce_require_s256", bool(rec.oidc_pkce_require_s256))
            params.set_param("odoo_oidc.require_nonce", bool(rec.oidc_require_nonce))
            params.set_param("odoo_oidc.allow_external_redirects", bool(rec.oidc_allow_external_redirects))
