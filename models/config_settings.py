from odoo import api, fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    oidc_require_https = fields.Boolean(
        string="Require HTTPS for OIDC endpoints",
        config_parameter="odoo_oidc.require_https",
        help="Serve OIDC endpoints only over HTTPS (recommended by OpenID Connect Core 1.0).",
    )
    oidc_require_pkce_public = fields.Boolean(
        string="Require PKCE for public clients",
        config_parameter="odoo_oidc.require_pkce_public",
        help="Enforce PKCE (RFC 7636) for public (non-confidential) clients during the authorization code flow.",
    )
    oidc_pkce_require_s256 = fields.Boolean(
        string="Require PKCE S256",
        config_parameter="odoo_oidc.pkce_require_s256",
        help="Disallow PKCE plain challenges; require S256 as recommended by RFC 7636.",
    )
    oidc_require_nonce = fields.Boolean(
        string="Require nonce for OIDC",
        config_parameter="odoo_oidc.require_nonce",
        help="Require the nonce parameter on OpenID Connect (openid) authorization requests to prevent replay (OIDC Core 3.1.2.1).",
    )
    oidc_allow_external_redirects = fields.Boolean(
        string="Allow external redirect URIs",
        config_parameter="odoo_oidc.allow_external_redirects",
        help="Allow redirects to registered external callback hosts (per OIDC Core 3.1.2.5). If disabled, redirects are restricted to the local host.",
    )

    @api.model
    def get_values(self):
        res = super(ResConfigSettings, self).get_values()
        ICPSudo = self.env['ir.config_parameter'].sudo()
        res.update(
            oidc_require_https=ICPSudo.get_param('odoo_oidc.require_https', default='True') == 'True',
            oidc_require_pkce_public=ICPSudo.get_param('odoo_oidc.require_pkce_public', default='True') == 'True',
            oidc_pkce_require_s256=ICPSudo.get_param('odoo_oidc.pkce_require_s256', default='True') == 'True',
            oidc_require_nonce=ICPSudo.get_param('odoo_oidc.require_nonce', default='True') == 'True',
            oidc_allow_external_redirects=ICPSudo.get_param('odoo_oidc.allow_external_redirects', default='True') == 'True',
        )
        return res

    def set_values(self):
        super(ResConfigSettings, self).set_values()
        ICPSudo = self.env['ir.config_parameter'].sudo()
        ICPSudo.set_param('odoo_oidc.require_https', self.oidc_require_https)
        ICPSudo.set_param('odoo_oidc.require_pkce_public', self.oidc_require_pkce_public)
        ICPSudo.set_param('odoo_oidc.pkce_require_s256', self.oidc_pkce_require_s256)
        ICPSudo.set_param('odoo_oidc.require_nonce', self.oidc_require_nonce)
        ICPSudo.set_param('odoo_oidc.allow_external_redirects', self.oidc_allow_external_redirects)

    def name_get(self):
        # Use a stable label in breadcrumbs instead of "New"
        return [(rec.id, "OIDC Settings") for rec in self]
