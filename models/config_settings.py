from odoo import api, fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    # Field "enable_ocn" is a depency of module "mail_mobile". Error about that missing field should only throw in developer mode and has nothing to do with our module
    #enable_ocn = fields.Boolean(string="Enable OCN", default=False, required=False)

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

        # Get parameter value with sensible security defaults for fresh installs
        # If parameter doesn't exist (None), use the default value
        # Security-related settings default to True, others to False
        def get_bool_param(key, default=False):
            value = ICPSudo.get_param(key)
            if value is None:
                return default
            return value == 'True'

        res.update(
            oidc_require_https=get_bool_param('odoo_oidc.require_https', default=True),
            oidc_require_pkce_public=get_bool_param('odoo_oidc.require_pkce_public', default=True),
            oidc_pkce_require_s256=get_bool_param('odoo_oidc.pkce_require_s256', default=True),
            oidc_require_nonce=get_bool_param('odoo_oidc.require_nonce', default=True),
            oidc_allow_external_redirects=get_bool_param('odoo_oidc.allow_external_redirects', default=True),
        )
        return res

    def set_values(self):
        super(ResConfigSettings, self).set_values()
        ICPSudo = self.env['ir.config_parameter'].sudo()

        # Store True/False as strings 'True'/'False'
        # This way we can distinguish between "not set" and "explicitly set to False"
        ICPSudo.set_param('odoo_oidc.require_https', str(self.oidc_require_https))
        ICPSudo.set_param('odoo_oidc.require_pkce_public', str(self.oidc_require_pkce_public))
        ICPSudo.set_param('odoo_oidc.pkce_require_s256', str(self.oidc_pkce_require_s256))
        ICPSudo.set_param('odoo_oidc.require_nonce', str(self.oidc_require_nonce))
        ICPSudo.set_param('odoo_oidc.allow_external_redirects', str(self.oidc_allow_external_redirects))

    def name_get(self):
        # Use a stable label in breadcrumbs instead of "New"
        return [(rec.id, "OIDC Settings") for rec in self]
