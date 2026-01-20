from odoo import fields, models


class AuthOidcSettings(models.TransientModel):
    _inherit = "res.config.settings"

    require_https = fields.Boolean(string="Require HTTPS", default=True)
    pkce_require_s256 = fields.Boolean(string="PKCE S256 only", default=True)
    allow_all_scopes_when_unset = fields.Boolean(
        string="Allow all scopes when unset (not recommended)", default=False
    )

    rate_limit_authorize_limit = fields.Integer(string="Authorize limit", default=30)
    rate_limit_authorize_window = fields.Integer(string="Authorize window (sec)", default=60)
    rate_limit_token_limit = fields.Integer(string="Token limit", default=60)
    rate_limit_token_window = fields.Integer(string="Token window (sec)", default=60)
    rate_limit_userinfo_limit = fields.Integer(string="Userinfo limit", default=120)
    rate_limit_userinfo_window = fields.Integer(string="Userinfo window (sec)", default=60)
    rate_limit_introspect_limit = fields.Integer(string="Introspect limit", default=60)
    rate_limit_introspect_window = fields.Integer(string="Introspect window (sec)", default=60)
    rate_limit_revoke_limit = fields.Integer(string="Revoke limit", default=60)
    rate_limit_revoke_window = fields.Integer(string="Revoke window (sec)", default=60)

    def get_values(self):
        res = super().get_values()
        params = self.env["ir.config_parameter"].sudo()
        get_bool = lambda key, default: str(params.get_param(key, str(default))).lower() in {"1", "true", "yes", "on"}
        get_int = lambda key, default: int(params.get_param(key, default) or default)
        res.update(
            require_https=get_bool("odoo_oidc.require_https", True),
            pkce_require_s256=get_bool("odoo_oidc.pkce_require_s256", True),
            allow_all_scopes_when_unset=get_bool("odoo_oidc.allow_all_scopes_when_unset", False),
            rate_limit_authorize_limit=get_int("odoo_oidc.rate_limit.authorize.limit", 30),
            rate_limit_authorize_window=get_int("odoo_oidc.rate_limit.authorize.window", 60),
            rate_limit_token_limit=get_int("odoo_oidc.rate_limit.token.limit", 60),
            rate_limit_token_window=get_int("odoo_oidc.rate_limit.token.window", 60),
            rate_limit_userinfo_limit=get_int("odoo_oidc.rate_limit.userinfo.limit", 120),
            rate_limit_userinfo_window=get_int("odoo_oidc.rate_limit.userinfo.window", 60),
            rate_limit_introspect_limit=get_int("odoo_oidc.rate_limit.introspect.limit", 60),
            rate_limit_introspect_window=get_int("odoo_oidc.rate_limit.introspect.window", 60),
            rate_limit_revoke_limit=get_int("odoo_oidc.rate_limit.revoke.limit", 60),
            rate_limit_revoke_window=get_int("odoo_oidc.rate_limit.revoke.window", 60),
        )
        return res

    def set_values(self):
        super().set_values()
        params = self.env["ir.config_parameter"].sudo()
        set_bool = lambda key, value: params.set_param(key, "1" if value else "0")
        set_int = lambda key, value: params.set_param(key, int(value or 0))
        set_bool("odoo_oidc.require_https", self.require_https)
        set_bool("odoo_oidc.pkce_require_s256", self.pkce_require_s256)
        set_bool("odoo_oidc.allow_all_scopes_when_unset", self.allow_all_scopes_when_unset)
        set_int("odoo_oidc.rate_limit.authorize.limit", self.rate_limit_authorize_limit)
        set_int("odoo_oidc.rate_limit.authorize.window", self.rate_limit_authorize_window)
        set_int("odoo_oidc.rate_limit.token.limit", self.rate_limit_token_limit)
        set_int("odoo_oidc.rate_limit.token.window", self.rate_limit_token_window)
        set_int("odoo_oidc.rate_limit.userinfo.limit", self.rate_limit_userinfo_limit)
        set_int("odoo_oidc.rate_limit.userinfo.window", self.rate_limit_userinfo_window)
        set_int("odoo_oidc.rate_limit.introspect.limit", self.rate_limit_introspect_limit)
        set_int("odoo_oidc.rate_limit.introspect.window", self.rate_limit_introspect_window)
        set_int("odoo_oidc.rate_limit.revoke.limit", self.rate_limit_revoke_limit)
        set_int("odoo_oidc.rate_limit.revoke.window", self.rate_limit_revoke_window)
