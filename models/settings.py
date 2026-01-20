from odoo import fields, models


class AuthOidcSettings(models.TransientModel):
    _inherit = "res.config.settings"

    require_https = fields.Boolean(
        string="Require HTTPS",
        default=True,
        config_parameter="odoo_oidc.require_https",
        help="Reject non-HTTPS calls to OIDC endpoints.",
    )
    pkce_require_s256 = fields.Boolean(
        string="PKCE S256 only",
        default=True,
        config_parameter="odoo_oidc.pkce_require_s256",
        help="Forbid PKCE 'plain'; enforce S256 challenges.",
    )
    allow_all_scopes_when_unset = fields.Boolean(
        string="Allow all scopes when unset (not recommended)",
        default=False,
        config_parameter="odoo_oidc.allow_all_scopes_when_unset",
        help="If enabled, clients with no allowed scopes configured get all requested scopes.",
    )

    rate_limit_authorize_limit = fields.Integer(
        string="Authorize limit",
        default=30,
        config_parameter="odoo_oidc.rate_limit.authorize.limit",
    )
    rate_limit_authorize_window = fields.Integer(
        string="Authorize window (sec)",
        default=60,
        config_parameter="odoo_oidc.rate_limit.authorize.window",
    )
    rate_limit_token_limit = fields.Integer(
        string="Token limit",
        default=60,
        config_parameter="odoo_oidc.rate_limit.token.limit",
    )
    rate_limit_token_window = fields.Integer(
        string="Token window (sec)",
        default=60,
        config_parameter="odoo_oidc.rate_limit.token.window",
    )
    rate_limit_userinfo_limit = fields.Integer(
        string="Userinfo limit",
        default=120,
        config_parameter="odoo_oidc.rate_limit.userinfo.limit",
    )
    rate_limit_userinfo_window = fields.Integer(
        string="Userinfo window (sec)",
        default=60,
        config_parameter="odoo_oidc.rate_limit.userinfo.window",
    )
    rate_limit_introspect_limit = fields.Integer(
        string="Introspect limit",
        default=60,
        config_parameter="odoo_oidc.rate_limit.introspect.limit",
    )
    rate_limit_introspect_window = fields.Integer(
        string="Introspect window (sec)",
        default=60,
        config_parameter="odoo_oidc.rate_limit.introspect.window",
    )
    rate_limit_revoke_limit = fields.Integer(
        string="Revoke limit",
        default=60,
        config_parameter="odoo_oidc.rate_limit.revoke.limit",
    )
    rate_limit_revoke_window = fields.Integer(
        string="Revoke window (sec)",
        default=60,
        config_parameter="odoo_oidc.rate_limit.revoke.window",
    )
