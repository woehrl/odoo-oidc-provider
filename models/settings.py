from urllib.parse import urlparse

from odoo import _, fields, models
from odoo.exceptions import ValidationError


def issuer_problem(issuer, require_https=True):
    """Return a human-readable problem with an issuer URL, or None if it is usable.

    OIDC Discovery 1.0 §3 and OIDC Core 1.0 §2 require the issuer to be an https
    URL without query or fragment. Plain http is tolerated only when HTTPS
    enforcement is switched off (local development).
    """
    if not issuer:
        return "Issuer is empty"
    parsed = urlparse(issuer)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return "Issuer must be an absolute http(s) URL"
    if parsed.query or parsed.fragment:
        return "Issuer must not contain a query string or fragment"
    if parsed.scheme != "https" and require_https:
        return "Issuer must use https (OIDC Discovery 1.0 §3)"
    return None


class AuthOidcSettings(models.TransientModel):
    _inherit = "res.config.settings"

    issuer = fields.Char(
        string="Issuer URL",
        config_parameter="odoo_oidc.issuer",
        help=(
            "Stable https URL published as 'issuer' in the discovery document and as "
            "'iss' in ID tokens, e.g. https://odoo.example.com. Leave empty to fall back "
            "to web.base.url — note that Odoo rewrites web.base.url on admin login unless "
            "web.base.url.freeze is set, which can silently break all relying parties."
        ),
    )
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

    consent_css = fields.Char(
        string="Consent Page CSS (global)",
        config_parameter="odoo_oidc.consent_css",
        help="Global CSS injected into all consent pages.",
    )

    def set_values(self):
        # Normalise and validate before the config_parameter mechanism persists it,
        # so a misconfigured issuer is rejected at save time instead of surfacing as
        # a broken discovery document for every relying party.
        for rec in self:
            if rec.issuer:
                rec.issuer = rec.issuer.strip().rstrip("/")
                problem = issuer_problem(rec.issuer, require_https=rec.require_https)
                if problem:
                    raise ValidationError(_("Invalid Issuer URL: %s", problem))
        return super().set_values()
