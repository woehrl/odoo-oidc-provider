from odoo import SUPERUSER_ID, api


def uninstall_hook(cr, registry):
    """Clean up OIDC system parameters on uninstall."""
    env = api.Environment(cr, SUPERUSER_ID, {})
    params = env["ir.config_parameter"].sudo()
    for key in [
        "odoo_oidc.require_https",
        "odoo_oidc.require_pkce_public",
        "odoo_oidc.pkce_require_s256",
        "odoo_oidc.require_nonce",
        "odoo_oidc.allow_external_redirects",
    ]:
        params.search([("key", "=", key)]).unlink()
