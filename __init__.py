from . import models  # noqa: F401
from . import controllers  # noqa: F401


def uninstall_hook(env):
    """Clean up config parameters when uninstalling the module."""
    params_to_remove = [
        'odoo_oidc.require_https',
        'odoo_oidc.require_pkce_public',
        'odoo_oidc.pkce_require_s256',
        'odoo_oidc.require_nonce',
        'odoo_oidc.allow_external_redirects',
    ]
    ICPSudo = env['ir.config_parameter'].sudo()
    for param in params_to_remove:
        ICPSudo.search([('key', '=', param)]).unlink()
