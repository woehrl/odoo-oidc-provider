from . import models  # noqa: F401
from . import controllers  # noqa: F401


def post_init_hook(env):
    """Initialize default OIDC settings on module installation."""
    ICPSudo = env['ir.config_parameter'].sudo()

    # Set secure defaults for all OIDC settings
    default_params = {
        'odoo_oidc.require_https': 'True',
        'odoo_oidc.require_pkce_public': 'True',
        'odoo_oidc.pkce_require_s256': 'True',
        'odoo_oidc.require_nonce': 'True',
        'odoo_oidc.allow_external_redirects': 'True',
    }

    for key, value in default_params.items():
        # Only set if not already configured
        if not ICPSudo.get_param(key):
            ICPSudo.set_param(key, value)


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
