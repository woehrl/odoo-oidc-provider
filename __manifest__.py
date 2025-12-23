{
    "name": "Odoo OIDC Provider",
    "summary": "Use Odoo as an OAuth2 / OpenID Connect Identity Provider",
    "version": "18.0.1.0.0",
    "author": "Florian Woehrl <fw@woehrl.biz>",
    "license": "LGPL-3",
    "category": "Authentication",
    "icon": "/odoo_oidc_provider/static/description/icon.png",
    "depends": ["base", "base_setup", "web", "auth_signup"],
    "data": [
        "security/ir.model.access.csv",
        "data/oauth_scopes.xml",
        "views/consent_templates.xml",
        "data/cron.xml",
        "views/oidc_views.xml",
        "views/res_config_settings_view.xml"
    ],
    "installable": True,
    "application": False,
    "post_init_hook": "post_init_hook",
    "uninstall_hook": "uninstall_hook",
}
