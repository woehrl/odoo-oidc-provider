{
    "name": "Odoo OIDC Provider",
    "summary": "Use Odoo as an OAuth2 / OpenID Connect Identity Provider",
    "icon": "static/description/icon.png",
    "version": "18.0.1.0.0",
    "author": "Florian Wöhrl <fw@woehrl.biz>",
    "license": "LGPL-3",
    "category": "Authentication",
    "depends": ["base", "web", "auth_signup"],
    "external_dependencies": {
        "python": ["jwt", "cryptography"],
    },
    "data": [
        "security/ir.model.access.csv",
        "data/oauth_scopes.xml",
        "views/consent_templates.xml",
        "data/cron.xml",
        "views/oidc_views.xml"
    ],
    "installable": True,
    "application": False
}
