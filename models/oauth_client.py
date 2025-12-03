from odoo import api, fields, models
import secrets


class OAuthClient(models.Model):
    _name = "auth_oidc.client"
    _description = "OIDC/OAuth2 Client"

    name = fields.Char(required=True)
    client_id = fields.Char(required=True, index=True)
    client_secret = fields.Char(required=True, groups="base.group_system")
    redirect_uris = fields.Text(
        help="One redirect URI per line (exact match).",
    )
    allowed_scopes = fields.Many2many(
        "auth_oidc.scope",
        "auth_oidc_client_scope_rel",
        "client_id",
        "scope_id",
        string="Allowed Scopes",
    )
    is_confidential = fields.Boolean(
        default=True,
        help="Marks whether client secrets are expected and validated.",
    )
    active = fields.Boolean(default=True)

    _sql_constraints = [
        ("client_id_unique", "unique(client_id)", "Client ID must be unique."),
    ]

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if not vals.get("client_secret"):
                vals["client_secret"] = secrets.token_urlsafe(32)
        return super().create(vals_list)

    @api.model
    def get_by_client_id(self, client_id):
        """Return a single active client by its public identifier."""
        return self.search(
            [("client_id", "=", client_id), ("active", "=", True)], limit=1
        )

    def _parsed_redirect_uris(self):
        """Normalize configured redirect URIs into a list for comparisons."""
        self.ensure_one()
        return [
            uri.strip()
            for uri in (self.redirect_uris or "").splitlines()
            if uri.strip()
        ]

    def validate_redirect_uri(self, uri):
        """Check if the provided URI is contained in the configured list."""
        self.ensure_one()
        if not uri:
            return False
        return uri.strip() in self._parsed_redirect_uris()

    def action_generate_secret(self):
        self.ensure_one()
        self.client_secret = secrets.token_urlsafe(32)
        return True
