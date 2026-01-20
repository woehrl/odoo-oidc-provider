from odoo import api, fields, models, _
from odoo.exceptions import ValidationError
import secrets


class OAuthClient(models.Model):
    _name = "auth_oidc.client"
    _description = "OIDC/OAuth2 Client"

    name = fields.Char(required=True)
    client_id = fields.Char(required=True, index=True)
    client_secret = fields.Char(groups="base.group_system", copy=False)
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
            if vals.get("is_confidential", True) and not vals.get("client_secret"):
                vals["client_secret"] = secrets.token_urlsafe(32)
        return super().create(vals_list)

    def write(self, vals):
        res = super().write(vals)
        for client in self:
            if client.is_confidential and not client.client_secret:
                client.client_secret = secrets.token_urlsafe(32)
        return res

    @api.constrains("is_confidential", "client_secret")
    def _check_confidential_secret(self):
        for client in self:
            if client.is_confidential and not client.client_secret:
                raise ValidationError(_("Confidential clients must have a client secret."))

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
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": _("New client secret generated"),
                "message": self.client_secret,
                "sticky": False,
                "type": "warning",
            },
        }

    def action_show_secret(self):
        self.ensure_one()
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": _("Client secret"),
                "message": self.client_secret or _("No secret set"),
                "sticky": False,
                "type": "success",
            },
        }

    def action_revoke_authorizations(self):
        """Remove all tokens, auth codes, and consents for this client."""
        token_model = self.env["auth_oidc.token"].sudo()
        code_model = self.env["auth_oidc.authorization_code"].sudo()
        consent_model = self.env["auth_oidc.consent"].sudo()
        event_model = self.env["auth_oidc.event"].sudo()

        for client in self:
            tokens = token_model.search([("client_id", "=", client.id)])
            codes = code_model.search([("client_id", "=", client.id)])
            consents = consent_model.search([("client_id", "=", client.id)])

            token_count = len(tokens)
            code_count = len(codes)
            consent_count = len(consents)

            tokens.unlink()
            codes.unlink()
            consents.unlink()

            event_model.create(
                {
                    "event_type": "client_revoked",
                    "description": (
                        f"Revoked {token_count} tokens, {code_count} codes, "
                        f"and {consent_count} consents"
                    ),
                    "client_id": client.id,
                }
            )
        return True
