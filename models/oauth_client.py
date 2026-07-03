from odoo import api, fields, models, _
from odoo.exceptions import ValidationError
import hashlib
import hmac
import secrets

# Prefix marking a client_secret stored as SHA-256 rather than plaintext.
# Secrets from before the hashing change are migrated on first successful use.
SECRET_HASH_PREFIX = "sha256$"  # noqa: S105 - storage format marker, not a credential


def _hash_secret(raw_secret):
    return SECRET_HASH_PREFIX + hashlib.sha256(raw_secret.encode()).hexdigest()


class OAuthClient(models.Model):
    _name = "auth_oidc.client"
    _description = "OIDC/OAuth2 Client"

    name = fields.Char(required=True)
    client_id = fields.Char(required=True, index=True)
    client_secret = fields.Char(groups="base.group_system", copy=False)
    redirect_uris = fields.Text(
        help="One redirect URI per line (exact match).",
    )
    post_logout_redirect_uris = fields.Text(
        string="Post-Logout Redirect URIs",
        help="One URI per line (exact match). Only these targets are allowed "
        "for post_logout_redirect_uri at the end_session endpoint.",
    )
    allowed_scopes = fields.Many2many(
        "auth_oidc.scope",
        "auth_oidc_client_scope_rel",
        "client_id",
        "scope_id",
        string="Allowed Scopes",
    )
    consent_css = fields.Text(
        string="Consent Page CSS",
        help="Custom CSS injected into the consent page for this client.",
    )
    allow_public_spa = fields.Boolean(
        string="Allow Public SPA",
        help="Allow public single-page apps without a client secret (PKCE required).",
        default=False,
    )
    auto_consent = fields.Boolean(
        string="Auto-Consent",
        help="Skip consent screen for this client unless prompt=consent is used.",
        default=False,
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
            allow_public_spa = vals.get("allow_public_spa", False)
            if not allow_public_spa and vals.get("is_confidential", True) and not vals.get("client_secret"):
                # Auto-generated secrets are stored hashed and therefore not
                # retrievable; use "Generate Secret" to obtain a usable value.
                vals["client_secret"] = _hash_secret(secrets.token_urlsafe(32))
        return super().create(vals_list)

    def write(self, vals):
        res = super().write(vals)
        for client in self:
            if not client.allow_public_spa and client.is_confidential and not client.client_secret:
                client.client_secret = _hash_secret(secrets.token_urlsafe(32))
        return res

    def verify_secret(self, provided_secret):
        """Constant-time client secret check. Secrets are stored as SHA-256;
        plaintext values from before the hashing change are verified once and
        upgraded in place."""
        self.ensure_one()
        stored = self.client_secret or ""
        if not provided_secret or not stored:
            return False
        if stored.startswith(SECRET_HASH_PREFIX):
            return hmac.compare_digest(stored, _hash_secret(provided_secret))
        if hmac.compare_digest(stored, provided_secret):
            self.sudo().client_secret = _hash_secret(provided_secret)
            return True
        return False

    @api.constrains("is_confidential", "client_secret", "allow_public_spa")
    def _check_confidential_secret(self):
        for client in self:
            if client.allow_public_spa and client.is_confidential:
                raise ValidationError(_("Public SPA clients cannot be confidential."))
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

    def _parsed_post_logout_uris(self):
        self.ensure_one()
        return [
            uri.strip()
            for uri in (self.post_logout_redirect_uris or "").splitlines()
            if uri.strip()
        ]

    def validate_post_logout_uri(self, uri):
        """Exact match against the registered post-logout redirect URIs."""
        self.ensure_one()
        if not uri:
            return False
        return uri.strip() in self._parsed_post_logout_uris()

    def action_generate_secret(self):
        self.ensure_one()
        raw_secret = secrets.token_urlsafe(32)
        self.client_secret = _hash_secret(raw_secret)
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": _("New client secret generated"),
                "message": _(
                    "Copy it now — it is stored hashed and cannot be shown again: %s"
                ) % raw_secret,
                "sticky": True,
                "type": "warning",
            },
        }

    def action_show_secret(self):
        self.ensure_one()
        if not self.client_secret:
            message = _("No secret set")
        elif self.client_secret.startswith(SECRET_HASH_PREFIX):
            message = _(
                "The secret is stored hashed and cannot be displayed. "
                "Use 'Generate Secret' to obtain a new one."
            )
        else:
            # Legacy plaintext secret from before the hashing change.
            message = self.client_secret
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": _("Client secret"),
                "message": message,
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
