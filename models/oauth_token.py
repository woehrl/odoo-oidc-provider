from datetime import datetime, timedelta
import hashlib
import secrets

from odoo import api, fields, models


class OAuthScope(models.Model):
    _name = "auth_oidc.scope"
    _description = "OIDC Scope"

    name = fields.Char(required=True)
    description = fields.Text()
    active = fields.Boolean(default=True)

    _sql_constraints = [
        ("auth_oidc_scope_name_unique", "unique(name)", "Scope name must be unique."),
    ]


class OAuthToken(models.Model):
    _name = "auth_oidc.token"
    _description = "OIDC Token"

    token_type = fields.Selection(
        [("access", "Access Token"), ("refresh", "Refresh Token")],
        required=True,
        index=True,
    )
    token = fields.Char(required=True, index=True)
    token_value = fields.Char(
        string="Raw Token",
        compute="_compute_token_value",
        store=False,
        help="Raw token value, only available in-memory after creation.",
    )
    client_id = fields.Many2one(
        "auth_oidc.client",
        required=True,
        ondelete="cascade",
    )
    user_id = fields.Many2one(
        "res.users",
        required=True,
        ondelete="cascade",
    )
    expires_at = fields.Datetime(required=True, index=True)
    scope_ids = fields.Many2many(
        "auth_oidc.scope",
        "auth_oidc_token_scope_rel",
        "token_id",
        "scope_id",
    )

    _sql_constraints = [
        ("auth_oidc_token_unique", "unique(token)", "Token value must be unique."),
    ]

    def _compute_token_value(self):
        """Expose raw token via context after creation without persisting it."""
        token_map = self.env.context.get("token_value_map") or {}
        default_val = self.env.context.get("token_value")
        for rec in self:
            rec.token_value = token_map.get(rec.id) or default_val

    @staticmethod
    def _hash_token(token_value):
        return hashlib.sha256(token_value.encode()).hexdigest()

    @api.model
    def _normalize_scopes(self, scopes):
        """Return a scope recordset for the given input (names or records)."""
        scope_model = self.env["auth_oidc.scope"]
        if isinstance(scopes, models.Model):
            return scopes
        if not scopes:
            return scope_model.browse()
        names = []
        ids = []
        for scope in scopes:
            if isinstance(scope, models.Model):
                ids.append(scope.id)
            else:
                names.append(scope)
        domain = []
        if ids:
            domain.append(("id", "in", ids))
        if names:
            domain.append(("name", "in", names))
        return scope_model.search(domain or [])

    @api.model
    def _create_token(self, token_type, client, user, scopes, ttl_seconds):
        expires_at = fields.Datetime.to_string(
            datetime.utcnow() + timedelta(seconds=ttl_seconds)
        )
        scope_records = self._normalize_scopes(scopes)
        token_value = secrets.token_urlsafe(32)
        hashed = self._hash_token(token_value)
        record = self.create(
            {
                "token_type": token_type,
                "token": hashed,
                "client_id": client.id,
                "user_id": user.id,
                "expires_at": expires_at,
                "scope_ids": [(6, 0, scope_records.ids)],
            }
        )
        # Keep raw token in context only (not persisted) for immediate return.
        token_map = {rec.id: token_value for rec in record}
        return record.with_context(token_value_map=token_map, token_value=token_value)

    @api.model
    def create_access_token(self, client, user, scopes, ttl_seconds=3600):
        """Minimal access token creation helper."""
        return self._create_token("access", client, user, scopes, ttl_seconds)

    @api.model
    def create_refresh_token(self, client, user, scopes, ttl_seconds=30 * 24 * 3600):
        """Minimal refresh token creation helper."""
        return self._create_token("refresh", client, user, scopes, ttl_seconds)

    @api.model
    def validate_access_token(self, token_value):
        """Return a valid access token record or False."""
        if not token_value:
            return False
        hashed = self._hash_token(token_value)
        token = self.search(
            [
                ("token", "=", hashed),
                ("token_type", "=", "access"),
            ],
            limit=1,
        )
        if not token:
            return False
        if token.expires_at and fields.Datetime.to_datetime(
            token.expires_at
        ) < datetime.utcnow():
            return False
        if not token.user_id or not token.client_id or not token.client_id.active:
            return False
        return token

    @api.model
    def rotate_refresh_token(self, refresh_token_value, client):
        """Simple rotation: create new access+refresh tokens and drop the old one."""
        if not refresh_token_value or not client:
            return False, False
        hashed = self._hash_token(refresh_token_value)
        refresh_token = self.search(
            [
                ("token", "=", hashed),
                ("token_type", "=", "refresh"),
            ],
            limit=1,
        )
        if not refresh_token:
            return False, False
        if refresh_token.client_id != client:
            return False, False
        if refresh_token.expires_at and fields.Datetime.to_datetime(
            refresh_token.expires_at
        ) < datetime.utcnow():
            return False, False
        if not refresh_token.client_id.active or not client.active:
            return False, False

        scopes = refresh_token.scope_ids
        client = refresh_token.client_id
        user = refresh_token.user_id
        new_access = self.create_access_token(client, user, scopes)
        new_refresh = self.create_refresh_token(client, user, scopes)
        refresh_token.unlink()
        return new_access, new_refresh

    @api.model
    def cron_cleanup_expired(self):
        """Remove expired tokens to limit table growth."""
        now = fields.Datetime.to_string(datetime.utcnow())
        expired = self.search([("expires_at", "<", now)], limit=500)
        expired.unlink()
