import json
import logging
import re
from datetime import datetime, timedelta
import hmac
import secrets
import hashlib
import base64

from odoo import api, fields, models, _
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


def _b64url_encode(raw_bytes):
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode()


def _b64url_int(value):
    length = (value.bit_length() + 7) // 8
    return _b64url_encode(value.to_bytes(length, byteorder="big"))


class OAuthKey(models.Model):
    _name = "auth_oidc.key"
    _description = "OIDC Signing/Verification Key"

    name = fields.Char(required=True)
    kid = fields.Char(required=True, index=True, help="Key identifier published in JWKS")
    alg = fields.Selection(
        [("RS256", "RS256")],
        required=True,
        default="RS256",
    )
    kty = fields.Selection(
        [("RSA", "RSA")],
        required=True,
        default="RSA",
    )
    use = fields.Selection(
        [("sig", "Signature")],
        required=True,
        default="sig",
    )
    public_jwk = fields.Text(
        help="JSON representation of the public JWK that will be exposed at the JWKS endpoint.",
    )
    private_key_pem = fields.Text(
        groups="base.group_system",
        help="Private key in PEM format (required for signing). Restrict access.",
    )
    active = fields.Boolean(default=True)
    expires_at = fields.Datetime()

    _sql_constraints = [
        ("auth_oidc_kid_unique", "unique(kid)", "Key ID must be unique."),
    ]

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if not vals.get("kid"):
                vals["kid"] = secrets.token_hex(8)
        records = super().create(vals_list)
        records._sync_public_jwk()
        return records

    def write(self, vals):
        res = super().write(vals)
        if {"public_jwk", "private_key_pem", "alg", "kty"} & set(vals):
            self._sync_public_jwk()
        return res

    @api.model
    def get_active_signing_key(self):
        domain = [("use", "=", "sig"), ("active", "=", True)]
        candidates = self.search(domain, order="expires_at asc, id desc")
        now = datetime.utcnow()
        for key in candidates:
            if not key.expires_at:
                return key
            if fields.Datetime.to_datetime(key.expires_at) > now:
                return key
        return candidates[:1]

    def _sync_public_jwk(self):
        """Fill in public_jwk from stored private key (HS auto, RSA if cryptography is installed)."""
        for key in self:
            if key.public_jwk or not key.private_key_pem:
                continue
            if key.alg.startswith("HS") or key.kty == "oct":
                jwk_value = json.dumps(
                    {
                        "kty": "oct",
                        "alg": key.alg,
                        "k": _b64url_encode(key.private_key_pem.encode()),
                        "kid": key.kid,
                        "use": key.use,
                    }
                )
                key.public_jwk = jwk_value
            elif key.kty == "RSA":
                try:
                    from cryptography.hazmat.primitives import serialization
                    from cryptography.hazmat.backends import default_backend
                except Exception:
                    _logger.warning("cryptography package unavailable; cannot derive public JWK for key %s", key.kid)
                    continue
                try:
                    private_key = serialization.load_pem_private_key(
                        key.private_key_pem.encode(), password=None, backend=default_backend()
                    )
                    numbers = private_key.public_key().public_numbers()
                    jwk_value = json.dumps(
                        {
                            "kty": "RSA",
                            "alg": key.alg,
                            "use": key.use,
                            "kid": key.kid,
                            "n": _b64url_int(numbers.n),
                            "e": _b64url_int(numbers.e),
                        }
                    )
                    key.public_jwk = jwk_value
                except Exception:
                    _logger.warning("Could not derive public JWK for key %s", key.kid, exc_info=True)
                    continue

    def action_generate_rsa_key(self):
        """Generate an RSA key pair and fill public JWK."""
        self.ensure_one()
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
        except Exception as exc:
            raise UserError(
                _("cryptography package is required for RSA generation: %s") % exc
            ) from exc
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        numbers = private_key.public_key().public_numbers()
        jwk_value = json.dumps(
            {
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": self.kid or secrets.token_hex(8),
                "n": _b64url_int(numbers.n),
                "e": _b64url_int(numbers.e),
            }
        )
        vals = {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "private_key_pem": pem,
            "public_jwk": jwk_value,
        }
        if not self.kid:
            vals["kid"] = secrets.token_hex(8)
        self.write(vals)
        return True


# RFC 7636 §4.1: code_verifier is 43-128 characters from the unreserved set.
PKCE_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")


class OAuthAuthorizationCode(models.Model):
    _name = "auth_oidc.authorization_code"
    _description = "OIDC Authorization Code"

    code = fields.Char(required=True, index=True, help="SHA-256 hash of the code.")
    code_value = fields.Char(
        string="Raw Code",
        compute="_compute_code_value",
        store=False,
        help="Raw authorization code, only available in-memory after creation.",
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
    redirect_uri = fields.Char(required=True)
    redirect_uri_explicit = fields.Boolean(
        default=True,
        help="Whether the client sent redirect_uri in the authorization request. "
        "If so, RFC 6749 §4.1.3 requires the identical value at the token endpoint.",
    )
    scope = fields.Char(help="Space-delimited scopes.")
    nonce = fields.Char(help="Opaque client-provided nonce for ID Token.")
    code_challenge = fields.Char()
    code_challenge_method = fields.Selection(
        [("plain", "plain"), ("S256", "S256")],
        default="plain",
    )
    expires_at = fields.Datetime(required=True)
    used = fields.Boolean(default=False)

    _sql_constraints = [
        ("auth_oidc_code_unique", "unique(code)", "Authorization code must be unique."),
    ]

    def _compute_code_value(self):
        """Expose the raw code via context after creation without persisting it."""
        code_map = self.env.context.get("code_value_map") or {}
        for rec in self:
            rec.code_value = code_map.get(rec.id)

    @staticmethod
    def _hash_code(code_value):
        return hashlib.sha256(code_value.encode()).hexdigest()

    @api.model
    def create_code(
        self,
        client,
        user,
        redirect_uri,
        scope,
        nonce=None,
        code_challenge=None,
        code_challenge_method="plain",
        lifetime_sec=600,
        redirect_uri_explicit=True,
    ):
        code_value = secrets.token_urlsafe(32)
        expires_at = fields.Datetime.to_string(
            datetime.utcnow() + timedelta(seconds=lifetime_sec)
        )
        record = self.create(
            {
                "code": self._hash_code(code_value),
                "client_id": client.id,
                "user_id": user.id,
                "redirect_uri": redirect_uri,
                "redirect_uri_explicit": redirect_uri_explicit,
                "scope": scope,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method or "plain",
                "expires_at": expires_at,
            }
        )
        return record.with_context(code_value_map={record.id: code_value})

    @api.model
    def find_by_code(self, code_value):
        if not code_value:
            return self.browse()
        return self.search([("code", "=", self._hash_code(code_value))], limit=1)

    def consume(self, code_verifier=None):
        self.ensure_one()
        if self.used:
            return False
        if self.expires_at and fields.Datetime.to_datetime(self.expires_at) < datetime.utcnow():
            return False
        if self.code_challenge:
            if not code_verifier or not PKCE_VERIFIER_RE.match(code_verifier):
                return False
            if self.code_challenge_method == "S256":
                hashed = hashlib.sha256(code_verifier.encode()).digest()
                verifier_challenge = _b64url_encode(hashed)
            else:
                verifier_challenge = code_verifier
            if not hmac.compare_digest(verifier_challenge, self.code_challenge):
                return False
        self.used = True
        return True

    @api.model
    def cron_cleanup_expired(self):
        """Remove expired or used authorization codes."""
        now = fields.Datetime.to_string(datetime.utcnow())
        expired = self.search(
            ["|", ("used", "=", True), ("expires_at", "<", now)], limit=500
        )
        expired.unlink()


class OAuthConsent(models.Model):
    _name = "auth_oidc.consent"
    _description = "OIDC User Consent"

    user_id = fields.Many2one("res.users", required=True, ondelete="cascade")
    client_id = fields.Many2one("auth_oidc.client", required=True, ondelete="cascade")
    scope_ids = fields.Many2many(
        "auth_oidc.scope",
        "auth_oidc_consent_scope_rel",
        "consent_id",
        "scope_id",
    )
    granted = fields.Boolean(default=True)
    granted_at = fields.Datetime(default=lambda self: fields.Datetime.now())

    _sql_constraints = [
        (
            "auth_oidc_consent_unique",
            "unique(user_id, client_id)",
            "A consent per user/client already exists.",
        ),
    ]

    def covers_scopes(self, requested_scopes):
        self.ensure_one()
        if not self.granted:
            return False
        consented = set(self.scope_ids.mapped("name"))
        return set(requested_scopes).issubset(consented)


class OAuthEvent(models.Model):
    _name = "auth_oidc.event"
    _description = "OIDC Event Log"
    _order = "create_date desc"

    event_type = fields.Char(required=True)
    description = fields.Text()
    client_id = fields.Many2one("auth_oidc.client", ondelete="set null")
    user_id = fields.Many2one("res.users", ondelete="set null")
    ip_address = fields.Char()
    user_agent = fields.Char()
