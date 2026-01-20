import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from odoo import http, fields
from odoo.http import request


RATE_LIMIT_DEFAULTS = {
    "authorize": (30, 60),
    "token": (60, 60),
    "userinfo": (120, 60),
    "introspect": (60, 60),
    "revoke": (60, 60),
}


def _json_response(payload, status=200, headers=None):
    base_headers = {"Content-Type": "application/json"}
    if headers:
        base_headers.update(headers)
    return http.Response(json.dumps(payload), status=status, headers=base_headers)


def _base_url():
    return request.httprequest.host_url.rstrip("/")


def _bool_param(key, default=False):
    param = request.env["ir.config_parameter"].sudo().get_param(key, str(default))
    return str(param).lower() in {"1", "true", "yes", "on"}


def _rate_limit(bucket, client=None):
    defaults = RATE_LIMIT_DEFAULTS.get(bucket, (30, 60))
    config = request.env["ir.config_parameter"].sudo()
    try:
        limit = int(config.get_param(f"odoo_oidc.rate_limit.{bucket}.limit", defaults[0]))
    except Exception:
        limit = defaults[0]
    try:
        window = int(config.get_param(f"odoo_oidc.rate_limit.{bucket}.window", defaults[1]))
    except Exception:
        window = defaults[1]
    http_request = getattr(request, "httprequest", None)
    ip_addr = getattr(http_request, "remote_addr", "unknown")
    key_parts = [bucket, ip_addr]
    if client and getattr(client, "client_id", None):
        key_parts.append(client.client_id)
    key = ":".join(key_parts)
    allowed, retry_after = request.env["auth_oidc.rate_limit"].sudo().register_hit(
        key, limit, window
    )
    if not allowed:
        headers = {}
        if retry_after:
            headers["Retry-After"] = str(retry_after)
        return _json_response(
            {"error": "rate_limited", "error_description": "Too many requests"},
            status=429,
            headers=headers,
        )
    return None


def _log_event(event_type, description, client=None, user=None):
    http_request = getattr(request, "httprequest", None)
    ip_addr = getattr(http_request, "remote_addr", None)
    user_agent = None
    if http_request and hasattr(http_request, "headers"):
        user_agent = http_request.headers.get("User-Agent")
    request.env["auth_oidc.event"].sudo().create(
        {
            "event_type": event_type,
            "description": description,
            "client_id": getattr(client, "id", False),
            "user_id": getattr(user, "id", False),
            "ip_address": ip_addr,
            "user_agent": user_agent,
        }
    )


def _require_https():
    if not _bool_param("odoo_oidc.require_https", True):
        return None
    if request.httprequest.scheme != "https":
        return _json_response(
            {"error": "invalid_request", "error_description": "HTTPS required"},
            status=400,
        )
    return None


class OidcController(http.Controller):
    # TODO: Add enforcement hooks (HTTPS, rate limiting, audit logging)
    # TODO: Harden ID Token (azp/nonce validation, alg selection UI)
    # TODO: Style consent UI and add rate limiting hooks

    @http.route(
        "/.well-known/openid-configuration",
        auth="public",
        type="http",
        csrf=False,
    )
    def openid_configuration(self, **kwargs):
        https_guard = _require_https()
        if https_guard:
            return https_guard
        base_url = _base_url()
        scope_model = request.env["auth_oidc.scope"].sudo()
        scopes = scope_model.search([("active", "=", True)]).mapped("name")
        config = {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/oauth/authorize",
            "token_endpoint": f"{base_url}/oauth/token",
            "userinfo_endpoint": f"{base_url}/oauth/userinfo",
            "jwks_uri": f"{base_url}/.well-known/jwks.json",
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "response_types_supported": ["code"],
            "scopes_supported": scopes,
            "code_challenge_methods_supported": ["S256", "plain"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
        }
        return _json_response(config)

    @http.route(
        "/.well-known/jwks.json",
        auth="public",
        type="http",
        csrf=False,
    )
    def jwks(self, **kwargs):
        https_guard = _require_https()
        if https_guard:
            return https_guard
        key_model = request.env["auth_oidc.key"].sudo()
        keys = []
        now = datetime.utcnow()
        for key in key_model.search([("use", "=", "sig"), ("active", "=", True)]):
            if key.expires_at and fields.Datetime.to_datetime(key.expires_at) <= now:
                continue
            if not key.public_jwk:
                continue
            try:
                jwk = json.loads(key.public_jwk)
            except Exception:  # noqa: BLE001 - invalid JWK payload
                continue
            jwk["kid"] = key.kid
            jwk.setdefault("use", key.use)
            jwk.setdefault("alg", key.alg)
            keys.append(jwk)
        return _json_response({"keys": keys})

    def _render_consent(self, client, scopes, params):
        return request.render(
            "odoo_oidc_provider.consent_page",
            {
                "client": client,
                "scopes": scopes,
                "params": params,
            },
        )

    def _required_scopes(self, client, scope_string):
        scopes_requested = (scope_string or "").split()
        if not scopes_requested:
            return []
        allowed = set(client.allowed_scopes.mapped("name"))
        if allowed:
            scopes_requested = [s for s in scopes_requested if s in allowed]
        elif not _bool_param("odoo_oidc.allow_all_scopes_when_unset", False):
            scopes_requested = []
        return scopes_requested

    @http.route(
        "/oauth/authorize",
        auth="user",
        type="http",
        methods=["GET", "POST"],
    )
    def authorize(self, **params):
        https_guard = _require_https()
        if https_guard:
            return https_guard
        rl_guard = _rate_limit("authorize")
        if rl_guard:
            return rl_guard

        response_type = params.get("response_type")
        client_id = params.get("client_id")
        redirect_uri = params.get("redirect_uri")
        scope = params.get("scope", "")
        state = params.get("state")
        nonce = params.get("nonce")
        code_challenge = params.get("code_challenge")
        code_challenge_method = params.get("code_challenge_method", "plain")
        prompt = params.get("prompt")

        if response_type != "code" or not client_id:
            return _json_response({"error": "unsupported_response_type"}, status=400)

        client = request.env["auth_oidc.client"].sudo().get_by_client_id(client_id)
        if not client:
            return _json_response({"error": "unauthorized_client"}, status=401)

        redirect_target = redirect_uri or (client._parsed_redirect_uris() or [None])[0]
        if not redirect_target or not client.validate_redirect_uri(redirect_target):
            return _json_response({"error": "invalid_request"}, status=400)

        requested_scopes = self._required_scopes(client, scope)
        scope_str = " ".join(requested_scopes)

        if not client.is_confidential and not code_challenge:
            return _json_response({"error": "invalid_request", "error_description": "PKCE required for public clients"}, status=400)

        if code_challenge_method == "plain" and _bool_param("odoo_oidc.pkce_require_s256", True):
            return _json_response({"error": "invalid_request", "error_description": "S256 PKCE required"}, status=400)

        consent_model = request.env["auth_oidc.consent"].sudo()
        consent = consent_model.search(
            [("user_id", "=", request.env.user.id), ("client_id", "=", client.id)],
            limit=1,
        )
        consent_needed = prompt == "consent" or not consent or not consent.covers_scopes(requested_scopes)

        if request.httprequest.method == "GET" and consent_needed:
            scopes = request.env["auth_oidc.scope"].sudo().search(
                [("name", "in", requested_scopes)]
            )
            return self._render_consent(client, scopes, params)

        if request.httprequest.method == "POST" and consent_needed:
            decision = params.get("decision")
            if decision != "approve":
                _log_event("consent_denied", "User denied consent", client=client, user=request.env.user)
                return _json_response({"error": "access_denied"}, status=400)
            scopes = request.env["auth_oidc.scope"].sudo().search(
                [("name", "in", requested_scopes)]
            )
            if consent:
                consent.write({"scope_ids": [(6, 0, scopes.ids)], "granted": True})
            else:
                consent_model.create(
                    {
                        "user_id": request.env.user.id,
                        "client_id": client.id,
                        "scope_ids": [(6, 0, scopes.ids)],
                        "granted": True,
                    }
                )

        code_model = request.env["auth_oidc.authorization_code"].sudo()
        auth_code = code_model.create_code(
            client=client,
            user=request.env.user,
            redirect_uri=redirect_target,
            scope=scope_str,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method or "plain",
        )
        _log_event("authorization_code", "Issued authorization code", client=client, user=request.env.user)

        parsed = urlparse(redirect_target)
        query = dict(parse_qsl(parsed.query))
        query["code"] = auth_code.code
        if state:
            query["state"] = state
        redirect_url = urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urlencode(query),
                parsed.fragment,
            )
        )
        # Allow off-site redirects (required for OIDC clients); default local=True would force current host.
        return request.redirect(redirect_url, local=False)

    def _authenticate_client(self, params):
        auth_header = request.httprequest.headers.get("Authorization", "")
        client_id = params.get("client_id")
        client_secret = params.get("client_secret")

        if auth_header.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth_header.split(" ", 1)[1]).decode()
                client_id, client_secret = decoded.split(":", 1)
            except Exception:  # noqa: BLE001 - minimal placeholder
                return None

        client = request.env["auth_oidc.client"].sudo().get_by_client_id(client_id)
        if not client:
            return None
        if client.is_confidential and client.client_secret != client_secret:
            return None
        if not client.is_confidential and client_secret:
            return None
        return client

    def _build_id_token(self, client, user, scope_names, nonce, access_token=None):
        try:
            import jwt  # type: ignore
        except Exception as exc:  # noqa: BLE001
            return None, f"JWT library missing: {exc}"

        key = request.env["auth_oidc.key"].sudo().get_active_signing_key()
        if not key:
            return None, "No active signing key"
        if not key.private_key_pem:
            return None, "Signing key missing secret material"
        claims = {
            "iss": _base_url(),
            "sub": str(user.id),
            "aud": client.client_id,
            "iat": int(datetime.utcnow().timestamp()),
            "exp": int((datetime.utcnow() + timedelta(minutes=60)).timestamp()),
        }
        if nonce:
            claims["nonce"] = nonce
        if "email" in scope_names and user.email:
            claims["email"] = user.email
            claims["email_verified"] = False
        if "profile" in scope_names:
            claims["name"] = user.name
        if "org" in scope_names:
            if user.company_id:
                claims["company_id"] = user.company_id.id
                claims["company_name"] = user.company_id.name
                if user.company_id.vat:
                    claims["company_vat"] = user.company_id.vat
                if user.company_id.country_id:
                    claims["company_country"] = user.company_id.country_id.code or user.company_id.country_id.name
                if user.company_id.city:
                    claims["company_city"] = user.company_id.city
                if user.company_id.street:
                    claims["company_street"] = user.company_id.street
                if user.company_id.phone:
                    claims["company_phone"] = user.company_id.phone
            if user.partner_id:
                claims["partner_id"] = user.partner_id.id
                if user.partner_id.ref:
                    claims["partner_ref"] = user.partner_id.ref
        if "groups" in scope_names:
            group_names = user.groups_id.mapped("display_name")
            if group_names:
                claims["groups"] = group_names
        if "role" in scope_names:
            role = user.groups_id[:1].display_name if user.groups_id else None
            if role:
                claims["role"] = role
        if "address" in scope_names and user.partner_id:
            partner = user.partner_id
            if partner.street:
                claims["street"] = partner.street
            if partner.street2:
                claims["street2"] = partner.street2
            if partner.city:
                claims["city"] = partner.city
            if partner.zip:
                claims["zip"] = partner.zip
            if partner.state_id:
                claims["state"] = partner.state_id.code or partner.state_id.name
            if partner.country_id:
                claims["country"] = partner.country_id.code or partner.country_id.name
        if "phone" in scope_names:
            if user.phone:
                claims["phone"] = user.phone
            if user.mobile:
                claims["mobile"] = user.mobile
        if "preferences" in scope_names:
            if user.lang:
                claims["lang"] = user.lang
            if user.tz:
                claims["tz"] = user.tz

        if access_token:
            try:
                digest = hashlib.sha256(access_token.encode()).digest()[:16]
                claims["at_hash"] = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
            except Exception:  # noqa: BLE001
                pass

        headers = {"kid": key.kid, "alg": key.alg}
        signed = jwt.encode(
            claims,
            key.private_key_pem if key.alg.startswith("RS") else key.private_key_pem,
            algorithm=key.alg,
            headers=headers,
        )
        return signed, None

    @http.route(
        "/oauth/token",
        auth="public",
        type="http",
        csrf=False,
        methods=["POST"],
    )
    def token(self, **params):
        https_guard = _require_https()
        if https_guard:
            return https_guard
        rl_guard = _rate_limit("token")
        if rl_guard:
            return rl_guard

        grant_type = params.get("grant_type")
        token_model = request.env["auth_oidc.token"].sudo()
        code_model = request.env["auth_oidc.authorization_code"].sudo()
        client = self._authenticate_client(params)
        if not client:
            return _json_response({"error": "invalid_client"}, status=401)

        if grant_type == "authorization_code":
            code_value = params.get("code")
            redirect_uri = params.get("redirect_uri")
            code_verifier = params.get("code_verifier")
            auth_code = code_model.search([("code", "=", code_value)], limit=1)

            if (
                not auth_code
                or auth_code.client_id != client
                or auth_code.redirect_uri != redirect_uri
                or not auth_code.consume(code_verifier)
            ):
                return _json_response({"error": "invalid_grant"}, status=400)

            scope_names = (auth_code.scope or "").split()
            scopes = request.env["auth_oidc.scope"].sudo().search(
                [("name", "in", scope_names)]
            )
            user = auth_code.user_id.sudo()
            access = token_model.create_access_token(client, user, scopes)
            refresh = token_model.create_refresh_token(client, user, scopes)
            access_token_value = getattr(access, "token_value", None) or access.token
            refresh_token_value = getattr(refresh, "token_value", None) or refresh.token

            id_token = None
            id_token_error = None
            if "openid" in scope_names:
                id_token, id_token_error = self._build_id_token(
                    client,
                    user,
                    scope_names,
                    nonce=auth_code.nonce,
                    access_token=access_token_value,
                )

            response = {
                "access_token": access_token_value,
                "token_type": "bearer",
                "expires_in": 3600,
                "refresh_token": refresh_token_value,
                "scope": " ".join(scope_names),
            }
            if id_token:
                response["id_token"] = id_token
            elif id_token_error:
                response["id_token_error"] = id_token_error

            _log_event("token_issued", "Issued access/refresh tokens", client=client, user=user)
            return _json_response(response)

        if grant_type == "refresh_token":
            refresh_token_value = params.get("refresh_token")
            access, new_refresh = token_model.rotate_refresh_token(
                refresh_token_value, client
            )
            if not access:
                return _json_response({"error": "invalid_grant"}, status=400)
            access_token_value = getattr(access, "token_value", None) or access.token
            refresh_token_value = getattr(new_refresh, "token_value", None) if new_refresh else None
            response = {
                "access_token": access_token_value,
                "token_type": "bearer",
                "expires_in": 3600,
                "scope": " ".join(access.scope_ids.mapped("name")),
            }
            if new_refresh:
                response["refresh_token"] = refresh_token_value or new_refresh.token
            _log_event("token_rotated", "Rotated refresh token", client=client, user=access.user_id)
            return _json_response(response)

        return _json_response({"error": "unsupported_grant_type"}, status=400)

    @http.route(
        "/oauth/revoke",
        auth="public",
        type="http",
        csrf=False,
        methods=["POST"],
    )
    def revoke(self, **params):
        https_guard = _require_https()
        if https_guard:
            return https_guard
        rl_guard = _rate_limit("revoke")
        if rl_guard:
            return rl_guard

        client = self._authenticate_client(params)
        if not client:
            return _json_response({"error": "invalid_client"}, status=401)
        token_value = params.get("token")
        if not token_value:
            return _json_response({"error": "invalid_request"}, status=400)
        token_model = request.env["auth_oidc.token"].sudo()
        hashed = token_model._hash_token(token_value)
        token = token_model.search([("token", "=", hashed)], limit=1)
        if token and token.client_id == client:
            token.unlink()
            _log_event("token_revoked", "Token revoked", client=client, user=token.user_id)
        return _json_response({})

    @http.route(
        "/oauth/introspect",
        auth="public",
        type="http",
        csrf=False,
        methods=["POST"],
    )
    def introspect(self, **params):
        https_guard = _require_https()
        if https_guard:
            return https_guard
        rl_guard = _rate_limit("introspect")
        if rl_guard:
            return rl_guard

        client = self._authenticate_client(params)
        if not client:
            return _json_response({"error": "invalid_client"}, status=401)
        token_value = params.get("token")
        if not token_value:
            return _json_response({"error": "invalid_request"}, status=400)
        token_model = request.env["auth_oidc.token"].sudo()
        hashed = token_model._hash_token(token_value)
        token = token_model.search([("token", "=", hashed)], limit=1)
        if not token or token.client_id != client:
            return _json_response({"active": False})
        active = token.expires_at and fields.Datetime.to_datetime(
            token.expires_at
        ) > datetime.utcnow()
        if not active:
            return _json_response({"active": False})
        payload = {
            "active": True,
            "client_id": token.client_id.client_id,
            "token_type": token.token_type,
            "exp": int(fields.Datetime.to_datetime(token.expires_at).timestamp()),
            "sub": str(token.user_id.id),
            "scope": " ".join(token.scope_ids.mapped("name")),
        }
        _log_event("token_introspected", "Token introspection", client=client, user=token.user_id)
        return _json_response(payload)

    @http.route(
        "/oauth/userinfo",
        auth="public",
        type="http",
        csrf=False,
    )
    def userinfo(self, **kwargs):
        https_guard = _require_https()
        if https_guard:
            return https_guard
        rl_guard = _rate_limit("userinfo")
        if rl_guard:
            return rl_guard

        auth_header = request.httprequest.headers.get("Authorization", "")
        if not auth_header.lower().startswith("bearer "):
            return _json_response({"error": "invalid_token"}, status=401)

        token_value = auth_header.split(" ", 1)[1]
        token = request.env["auth_oidc.token"].sudo().validate_access_token(token_value)
        if not token:
            return _json_response({"error": "invalid_token"}, status=401)

        user = token.user_id.sudo()
        scopes = set(token.scope_ids.mapped("name"))
        payload = {
            "sub": str(user.id),
            "preferred_username": user.login,
        }
        if "profile" in scopes:
            payload["name"] = user.name
        if "email" in scopes:
            payload["email"] = user.email or user.login
            payload["email_verified"] = False
        if "org" in scopes:
            if user.company_id:
                payload["company_id"] = user.company_id.id
                payload["company_name"] = user.company_id.name
                if user.company_id.vat:
                    payload["company_vat"] = user.company_id.vat
                if user.company_id.country_id:
                    payload["company_country"] = user.company_id.country_id.code or user.company_id.country_id.name
                if user.company_id.city:
                    payload["company_city"] = user.company_id.city
                if user.company_id.street:
                    payload["company_street"] = user.company_id.street
                if user.company_id.phone:
                    payload["company_phone"] = user.company_id.phone
            if user.partner_id:
                payload["partner_id"] = user.partner_id.id
                if user.partner_id.ref:
                    payload["partner_ref"] = user.partner_id.ref
        if "groups" in scopes:
            group_names = user.groups_id.mapped("display_name")
            if group_names:
                payload["groups"] = group_names
        if "role" in scopes:
            role = user.groups_id[:1].display_name if user.groups_id else None
            if role:
                payload["role"] = role
        if "address" in scopes and user.partner_id:
            partner = user.partner_id
            if partner.street:
                payload["street"] = partner.street
            if partner.street2:
                payload["street2"] = partner.street2
            if partner.city:
                payload["city"] = partner.city
            if partner.zip:
                payload["zip"] = partner.zip
            if partner.state_id:
                payload["state"] = partner.state_id.code or partner.state_id.name
            if partner.country_id:
                payload["country"] = partner.country_id.code or partner.country_id.name
        if "phone" in scopes:
            if user.phone:
                payload["phone"] = user.phone
            if user.mobile:
                payload["mobile"] = user.mobile
        if "preferences" in scopes:
            if user.lang:
                payload["lang"] = user.lang
            if user.tz:
                payload["tz"] = user.tz

        return _json_response(payload)
