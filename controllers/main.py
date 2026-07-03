import base64
import hashlib
import json
import logging
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from odoo import http, fields
from odoo.http import request

_logger = logging.getLogger(__name__)

RATE_LIMIT_DEFAULTS = {
    "authorize": (30, 60),
    "token": (60, 60),
    "userinfo": (120, 60),
    "introspect": (60, 60),
    "revoke": (60, 60),
    "end_session": (30, 60),
}

def _json_response(payload, status=200, headers=None):
    base_headers = {"Content-Type": "application/json"}
    if headers:
        base_headers.update(headers)
    return http.Response(json.dumps(payload), status=status, headers=base_headers)


def _base_url():
    """Canonical issuer URL. Uses web.base.url so the issuer in discovery and
    signed ID tokens cannot be influenced by the request's Host header."""
    base = request.env["ir.config_parameter"].sudo().get_param("web.base.url")
    if base:
        return base.rstrip("/")
    return request.httprequest.host_url.rstrip("/")


def _utc_epoch(naive_utc_dt):
    """Epoch seconds for a naive datetime that is known to be UTC (Odoo's
    storage convention). A bare .timestamp() would interpret it as local time."""
    return int(naive_utc_dt.replace(tzinfo=timezone.utc).timestamp())


def _expires_in(token):
    """Remaining lifetime of a token record in seconds."""
    delta = fields.Datetime.to_datetime(token.expires_at) - datetime.utcnow()
    return max(0, int(delta.total_seconds()))


def _user_type(user):
    """Return a simple user type label."""
    # Public user check: Odoo flags the website anonymous user via _is_public().
    if getattr(user, "_is_public", lambda: False)():
        return "public"
    # Portal users are marked by the built-in 'share' boolean.
    if getattr(user, "share", False):
        return "portal"
    # Everything else is an internal user.
    return "internal"


def _origin_host(origin):
    try:
        parsed = urlparse(origin)
    except Exception:
        return None, None
    if not parsed.scheme or not parsed.netloc:
        return None, None
    return parsed.scheme, parsed.netloc.lower()


def _normalize_netloc(scheme, netloc):
    """Strip default ports (80 for http, 443 for https) so that
    'https://host:443' and 'https://host' compare equal."""
    _STANDARD = {"http": "80", "https": "443"}
    if netloc.startswith("["):
        return netloc  # IPv6 — leave as-is
    if ":" in netloc:
        host, port = netloc.rsplit(":", 1)
        if _STANDARD.get(scheme) == port:
            return host
    return netloc


def _origin_allowed_for_client(origin, client):
    """Exact origin match (scheme + host + port, default ports normalized)
    against the origins of the client's registered redirect URIs.
    No subdomain wildcards: a registered https://app.example.com/callback
    allows exactly the origin https://app.example.com and nothing else."""
    scheme, origin_netloc = _origin_host(origin)
    if not scheme or not origin_netloc:
        return False
    origin_norm = _normalize_netloc(scheme, origin_netloc)
    for uri in client._parsed_redirect_uris():
        parsed = urlparse(uri)
        if not parsed.scheme or not parsed.netloc:
            continue
        redirect_norm = _normalize_netloc(parsed.scheme, parsed.netloc.lower())
        if scheme == parsed.scheme and origin_norm == redirect_norm:
            return True
    return False


def _cors_headers(origin, client=None):
    if not origin:
        return {}
    if client and _origin_allowed_for_client(origin, client):
        allowed = True
    else:
        # Preflight arrives before client authentication; match the origin
        # against any active client's registered redirect URI origins.
        allowed = False
        for c in request.env["auth_oidc.client"].sudo().search([("active", "=", True)]):
            if _origin_allowed_for_client(origin, c):
                allowed = True
                break
    if not allowed:
        return {}
    # No Access-Control-Allow-Credentials: these endpoints authenticate via
    # Authorization header / body parameters, never via cookies.
    return {
        "Access-Control-Allow-Origin": origin,
        "Vary": "Origin",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
    }


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


def _bool_param(name, default=False):
    """Retrieve a boolean system parameter from ir.config_parameter."""
    val = request.env["ir.config_parameter"].sudo().get_param(name)
    if val is False or val is None:
        return default
    return str(val).lower() in ("1", "true", "yes")


def _cors_public_headers():
    """Wildcard CORS headers for public discovery documents (any origin)."""
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Accept, Content-Type",
    }


def _verify_id_token_hint(hint):
    """Verify an id_token_hint against our own signing keys and issuer.
    Expired tokens are accepted (per OIDC RP-Initiated Logout) but the
    signature must be ours. Returns the claims dict or None."""
    try:
        import jwt
        from cryptography.hazmat.primitives import serialization
    except Exception:  # noqa: BLE001 - optional dependency missing
        return None
    try:
        header = jwt.get_unverified_header(hint)
    except Exception:  # noqa: BLE001 - not a JWT
        return None
    key_model = request.env["auth_oidc.key"].sudo()
    domain = [("use", "=", "sig")]
    if header.get("kid"):
        domain.append(("kid", "=", header["kid"]))
    for key in key_model.search(domain):
        if not key.private_key_pem:
            continue
        try:
            private_key = serialization.load_pem_private_key(
                key.private_key_pem.encode(), password=None
            )
            return jwt.decode(
                hint,
                key=private_key.public_key(),
                algorithms=["RS256"],
                issuer=_base_url(),
                options={"verify_exp": False, "verify_aud": False},
            )
        except Exception:  # noqa: BLE001 - try remaining keys
            _logger.debug("id_token_hint did not verify against key %s", key.kid)
            continue
    return None


def _redirect_error(redirect_uri, error, description=None, state=None):
    """Redirect to redirect_uri with an OAuth2 error response."""
    parsed = urlparse(redirect_uri)
    query = dict(parse_qsl(parsed.query))
    query["error"] = error
    if description:
        query["error_description"] = description
    if state:
        query["state"] = state
    redirect_url = urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, urlencode(query), parsed.fragment,
    ))
    return request.redirect(redirect_url, local=False)


class OidcController(http.Controller):
    @http.route(
        "/.well-known/openid-configuration",
        auth="public",
        type="http",
        csrf=False,
        methods=["GET", "OPTIONS"],
    )
    def openid_configuration(self, **kwargs):
        # Handle CORS preflight — discovery documents must be reachable from
        # any origin so browser-based OIDC clients can auto-discover endpoints.
        if request.httprequest.method == "OPTIONS":
            return http.Response(status=204, headers=_cors_public_headers())
        https_guard = _require_https()
        if https_guard:
            return https_guard
        base_url = _base_url()
        scope_model = request.env["auth_oidc.scope"].sudo()
        scopes = scope_model.search([("active", "=", True)]).mapped("name")
        # Reflect actual PKCE methods: if S256-only is enforced, drop plain.
        pkce_methods = ["S256"]
        if not _bool_param("odoo_oidc.pkce_require_s256", True):
            pkce_methods.append("plain")
        config = {
            # RFC 8414 / OIDC Discovery required fields
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/oauth/authorize",
            "token_endpoint": f"{base_url}/oauth/token",
            "jwks_uri": f"{base_url}/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            # Recommended / commonly expected fields
            "userinfo_endpoint": f"{base_url}/oauth/userinfo",
            "end_session_endpoint": f"{base_url}/oauth/end_session",
            "revocation_endpoint": f"{base_url}/oauth/revoke",
            "introspection_endpoint": f"{base_url}/oauth/introspect",
            "scopes_supported": scopes,
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "code_challenge_methods_supported": pkce_methods,
            "claims_supported": [
                "sub", "iss", "aud", "iat", "exp", "auth_time", "azp",
                "nonce", "at_hash", "user_type",
                # profile
                "name", "preferred_username",
                # email
                "email", "email_verified",
                # address
                "street", "street2", "city", "zip", "state", "country",
                # phone
                "phone", "mobile",
                # preferences
                "lang", "tz",
                # org
                "company_id", "company_name", "company_vat",
                "company_registry", "company_country", "company_city",
                "company_zip", "company_street", "company_street2",
                "company_phone", "partner_id", "partner_ref",
                # groups
                "groups",
            ],
        }
        return _json_response(config, headers=_cors_public_headers())

    @http.route(
        "/.well-known/jwks.json",
        auth="public",
        type="http",
        csrf=False,
        methods=["GET", "OPTIONS"],
    )
    def jwks(self, **kwargs):
        # Handle CORS preflight — JWKS must be reachable from any origin so
        # clients can validate ID Token signatures in the browser.
        if request.httprequest.method == "OPTIONS":
            return http.Response(status=204, headers=_cors_public_headers())
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
                _logger.warning("Skipping key %s: public_jwk is not valid JSON", key.kid)
                continue
            jwk["kid"] = key.kid
            jwk.setdefault("use", key.use)
            jwk.setdefault("alg", key.alg)
            keys.append(jwk)
        return _json_response({"keys": keys}, headers=_cors_public_headers())

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
        code_challenge_method = params.get("code_challenge_method", "S256")
        prompt = params.get("prompt")

        if response_type != "code" or not client_id:
            return _json_response({"error": "unsupported_response_type"}, status=400)

        client = request.env["auth_oidc.client"].sudo().get_by_client_id(client_id)
        if not client:
            return _json_response({"error": "unauthorized_client"}, status=401)

        redirect_target = redirect_uri or (client._parsed_redirect_uris() or [None])[0]
        if not redirect_target or not client.validate_redirect_uri(redirect_target):
            return _json_response({"error": "invalid_request"}, status=400)

        # From this point redirect_uri is validated; errors must be returned
        # as redirects per RFC 6749 §4.1.2.1 / OIDC Core §3.1.2.6.
        scopes_asked = (scope or "").split()
        requested_scopes = self._required_scopes(client, scope)
        scope_str = " ".join(requested_scopes)

        # RFC 6749 §4.1.2.1: reject rather than silently grant nothing, and
        # never drop openid silently — the client expects an OIDC response.
        if scopes_asked and not requested_scopes:
            return _redirect_error(redirect_target, "invalid_scope",
                                   "None of the requested scopes are allowed for this client", state)
        if "openid" in scopes_asked and "openid" not in requested_scopes:
            return _redirect_error(redirect_target, "invalid_scope",
                                   "openid scope is not allowed for this client", state)

        if not client.is_confidential and not code_challenge:
            return _redirect_error(redirect_target, "invalid_request",
                                   "PKCE code_challenge required for public clients", state)

        if code_challenge_method not in {"S256", "plain"}:
            return _redirect_error(redirect_target, "invalid_request",
                                   "Unsupported code_challenge_method", state)

        # Enforce server-side PKCE S256 requirement (configurable).
        if code_challenge and code_challenge_method == "plain":
            if _bool_param("odoo_oidc.pkce_require_s256", True):
                return _redirect_error(redirect_target, "invalid_request",
                                       "code_challenge_method=plain not allowed; use S256", state)

        consent_model = request.env["auth_oidc.consent"].sudo()
        consent = consent_model.search(
            [("user_id", "=", request.env.user.id), ("client_id", "=", client.id)],
            limit=1,
        )
        consent_needed = prompt == "consent" or not consent or not consent.covers_scopes(requested_scopes)
        if client.auto_consent and prompt != "consent":
            consent_needed = False

        if request.httprequest.method == "GET" and consent_needed:
            scopes = request.env["auth_oidc.scope"].sudo().search(
                [("name", "in", requested_scopes)]
            )
            return self._render_consent(client, scopes, params)

        if request.httprequest.method == "POST" and consent_needed:
            decision = params.get("decision")
            if decision != "approve":
                _log_event("consent_denied", "User denied consent", client=client, user=request.env.user)
                return _redirect_error(redirect_target, "access_denied",
                                       "User denied consent", state)
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
            code_challenge_method=code_challenge_method or "S256",
            redirect_uri_explicit=bool(redirect_uri),
        )
        _log_event("authorization_code", "Issued authorization code", client=client, user=request.env.user)

        parsed = urlparse(redirect_target)
        query = dict(parse_qsl(parsed.query))
        query["code"] = auth_code.code_value
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
        if client.is_confidential and not client.verify_secret(client_secret):
            return None
        if not client.is_confidential and client_secret:
            return None
        if client.allow_public_spa and client_secret:
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
        now_epoch = _utc_epoch(datetime.utcnow())
        # auth_time is when the user actually authenticated (OIDC Core §2),
        # not when this token was minted; login_date is Odoo's record of that.
        login_date = user.login_date
        claims = {
            "iss": _base_url(),
            "sub": str(user.id),
            "aud": [client.client_id],
            "iat": now_epoch,
            "exp": now_epoch + 3600,
            "auth_time": _utc_epoch(login_date) if login_date else now_epoch,
            "azp": client.client_id,
        }
        partner = user.partner_id
        commercial_partner = partner.commercial_partner_id if partner else False
        if nonce:
            claims["nonce"] = nonce
        if "email" in scope_names and user.email:
            claims["email"] = user.email
            claims["email_verified"] = False
        if "profile" in scope_names:
            claims["name"] = user.name
        claims["user_type"] = _user_type(user)
        if "org" in scope_names:
            if commercial_partner:
                claims["company_id"] = commercial_partner.id
                claims["company_name"] = commercial_partner.name
                if commercial_partner.vat:
                    claims["company_vat"] = commercial_partner.vat
                if commercial_partner.company_registry:
                    claims["company_registry"] = commercial_partner.company_registry
                if commercial_partner.country_id:
                    claims["company_country"] = commercial_partner.country_id.code or commercial_partner.country_id.name
                if commercial_partner.city:
                    claims["company_city"] = commercial_partner.city
                if commercial_partner.zip:
                    claims["company_zip"] = commercial_partner.zip
                if commercial_partner.street:
                    claims["company_street"] = commercial_partner.street
                if commercial_partner.street2:
                    claims["company_street2"] = commercial_partner.street2
                if commercial_partner.phone:
                    claims["company_phone"] = commercial_partner.phone
            if partner:
                claims["partner_id"] = partner.id
                if partner.ref:
                    claims["partner_ref"] = partner.ref
        if "groups" in scope_names:
            group_names = user.groups_id.mapped("display_name")
            if group_names:
                claims["groups"] = group_names
        if "address" in scope_names and commercial_partner:
            if commercial_partner.street:
                claims["street"] = commercial_partner.street
            if commercial_partner.street2:
                claims["street2"] = commercial_partner.street2
            if commercial_partner.city:
                claims["city"] = commercial_partner.city
            if commercial_partner.zip:
                claims["zip"] = commercial_partner.zip
            if commercial_partner.state_id:
                claims["state"] = commercial_partner.state_id.code or commercial_partner.state_id.name
            if commercial_partner.country_id:
                claims["country"] = commercial_partner.country_id.code or commercial_partner.country_id.name
        if "phone" in scope_names:
            if commercial_partner and commercial_partner.phone:
                claims["phone"] = commercial_partner.phone
            elif user.phone:
                claims["phone"] = user.phone
            if commercial_partner and commercial_partner.mobile:
                claims["mobile"] = commercial_partner.mobile
            elif user.mobile:
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
                _logger.warning("Could not compute at_hash for ID token", exc_info=True)

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
        methods=["POST", "OPTIONS"],
    )
    def token(self, **params):
        https_guard = _require_https()
        if https_guard:
            return https_guard
        origin = request.httprequest.headers.get("Origin")
        if request.httprequest.method == "OPTIONS":
            return http.Response(status=204, headers=_cors_headers(origin))
        try:
            rl_guard = _rate_limit("token")
            if rl_guard:
                return rl_guard

            grant_type = params.get("grant_type")
            token_model = request.env["auth_oidc.token"].sudo()
            code_model = request.env["auth_oidc.authorization_code"].sudo()
            client = self._authenticate_client(params)
            if not client:
                return _json_response({"error": "invalid_client"}, status=401, headers=_cors_headers(origin))

            if grant_type == "authorization_code":
                code_value = params.get("code")
                redirect_uri = params.get("redirect_uri")
                code_verifier = params.get("code_verifier")
                auth_code = code_model.find_by_code(code_value)

                if not auth_code or auth_code.client_id != client:
                    return _json_response({"error": "invalid_grant"}, status=400, headers=_cors_headers(origin, client))

                if auth_code.used:
                    # RFC 6749 §4.1.2: a replayed code revokes everything
                    # previously issued on the strength of that code.
                    revoked = token_model.revoke_for_auth_code(auth_code)
                    if revoked:
                        _log_event(
                            "token_revoked",
                            f"Authorization code replay detected; revoked {revoked} token(s)",
                            client=client,
                            user=auth_code.user_id,
                        )
                    return _json_response({"error": "invalid_grant"}, status=400, headers=_cors_headers(origin, client))

                # RFC 6749 §4.1.3: redirect_uri is required and must match if it
                # was sent in the authorization request, and must be absent or
                # matching if the authorization request relied on the default.
                if auth_code.redirect_uri_explicit:
                    redirect_ok = redirect_uri == auth_code.redirect_uri
                else:
                    redirect_ok = not redirect_uri or redirect_uri == auth_code.redirect_uri

                if not redirect_ok or not auth_code.consume(code_verifier):
                    return _json_response({"error": "invalid_grant"}, status=400, headers=_cors_headers(origin, client))

                scope_names = (auth_code.scope or "").split()
                scopes = request.env["auth_oidc.scope"].sudo().search(
                    [("name", "in", scope_names)]
                )
                user = auth_code.user_id.sudo()
                access = token_model.create_access_token(client, user, scopes, auth_code=auth_code)
                refresh = token_model.create_refresh_token(client, user, scopes, auth_code=auth_code)
                access_token_value = access.token_value
                refresh_token_value = refresh.token_value
                if not access_token_value or not refresh_token_value:
                    # Never fall back to the stored hash; fail loudly instead.
                    raise ValueError("Raw token value unavailable after creation")

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
                    "expires_in": _expires_in(access),
                    "refresh_token": refresh_token_value,
                    "scope": " ".join(scope_names),
                }
                if id_token:
                    response["id_token"] = id_token
                elif id_token_error:
                    response["id_token_error"] = id_token_error

                _log_event("token_issued", "Issued access/refresh tokens", client=client, user=user)
                return _json_response(response, headers=_cors_headers(origin, client))

            if grant_type == "refresh_token":
                refresh_token_value = params.get("refresh_token")
                access, new_refresh = token_model.rotate_refresh_token(
                    refresh_token_value, client
                )
                if not access:
                    return _json_response({"error": "invalid_grant"}, status=400, headers=_cors_headers(origin, client))
                access_token_value = access.token_value
                refresh_token_value = new_refresh.token_value if new_refresh else None
                if not access_token_value or (new_refresh and not refresh_token_value):
                    raise ValueError("Raw token value unavailable after rotation")
                scope_names = access.scope_ids.mapped("name")
                response = {
                    "access_token": access_token_value,
                    "token_type": "bearer",
                    "expires_in": _expires_in(access),
                    "scope": " ".join(scope_names),
                }
                if new_refresh:
                    response["refresh_token"] = refresh_token_value
                # Per OIDC Core §12.2, return a fresh id_token when openid scope is present
                if "openid" in scope_names:
                    id_token, id_token_error = self._build_id_token(
                        client,
                        access.user_id.sudo(),
                        scope_names,
                        access_token=access_token_value,
                    )
                    if id_token:
                        response["id_token"] = id_token
                    elif id_token_error:
                        response["id_token_error"] = id_token_error
                _log_event("token_rotated", "Rotated refresh token", client=client, user=access.user_id)
                return _json_response(response, headers=_cors_headers(origin, client))

            return _json_response({"error": "unsupported_grant_type"}, status=400, headers=_cors_headers(origin, client))
        except Exception:
            _logger.exception("Unhandled error in /oauth/token")
            return _json_response({"error": "server_error"}, status=500, headers=_cors_headers(origin))

    @http.route(
        "/oauth/revoke",
        auth="public",
        type="http",
        csrf=False,
        methods=["POST", "OPTIONS"],
    )
    def revoke(self, **params):
        https_guard = _require_https()
        if https_guard:
            return https_guard
        origin = request.httprequest.headers.get("Origin")
        if request.httprequest.method == "OPTIONS":
            return http.Response(status=204, headers=_cors_headers(origin))
        try:
            rl_guard = _rate_limit("revoke")
            if rl_guard:
                return rl_guard

            client = self._authenticate_client(params)
            if not client:
                return _json_response({"error": "invalid_client"}, status=401, headers=_cors_headers(origin))
            token_value = params.get("token")
            if not token_value:
                return _json_response({"error": "invalid_request"}, status=400, headers=_cors_headers(origin, client))
            token_model = request.env["auth_oidc.token"].sudo()
            hashed = token_model._hash_token(token_value)
            token = token_model.search([("token", "=", hashed)], limit=1)
            if token and token.client_id == client:
                token.unlink()
                _log_event("token_revoked", "Token revoked", client=client, user=token.user_id)
            else:
                _log_event("token_revoke_failed", "No token revoked", client=client, user=None)
            return _json_response({}, headers=_cors_headers(origin, client))
        except Exception:
            _logger.exception("Unhandled error in /oauth/revoke")
            return _json_response({"error": "server_error"}, status=500, headers=_cors_headers(origin))

    @http.route(
        "/oauth/introspect",
        auth="public",
        type="http",
        csrf=False,
        methods=["POST", "OPTIONS"],
    )
    def introspect(self, **params):
        https_guard = _require_https()
        if https_guard:
            return https_guard
        origin = request.httprequest.headers.get("Origin")
        if request.httprequest.method == "OPTIONS":
            return http.Response(status=204, headers=_cors_headers(origin))
        try:
            rl_guard = _rate_limit("introspect")
            if rl_guard:
                return rl_guard

            client = self._authenticate_client(params)
            if not client:
                return _json_response({"error": "invalid_client"}, status=401, headers=_cors_headers(origin))
            token_value = params.get("token")
            if not token_value:
                return _json_response({"error": "invalid_request"}, status=400, headers=_cors_headers(origin, client))
            token_model = request.env["auth_oidc.token"].sudo()
            hashed = token_model._hash_token(token_value)
            token = token_model.search([("token", "=", hashed)], limit=1)
            if not token or token.client_id != client:
                _log_event("token_introspection_failed", "Inactive or foreign token", client=client, user=None)
                return _json_response({"active": False}, headers=_cors_headers(origin, client))
            active = token.expires_at and fields.Datetime.to_datetime(
                token.expires_at
            ) > datetime.utcnow()
            if not active:
                _log_event("token_introspection_failed", "Expired token", client=client, user=token.user_id)
                return _json_response({"active": False}, headers=_cors_headers(origin, client))
            payload = {
                "active": True,
                "client_id": token.client_id.client_id,
                "token_type": token.token_type,
                "exp": _utc_epoch(fields.Datetime.to_datetime(token.expires_at)),
                "sub": str(token.user_id.id),
                "scope": " ".join(token.scope_ids.mapped("name")),
            }
            _log_event("token_introspected", "Token introspection", client=client, user=token.user_id)
            return _json_response(payload, headers=_cors_headers(origin, client))
        except Exception:
            _logger.exception("Unhandled error in /oauth/introspect")
            return _json_response({"error": "server_error"}, status=500, headers=_cors_headers(origin))

    @http.route(
        "/oauth/userinfo",
        auth="public",
        type="http",
        csrf=False,
        methods=["GET", "OPTIONS"],
    )
    def userinfo(self, **kwargs):
        https_guard = _require_https()
        if https_guard:
            return https_guard
        origin = request.httprequest.headers.get("Origin")
        if request.httprequest.method == "OPTIONS":
            return http.Response(status=204, headers=_cors_headers(origin))
        try:
            rl_guard = _rate_limit("userinfo")
            if rl_guard:
                return rl_guard

            auth_header = request.httprequest.headers.get("Authorization", "")
            if not auth_header.lower().startswith("bearer "):
                return _json_response({"error": "invalid_token"}, status=401, headers=_cors_headers(origin))

            token_value = auth_header.split(" ", 1)[1]
            token = request.env["auth_oidc.token"].sudo().validate_access_token(token_value)
            if not token:
                _log_event("userinfo_failed", "Invalid access token", client=None, user=None)
                return _json_response({"error": "invalid_token"}, status=401, headers=_cors_headers(origin))

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
            partner = user.partner_id
            commercial_partner = partner.commercial_partner_id if partner else False
            payload["user_type"] = _user_type(user)
            if "org" in scopes:
                if commercial_partner:
                    payload["company_id"] = commercial_partner.id
                    payload["company_name"] = commercial_partner.name
                    if commercial_partner.vat:
                        payload["company_vat"] = commercial_partner.vat
                    if commercial_partner.company_registry:
                        payload["company_registry"] = commercial_partner.company_registry
                    if commercial_partner.country_id:
                        payload["company_country"] = commercial_partner.country_id.code or commercial_partner.country_id.name
                    if commercial_partner.city:
                        payload["company_city"] = commercial_partner.city
                    if commercial_partner.zip:
                        payload["company_zip"] = commercial_partner.zip
                    if commercial_partner.street:
                        payload["company_street"] = commercial_partner.street
                    if commercial_partner.street2:
                        payload["company_street2"] = commercial_partner.street2
                    if commercial_partner.phone:
                        payload["company_phone"] = commercial_partner.phone
                if partner:
                    payload["partner_id"] = partner.id
                    if partner.ref:
                        payload["partner_ref"] = partner.ref
            if "groups" in scopes:
                group_names = user.groups_id.mapped("display_name")
                if group_names:
                    payload["groups"] = group_names
            if "address" in scopes and commercial_partner:
                if commercial_partner.street:
                    payload["street"] = commercial_partner.street
                if commercial_partner.street2:
                    payload["street2"] = commercial_partner.street2
                if commercial_partner.city:
                    payload["city"] = commercial_partner.city
                if commercial_partner.zip:
                    payload["zip"] = commercial_partner.zip
                if commercial_partner.state_id:
                    payload["state"] = commercial_partner.state_id.code or commercial_partner.state_id.name
                if commercial_partner.country_id:
                    payload["country"] = commercial_partner.country_id.code or commercial_partner.country_id.name
            if "phone" in scopes:
                if commercial_partner and commercial_partner.phone:
                    payload["phone"] = commercial_partner.phone
                elif user.phone:
                    payload["phone"] = user.phone
                if commercial_partner and commercial_partner.mobile:
                    payload["mobile"] = commercial_partner.mobile
                elif user.mobile:
                    payload["mobile"] = user.mobile
            if "preferences" in scopes:
                if user.lang:
                    payload["lang"] = user.lang
                if user.tz:
                    payload["tz"] = user.tz

            _log_event("userinfo", "Userinfo fetched", client=token.client_id, user=user)
            return _json_response(payload, headers=_cors_headers(origin, token.client_id))
        except Exception:
            _logger.exception("Unhandled error in /oauth/userinfo")
            return _json_response({"error": "server_error"}, status=500, headers=_cors_headers(origin))

    @http.route(
        "/oauth/end_session",
        auth="public",
        type="http",
        csrf=False,  # RPs legitimately GET/POST here cross-site; the local
        # confirmation form is CSRF-checked manually below.
        methods=["GET", "POST"],
    )
    def end_session(self, **params):
        https_guard = _require_https()
        if https_guard:
            return https_guard
        rl_guard = _rate_limit("end_session")
        if rl_guard:
            return rl_guard

        id_token_hint = params.get("id_token_hint")
        post_logout = params.get("post_logout_redirect_uri")
        state = params.get("state")
        client_id_param = params.get("client_id")

        hint_claims = _verify_id_token_hint(id_token_hint) if id_token_hint else None
        hint_client_id = None
        if hint_claims:
            aud = hint_claims.get("aud")
            if isinstance(aud, list):
                hint_client_id = aud[0] if aud else None
            elif isinstance(aud, str):
                hint_client_id = aud
        if client_id_param and hint_client_id and client_id_param != hint_client_id:
            return _json_response(
                {"error": "invalid_request",
                 "error_description": "client_id does not match id_token_hint audience"},
                status=400,
            )

        client = None
        lookup_id = hint_client_id or client_id_param
        if lookup_id:
            client = request.env["auth_oidc.client"].sudo().get_by_client_id(lookup_id)

        # Only exact matches against the client's registered post-logout URIs
        # are followed; anything else falls back to the JSON confirmation.
        redirect_target = None
        if post_logout and client and client.validate_post_logout_uri(post_logout):
            redirect_target = post_logout

        # A verified id_token_hint proves the request comes from an RP we
        # issued a token to; without it, ask the user before ending the
        # session (OIDC RP-Initiated Logout 1.0 §6).
        if request.session.uid and not hint_claims:
            decision = params.get("decision")
            csrf_ok = request.validate_csrf(params.get("csrf_token") or "")
            if request.httprequest.method == "POST" and decision == "cancel" and csrf_ok:
                return request.redirect("/", local=True)
            if not (request.httprequest.method == "POST" and decision == "confirm" and csrf_ok):
                safe_params = {
                    k: params[k]
                    for k in ("post_logout_redirect_uri", "client_id", "id_token_hint", "state")
                    if params.get(k)
                }
                return request.render(
                    "odoo_oidc_provider.logout_confirm_page",
                    {"client": client, "params": safe_params},
                )

        if request.session.uid:
            _log_event("session_ended", "Session ended via end_session", client=client, user=request.env.user)
            request.session.logout()

        if redirect_target:
            if state:
                parsed = urlparse(redirect_target)
                query = dict(parse_qsl(parsed.query))
                query["state"] = state
                redirect_target = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(query), parsed.fragment,
                ))
            return request.redirect(redirect_target, local=False)
        return _json_response({"message": "Session ended"})
