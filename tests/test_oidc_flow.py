import base64
import hashlib
from urllib.parse import parse_qs, urlparse

from odoo.tests import HttpCase, SavepointCase, tagged


class TestOidcPkce(SavepointCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.client = cls.env["auth_oidc.client"].create(
            {
                "name": "Test Client",
                "client_id": "client-pkce",
                "client_secret": "secret",
                "redirect_uris": "https://app.local/callback",
                "is_confidential": False,
            }
        )
        cls.scope = cls.env["auth_oidc.scope"].create(
            {"name": "openid", "description": "OpenID"}
        )
        cls.env["auth_oidc.consent"].create(
            {
                "user_id": cls.env.ref("base.user_admin").id,
                "client_id": cls.client.id,
                "scope_ids": [(6, 0, cls.scope.ids)],
            }
        )

    def test_authorization_code_pkce(self):
        code_model = self.env["auth_oidc.authorization_code"]
        verifier = "verifier123"
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

        code = code_model.create_code(
            client=self.client,
            user=self.env.ref("base.user_admin"),
            redirect_uri="https://app.local/callback",
            scope="openid",
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        self.assertTrue(code.consume(verifier))
        self.assertFalse(code.consume(verifier))

    def test_refresh_rotation_requires_active_client(self):
        token_model = self.env["auth_oidc.token"]
        rt = token_model.create_refresh_token(
            self.client,
            self.env.ref("base.user_admin"),
            self.scope,
        )
        self.client.write({"active": False})
        access, new_refresh = token_model.rotate_refresh_token(
            rt.token_value, self.client
        )
        self.assertFalse(access)
        self.assertFalse(new_refresh)

    def test_refresh_token_bound_to_client(self):
        token_model = self.env["auth_oidc.token"]
        rt = token_model.create_refresh_token(
            self.client, self.env.ref("base.user_admin"), self.scope
        )
        other_client = self.env["auth_oidc.client"].create(
            {
                "name": "Other",
                "client_id": "other-client",
                "client_secret": "secret2",
                "redirect_uris": "https://other.local/callback",
            }
        )
        access, new_refresh = token_model.rotate_refresh_token(rt.token_value, other_client)
        self.assertFalse(access)
        self.assertFalse(new_refresh)

    def test_access_token_validation_uses_raw_value(self):
        token_model = self.env["auth_oidc.token"]
        access = token_model.create_access_token(
            self.client, self.env.ref("base.user_admin"), self.scope
        )
        validated = token_model.validate_access_token(access.token_value)
        self.assertEqual(validated.id, access.id)


@tagged("post_install", "-at_install")
class TestOidcHttp(HttpCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env["ir.config_parameter"].sudo().set_param("odoo_oidc.require_https", "False")
        cls.env["ir.config_parameter"].sudo().set_param("odoo_oidc.pkce_require_s256", "True")
        cls.scope_openid = cls.env["auth_oidc.scope"].search([("name", "=", "openid")], limit=1)
        if not cls.scope_openid:
            cls.scope_openid = cls.env["auth_oidc.scope"].create(
                {"name": "openid", "description": "OpenID"}
            )
        cls.scope_email = cls.env["auth_oidc.scope"].search([("name", "=", "email")], limit=1)
        if not cls.scope_email:
            cls.scope_email = cls.env["auth_oidc.scope"].create(
                {"name": "email", "description": "Email"}
            )
        cls.client = cls.env["auth_oidc.client"].create(
            {
                "name": "HTTP Client",
                "client_id": "http-client",
                "redirect_uris": "https://app.local/callback",
                "is_confidential": False,
                "allowed_scopes": [(6, 0, (cls.scope_openid | cls.scope_email).ids)],
            }
        )
        cls.env["auth_oidc.consent"].create(
            {
                "user_id": cls.env.ref("base.user_admin").id,
                "client_id": cls.client.id,
                "scope_ids": [(6, 0, (cls.scope_openid | cls.scope_email).ids)],
            }
        )
        # HS key for ID Tokens
        cls.env["auth_oidc.key"].create(
            {
                "name": "Test HS",
                "alg": "HS256",
                "kty": "oct",
                "use": "sig",
                "private_key_pem": "super-secret-key",
            }
        )

    def test_authorize_token_flow_and_introspection_scope(self):
        self.authenticate("admin", "admin")
        verifier = "verifier123"
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        authorize_url = (
            "/oauth/authorize?"
            "response_type=code&client_id=http-client&redirect_uri=https%3A%2F%2Fapp.local%2Fcallback"
            f"&scope=openid%20email&code_challenge={challenge}&code_challenge_method=S256&state=abc&nonce=xyz"
        )
        response = self.url_open(authorize_url, allow_redirects=False)
        self.assertEqual(response.status_code, 303)
        location = response.headers["Location"]
        parsed = urlparse(location)
        params = parse_qs(parsed.query)
        self.assertIn("code", params)
        code = params["code"][0]

        token_response = self.url_open(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.local/callback",
                "code_verifier": verifier,
                "client_id": "http-client",
            },
            allow_redirects=False,
        )
        payload = token_response.json()
        self.assertIn("access_token", payload)
        self.assertIn("refresh_token", payload)
        self.assertEqual(payload["token_type"], "bearer")
        self.assertEqual(set(payload["scope"].split()), {"openid", "email"})

        # Introspection with the same client returns active True
        basic = base64.b64encode(b"http-client:").decode()
        introspect_response = self.url_open(
            "/oauth/introspect",
            data={"token": payload["access_token"], "client_id": "http-client"},
            headers={"Authorization": f"Basic {basic}"},
            allow_redirects=False,
        )
        body = introspect_response.json()
        self.assertTrue(body["active"])
        self.assertEqual(body["client_id"], "http-client")

        # Different client cannot introspect
        other_client = self.env["auth_oidc.client"].create(
            {
                "name": "Forbidden",
                "client_id": "forbidden-client",
                "client_secret": "forbid",
                "redirect_uris": "https://other.local/callback",
                "is_confidential": True,
            }
        )
        bad_basic = base64.b64encode(b"forbidden-client:forbid").decode()
        denied_response = self.url_open(
            "/oauth/introspect",
            data={"token": payload["access_token"], "client_id": "forbidden-client"},
            headers={"Authorization": f"Basic {bad_basic}"},
            allow_redirects=False,
        )
        self.assertFalse(denied_response.json()["active"])
