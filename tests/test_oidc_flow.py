import base64
import hashlib
from urllib.parse import urlparse, parse_qs

from odoo.tests import SavepointCase
from odoo.tests.common import HttpCase, tagged


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
        access, new_refresh = token_model.rotate_refresh_token(rt.token)
        self.assertFalse(access)
        self.assertFalse(new_refresh)


@tagged("post_install", "-at_install")
class TestOidcHttpFlows(HttpCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env["ir.config_parameter"].sudo().set_param("odoo_oidc.require_https", False)
        cls.client = cls.env["auth_oidc.client"].create(
            {
                "name": "HTTP Client",
                "client_id": "http-client",
                "client_secret": "secret",
                "redirect_uris": "https://oidcdebugger.com/debug\nhttps://openidconnect.net/callback",
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
        cls.verifier = "verifier123"
        digest = hashlib.sha256(cls.verifier.encode()).digest()
        cls.challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    def test_nonce_required_for_openid(self):
        """OIDC Core 3.1.2.1 requires nonce on authorization requests when requesting openid."""
        query = {
            "response_type": "code",
            "client_id": self.client.client_id,
            "redirect_uri": "https://oidcdebugger.com/debug",
            "scope": "openid",
            "state": "abc",
            "code_challenge": self.challenge,
            "code_challenge_method": "S256",
        }
        resp = self.url_open("/oauth/authorize", data=query, allow_redirects=False, timeout=10)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("nonce required", resp.text)

    def test_redirect_uri_external_and_trimmed(self):
        """Ensure external redirect URIs are honored exactly (trim whitespace, keep host)."""
        query = {
            "response_type": "code",
            "client_id": self.client.client_id,
            "redirect_uri": " https://oidcdebugger.com/debug ",  # intentional spaces
            "scope": "openid",
            "state": "state123",
            "nonce": "n1",
            "code_challenge": self.challenge,
            "code_challenge_method": "S256",
        }
        resp = self.url_open("/oauth/authorize", data=query, allow_redirects=False, timeout=10)
        self.assertEqual(resp.status_code, 302)
        parsed = urlparse(resp.headers["Location"])
        self.assertEqual(f"{parsed.scheme}://{parsed.netloc}", "https://oidcdebugger.com")
        self.assertEqual(parsed.path, "/debug")
        returned = parse_qs(parsed.query)
        self.assertEqual(returned.get("state"), ["state123"])
        self.assertIn("code", returned)
