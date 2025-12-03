import base64
import hashlib

from odoo.tests import SavepointCase


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
