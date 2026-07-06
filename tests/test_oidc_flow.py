import base64
import hashlib
from urllib.parse import parse_qs, urlparse

from odoo.tests import HttpCase, TransactionCase, tagged

# RFC 7636 requires 43-128 chars from the unreserved set.
VALID_VERIFIER = "a-valid_verifier.with~43-chars-minimum-okay"


def _challenge_s256(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


class TestOidcPkce(TransactionCase):
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
        cls.scope = cls.env["auth_oidc.scope"].search([("name", "=", "openid")], limit=1)
        if not cls.scope:
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

    def _create_code(self, verifier=VALID_VERIFIER):
        return self.env["auth_oidc.authorization_code"].create_code(
            client=self.client,
            user=self.env.ref("base.user_admin"),
            redirect_uri="https://app.local/callback",
            scope="openid",
            code_challenge=_challenge_s256(verifier),
            code_challenge_method="S256",
        )

    def test_authorization_code_pkce(self):
        code = self._create_code()
        self.assertTrue(code.consume(VALID_VERIFIER))
        self.assertFalse(code.consume(VALID_VERIFIER))

    def test_code_stored_hashed(self):
        code = self._create_code()
        raw = code.code_value
        self.assertTrue(raw)
        self.assertNotEqual(code.code, raw)
        found = self.env["auth_oidc.authorization_code"].find_by_code(raw)
        self.assertEqual(found.id, code.id)

    def test_pkce_verifier_format_enforced(self):
        # RFC 7636: verifiers shorter than 43 chars must be rejected.
        short_verifier = "tooshort123"
        code = self._create_code(verifier=short_verifier)
        self.assertFalse(code.consume(short_verifier))

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

    def test_replay_revokes_tokens_issued_from_code(self):
        token_model = self.env["auth_oidc.token"]
        code = self._create_code()
        self.assertTrue(code.consume(VALID_VERIFIER))
        access = token_model.create_access_token(
            self.client, self.env.ref("base.user_admin"), self.scope, auth_code=code
        )
        raw_access = access.token_value
        self.assertTrue(token_model.validate_access_token(raw_access))
        revoked = token_model.revoke_for_auth_code(code)
        self.assertEqual(revoked, 1)
        self.assertFalse(token_model.validate_access_token(raw_access))


class TestClientSecret(TransactionCase):
    def test_secret_hashed_on_generate(self):
        client = self.env["auth_oidc.client"].create(
            {
                "name": "Confidential",
                "client_id": "conf-client",
                "redirect_uris": "https://app.local/callback",
                "is_confidential": True,
            }
        )
        # Auto-generated secret must already be stored hashed.
        self.assertTrue(client.client_secret.startswith("sha256$"))
        action = client.action_generate_secret()
        raw = action["params"]["message"].rsplit(" ", 1)[-1]
        self.assertTrue(client.client_secret.startswith("sha256$"))
        self.assertNotIn(raw, client.client_secret)
        self.assertTrue(client.verify_secret(raw))
        self.assertFalse(client.verify_secret("wrong-secret"))

    def test_legacy_plaintext_secret_upgraded_on_use(self):
        client = self.env["auth_oidc.client"].create(
            {
                "name": "Legacy",
                "client_id": "legacy-client",
                "client_secret": "plain-legacy-secret",
                "redirect_uris": "https://app.local/callback",
                "is_confidential": True,
            }
        )
        self.assertEqual(client.client_secret, "plain-legacy-secret")
        self.assertTrue(client.verify_secret("plain-legacy-secret"))
        # First successful verification migrates the stored value to a hash.
        self.assertTrue(client.client_secret.startswith("sha256$"))
        self.assertTrue(client.verify_secret("plain-legacy-secret"))
        self.assertFalse(client.verify_secret("wrong"))

    def test_public_spa_forces_non_confidential(self):
        # Creating a SPA client must not leave is_confidential True (which the
        # constraint would reject).
        client = self.env["auth_oidc.client"].create(
            {
                "name": "SPA",
                "client_id": "spa-client",
                "redirect_uris": "https://app.local/callback",
                "allow_public_spa": True,
                "is_confidential": True,
            }
        )
        self.assertFalse(client.is_confidential)
        self.assertFalse(client.client_secret)
        # Switching an existing confidential client to SPA also clears the flag.
        conf = self.env["auth_oidc.client"].create(
            {
                "name": "Conf",
                "client_id": "conf-to-spa",
                "redirect_uris": "https://app.local/callback",
                "is_confidential": True,
            }
        )
        self.assertTrue(conf.is_confidential)
        conf.write({"allow_public_spa": True})
        self.assertFalse(conf.is_confidential)

    def test_post_logout_uri_exact_match(self):
        client = self.env["auth_oidc.client"].create(
            {
                "name": "Logout Client",
                "client_id": "logout-client",
                "redirect_uris": "https://app.local/callback",
                "post_logout_redirect_uris": "https://app.local/logged-out",
                "is_confidential": False,
            }
        )
        self.assertTrue(client.validate_post_logout_uri("https://app.local/logged-out"))
        self.assertFalse(client.validate_post_logout_uri("https://app.local/other"))
        self.assertFalse(client.validate_post_logout_uri("https://evil.example/logged-out"))
        self.assertFalse(client.validate_post_logout_uri(None))


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
        # RSA signing key for ID tokens
        key = cls.env["auth_oidc.key"].create({"name": "Test RSA"})
        key.action_generate_rsa_key()

    def _authorize_and_get_code(self, verifier=VALID_VERIFIER, scope="openid%20email"):
        challenge = _challenge_s256(verifier)
        authorize_url = (
            "/oauth/authorize?"
            "response_type=code&client_id=http-client&redirect_uri=https%3A%2F%2Fapp.local%2Fcallback"
            f"&scope={scope}&code_challenge={challenge}&code_challenge_method=S256&state=abc&nonce=xyz"
        )
        response = self.url_open(authorize_url, allow_redirects=False)
        self.assertEqual(response.status_code, 303)
        params = parse_qs(urlparse(response.headers["Location"]).query)
        return params

    def test_authorize_token_flow_and_introspection_scope(self):
        self.authenticate("admin", "admin")
        params = self._authorize_and_get_code()
        self.assertIn("code", params)
        code = params["code"][0]

        token_response = self.url_open(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.local/callback",
                "code_verifier": VALID_VERIFIER,
                "client_id": "http-client",
            },
            allow_redirects=False,
        )
        payload = token_response.json()
        self.assertIn("access_token", payload)
        self.assertIn("refresh_token", payload)
        self.assertIn("id_token", payload)
        self.assertEqual(payload["token_type"], "bearer")
        self.assertEqual(set(payload["scope"].split()), {"openid", "email"})
        self.assertLessEqual(payload["expires_in"], 3600)

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

        # Replaying the same code is rejected and revokes the issued tokens
        replay_response = self.url_open(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.local/callback",
                "code_verifier": VALID_VERIFIER,
                "client_id": "http-client",
            },
            allow_redirects=False,
        )
        self.assertEqual(replay_response.status_code, 400)
        self.assertEqual(replay_response.json()["error"], "invalid_grant")
        introspect_after = self.url_open(
            "/oauth/introspect",
            data={"token": payload["access_token"], "client_id": "http-client"},
            headers={"Authorization": f"Basic {basic}"},
            allow_redirects=False,
        )
        self.assertFalse(introspect_after.json()["active"])

        # Different client cannot introspect
        self.env["auth_oidc.client"].create(
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

    def test_disallowed_scope_returns_invalid_scope(self):
        self.authenticate("admin", "admin")
        params = self._authorize_and_get_code(scope="profile")
        self.assertNotIn("code", params)
        self.assertEqual(params["error"][0], "invalid_scope")

    def test_end_session_does_not_open_redirect(self):
        # Unauthenticated request with an unregistered redirect target must
        # not be followed.
        response = self.url_open(
            "/oauth/end_session?post_logout_redirect_uri=https%3A%2F%2Fevil.example%2Fphish",
            allow_redirects=False,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["message"], "Session ended")

    def test_end_session_asks_for_confirmation(self):
        self.authenticate("admin", "admin")
        response = self.url_open("/oauth/end_session", allow_redirects=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Sign out", response.text)
        # The GET alone must not have ended the session.
        check = self.url_open("/oauth/end_session", allow_redirects=False)
        self.assertIn("Sign out", check.text)

    def test_cors_exact_origin_only(self):
        registered_origin = "https://app.local"
        response = self.url_open(
            "/oauth/token",
            data={"grant_type": "unsupported"},
            headers={"Origin": registered_origin},
            allow_redirects=False,
        )
        self.assertEqual(
            response.headers.get("Access-Control-Allow-Origin"), registered_origin
        )
        self.assertFalse(response.headers.get("Access-Control-Allow-Credentials"))
        # Subdomains of a registered origin are no longer allowed.
        response = self.url_open(
            "/oauth/token",
            data={"grant_type": "unsupported"},
            headers={"Origin": "https://sub.app.local"},
            allow_redirects=False,
        )
        self.assertFalse(response.headers.get("Access-Control-Allow-Origin"))
