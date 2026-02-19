Odoo OIDC Provider
==================

Odoo module that turns Odoo into an OpenID Connect / OAuth2 Identity Provider.
Target versions: Odoo 18+ (Community and Enterprise). Status: experimental.

Installation
------------
- Place this repository in the Odoo addons_path (or pass via --addons-path).
- Install requirements.txt (PyJWT for ID Tokens, cryptography for RSA generation).
- Restart Odoo and update the apps list.
- Install the Odoo OIDC Provider module.

odoo.sh notes
--------------
- Add this repo as a custom addon in odoo.sh and enable requirements.txt.
- After deployment, log in to the instance and complete the configuration below.

Configuration (post-install)
----------------------------
1. Create a signing key at Settings > Technical > Auth OIDC Keys:
   - Use the built-in buttons to generate RSA (recommended) or HS keys; the public JWK is filled automatically.
   - Distribute only the public key/JWK; keep the private key in Odoo (System group).
2. Review/extend scopes under Auth OIDC Scopes (openid/profile/email are seeded).
3. Register a client under Auth OIDC Clients:
   - Set client_id/client_secret (public clients: set is_confidential to False and leave the secret blank).
   - Enter redirect URIs exactly (one per line) and define allowed scopes.
4. Security/hardening (system parameters):
   - odoo_oidc.require_https (default True): enforce HTTPS for all endpoints.
   - odoo_oidc.pkce_require_s256 (default True): forbid PKCE plain.
   - odoo_oidc.rate_limit.<bucket>.limit / .window: per-endpoint abuse protection (authorize/token/userinfo/introspect/revoke).
   - odoo_oidc.allow_all_scopes_when_unset (default False): keep default-deny when a client has no allowed scopes set.
5. Cron jobs: expired tokens and codes are cleaned up every 30 minutes (see data/cron.xml).

Scopes and Claims
-----------------
- Supported scopes and their claims are documented in `docs/scopes.md`.
- Scope requests are filtered to each client’s Allowed Scopes. If a client has
  no Allowed Scopes configured, requests are denied unless
  `odoo_oidc.allow_all_scopes_when_unset` is explicitly enabled.

Hardened rollout checklist
--------------------------
- Enforce HTTPS, HSTS, and secure cookies on the reverse proxy; keep `odoo_oidc.require_https` True.
- Configure allowed scopes per client (default-deny if unset); avoid wildcard redirect URIs.
- Generate RSA signing keys and plan rotation; keep private keys restricted to the System group.
- Keep PKCE with S256 required; public clients must not send secrets.
- Rate-limit public endpoints (system params above) and monitor `auth_oidc.event` for anomalies.
- Tokens are hashed at rest; still limit database access and add IP/device binding if required.
- Ensure `PyJWT` and `cryptography` are available (declared in requirements.txt / external_dependencies).

Admin Dashboard
---------------
- Go to Settings > OIDC Provider > Dashboard for an overview (counts for clients/keys/scopes/events) and a link to the GitHub project page.
- The dashboard lists the first steps to configure keys, scopes, and clients.

Endpoints
---------
- Discovery: /.well-known/openid-configuration (RFC 8414 / OIDC Discovery)
- JWKS: /.well-known/jwks.json
- Authorize: /oauth/authorize (Authorization Code + PKCE)
- Token: /oauth/token (authorization_code, refresh_token)
- Userinfo: /oauth/userinfo
- Revocation: /oauth/revoke (RFC 7009)
- Introspection: /oauth/introspect (RFC 7662)
- End Session: /oauth/end_session

CORS
----
CORS is handled natively by this addon — no changes to odoo.conf are needed.

- ``/.well-known/openid-configuration`` and ``/.well-known/jwks.json`` respond
  with ``Access-Control-Allow-Origin: *`` so any browser-based OIDC client can
  fetch the discovery document and validate ID Token signatures.
- ``/oauth/token``, ``/oauth/userinfo``, ``/oauth/introspect``, and
  ``/oauth/revoke`` use origin-based CORS: only origins that match a registered
  client's redirect URI domain are permitted. ``Access-Control-Allow-Credentials: true``
  is set so Bearer tokens can be sent.
- All CORS-enabled endpoints handle OPTIONS preflight requests.

Example: React/TypeScript app
-----------------------------
Assume the app runs at https://example-app.test and uses the redirect URI https://example-app.test/auth/callback.

1. Create an OIDC client in Odoo:
   - client_id: example-web
   - client_secret: leave empty for a public client with PKCE
   - Redirect URI: https://example-app.test/auth/callback
   - Allowed Scopes: openid, profile, email

2. In React/TypeScript (example with openid-client)::

      const issuer = await Issuer.discover('https://<your-odoo-host>/.well-known/openid-configuration');
      const client = new issuer.Client({
        client_id: 'example-web',
        token_endpoint_auth_method: 'none',
      });
      const codeVerifier = generators.codeVerifier();
      const codeChallenge = generators.codeChallenge(codeVerifier);
      const authUrl = client.authorizationUrl({
        redirect_uri: 'https://example-app.test/auth/callback',
        scope: 'openid profile email',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        response_type: 'code',
      });
      // Redirect user to authUrl

   Token exchange in the callback::

      const params = client.callbackParams(requestUrl);
      const tokenSet = await client.callback('https://example-app.test/auth/callback', params, {
        code_verifier: codeVerifier,
      });
      // tokenSet.id_token (JWT), tokenSet.access_token etc.

   Fetching userinfo::

      const userinfo = await client.userinfo(tokenSet.access_token as string);

3. If React app runs without openid-client:
   - Redirect the user to /oauth/authorize?...&code_challenge=<S256>&code_challenge_method=S256.
   - In the callback, POST the code to /oauth/token with grant_type=authorization_code, code_verifier, redirect_uri.
   - Use the access token for /oauth/userinfo.
