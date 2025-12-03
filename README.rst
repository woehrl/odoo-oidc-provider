Odoo OIDC Provider
==================

Odoo module that turns Odoo into an OpenID Connect / OAuth2 Identity Provider.
Target versions: Odoo 18/19 (Community and Enterprise). Status: **experimental**.

Installation
------------

- Place this repository in the Odoo ``addons_path`` (or pass via ``--addons-path``).
- Install ``requirements.txt`` (PyJWT is needed for ID Tokens).
- Restart Odoo and update the apps list.
- Install the **Odoo OIDC Provider** module.

odoo.sh notes
-------------

- Add this repo as a custom addon in odoo.sh and enable ``requirements.txt`` (PyJWT).
- After deployment, log in to the instance and complete the configuration below.

Configuration (post-install)
----------------------------

1. Create a signing key at **Settings > Technical > Auth OIDC Keys**:

   - Prefer RSA (RS256). Public JWK must be provided manually for RSA; HS (oct) auto-generates a public JWK.
   - Distribute only the public key; keep the private key in Odoo (System group).

2. Review/extend scopes under **Auth OIDC Scopes** (openid/profile/email are seeded).

3. Register a client under **Auth OIDC Clients**:

   - Set ``client_id``/``client_secret`` (public clients: set ``is_confidential`` to False and leave the secret blank).
   - Enter redirect URIs exactly (one per line) and define allowed scopes.

4. Security/hardening (system parameters):

   - ``odoo_oidc.require_https`` (default True): enforce HTTPS for all endpoints.
   - ``odoo_oidc.pkce_require_s256`` (default True): forbid PKCE ``plain``.

5. Cron jobs: expired tokens and codes are cleaned up every 30 minutes (see ``data/cron.xml``).

Endpoints
---------

- Discovery: ``/.well-known/openid-configuration``
- JWKS: ``/.well-known/jwks.json``
- Authorize: ``/oauth/authorize`` (Authorization Code + PKCE)
- Token: ``/oauth/token`` (authorization_code, refresh_token)
- Userinfo: ``/oauth/userinfo``
- Revocation: ``/oauth/revoke``
- Introspection: ``/oauth/introspect``

Example: React/TypeScript app
-----------------------------

Assume the app runs at ``https://example-app.test`` and uses the redirect URI
``https://example-app.test/auth/callback``.

1. Create an OIDC client in Odoo:

   - ``client_id``: ``pd-web``
   - ``client_secret``: leave empty for a public client with PKCE
   - Redirect URI: ``https://example-app.test/auth/callback``
   - Allowed Scopes: ``openid``, ``profile``, ``email``

2. In React/TypeScript (example with ``openid-client``): ::

      const issuer = await Issuer.discover('https://<your-odoo-host>/.well-known/openid-configuration');
      const client = new issuer.Client({
        client_id: 'pd-web',
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

Token exchange in the callback: ::

      const params = client.callbackParams(requestUrl);
      const tokenSet = await client.callback('https://example-app.test/auth/callback', params, {
        code_verifier: codeVerifier,
      });
      // tokenSet.id_token (JWT), tokenSet.access_token etc.

Fetching userinfo: ::

      const userinfo = await client.userinfo(tokenSet.access_token as string);

3. If React app runs without ``openid-client``:

   - Step 1: Redirect the user to ``/oauth/authorize?...&code_challenge=<S256>&code_challenge_method=S256``.
   - Step 2: In the callback, POST the ``code`` to ``/oauth/token`` with ``grant_type=authorization_code``, ``code_verifier``, ``redirect_uri``.
   - Step 3: Use the access token for ``/oauth/userinfo``.
