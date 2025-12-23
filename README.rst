Odoo OIDC Provider
==================

Odoo module that turns Odoo into an OpenID Connect / OAuth2 Identity Provider.
Target versions: Odoo 18+ (Community and Enterprise). Status: experimental.

Installation
------------

Self-Hosted Installation
~~~~~~~~~~~~~~~~~~~~~~~~
1. Clone or download this repository into your Odoo addons path::

    cd /path/to/odoo/addons
    git clone <repository-url> odoo_oidc_provider

2. Install Python dependencies::

    pip install -r odoo_oidc_provider/requirements.txt

   Required packages: PyJWT (for ID Tokens), cryptography (for RSA key generation).

3. Restart Odoo and update the apps list::

    odoo-bin -u all --stop-after-init

4. Navigate to Apps, search for "OIDC Provider", and click Install.

Odoo.sh Installation (Git Submodule Method)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1. Add this repository as a Git submodule to your odoo.sh project::

    git submodule add <repository-url> odoo_oidc_provider
    git submodule update --init --recursive

2. Add the submodule path to your .gitmodules file if not automatically added.

3. Ensure requirements.txt is in the root of your repository or merge with existing requirements.txt::

    PyJWT>=2.8.0
    cryptography>=41.0.0

4. Commit and push to odoo.sh::

    git add .
    git commit -m "Add OIDC Provider module as submodule"
    git push odoo <your-branch>

5. After deployment completes, log in to your odoo.sh instance.

6. Navigate to Apps > Update Apps List, then search for "OIDC Provider" and install.

Odoo.sh Installation (Custom Addon Method)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1. Upload this repository as a custom addon in the odoo.sh dashboard.

2. Ensure requirements.txt is enabled in your odoo.sh project settings.

3. After deployment, navigate to Apps and install "OIDC Provider".

Enterprise Edition Notes
~~~~~~~~~~~~~~~~~~~~~~~~~
- This module is compatible with both Odoo Community and Enterprise editions.
- If using Odoo Enterprise on odoo.sh, the mail_mobile module may cause field conflicts.
- See "Known Issues" section below for the developer mode workaround.

Configuration (post-install)
----------------------------

Settings Menu
~~~~~~~~~~~~~
Navigate to **Settings > OIDC Provider > Settings** to configure security options:

- **Require HTTPS for OIDC endpoints** (default: enabled)
  Enforce HTTPS for all OpenID Connect endpoints (recommended by OIDC Core 1.0).

- **Require PKCE for public clients** (default: enabled)
  Enforce PKCE (RFC 7636) for public (non-confidential) clients during authorization code flow.

- **Require PKCE S256** (default: enabled)
  Disallow PKCE plain challenges; require S256 as recommended by RFC 7636.

- **Require nonce for OIDC** (default: enabled)
  Require the nonce parameter on OpenID Connect (openid) authorization requests to prevent replay (OIDC Core 3.1.2.1).

- **Allow external redirect URIs** (default: enabled)
  Allow redirects to registered external callback hosts (per OIDC Core 3.1.2.5). If disabled, redirects are restricted to the local host.

**Note**: On fresh installation, all security settings default to enabled (checked). You can customize these based on your requirements.

Initial Setup Steps
~~~~~~~~~~~~~~~~~~~
1. **Configure Security Settings**:
   Navigate to Settings > OIDC Provider > Settings and review the security options above.

2. **Create a signing key** at Settings > Technical > Auth OIDC Keys:
   - Use the built-in buttons to generate RSA (recommended) or HS keys; the public JWK is filled automatically.
   - Distribute only the public key/JWK; keep the private key in Odoo (System group).

3. **Review/extend scopes** under Auth OIDC Scopes (openid/profile/email are seeded).

4. **Register a client** under Auth OIDC Clients:
   - Set client_id/client_secret (public clients: set is_confidential to False and leave the secret blank).
   - Enter redirect URIs exactly (one per line) and define allowed scopes.

5. **Cron jobs**: Expired tokens and codes are cleaned up every 30 minutes (see data/cron.xml).

Admin Dashboard
---------------
- Go to Settings > OIDC Provider > Dashboard for an overview (counts for clients/keys/scopes/events) and a link to the GitHub project page.
- The dashboard lists the first steps to configure keys, scopes, and clients.

Endpoints
---------
- Discovery: /.well-known/openid-configuration
- JWKS: /.well-known/jwks.json
- Authorize: /oauth/authorize (Authorization Code + PKCE)
- Token: /oauth/token (authorization_code, refresh_token)
- Userinfo: /oauth/userinfo
- Revocation: /oauth/revoke
- Introspection: /oauth/introspect

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

Known Issues
------------

Developer Mode + Enterprise Edition (mail_mobile conflict)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
**Issue**: When using Odoo Enterprise Edition with developer mode enabled, you may encounter an error about the ``enable_ocn`` field being undefined in ``res.config.settings``.

**Cause**: The ``enable_ocn`` field belongs to the Enterprise ``mail_mobile`` module (Odoo Cloud Notification for push notifications). When this module references fields in the settings view but isn't properly installed or configured, Odoo's developer mode performs stricter field validation and throws this error.

**Solutions**:

1. **Install mail_mobile module** (Recommended for Enterprise users):
   - Navigate to Apps and search for "Mobile"
   - Install the "Mobile" or "Push Notifications" module
   - This resolves the field conflict permanently

2. **Disable developer mode** (Temporary workaround):
   - The error only appears in developer mode
   - Normal operation is not affected
   - Settings will work correctly without developer mode enabled

3. **For odoo.sh users**:
   - The mail_mobile module should be available by default in Enterprise installations
   - If the error persists, ensure your Enterprise license is active and properly configured

**Note**: This issue is not caused by the OIDC Provider module. It's a field reference conflict in the shared ``res.config.settings`` form that becomes visible when developer mode performs enhanced validation.

Uninstallation
--------------
The module includes an uninstall hook that automatically cleans up all OIDC-related configuration parameters when uninstalled:

- ``odoo_oidc.require_https``
- ``odoo_oidc.require_pkce_public``
- ``odoo_oidc.pkce_require_s256``
- ``odoo_oidc.require_nonce``
- ``odoo_oidc.allow_external_redirects``

Database records (clients, keys, tokens, scopes, consents) are managed by Odoo's standard uninstall process.
