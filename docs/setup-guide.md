# Practical Setup Guide

This guide walks you through setting up the Odoo OIDC Provider module from scratch.

## Prerequisites

- Odoo 18+ installed and running
- OIDC Provider module installed (see README.rst for installation instructions)
- Admin access to your Odoo instance

## Step 1: Configure Security Settings

1. Log in to Odoo as an administrator
2. Navigate to **Settings > OIDC Provider > Settings**
3. Review the default security configuration:
   - ✓ Require HTTPS for OIDC endpoints (enabled by default)
   - ✓ Require PKCE for public clients (enabled by default)
   - ✓ Require PKCE S256 (enabled by default)
   - ✓ Require nonce for OIDC (enabled by default)
   - ✓ Allow external redirect URIs (enabled by default)

4. Click **Save** to confirm the settings

**For production environments**: Keep all security options enabled.

**For local development/testing**: You may temporarily disable "Require HTTPS" if testing on localhost without SSL.

## Step 2: Generate Signing Keys

Signing keys are used to sign ID tokens (JWTs) that clients receive.

### Creating an RSA Key (Recommended)

1. Navigate to **Settings > Technical > OIDC Provider > Auth OIDC Keys**
2. Click **Create**
3. Fill in the form:
   - **Name**: `Primary RSA Key` (or any descriptive name)
   - **Algorithm**: `RS256` (RSA with SHA-256)
   - **Key Type**: `RSA`
   - **Active**: Check this box
4. Click **Generate RSA Key** button
   - This automatically generates a 2048-bit RSA key pair
   - The **Private Key** field is filled with the PEM-encoded private key
   - The **Public JWK** field is filled with the JSON Web Key (public key in JWK format)
5. Click **Save**

### Security Notes

- **Private Key**: Keep this secret! It's stored in Odoo and should only be accessible to system administrators
- **Public JWK**: This can be safely shared with clients and is automatically exposed at `/.well-known/jwks.json`
- **Key Rotation**: Plan to rotate keys periodically (every 6-12 months). Create a new key, mark the old one inactive after a grace period

### Alternative: Creating an HS256 Key

For testing purposes only, you can use HMAC-SHA256 (symmetric key):

1. Follow steps 1-3 above
2. Set **Algorithm**: `HS256`
3. Set **Key Type**: `HS`
4. Click **Generate HS Key** button
5. Click **Save**

⚠️ **Warning**: HS256 uses a shared secret. Only use this for testing. Always use RS256 in production.

## Step 3: Configure Scopes

Scopes define what information clients can request about users.

### Default Scopes

The module comes with three pre-configured scopes:

1. **openid** - Required for OIDC. Provides the `sub` (subject/user ID) claim
2. **profile** - Provides user profile information (name, username)
3. **email** - Provides user email address

### Viewing/Editing Scopes

1. Navigate to **Settings > OIDC Provider > Dashboard**
2. Click **Auth OIDC Scopes**
3. You'll see the default scopes listed

### Adding Custom Scopes

To add a custom scope (e.g., for accessing specific API resources):

1. Click **Create**
2. Fill in the form:
   - **Name**: `read:documents` (use colon notation for API scopes)
   - **Description**: `Read access to user documents`
3. Click **Save**

**Note**: Custom scopes don't automatically add claims to ID tokens or userinfo. You'll need to customize the userinfo endpoint in code to return data for custom scopes.

## Step 4: Register OAuth Clients

Clients represent applications that will authenticate users through your Odoo instance.

### Example 1: Public Client (SPA / Mobile App)

Public clients cannot securely store secrets (e.g., JavaScript SPAs, mobile apps).

1. Navigate to **Settings > OIDC Provider > Dashboard**
2. Click **Auth OIDC Clients**
3. Click **Create**
4. Fill in the form:
   - **Client ID**: `my-react-app` (unique identifier)
   - **Client Name**: `My React Application`
   - **Confidential**: Uncheck this box (public client)
   - **Client Secret**: Leave empty (public clients don't have secrets)
   - **Redirect URIs**: Enter one URI per line:
     ```
     https://myapp.example.com/auth/callback
     http://localhost:3000/auth/callback
     ```
   - **Allowed Scopes**: Select the scopes this client can request:
     - `openid`
     - `profile`
     - `email`
5. Click **Save**

### Example 2: Confidential Client (Backend Application)

Confidential clients can securely store secrets (e.g., server-side applications).

1. Follow steps 1-3 above
2. Fill in the form:
   - **Client ID**: `my-backend-service`
   - **Client Name**: `My Backend Service`
   - **Confidential**: Check this box
   - **Client Secret**: `generate-a-secure-random-secret-here`
     - Use a strong random string (32+ characters)
     - Example: `my-secret-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6`
   - **Redirect URIs**: Enter exact callback URLs:
     ```
     https://backend.example.com/oauth/callback
     ```
   - **Allowed Scopes**: Select:
     - `openid`
     - `profile`
     - `email`
3. Click **Save**

### Important Notes on Redirect URIs

- ✓ Use **exact** URLs (no wildcards)
- ✓ Use **HTTPS** in production
- ✓ One URI per line
- ✓ Include port numbers if non-standard: `http://localhost:3000/callback`
- ✗ Do NOT use wildcards: `https://*.example.com/callback` (insecure)

## Step 5: Test the Configuration

### Access Discovery Endpoint

Open your browser and navigate to:

```
https://your-odoo-instance.com/.well-known/openid-configuration
```

You should see a JSON response with all OIDC endpoints and supported features.

### Access JWKS Endpoint

Navigate to:

```
https://your-odoo-instance.com/.well-known/jwks.json
```

You should see your public signing key(s) in JWK format.

### Test Authorization Flow

1. Construct an authorization URL:
   ```
   https://your-odoo-instance.com/oauth/authorize
     ?client_id=my-react-app
     &redirect_uri=http://localhost:3000/auth/callback
     &response_type=code
     &scope=openid profile email
     &code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
     &code_challenge_method=S256
     &nonce=random-nonce-value
   ```

2. Open this URL in your browser
3. Log in to Odoo if not already logged in
4. You should see a consent screen asking to authorize the application
5. Click **Allow**
6. You'll be redirected to your redirect_uri with an authorization code

## Step 6: Integrate with Your Application

Now that the server is configured, integrate OIDC authentication into your client applications.

See the integration guides:
- **Python**: `docs/client-python.md`
- **PHP**: `docs/client-php.md`

## Monitoring and Maintenance

### View Audit Logs

1. Navigate to **Settings > Technical > OIDC Provider > Auth OIDC Events**
2. Review logs for:
   - Authorization code issuance
   - Token issuance and rotation
   - Introspection requests
   - Revocation requests
   - Consent denials

### Monitor Active Tokens

1. Navigate to **Settings > Technical > OIDC Provider > Auth OIDC Tokens**
2. View all active access and refresh tokens
3. Manually revoke tokens if needed

### Cleanup Cron Jobs

The module automatically cleans up expired data every 30 minutes:
- Expired authorization codes
- Expired access tokens
- Expired refresh tokens

View cron jobs at **Settings > Technical > Automation > Scheduled Actions**

## Troubleshooting

### "Redirect URI mismatch" Error

- Ensure the redirect URI in your authorization request exactly matches one of the registered URIs
- Check for trailing slashes, http vs https, port numbers

### "Invalid client" Error

- Verify the client_id is correct
- For confidential clients, ensure you're sending the client_secret
- For public clients, ensure the confidential flag is unchecked

### "PKCE required" Error

- Public clients must send code_challenge and code_challenge_method
- Use S256 method (plain is disabled by default for security)

### "HTTPS required" Error

- The "Require HTTPS" setting is enabled
- Either:
  - Use HTTPS in production (recommended)
  - For local development only, temporarily disable this setting

### consent screen not appearing

- Check that the user hasn't already granted consent
- Try adding `prompt=consent` to the authorization URL to force consent
- Check consent records at **Settings > Technical > OIDC Provider > Auth OIDC Consents**

## Production Checklist

Before going live:

- [ ] All security settings enabled (especially HTTPS)
- [ ] RSA signing keys generated and active
- [ ] HSTS enabled on reverse proxy
- [ ] All client redirect URIs use HTTPS
- [ ] Strong client secrets for confidential clients (32+ characters)
- [ ] No public clients have secrets configured
- [ ] Scopes properly limited per client
- [ ] Key rotation plan documented
- [ ] Monitoring/alerting set up for failed authentication attempts
- [ ] Backup strategy for signing keys

## Next Steps

- [Python Client Integration](client-python.md)
- [PHP Client Integration](client-php.md)
- [Security Best Practices](security.md)
- [Architecture Overview](architecture.md)
