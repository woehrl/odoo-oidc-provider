# Python Client Integration Guide

This guide shows how to integrate OIDC authentication with your Odoo OIDC Provider using Python 3.7+.

## Prerequisites

- Python 3.7 or higher
- Odoo OIDC Provider configured and running
- A registered OAuth client (see [Setup Guide](setup-guide.md))

## Installation

Install required packages:

```bash
pip install authlib requests
```

For Flask applications:
```bash
pip install authlib requests Flask
```

For Django applications:
```bash
pip install authlib requests Django
```

## Method 1: Using Authlib (Recommended)

Authlib is a comprehensive OAuth/OIDC library that handles all the complexities.

### Basic Integration

```python
from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.rfc7636 import create_s256_code_challenge
import secrets

# Configuration
OIDC_ISSUER = "https://your-odoo-instance.com"
CLIENT_ID = "my-python-app"
CLIENT_SECRET = None  # None for public clients, or your secret for confidential clients
REDIRECT_URI = "http://localhost:5000/auth/callback"
SCOPES = ["openid", "profile", "email"]

# Step 1: Create authorization URL with PKCE
def get_authorization_url():
    """Generate the authorization URL for the user to visit."""

    # Generate PKCE code verifier and challenge
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = create_s256_code_challenge(code_verifier)
    nonce = secrets.token_urlsafe(32)

    # Create OAuth2 session
    client = OAuth2Session(
        CLIENT_ID,
        CLIENT_SECRET,
        redirect_uri=REDIRECT_URI,
        scope=" ".join(SCOPES),
        code_challenge_method='S256'
    )

    # Generate authorization URL
    authorization_url, state = client.create_authorization_url(
        f"{OIDC_ISSUER}/oauth/authorize",
        code_verifier=code_verifier,
        nonce=nonce
    )

    # Store code_verifier, state, and nonce in session
    # (you'll need these in the callback)
    return authorization_url, code_verifier, state, nonce


# Step 2: Handle the callback
def handle_callback(authorization_response, code_verifier, state):
    """Exchange authorization code for tokens."""

    client = OAuth2Session(
        CLIENT_ID,
        CLIENT_SECRET,
        redirect_uri=REDIRECT_URI,
        state=state,
        code_verifier=code_verifier
    )

    # Exchange code for tokens
    token = client.fetch_token(
        f"{OIDC_ISSUER}/oauth/token",
        authorization_response=authorization_response
    )

    return token  # Contains: access_token, id_token, refresh_token, expires_in


# Step 3: Get user information
def get_userinfo(access_token):
    """Fetch user information from the userinfo endpoint."""
    import requests

    response = requests.get(
        f"{OIDC_ISSUER}/oauth/userinfo",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    response.raise_for_status()
    return response.json()


# Step 4: Verify ID token
from authlib.jose import jwt, JsonWebKey
import requests

def verify_id_token(id_token, nonce):
    """Verify the ID token signature and claims."""

    # Fetch JWKS
    jwks_response = requests.get(f"{OIDC_ISSUER}/.well-known/jwks.json")
    jwks = jwks_response.json()

    # Verify token
    claims = jwt.decode(
        id_token,
        JsonWebKey.import_key_set(jwks)
    )

    # Validate claims
    claims.validate()

    # Verify nonce
    if claims.get('nonce') != nonce:
        raise ValueError("Invalid nonce")

    # Verify audience
    if claims.get('aud') != CLIENT_ID:
        raise ValueError("Invalid audience")

    return claims


# Step 5: Refresh access token
def refresh_access_token(refresh_token):
    """Refresh an expired access token."""

    client = OAuth2Session(CLIENT_ID, CLIENT_SECRET)

    token = client.refresh_token(
        f"{OIDC_ISSUER}/oauth/token",
        refresh_token=refresh_token
    )

    return token


# Step 6: Revoke token
def revoke_token(token, token_type_hint="access_token"):
    """Revoke an access or refresh token."""
    import requests

    response = requests.post(
        f"{OIDC_ISSUER}/oauth/revoke",
        data={
            "token": token,
            "token_type_hint": token_type_hint,
            "client_id": CLIENT_ID
        },
        auth=(CLIENT_ID, CLIENT_SECRET) if CLIENT_SECRET else None
    )

    return response.status_code == 200
```

### Usage Example

```python
# In your login route
auth_url, code_verifier, state, nonce = get_authorization_url()

# Store in session
session['code_verifier'] = code_verifier
session['state'] = state
session['nonce'] = nonce

# Redirect user to Odoo
return redirect(auth_url)

# In your callback route
code_verifier = session.pop('code_verifier')
state = session.pop('state')
nonce = session.pop('nonce')

# Get the full callback URL
authorization_response = request.url

# Exchange code for tokens
token = handle_callback(authorization_response, code_verifier, state)

# Verify ID token
id_claims = verify_id_token(token['id_token'], nonce)

# Get user info
userinfo = get_userinfo(token['access_token'])

# Store in session
session['user'] = userinfo
session['access_token'] = token['access_token']
session['refresh_token'] = token.get('refresh_token')
```

## Method 2: Flask Integration

Complete Flask application example:

```python
from flask import Flask, redirect, url_for, session, request, jsonify
from authlib.integrations.flask_client import OAuth
from authlib.oauth2.rfc7636 import create_s256_code_challenge
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configure OAuth
oauth = OAuth(app)
odoo = oauth.register(
    name='odoo',
    client_id='my-flask-app',
    client_secret=None,  # None for public client
    server_metadata_url='https://your-odoo-instance.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid profile email',
        'code_challenge_method': 'S256'
    }
)

@app.route('/')
def index():
    user = session.get('user')
    if user:
        return f'Hello {user["name"]}! <a href="/logout">Logout</a>'
    return '<a href="/login">Login with Odoo</a>'

@app.route('/login')
def login():
    # Generate nonce
    nonce = secrets.token_urlsafe(32)
    session['nonce'] = nonce

    # Redirect to Odoo for authorization
    redirect_uri = url_for('authorize', _external=True)
    return odoo.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/auth/callback')
def authorize():
    # Exchange code for token
    token = odoo.authorize_access_token()

    # Verify nonce in ID token
    nonce = session.pop('nonce', None)
    id_token = odoo.parse_id_token(token, nonce=nonce)

    # Get user info
    userinfo = odoo.userinfo(token=token)

    # Store in session
    session['user'] = userinfo
    session['token'] = token

    return redirect('/')

@app.route('/logout')
def logout():
    # Revoke token
    token = session.get('token')
    if token and 'access_token' in token:
        odoo.revoke_token(token['access_token'])

    # Clear session
    session.clear()
    return redirect('/')

@app.route('/api/profile')
def profile():
    """Protected API endpoint example."""
    token = session.get('token')
    if not token:
        return jsonify({'error': 'Not authenticated'}), 401

    user = session.get('user')
    return jsonify(user)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

## Method 3: Django Integration

### settings.py

```python
INSTALLED_APPS = [
    # ...
    'authlib',
]

# OAuth Configuration
OIDC_ISSUER = 'https://your-odoo-instance.com'
OIDC_CLIENT_ID = 'my-django-app'
OIDC_CLIENT_SECRET = None  # or your secret
OIDC_REDIRECT_URI = 'http://localhost:8000/auth/callback'
OIDC_SCOPES = ['openid', 'profile', 'email']

SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_SECURE = True  # For production with HTTPS
```

### views.py

```python
from django.shortcuts import redirect
from django.http import JsonResponse
from django.views import View
from authlib.integrations.django_client import OAuth
from authlib.oauth2.rfc7636 import create_s256_code_challenge
import secrets

oauth = OAuth()
oauth.register(
    name='odoo',
    client_id=settings.OIDC_CLIENT_ID,
    client_secret=settings.OIDC_CLIENT_SECRET,
    server_metadata_url=f'{settings.OIDC_ISSUER}/.well-known/openid-configuration',
    client_kwargs={
        'scope': ' '.join(settings.OIDC_SCOPES),
        'code_challenge_method': 'S256'
    }
)

class LoginView(View):
    def get(self, request):
        # Generate nonce
        nonce = secrets.token_urlsafe(32)
        request.session['nonce'] = nonce

        # Redirect to authorization endpoint
        redirect_uri = request.build_absolute_uri('/auth/callback')
        return oauth.odoo.authorize_redirect(request, redirect_uri, nonce=nonce)

class CallbackView(View):
    def get(self, request):
        # Exchange code for token
        token = oauth.odoo.authorize_access_token(request)

        # Verify ID token
        nonce = request.session.pop('nonce', None)
        id_token = oauth.odoo.parse_id_token(request, token, nonce=nonce)

        # Get userinfo
        userinfo = oauth.odoo.userinfo(request, token=token)

        # Store in session
        request.session['user'] = userinfo
        request.session['token'] = token

        return redirect('/')

class LogoutView(View):
    def get(self, request):
        # Revoke token
        token = request.session.get('token')
        if token:
            oauth.odoo.revoke_token(request, token['access_token'])

        # Clear session
        request.session.flush()
        return redirect('/')
```

### urls.py

```python
from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.LoginView.as_view(), name='login'),
    path('auth/callback', views.CallbackView.as_view(), name='callback'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
]
```

## Method 4: Manual Implementation (No Libraries)

For learning purposes or minimal dependencies:

```python
import requests
import secrets
import base64
import hashlib
import json
from urllib.parse import urlencode, parse_qs, urlparse

# Configuration
OIDC_ISSUER = "https://your-odoo-instance.com"
CLIENT_ID = "my-python-app"
REDIRECT_URI = "http://localhost:5000/callback"

# Step 1: Generate PKCE parameters
def generate_pkce():
    """Generate PKCE code verifier and challenge."""
    # Generate code verifier (43-128 characters)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

    # Generate code challenge (SHA256 of verifier)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')

    return code_verifier, code_challenge

# Step 2: Build authorization URL
def build_auth_url():
    """Build the authorization URL."""
    code_verifier, code_challenge = generate_pkce()
    nonce = secrets.token_urlsafe(32)
    state = secrets.token_urlsafe(32)

    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid profile email',
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'nonce': nonce,
        'state': state
    }

    auth_url = f"{OIDC_ISSUER}/oauth/authorize?{urlencode(params)}"
    return auth_url, code_verifier, state, nonce

# Step 3: Exchange authorization code for tokens
def exchange_code(code, code_verifier):
    """Exchange authorization code for access token."""

    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'code_verifier': code_verifier
    }

    response = requests.post(
        f"{OIDC_ISSUER}/oauth/token",
        data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )

    response.raise_for_status()
    return response.json()

# Step 4: Get user info
def get_userinfo(access_token):
    """Fetch user information."""
    response = requests.get(
        f"{OIDC_ISSUER}/oauth/userinfo",
        headers={'Authorization': f'Bearer {access_token}'}
    )

    response.raise_for_status()
    return response.json()

# Usage
auth_url, code_verifier, state, nonce = build_auth_url()
print(f"Visit: {auth_url}")

# After user authorizes and returns with code
callback_url = input("Paste callback URL: ")
parsed = urlparse(callback_url)
params = parse_qs(parsed.query)

returned_state = params['state'][0]
code = params['code'][0]

# Verify state
if returned_state != state:
    raise ValueError("Invalid state")

# Exchange code for tokens
tokens = exchange_code(code, code_verifier)
print("Tokens:", json.dumps(tokens, indent=2))

# Get user info
userinfo = get_userinfo(tokens['access_token'])
print("User Info:", json.dumps(userinfo, indent=2))
```

## Best Practices

### Security

1. **Always use PKCE** for public clients (SPAs, mobile apps, CLIs)
2. **Verify ID token signature** using the JWKS endpoint
3. **Validate nonce** in the ID token to prevent replay attacks
4. **Verify state parameter** to prevent CSRF attacks
5. **Use HTTPS** in production for all OAuth endpoints
6. **Store tokens securely** (encrypted session storage, secure cookies)
7. **Don't log tokens** or include them in error messages

### Token Management

1. **Check token expiration** before API calls
2. **Refresh tokens proactively** before they expire
3. **Revoke tokens** on logout
4. **Handle token errors gracefully** (expired, revoked, invalid)

### Error Handling

```python
from authlib.common.errors import AuthlibBaseError

try:
    token = client.fetch_token(...)
except AuthlibBaseError as e:
    if e.error == 'invalid_grant':
        # Authorization code expired or was already used
        return redirect(url_for('login'))
    elif e.error == 'invalid_client':
        # Client authentication failed
        logger.error(f"OAuth client error: {e.description}")
    raise
```

## Troubleshooting

### "PKCE required" Error
Ensure you're sending both `code_challenge` and `code_challenge_method=S256` in the authorization request.

### "Invalid redirect_uri" Error
The redirect URI in your request must exactly match one registered in the Odoo client configuration.

### "Invalid nonce" Error
Ensure you're storing the nonce from the authorization request and validating it against the ID token claim.

### Token Verification Fails
- Ensure you're fetching the latest JWKS from `/.well-known/jwks.json`
- Check that the token hasn't expired
- Verify the audience (`aud`) claim matches your client_id

## Next Steps

- [PHP Client Integration](client-php.md)
- [Setup Guide](setup-guide.md)
- [Security Best Practices](security.md)
