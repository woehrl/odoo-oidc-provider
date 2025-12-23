# PHP Client Integration Guide

This guide shows how to integrate OIDC authentication with your Odoo OIDC Provider using PHP 7.4+ and PHP 8.x.

## Prerequisites

- PHP 7.4 or higher
- Composer (PHP package manager)
- Odoo OIDC Provider configured and running
- A registered OAuth client (see [Setup Guide](setup-guide.md))

## Installation

Install the League OAuth2 Client library:

```bash
composer require league/oauth2-client
```

For ID token verification (recommended):

```bash
composer require firebase/php-jwt
```

## Method 1: Using League OAuth2 Client (Recommended)

### Basic Integration

```php
<?php
require 'vendor/autoload.php';

use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;

// Session management
session_start();

// Configuration
define('OIDC_ISSUER', 'https://your-odoo-instance.com');
define('CLIENT_ID', 'my-php-app');
define('CLIENT_SECRET', null); // null for public clients, or your secret string
define('REDIRECT_URI', 'http://localhost:8000/callback.php');
define('SCOPES', 'openid profile email');

// Create OAuth2 provider
$provider = new GenericProvider([
    'clientId'                => CLIENT_ID,
    'clientSecret'            => CLIENT_SECRET,
    'redirectUri'             => REDIRECT_URI,
    'urlAuthorize'            => OIDC_ISSUER . '/oauth/authorize',
    'urlAccessToken'          => OIDC_ISSUER . '/oauth/token',
    'urlResourceOwnerDetails' => OIDC_ISSUER . '/oauth/userinfo',
    'scopes'                  => SCOPES,
    'scopeSeparator'          => ' ',
]);

// Helper function to generate PKCE parameters
function generatePKCE() {
    // Generate code verifier (43-128 characters)
    $codeVerifier = bin2hex(random_bytes(32));

    // Generate code challenge (SHA256 base64url encoded)
    $codeChallenge = rtrim(
        strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'),
        '='
    );

    return [$codeVerifier, $codeChallenge];
}

// Helper function to generate nonce
function generateNonce() {
    return bin2hex(random_bytes(16));
}
```

### Login Flow (login.php)

```php
<?php
require 'oauth-config.php';

// Generate PKCE parameters
list($codeVerifier, $codeChallenge) = generatePKCE();
$nonce = generateNonce();

// Store in session
$_SESSION['oauth2_code_verifier'] = $codeVerifier;
$_SESSION['oauth2_nonce'] = $nonce;

// Get authorization URL
$authorizationUrl = $provider->getAuthorizationUrl([
    'scope' => SCOPES,
    'code_challenge' => $codeChallenge,
    'code_challenge_method' => 'S256',
    'nonce' => $nonce,
]);

// Store state
$_SESSION['oauth2_state'] = $provider->getState();

// Redirect to Odoo
header('Location: ' . $authorizationUrl);
exit;
```

### Callback Handler (callback.php)

```php
<?php
require 'oauth-config.php';

// Check for errors
if (isset($_GET['error'])) {
    die('OAuth Error: ' . htmlspecialchars($_GET['error']));
}

// Verify state to prevent CSRF
if (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2_state'])) {
    unset($_SESSION['oauth2_state']);
    die('Invalid state');
}

// Retrieve code verifier from session
$codeVerifier = $_SESSION['oauth2_code_verifier'] ?? null;
$nonce = $_SESSION['oauth2_nonce'] ?? null;

if (!$codeVerifier) {
    die('Code verifier not found in session');
}

try {
    // Exchange authorization code for access token
    $accessToken = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code'],
        'code_verifier' => $codeVerifier,
    ]);

    // Get user information
    $resourceOwner = $provider->getResourceOwner($accessToken);
    $userInfo = $resourceOwner->toArray();

    // Verify ID token (if present)
    $idToken = $accessToken->getValues()['id_token'] ?? null;
    if ($idToken) {
        $claims = verifyIdToken($idToken, $nonce);
        // Merge claims into userInfo
        $userInfo = array_merge($userInfo, $claims);
    }

    // Store in session
    $_SESSION['user'] = $userInfo;
    $_SESSION['access_token'] = $accessToken->getToken();
    $_SESSION['refresh_token'] = $accessToken->getRefreshToken();
    $_SESSION['token_expires'] = $accessToken->getExpires();

    // Clean up temporary session data
    unset($_SESSION['oauth2_state']);
    unset($_SESSION['oauth2_code_verifier']);
    unset($_SESSION['oauth2_nonce']);

    // Redirect to home page
    header('Location: index.php');
    exit;

} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
    die('Failed to get access token: ' . $e->getMessage());
}
```

### ID Token Verification

```php
<?php
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;

function verifyIdToken($idToken, $expectedNonce) {
    // Fetch JWKS
    $jwksUrl = OIDC_ISSUER . '/.well-known/jwks.json';
    $jwks = json_decode(file_get_contents($jwksUrl), true);

    try {
        // Parse JWKS
        $keys = JWK::parseKeySet($jwks);

        // Decode and verify token
        $decoded = JWT::decode($idToken, $keys);

        // Verify issuer
        if ($decoded->iss !== OIDC_ISSUER) {
            throw new Exception('Invalid issuer');
        }

        // Verify audience
        if ($decoded->aud !== CLIENT_ID) {
            throw new Exception('Invalid audience');
        }

        // Verify nonce
        if ($decoded->nonce !== $expectedNonce) {
            throw new Exception('Invalid nonce');
        }

        // Verify expiration
        if ($decoded->exp < time()) {
            throw new Exception('Token expired');
        }

        return (array) $decoded;

    } catch (Exception $e) {
        error_log('ID token verification failed: ' . $e->getMessage());
        throw $e;
    }
}
```

### Protected Resource (index.php)

```php
<?php
require 'oauth-config.php';

// Check if user is logged in
if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}

$user = $_SESSION['user'];
?>
<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
</head>
<body>
    <h1>Welcome, <?php echo htmlspecialchars($user['name'] ?? 'User'); ?>!</h1>
    <p>Email: <?php echo htmlspecialchars($user['email'] ?? 'N/A'); ?></p>
    <p>User ID: <?php echo htmlspecialchars($user['sub'] ?? 'N/A'); ?></p>

    <h2>Profile Information:</h2>
    <pre><?php print_r($user); ?></pre>

    <a href="logout.php">Logout</a>
</body>
</html>
```

### Logout (logout.php)

```php
<?php
require 'oauth-config.php';

// Revoke access token
if (isset($_SESSION['access_token'])) {
    $accessToken = $_SESSION['access_token'];

    // Revoke token at Odoo
    $ch = curl_init(OIDC_ISSUER . '/oauth/revoke');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query([
            'token' => $accessToken,
            'token_type_hint' => 'access_token',
            'client_id' => CLIENT_ID,
        ]),
        CURLOPT_RETURNTRANSFER => true,
    ]);

    $response = curl_exec($ch);
    curl_close($ch);
}

// Clear session
session_destroy();

// Redirect to login
header('Location: login.php');
exit;
```

### Token Refresh

```php
<?php
function refreshAccessToken(GenericProvider $provider) {
    if (!isset($_SESSION['refresh_token'])) {
        return false;
    }

    try {
        $newAccessToken = $provider->getAccessToken('refresh_token', [
            'refresh_token' => $_SESSION['refresh_token']
        ]);

        // Update session with new tokens
        $_SESSION['access_token'] = $newAccessToken->getToken();
        $_SESSION['refresh_token'] = $newAccessToken->getRefreshToken();
        $_SESSION['token_expires'] = $newAccessToken->getExpires();

        return true;

    } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
        error_log('Token refresh failed: ' . $e->getMessage());
        return false;
    }
}

// Check if token is expired and refresh
function ensureValidToken(GenericProvider $provider) {
    $expires = $_SESSION['token_expires'] ?? 0;

    // Refresh if token expires in less than 5 minutes
    if ($expires < (time() + 300)) {
        if (!refreshAccessToken($provider)) {
            // Refresh failed, redirect to login
            header('Location: login.php');
            exit;
        }
    }
}
```

## Method 2: Laravel Integration

### Installation

```bash
composer require laravel/socialite
composer require socialiteproviders/odoo
```

### config/services.php

```php
'odoo' => [
    'client_id' => env('ODOO_CLIENT_ID'),
    'client_secret' => env('ODOO_CLIENT_SECRET'),
    'redirect' => env('ODOO_REDIRECT_URI'),
    'base_url' => env('ODOO_BASE_URL'), // https://your-odoo-instance.com
],
```

### .env

```env
ODOO_CLIENT_ID=my-laravel-app
ODOO_CLIENT_SECRET=
ODOO_REDIRECT_URI=http://localhost:8000/auth/callback
ODOO_BASE_URL=https://your-odoo-instance.com
```

### app/Http/Controllers/AuthController.php

```php
<?php
namespace App\Http\Controllers;

use Laravel\Socialite\Facades\Socialite;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function redirectToProvider()
    {
        return Socialite::driver('odoo')
            ->with([
                'code_challenge' => session('code_challenge'),
                'code_challenge_method' => 'S256',
                'nonce' => session('nonce'),
            ])
            ->scopes(['openid', 'profile', 'email'])
            ->redirect();
    }

    public function handleProviderCallback()
    {
        try {
            $odooUser = Socialite::driver('odoo')->user();

            // Find or create user
            $user = User::updateOrCreate(
                ['email' => $odooUser->getEmail()],
                [
                    'name' => $odooUser->getName(),
                    'odoo_id' => $odooUser->getId(),
                ]
            );

            // Login
            Auth::login($user);

            return redirect('/dashboard');

        } catch (\Exception $e) {
            return redirect('/login')->withErrors(['error' => 'Authentication failed']);
        }
    }

    public function logout(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect('/');
    }
}
```

### routes/web.php

```php
Route::get('/auth/redirect', [AuthController::class, 'redirectToProvider']);
Route::get('/auth/callback', [AuthController::class, 'handleProviderCallback']);
Route::post('/logout', [AuthController::class, 'logout']);
```

## Method 3: Symfony Integration

### Installation

```bash
composer require knpuniversity/oauth2-client-bundle
composer require league/oauth2-client
```

### config/packages/knpu_oauth2_client.yaml

```yaml
knpu_oauth2_client:
    clients:
        odoo:
            type: generic
            provider_class: League\OAuth2\Client\Provider\GenericProvider
            client_id: '%env(ODOO_CLIENT_ID)%'
            client_secret: '%env(ODOO_CLIENT_SECRET)%'
            redirect_route: connect_odoo_check
            redirect_params: {}
            provider_options:
                urlAuthorize: '%env(ODOO_BASE_URL)%/oauth/authorize'
                urlAccessToken: '%env(ODOO_BASE_URL)%/oauth/token'
                urlResourceOwnerDetails: '%env(ODOO_BASE_URL)%/oauth/userinfo'
                scopes: 'openid profile email'
```

### src/Controller/OAuthController.php

```php
<?php
namespace App\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

class OAuthController extends AbstractController
{
    /**
     * @Route("/connect/odoo", name="connect_odoo_start")
     */
    public function connectAction(ClientRegistry $clientRegistry)
    {
        return $clientRegistry
            ->getClient('odoo')
            ->redirect(['openid', 'profile', 'email']);
    }

    /**
     * @Route("/connect/odoo/check", name="connect_odoo_check")
     */
    public function connectCheckAction(Request $request, ClientRegistry $clientRegistry)
    {
        $client = $clientRegistry->getClient('odoo');

        try {
            $accessToken = $client->getAccessToken();
            $user = $client->fetchUserFromToken($accessToken);

            // Handle user login/registration
            // ...

            return $this->redirectToRoute('home');

        } catch (\Exception $e) {
            return $this->redirectToRoute('login');
        }
    }
}
```

## Method 4: WordPress Integration

### functions.php

```php
<?php
// Add to your theme's functions.php

function odoo_oauth_login_button() {
    ?>
    <a href="<?php echo wp_login_url(); ?>?action=odoo_oauth" class="button">
        Login with Odoo
    </a>
    <?php
}

function odoo_oauth_init() {
    if (isset($_GET['action']) && $_GET['action'] === 'odoo_oauth') {
        odoo_oauth_redirect();
    }

    if (isset($_GET['code']) && isset($_GET['state'])) {
        odoo_oauth_callback();
    }
}
add_action('login_init', 'odoo_oauth_init');

function odoo_oauth_redirect() {
    $params = [
        'client_id' => get_option('odoo_client_id'),
        'redirect_uri' => home_url('/wp-login.php'),
        'response_type' => 'code',
        'scope' => 'openid profile email',
        'state' => wp_create_nonce('odoo_oauth_state'),
    ];

    $auth_url = get_option('odoo_base_url') . '/oauth/authorize?' . http_build_query($params);
    wp_redirect($auth_url);
    exit;
}

function odoo_oauth_callback() {
    if (!wp_verify_nonce($_GET['state'], 'odoo_oauth_state')) {
        wp_die('Invalid state parameter');
    }

    // Exchange code for token
    $response = wp_remote_post(get_option('odoo_base_url') . '/oauth/token', [
        'body' => [
            'grant_type' => 'authorization_code',
            'code' => $_GET['code'],
            'redirect_uri' => home_url('/wp-login.php'),
            'client_id' => get_option('odoo_client_id'),
        ]
    ]);

    $token = json_decode(wp_remote_retrieve_body($response), true);

    // Get user info
    $user_response = wp_remote_get(get_option('odoo_base_url') . '/oauth/userinfo', [
        'headers' => [
            'Authorization' => 'Bearer ' . $token['access_token']
        ]
    ]);

    $userinfo = json_decode(wp_remote_retrieve_body($user_response), true);

    // Login or create WordPress user
    $user = get_user_by('email', $userinfo['email']);

    if (!$user) {
        $user_id = wp_create_user($userinfo['email'], wp_generate_password(), $userinfo['email']);
        wp_update_user([
            'ID' => $user_id,
            'display_name' => $userinfo['name'],
        ]);
        $user = get_user_by('id', $user_id);
    }

    wp_set_auth_cookie($user->ID);
    wp_redirect(admin_url());
    exit;
}
```

## Best Practices

### Security Checklist

1. ✓ Always use PKCE (S256 method) for public clients
2. ✓ Verify the state parameter to prevent CSRF
3. ✓ Validate nonce in ID tokens
4. ✓ Verify ID token signatures using JWKS
5. ✓ Use HTTPS in production
6. ✓ Store tokens securely (encrypted sessions, HttpOnly cookies)
7. ✓ Set secure session cookie flags:

```php
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => $_SERVER['HTTP_HOST'],
    'secure' => true,    // HTTPS only
    'httponly' => true,  // No JavaScript access
    'samesite' => 'Lax'  // CSRF protection
]);
```

### Error Handling

```php
try {
    $accessToken = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code'],
        'code_verifier' => $codeVerifier,
    ]);
} catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
    $error = $e->getResponseBody();

    error_log('OAuth error: ' . json_encode($error));

    switch ($error['error'] ?? 'unknown') {
        case 'invalid_grant':
            die('Authorization code expired or was already used. Please try again.');
        case 'invalid_client':
            die('Client authentication failed. Please contact support.');
        case 'access_denied':
            die('You denied access to the application.');
        default:
            die('Authentication failed: ' . htmlspecialchars($error['error_description'] ?? 'Unknown error'));
    }
}
```

## Troubleshooting

### "Failed to get access token" Error
- Check that CLIENT_ID and CLIENT_SECRET match your Odoo client configuration
- Verify REDIRECT_URI exactly matches the registered URI
- Ensure you're passing the code_verifier in the token exchange

### "Invalid state" Error
- State mismatch indicates potential CSRF attack or session issues
- Ensure sessions are properly configured and working
- Check that cookies are enabled

### cURL SSL Certificate Errors
For local development only:

```php
$provider = new GenericProvider([
    // ... config ...
    'verify' => false, // ONLY FOR LOCAL DEVELOPMENT
]);
```

Never disable SSL verification in production!

## Next Steps

- [Python Client Integration](client-python.md)
- [Setup Guide](setup-guide.md)
- [Security Best Practices](security.md)
