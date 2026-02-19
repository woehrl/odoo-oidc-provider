# Scopes and Claims

This document describes the scopes supported by this OIDC provider and the
claims they add to ID Tokens and the Userinfo response.

## How scopes are filtered

Requested scopes are filtered to the client’s Allowed Scopes. If the client
has no Allowed Scopes configured, requests are denied unless the system
parameter `odoo_oidc.allow_all_scopes_when_unset` is explicitly enabled.

## Always included claims

ID Token (when `openid` is granted):
- `iss`, `sub`, `aud`, `iat`, `exp`, `auth_time`, `azp`
- `nonce` (only if provided in the authorize request)
- `user_type` (`public`, `portal`, or `internal`)
- `at_hash` (when an access token is present during ID Token creation)

Userinfo:
- `sub`
- `preferred_username`
- `user_type` (`public`, `portal`, or `internal`)

## Scope-specific claims

| Scope | ID Token claims | Userinfo claims |
| --- | --- | --- |
| `openid` | Enables ID Token issuance; no additional claims by itself. | No additional claims. |
| `profile` | `name` | `name` |
| `email` | `email`, `email_verified` (always `false`) | `email` (falls back to login), `email_verified` (always `false`) |
| `org` | `company_id`, `company_name`, `company_vat`, `company_registry`, `company_country`, `company_city`, `company_zip`, `company_street`, `company_street2`, `company_phone`, `partner_id`, `partner_ref` | Same as ID Token |
| `groups` | `groups` (list of group display names) | `groups` |
| `address` | `street`, `street2`, `city`, `zip`, `state`, `country` | Same as ID Token |
| `phone` | `phone`, `mobile` | Same as ID Token |
| `preferences` | `lang`, `tz` | Same as ID Token |

Notes:
- Organization and address fields are sourced from the user’s commercial
  partner record when available.
- Phone fields prefer commercial partner numbers and fall back to user fields.
