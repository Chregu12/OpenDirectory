# OIDC Provider Environment Variables

This document describes all environment variables required to run the authentication-service as a full OIDC Provider and to configure downstream services to validate tokens via JWKS.

## Authentication Service (OIDC Provider)

| Variable | Description | Example |
|---|---|---|
| `ISSUER_URL` | Public URL of the OIDC provider. Must match the `iss` claim in issued tokens and the `OIDC_ISSUER` value set on downstream services. | `https://auth.yourdomain.com` |
| `JWKS_PATH` | Filesystem path where the generated JWKS key pair is persisted across restarts. | `.oidc_jwks.json` (default) |
| `QA_CLIENT_SECRET` | OAuth2 client secret for the quick-actions service. | *(generate with `openssl rand -hex 32`)* |
| `DEVICE_SVC_SECRET` | OAuth2 client secret for the device-service. | *(generate with `openssl rand -hex 32`)* |
| `POLICY_SVC_SECRET` | OAuth2 client secret for the policy-service. | *(generate with `openssl rand -hex 32`)* |
| `WEB_APP_REDIRECT_URI` | OAuth2 redirect URI registered for the web frontend. Must exactly match the URI the frontend sends in the authorization request. | `https://yourdomain.com/oidc/callback` |
| `COOKIE_SECRET` | Secret used to sign OIDC session cookies. Must be at least 32 characters long and kept private. | *(generate with `openssl rand -hex 32`)* |

## Downstream Services (device-service, policy-service, conditional-access, …)

Each service that validates tokens must set:

| Variable | Description | Default |
|---|---|---|
| `JWKS_URI` | Full URL of the JWKS endpoint exposed by the auth-service. The service fetches public keys from this URL and caches them for up to 1 hour. | `http://localhost:3001/jwks` |
| `OIDC_ISSUER` | Expected value of the `iss` claim in incoming tokens. Must match `ISSUER_URL` on the auth-service. | `http://localhost:3001` |

### Production example

```env
# auth-service
ISSUER_URL=https://auth.yourdomain.com
JWKS_PATH=/secrets/oidc_jwks.json
QA_CLIENT_SECRET=<secret>
DEVICE_SVC_SECRET=<secret>
POLICY_SVC_SECRET=<secret>
WEB_APP_REDIRECT_URI=https://yourdomain.com/oidc/callback
COOKIE_SECRET=<32+ char secret>

# device-service / policy-service / conditional-access
JWKS_URI=https://auth.yourdomain.com/jwks
OIDC_ISSUER=https://auth.yourdomain.com
```
