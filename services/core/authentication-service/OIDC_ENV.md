# OIDC configuration moved to the central provider

`authentication-service` is the credential provider on port **3002**. Its former alternate OIDC issuer is retired. Discovery, authorization, token, JWKS and interaction requests return **410 `legacy_oidc_retired`**. The service no longer loads `oidc-provider`, generates alternate signing keys or starts clients with default secrets.

Configure OIDC/SAML at [oauth-provider](../oauth-provider/README.md). Its `OAUTH_ISSUER` is the actual issuer; downstream `OIDC_ISSUER`, `JWKS_URI` and access-state URLs must refer to that configured authority. Browser and workload clients must be explicitly registered and granted access there. Old client IDs, secrets, keys and subject links are not automatically migrated.

The former auth-service variables `ISSUER_URL`, `JWKS_PATH`, `JWKS_KEYS`, `QA_CLIENT_SECRET`, `DEVICE_SVC_SECRET`, `POLICY_SVC_SECRET`, `WEB_APP_REDIRECT_URI` and `COOKIE_SECRET` no longer configure an issuer here. Existing key files are not deleted. Use the central provider's documented protected configuration and key files.

OAuth continues verifying passwords via `AUTH_SERVICE_URL=http://auth-service:3002`. Configure this service's dedicated PostgreSQL and Redis connections as described in its [README](README.md); a password check does not replace canonical Identity eligibility, application assignment or OAuth MFA.
