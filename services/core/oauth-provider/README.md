# OAuth provider: OIDC and SAML

The central login exposes OIDC discovery at `/.well-known/openid-configuration`, authorization at `/oauth/authorize` and tokens at `/oauth/token`. Existing identity eligibility, application assignments, sessions and local MFA checks apply to external OIDC logins too.

## External OIDC adapter

Set `OAUTH_OIDC_CONFIG_FILE` to an absolute path to a JSON file owned by the service user or root, with mode `0600`. Configuration is loaded on startup:

```json
{
  "keycloak": {
    "issuer": "https://identity.example.com/realms/company",
    "clientId": "opendirectory",
    "clientSecret": "replace-with-the-provider-client-secret",
    "subjects": {
      "external-immutable-subject-id": "existing-local-credential-subject"
    }
  }
}
```

Register `${OAUTH_ISSUER}/oauth/federation/keycloak/callback` as the exact redirect URI at the external provider. It must support discovery, Authorization Code, S256 PKCE, RS256 ID tokens and `client_secret_basic`. Issuers are matched exactly, including any trailing slash. HTTPS is required; HTTP loopback is accepted only outside production.

Start at the normal `/oauth/authorize` page for a registered local client; configured providers appear as login links. `GET /oauth/federation/providers` lists their IDs. State, nonce and PKCE are bound to a short-lived HttpOnly browser cookie. Only an explicit issuer/subject mapping selects an existing local credential subject. Email addresses, usernames and external roles never create accounts or assign permissions. The local identity must be active, tenant eligible and assigned to the application. There is no just-in-time account creation or cross-tenant inference.

After the callback, submit the OpenDirectory OTP if configured. The normal local authorization-code and token flow follows. Tokens use `amr: ["federated"]` or `["federated", "otp"]`; external MFA claims alone do not establish OpenDirectory MFA. Identity state, application permissions and MFA revisions are rechecked by the existing authorities.

Transactions are one-use and in memory: five minutes for the external callback, one minute for local completion. A restart requires a new login. Like the existing authorization-code store, this requires a single instance or sticky routing; use a shared transaction store before running without affinity. Configuration changes require a restart.

## SAML 2.0 IdP launches

Supported: authenticated, **IdP-initiated HTTP-POST** launches to fixed applications. SP-initiated AuthnRequests, SAML SP federation into OpenDirectory and Single Logout are not implemented. This is separate from Apple account federation and device enrollment.

Set `OAUTH_SAML_CONFIG_FILE` to a protected JSON file (`0600`):

```json
{
  "keyFile": "/run/opendirectory/federation/saml-key.pem",
  "certFile": "/run/opendirectory/federation/saml-cert.pem",
  "apps": {
    "example": {
      "entityId": "https://app.example.com/saml/metadata",
      "acsUrl": "https://app.example.com/saml/acs",
      "clientId": "existing-local-application-client-id"
    }
  }
}
```

Use a persistent RSA key of at least 2048 bits (`0600`) and its matching, valid X.509 certificate. `clientId` references an enabled application in the local registry; its user/group assignments and MFA requirements govern the SAML launch. Give it dedicated assignments for the intended users. The launching bearer must be a current OpenDirectory user access token.

Import `${OAUTH_ISSUER}/saml/metadata` into the application and enable unsolicited/IdP-initiated responses there. The persistent NameID is the canonical credential subject (`sub`). Response and assertion are signed using XML canonicalization and RSA-SHA256; audience, recipient and destination come exclusively from configuration. Assertions expire after five minutes. No email or role attributes are currently emitted.

```bash
curl "$OAUTH_ISSUER/saml/sso" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"appId":"example"}'
```

The response is an HTML form the authenticated launcher can display for submission to the fixed ACS. Tokens never appear in query strings. `GET /saml/certificate` returns the real public certificate. Without configuration the SAML endpoints return `503 saml_not_configured`. Anonymous assertions, arbitrary ACS overrides and untrusted XML requests are rejected. The retired `/api/auth/sso/*` routes in authentication-service return `410`; migrate integrations to the central authorization page.

## Deployment and verification

Mount configuration, key and certificate read-only into the OAuth container and set the two environment variables there. The service UID must be able to read them; private files must remain `0600`. For Compose, use an override, for example:

```yaml
services:
  oauth-provider:
    environment:
      OAUTH_OIDC_CONFIG_FILE: /run/opendirectory/federation/oidc.json
      OAUTH_SAML_CONFIG_FILE: /run/opendirectory/federation/saml.json
    volumes:
      - ./secrets/federation:/run/opendirectory/federation:ro
```

Publish `/oauth/federation/*` and `/saml/*` at the configured HTTPS issuer alongside its existing OAuth endpoints. Those paths must be reachable without an additional gateway login challenge. The SAML launch itself requires a bearer token. Existing protected signing-key, MFA-key, identity and database configuration remains required.

Run `npm test -- --runInBand` here. Adapter tests run a real local discovery/token/JWKS server, finish the central authorization-code flow, reject invalid tokens and replay, and check SAML signatures with an independent XML signature verifier. Live external IdP/SAML tenant acceptance still requires your own configuration.

## App accounts and scripts

Use **App-Konto erstellen** in the OAuth/OIDC UI for a confidential workload with no redirects or default scopes. The [app-account automation guide](../../../docs/features/app-accounts-automation.md) describes the shipped `scripts/od.mjs` CLI, protected secrets, separate activation and existing permission boundaries. No additional mail-provider connection or tenant-wide automation permission is implicit in app registration.

The dedicated `company.automation` client-credentials scope supports [explicit company app grants and durable jobs](../../../docs/features/company-automation.md). Its JWT contains only that workload permission; an actual company owner separately approves fixed export, [saved group-rule](../../../docs/features/company-group-rule-automation.md) and/or [group license reconciliation](../../../docs/features/company-license-automation.md) actions for the exact client generation. OAuth 001–014, Identity 001–054, Policy 001–029 and current receivers/frontend/CLI are required for the current automation catalog. Group-rule grants change only configured canonical membership sources and retain independent first reviews. The worker uses its own credentials without a retained human session. Client rotation or disablement invalidates the previous generation. Local group-seat assignment and removal do not provision vendor licenses or mailboxes; mail provisioning remains open.

## Own-company app registry

Actual company owners use **Firmen-Apps** or `node scripts/od.mjs company-app …` to manage [their own confidential app accounts](../../../docs/features/company-apps.md), without global application roles. The existing `oauth_clients` registry retains an immutable tenant UUID, original request, exact generation and original audit/pending receipts. New accounts start disabled; secrets appear once. Purpose `company-automation` does not replace explicit per-action company delegation. Existing global web/public/unbound clients remain separate and are not adopted.

OAuth migration **014** and Identity **054** require coordinated current images, gateway/frontend and CLI. The OAuth receiver uses the configured `OAUTH_IDENTITY_AUTHORITY_URL` origin for its exact private human source and the separately signed body-bound tenant check. Company app tokens carry their actual `company_tenant`; pause/new tenant generation, rotation and disablement deny old access. Re-enabling a tenant does not silently refresh a stored app binding. The global registry APIs cannot manage the owned namespace. No Graph, mailbox or external provider permission is created.
