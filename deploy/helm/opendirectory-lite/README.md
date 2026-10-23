# OpenDirectory Lite Helm Chart

This chart packages the core services from `docker-compose.lite.yml` for one Kubernetes release: PostgreSQL, Redis, LLDAP, the identity/auth/device/policy/OAuth services, the API, the web app, and the licensing API and workers.

## Before installation

Build and push the application images to a private Harbor project. The default repository is `harbor.heusser.local/opendirectory`; override it in a values file for another registry. The cluster needs an image pull Secret named `harbor-opendirectory`.

Create these Kubernetes Secrets from your Secret Manager before installing the chart. The chart never stores secret values in Helm values or a rendered Secret manifest.

`opendirectory-runtime` keys:

| Key | Used for |
| --- | --- |
| `postgres-password` | PostgreSQL and the device service |
| `redis-password` | Redis |
| `redis-url` | Redis connection URL, including the password |
| `lldap-jwt-secret` | LLDAP signing key |
| `lldap-admin-password` | LLDAP admin password |
| `jwt-secret` | API and authentication services |
| `identity-database-url` | Identity database connection string |
| `auth-database-url` | Authentication database connection string |
| `policy-database-url` | Policy database connection string |
| `oauth-database-url` | OAuth database connection string |
| `api-database-url` | API database connection string |
| `license-fulfillment-database-url` | License fulfillment database connection string |
| `license-capacity-database-url` | License capacity database connection string |
| `graph-client-secret` | Optional Microsoft Graph app secret for invitation mail |
| `license-group-read-token` | Optional license group source token |
| `license-user-read-token` | Optional license user source token |

`opendirectory-files` keys (the key names become file names in `/run/opendirectory`):

| Key | Used for |
| --- | --- |
| `oauth-signing.pem` | OAuth signing private key |
| `mfa-encryption.key` | MFA data encryption key |
| `oauth-verification.jwks.json` | OAuth verification key set |
| `oauth-web-client.secret` | OAuth web client secret |
| `browser-cookie.key` | Browser session cookie encryption key |
| `browser-client.secret` | Browser OIDC client secret |
| `license-fulfillment.json` | License fulfillment source configuration |
| `license-capacity.json` | License capacity source configuration |

Use database URLs for user `opendirectory`, the database names initialized by the chart, and the password in `postgres-password`. Use distinct random values for PostgreSQL, Redis, JWT, LLDAP, and browser/OAuth keys.
Set `oauth-web-client.secret` and `browser-client.secret` to the same value; the provider and web app use the same OIDC client.

## Build and publish images

Authenticate to Harbor through your Secret Manager, then run the build helper. It uses a temporary Docker config and removes it when the push finishes.

```sh
HARBOR_USERNAME="$(your-secret-manager get harbor-robot-username)" \\
HARBOR_PASSWORD="$(your-secret-manager get harbor-robot-password)" \\
./deploy/helm/opendirectory-lite/build-and-push.sh harbor.heusser.local/opendirectory 1.0.0
```

The helper builds the ten application images used by this chart for `linux/amd64`. It does not print or save the robot credentials in the repository.

Create the namespace-scoped pull Secret from the same Secret Manager values with:

```sh
HARBOR_USERNAME="$(your-secret-manager get harbor-robot-username)" \
HARBOR_PASSWORD="$(your-secret-manager get harbor-robot-password)" \
./deploy/helm/opendirectory-lite/create-pull-secret.sh
```

Set `graphMail.tenantId`, `graphMail.clientId`, and `graphMail.sender` in a private values file to enable invitation mail through Microsoft Graph. Keep the client secret in `opendirectory-runtime`.

## Install on the homelab k3s cluster

```sh
helm upgrade --install opendirectory deploy/helm/opendirectory-lite \\
  --namespace opendirectory --create-namespace \\
  --values deploy/helm/opendirectory-lite/values.k3s.yaml
```

The k3s values use `opendirectory.heusser.local`, the `homelab-ca-issuer` ClusterIssuer, and the `longhorn` StorageClass. The ingress sends OIDC discovery and `/oauth` requests to the OAuth provider and the remaining web traffic to Next.js.

## Scope

MongoDB, Grafana, Prometheus, network infrastructure, printer service, and enterprise add-ons from Compose are outside this core chart. Add them as separate releases after their storage, network privileges, and ingress requirements are defined.
