# OpenDirectory Lite Helm Chart

This chart packages the core services from `docker-compose.lite.yml` for one Kubernetes release: PostgreSQL, Redis, LLDAP, the identity/auth/device/policy/OAuth services, the API, the web app, and the licensing API and workers.

## Before installation

Build and push the application images to a private Harbor project. The default repository is `harbor.heusser.local/opendirectory`; override it in a values file for another registry. The cluster needs an image pull Secret named `harbor-opendirectory`.

The applications consume Kubernetes Secrets named `opendirectory-runtime` and `opendirectory-files`. You can create them manually before install, or enable the optional ESO synchronization below. The chart never puts secret values in Helm values or rendered manifests.

The k3s profile mirrors the existing Grafana release's `admin-user` and `admin-password` through ESO into a separate namespaced Secret. Its reader can get only that exact monitoring Secret; application pods do not receive its Kubernetes token. This keeps the integration aligned with the actual external Grafana credential instead of generating an unrelated password in OpenBao. Disable `grafanaCredentials.enabled` or adjust its source namespace/name for another monitoring installation.

The k3s profile pins the web app and integration service to `1.0.16`, app store to `1.0.15`, gateway to `1.0.14`, OAuth to `1.0.11` and auth/API backend to `1.0.10`. Module navigation settings use PostgreSQL in the existing `integration` database; storage failures return 503 rather than reporting an in-memory save. Prometheus alert/rule failures are propagated instead of producing a healthy empty result. The catalog source refresh reads only fixed WinGet/Homebrew hosts, starts on service boot, and repeats every six hours when `CATALOG_RELEASE_SYNC_ENABLED=true`. An admin can start/observe the same single-flight job through `/api/store/catalog/sync`. Failed sources retain only matching last-confirmed observations; no device installation is inferred. Optional `CATALOG_GITHUB_TOKEN` is server-only; without it GitHub's public rate limit may yield a partial refresh. Webhook manual tests require explicit HTTPS origins in `GATEWAY_WEBHOOK_ALLOWED_ORIGINS`; credentials/redirects are rejected. Production signed event dispatch is not implemented. The build helper packages the core OIDC gateway with explicit Kubernetes upstreams. Enabled integrations and API dependencies must pass real readiness checks; optional services excluded from Lite are reported as disabled.

The chart consumes native Kubernetes Secrets. OpenBao is the source of truth; External Secrets Operator (ESO) reads OpenBao KV v2 using short-lived Kubernetes ServiceAccount tokens and writes the resulting values into the app namespace. PostgreSQL password rotation is handled by OpenBao's database engine, which changes the `opendirectory` database role password and publishes the replacement through ESO. For Harbor, use a scoped project robot and rotate its credential through Harbor's API before ESO refreshes the pull Secret.

OpenBao is installed separately with the official Helm chart. Deployment values and certificate resources are in `deploy/helm/openbao/` and `deploy/k8s/openbao/`. Initialize it only after you have a safe place to save its recovery shares and initial root token, such as a secure note in your existing Vaultwarden account or an offline password manager. Keep recovery material outside the cluster too. The Helm release is configured for three-node Raft storage on Longhorn, with TLS and no public ingress by default. Do not enable ESO synchronization until OpenBao is initialized, unsealed, and Kubernetes auth is configured.

Install the OpenBao service and its internal TLS certificate with:

```sh
./deploy/k8s/openbao/install.sh
```

The initial release remains uninitialized and sealed. For bootstrap, start `kubectl port-forward -n openbao pod/openbao-0 8200:8200`, copy the public CA certificate from `openbao-server-tls` to a local file, then set `BAO_ADDR=https://127.0.0.1:8200`, `BAO_TLS_SERVER_NAME=openbao-0.openbao-internal.openbao.svc.cluster.local`, and `BAO_CACERT` to that file. Initialize only one node with `bao operator init -key-shares=5 -key-threshold=3`. Save all shares and the initial root token in your existing password manager before unsealing; never put them in Git, Helm values, or chat. Unseal node 0, then unseal the two joining peers using the same threshold. Keep the service internal until initialization and recovery storage are complete. The cluster uses Shamir sealing, so nodes need manual unseal after restarts; no external KMS/auto-unseal is configured.

Example bootstrap shell setup (start the port-forward in another terminal):

```sh
kubectl get secret openbao-server-tls -n openbao -o jsonpath='{.data.ca\.crt}' | base64 -D > /tmp/openbao-ca.crt
export BAO_ADDR=https://127.0.0.1:8200
export BAO_TLS_SERVER_NAME=openbao-0.openbao-internal.openbao.svc.cluster.local
export BAO_CACERT=/tmp/openbao-ca.crt
bao operator init -key-shares=5 -key-threshold=3
```

Use separate port-forwards and the matching DNS name when unsealing `openbao-1` and `openbao-2`. `bao operator unseal` prompts for each share without placing it in shell history.

After initialization and unsealing, configure OpenBao from the repository root. The helper below uses `kubectl exec`, prompts for the initial root token without echoing it, and removes its temporary CLI token cache from the OpenBao pod on exit. It then configures Kubernetes auth and the Vaultwarden sync. The existing Vaultwarden account email and master password are requested locally; the password prompt is hidden, and the password is sent through the Kubernetes exec stream directly into OpenBao's encrypted storage. No secret is written to shell history or the repository.

```sh
umask 077
./deploy/k8s/openbao/connect-vaultwarden-via-kubectl.sh
./deploy/k8s/openbao/install-bitwarden-token-renewer.sh
```

The helper prompts for the initial root token, the existing Vaultwarden account email, and its master password. The Vaultwarden account must use PBKDF2-SHA256 and have no two-step login because the plugin cannot handle MFA. The plugin creates one personal-vault item for the current OpenDirectory PostgreSQL credential and refreshes it after OpenBao rotates the database password. Its scoped token can read only that database credential. A Kubernetes CronJob replaces the token twice monthly. Use a separate short-lived operator token for later administration; do not keep using the initial root token. Install or upgrade the OpenDirectory chart with ESO enabled so it creates the required ServiceAccounts, then apply `deploy/k8s/openbao/cluster-secret-store.yaml`. Apply `cluster-secret-store-harbor-rotation.yaml` only after enabling Harbor rotation and creating the `opendirectory-harbor-api-reader` ServiceAccount.

To enable ESO, copy [values.openbao.example.yaml](values.openbao.example.yaml) to a private values file and map each required `runtime` and `files` key to an OpenBao KV v2 path and property. The chart creates the `opendirectory-secret-reader` service account; ExternalSecrets reference the separately applied `ClusterSecretStore`. The optional Harbor pull-secret mapping expects a full Docker config JSON value at `secret/opendirectory/harbor/pull`, property `dockerconfigjson`. ESO refreshes the Kubernetes Secret on the configured interval; pods using the secret as an environment variable still need a restart after changes.

Treat this as an example only; keep actual secret values and private Helm values out of Git.

## Scheduled Harbor pull-robot rotation

The chart includes an opt-in blue/green rotation CronJob. It creates a replacement robot with only `repository:pull` access to the `opendirectory` Harbor project, updates the OpenBao KV entry, waits for ESO to refresh `harbor-opendirectory`, verifies registry authentication, and then deletes the previous robot. It runs monthly by default and can be enabled with:

```yaml
externalSecrets:
  enabled: true
  harborPullSecret:
    enabled: true
    path: opendirectory/harbor/pull
    property: dockerconfigjson
  harborRotation:
    enabled: true
    schedule: "0 4 1 * *"
    credentialsPath: opendirectory/harbor/rotation-api
    caConfigMapName: openbao-ca
```

Before enabling it, seed `secret/opendirectory/harbor/pull` with `robot_id` and `dockerconfigjson`, and seed `secret/opendirectory/harbor/rotation-api` with a dedicated Harbor API username and password. The API identity must be able to create, read, and delete robot accounts for this project. The current robot must already be project-scoped with repository pull permission only; the job refuses to rotate system robots or robots with broader access. Create the `opendirectory` namespace, copy the public CA certificate with `./deploy/k8s/openbao/sync-ca-to-opendirectory.sh opendirectory`, and apply `cluster-secret-store-harbor-rotation.yaml` before enabling rotation in the private values file. The Harbor API manager credential is read only by a separate ESO identity and exposed only to the rotation job through a namespaced Secret.

The job needs its first successful run before the project pull identity can be considered rotated. The existing cluster-wide `robot$k8s-deploy` credential is separate; check any external build clients before revoking it. The job cannot repair that global account automatically.

## OpenBao and Vaultwarden

The OpenBao-to-Vaultwarden bridge uses the independent community plugin `salir-se/openbao-plugin-secrets-bitwarden` v0.1.0. OpenBao downloads the architecture-specific GitHub release binary on pod startup and checks it against the published SHA-256 before registering it. It mirrors explicitly mapped OpenBao KV values one way into a Bitwarden-compatible vault; OpenBao remains the source of truth. The plugin is pre-1.0 and tested against Vaultwarden, but its compatibility with this deployment's OpenBao 2.7.1 release still needs an operational check after unsealing. It logs in with a regular Vaultwarden email and master password; it requires PBKDF2-SHA256 and does not support two-step login. It is not Bitwarden Secrets Manager and does not create a machine account. Using your existing account avoids creating another Vaultwarden user, but OpenBao stores that account's master password in its encrypted storage and the plugin can access that account's vault. Use a separate account only if you later decide that stronger separation is worth the extra user.

`deploy/k8s/openbao/install.sh` configures the Vaultwarden ingress to use the existing `homelab-ca-issuer`, then copies only that public CA certificate into OpenBao. OpenBao combines it with the standard public roots so the plugin can validate both Vaultwarden and the public OCI registry. Certificate renewal remains managed by cert-manager.

The plugin does not mirror every OpenBao secret automatically. Create explicit roles only for values that should be shared into Vaultwarden. Its sync token can read `runtime`, `files`, and the Harbor pull credential; the Harbor API manager password is excluded. The plugin's password and token are stored in OpenBao's encrypted barrier storage. The automated token-renewer only has permission to replace `bao_token` in the plugin configuration and to create the one scoped sync-token role.

The bridge mirrors values after they are written to OpenBao; it does not rotate credentials at Harbor, PostgreSQL, Redis, or other target systems. Harbor token rotation needs a Harbor API identity allowed to manage only the OpenDirectory project's robot accounts. Store that manager identity in OpenBao, run the rotation automation with its own Kubernetes ServiceAccount, and grant it write access only to the Harbor pull-secret path. Avoid using Harbor's global admin credential for scheduled rotation.

`opendirectory-runtime` keys:

| Key | Used for |
| --- | --- |
| `postgres-app-initial-password` | One-time initial password for the restricted `opendirectory` database role |
| `redis-password` | Redis |
| `redis-url` | Redis connection URL, including the password |
| `lldap-jwt-secret` | LLDAP signing key |
| `lldap-admin-password` | LLDAP admin password |
| `jwt-secret` | API and authentication services |
| `api-admin-password` | Initial OpenDirectory administrator password for the API backend |
| `grafana-admin-password` | Integration service credential for its Grafana connector |
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
| `license-fulfillment.json` | License fulfillment source configuration (only when the worker is enabled) |
| `license-capacity.json` | License capacity source configuration (only when the worker is enabled) |

Use the initial database URLs for user `opendirectory`, the databases initialized by the chart, and `postgres-app-initial-password`. The chart creates `bao_rotator` as the PostgreSQL bootstrap superuser and gives `opendirectory` ownership of its application databases without superuser rights. Use distinct random values for PostgreSQL, Redis, JWT, LLDAP, and browser/OAuth keys. The optional license workers are disabled by default; enabling them also requires reviewed source configuration, migrated schemas, and dedicated database grants.
Set `oauth-web-client.secret` and `browser-client.secret` to the same value; the provider and web app use the same OIDC client.

## PostgreSQL password rotation

Keep the `bao_rotator` bootstrap password separately at `secret/opendirectory/postgres-admin`, with property `postgres-admin-password`. Its ExternalSecret uses a separate OpenBao policy and service account; the general ESO role and app pods do not receive this value. The database rotation uses OpenBao's PostgreSQL static role for the `opendirectory` database user. OpenBao rotates it every 30 days by default (`ROTATION_PERIOD` can change this in the setup script). ESO reads the current password directly from `database/static-creds/opendirectory`, templates the database URLs, and updates `opendirectory-database`. A namespaced CronJob checks that Secret every five minutes and restarts only the database-connected app deployments after the password changes. PostgreSQL's separate `bao_rotator` account remains stable and is never managed by the static role.

With the port-forward still running and the OpenBao CLI installed locally, run `deploy/k8s/openbao/seed-opendirectory-secrets.sh`. It creates random runtime credentials, signing keys, and the separate PostgreSQL administrator password without printing their values. The shell needs the same `BAO_ADDR`, `BAO_CACERT`, and `BAO_TLS_SERVER_NAME` variables set above. Copy `values.openbao.example.yaml` to a private values file and apply `deploy/k8s/openbao/cluster-secret-store.yaml`. Install the chart with ESO enabled and `externalSecrets.databasePasswordRotation.enabled: false`; ESO will create the runtime, files, and administrator Secrets, then PostgreSQL will create the initial `opendirectory` role. Wait until `opendirectory-postgres` is Ready before configuring the OpenBao database connection and static role:

```sh
helm upgrade --install opendirectory deploy/helm/opendirectory-lite \
  --namespace opendirectory --create-namespace \
  --values deploy/helm/opendirectory-lite/values.k3s.yaml \
  --values /secure/path/opendirectory-values.private.yaml

kubectl wait --for=condition=Ready statefulset/opendirectory-postgres \
  --namespace opendirectory --timeout=10m

kubectl cp deploy/k8s/openbao/configure-postgres-rotation.sh openbao/openbao-0:/tmp/configure-postgres-rotation.sh
kubectl exec -it -n openbao openbao-0 -- bao login -no-print
kubectl exec -it -n openbao openbao-0 -- /bin/sh /tmp/configure-postgres-rotation.sh
```

Use the OpenBao administrator token for these commands. Role creation rotates the application password immediately. Set `externalSecrets.databasePasswordRotation.enabled: true` in the private Helm values and upgrade the release; ESO will publish the new password and the reloader will restart only database-connected deployments. Plan for a brief database connection interruption while the first rotation and rollout complete. Keep `postgres-admin-password` at `secret/opendirectory/postgres-admin` and `postgres-app-initial-password` in `secret/opendirectory/runtime`. The CronJob stores only a SHA-256 digest in its ConfigMap and has namespace-scoped access to the app Secret and deployments.

## Build and publish images

Authenticate to Harbor through your Secret Manager, then run the build helper. It uses a temporary Docker config and removes it when the push finishes.

```sh
HARBOR_USERNAME="$(your-secret-manager get harbor-robot-username)" \
HARBOR_PASSWORD="$(your-secret-manager get harbor-robot-password)" \
./deploy/helm/opendirectory-lite/build-and-push.sh harbor.heusser.local/opendirectory 1.0.1
```

The helper builds the ten application images used by this chart for `linux/amd64`. It does not print or save the robot credentials in the repository.

The web app can use a per-service image tag through `apps.web-app.imageTag`; other applications continue to use `global.image.tag`. Password reset links use `global.publicURL`. To send them, add `smtp-host`, `smtp-port`, `smtp-secure`, `smtp-user`, `smtp-password`, and `smtp-from` to the `opendirectory-runtime` Secret. These SMTP entries are optional, so the chart can install before mail delivery is configured.

Create the namespace-scoped pull Secret from the same Secret Manager values with:

```sh
HARBOR_USERNAME="$(your-secret-manager get harbor-robot-username)" \
HARBOR_PASSWORD="$(your-secret-manager get harbor-robot-password)" \
./deploy/helm/opendirectory-lite/create-pull-secret.sh
```

Set `graphMail.tenantId`, `graphMail.clientId`, and `graphMail.sender` in a private values file to enable invitation mail through Microsoft Graph. Keep the client secret in `opendirectory-runtime`.

## Install on the homelab k3s cluster

OAuth image `1.0.20` adds explicitly provisioned web-console access for the existing canonical installation administrator. `apps.oauth-provider.env.OAUTH_WEB_ADMIN_USER_IDS` is a JSON UUID list, empty by default; the k3s profile names the existing installation administrator. Access requires that exact identity to remain eligible with its current canonical `admin` role, and applies only to the configured protected web client. Password/MFA checks and other applications' assignments remain enforced. Remove the UUID to withdraw this configured entitlement; do not renew an eight-hour bootstrap grant as a permanent login solution.

Auth-service and web-app `1.0.21` repair the follow-up login flow: successful password logins and MFA prompts no longer consume the failed-login limit. Five failed attempts per account and twenty per source IP still throttle for fifteen minutes; registration retains its existing request limits. Browser callbacks with missing, expired or replaced login cookies return a German recovery page with an explicit fresh-login link. State, nonce, PKCE and session validation remain enforced, and API callers retain JSON denials.

Policy-service and web-app `1.0.22` extend `/licenses` with renewal attention, renewal/capacity filters, sorting, a filtered CSV export and confirmed catalog deletion. Renewal dates are reminders from the recorded contract, not provider-confirmed validity. Catalog writes validate costs, currency, license models and calendar dates; explicit blank/null values clear renewal dates and descriptions while omitted fields are preserved. Capacity conflicts return 409 with existing assignments retained. No schema migration or new manufacturer credential is required.

```sh
helm upgrade --install opendirectory deploy/helm/opendirectory-lite \
  --namespace opendirectory --create-namespace \
  --values deploy/helm/opendirectory-lite/values.k3s.yaml \
  --values /secure/path/opendirectory-values.private.yaml
```

The k3s values use `opendirectory.heusser.local`, the `homelab-ca-issuer` ClusterIssuer, and the `longhorn` StorageClass. The ingress sends OIDC discovery and `/oauth` requests to the OAuth provider and the remaining web traffic to Next.js.

## Scope

The existing app-store service is optional in the base chart and enabled in the k3s values. It uses the existing PostgreSQL instance, live OIDC access-state validation, and a persistent package volume. Its local catalog does not establish device management or provider-confirmed installation.

MongoDB, Grafana, Prometheus, network infrastructure, printer service, and the other enterprise add-ons from Compose are outside this core chart. Add them as separate releases after their storage, network privileges, and ingress requirements are defined.

## UI repair and redesign release (2 November 2026)

Release 1.0.12 uses web-app 1.0.12, oauth-provider 1.0.11, and the repaired gateway/backend/auth/app-store images 1.0.10. Images are built for linux/amd64 and pushed to Harbor before Helm is upgraded. Keep the per-component imageTag values in values.k3s.yaml aligned with the images actually built; choose a new version for later code changes. Do not overwrite a released tag.

The device and policy receivers must reach the release-prefixed OAuth access-state endpoint. Inventory additionally requires a current, at most five-minute-old MFA login; a 428 response is not an API outage and must not be bypassed.

See [the implementation and acceptance report](../../../docs/ui-redesign/report.html) and [the complete route/capability matrix](../../../docs/ui-redesign/capability-routes.json). Browser screenshots and full WCAG acceptance remain explicitly unverified while native computer use is unavailable.

The compact-density update uses web-app 1.0.13 (chart 0.1.17). Header, navigation, content spacing, typography and tables are smaller; other service versions retain the repair/redesign baseline. See [the compact delivery evidence](../../../docs/ui-redesign/compact-delivery.json).


Policy-service `1.0.23` adds Rust reads for an explicitly mapped Microsoft user's
license assignments, selected by `LICENSE_FULFILLMENT_READ_ENGINE=rust`. The
existing observation parser and reviewed Node write path remain authoritative.
k3s pins both disabled license workers to this image and selects Rust reads;
neither worker is enabled and no provider connection or consent is created.
The read-only probe and live-test procedure are documented in
[the Rust connector README](../../../services/connectors-rust/README.md#bound-microsoft-user-reads-8-november-2026).


Policy-service `1.0.24` includes read-only Rust clients for Google Workspace license
assignments and GitHub Copilot billed seats, plus the protected-file
`node scripts/license-provider-probe.js` connection test. Google uses service
account delegation; GitHub uses a reviewed organization token. There is no
scheduled sync, database import or automatic grant for these providers. Existing
Microsoft workers remain disabled. See
[configuration and live-test instructions](../../../services/connectors-rust/READ_PROVIDERS.md).

OAuth `1.0.28` and web `1.0.27` repair the application-register permission contract and
derive scoped OIDC group claims from current canonical memberships. The
[Rancher Generic OIDC guide](../../../docs/features/rancher-oidc.md) includes the
exact callback, reviewed CA trust, explicit assignments, and interactive login
checks. Rancher maintains its own roles and sessions; these changes do not imply
automatic external role grants or immediate revocation of existing Rancher tokens.

Web `1.0.29` adds an explicit recovery path when company-license access requires
a fresh MFA login. The page links to login and factor setup and returns to the
original license view after successful authentication. Return destinations are
restricted to local view paths and sealed into the existing state/nonce/PKCE
transaction. Backend MFA, tenant and license checks remain in force.


Policy-service `1.0.25` extends the protected manual read probe with Adobe Enterprise
product-profile members and Slack SCIM 2.0 users. Adobe checks profile ID, name and
type; Slack verifies workspace/Enterprise token context before directory access.
Both use fixed provider hosts, bounded pagination and redacted errors. Provider
credentials are not created or enabled by this release; Microsoft workers remain
disabled and no new provider daemon runs. See
[configuration and live-test instructions](../../../services/connectors-rust/READ_PROVIDERS.md).


Policy-service `1.0.26` extends the manual read probe with Atlassian Cloud directory
users and GitLab.com billable group members. Atlassian repeats an explicit directory
filter in the current search API; GitLab confirms the top-level group and validates
pagination links and counts. Existing license workers remain disabled. No new
credential, scheduled import or cloud grant is created. See
[configuration and live-test instructions](../../../services/connectors-rust/READ_PROVIDERS.md).
