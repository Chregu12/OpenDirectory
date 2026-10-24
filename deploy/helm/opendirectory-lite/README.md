# OpenDirectory Lite Helm Chart

This chart packages the core services from `docker-compose.lite.yml` for one Kubernetes release: PostgreSQL, Redis, LLDAP, the identity/auth/device/policy/OAuth services, the API, the web app, and the licensing API and workers.

## Before installation

Build and push the application images to a private Harbor project. The default repository is `harbor.heusser.local/opendirectory`; override it in a values file for another registry. The cluster needs an image pull Secret named `harbor-opendirectory`.

The applications consume Kubernetes Secrets named `opendirectory-runtime` and `opendirectory-files`. You can create them manually before install, or enable the optional ESO synchronization below. The chart never puts secret values in Helm values or rendered manifests.

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

After initialization and unsealing, authenticate interactively and configure OpenBao. Keep the CLI token in a local file with owner-only permissions. While the initial root token is active, configure Kubernetes auth and the Vaultwarden sync; the configuration helper can use your existing Vaultwarden account and prompts for its master password without echoing it or passing it on the command line. Create an operator token, save it in your existing password manager, and then revoke the initial root token:

```sh
umask 077
export BAO_TOKEN_PATH="$(mktemp)"
bao login -no-print
./deploy/k8s/openbao/configure-kubernetes-auth.sh
./deploy/k8s/openbao/configure-vaultwarden-plugin.sh
./deploy/k8s/openbao/install-bitwarden-token-renewer.sh
bao token create -policy=opendirectory-operator -orphan -period=24h
bao token revoke -self
bao login -no-print
```

The first `bao login` prompts for the initial root token; the final login prompts for the operator token. The Vaultwarden plugin account must use PBKDF2-SHA256 and have no two-step login because the plugin cannot handle MFA. The helper stores the password inside OpenBao's encrypted storage and creates a short-lived, read-only token scoped to OpenDirectory application secrets. A Kubernetes CronJob replaces that token twice monthly. Install or upgrade the OpenDirectory chart with ESO enabled so it creates the required ServiceAccounts, then apply `deploy/k8s/openbao/cluster-secret-store.yaml`. Apply `cluster-secret-store-harbor-rotation.yaml` only after enabling Harbor rotation and creating the `opendirectory-harbor-api-reader` ServiceAccount.

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
helm upgrade --install opendirectory deploy/helm/opendirectory-lite \
  --namespace opendirectory --create-namespace \
  --values deploy/helm/opendirectory-lite/values.k3s.yaml \
  --values /secure/path/opendirectory-values.private.yaml
```

The k3s values use `opendirectory.heusser.local`, the `homelab-ca-issuer` ClusterIssuer, and the `longhorn` StorageClass. The ingress sends OIDC discovery and `/oauth` requests to the OAuth provider and the remaining web traffic to Next.js.

## Scope

MongoDB, Grafana, Prometheus, network infrastructure, printer service, and enterprise add-ons from Compose are outside this core chart. Add them as separate releases after their storage, network privileges, and ingress requirements are defined.
