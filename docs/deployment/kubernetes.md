# Kubernetes / Helm Deployment

The OpenDirectory Helm chart at `deploy/helm/opendirectory/` deploys the full platform to a Kubernetes cluster. It includes 38 Deployment templates, ClusterIP Services for every workload, an Ingress, StatefulSets for PostgreSQL and RabbitMQ, and PersistentVolumeClaims for all stateful components.

## Prerequisites

- Kubernetes 1.25+
- Helm 3.10+
- An Ingress controller (nginx-ingress is the default; any controller works with `ingress.className` override)
- A `StorageClass` that supports `ReadWriteOnce` PVCs (standard on EKS, GKE, AKS, and k3s)
- 8 GB RAM and 4 CPU cores minimum across the cluster (16 GB / 8 CPU recommended for production)

## Installing the Chart

### Minimal install (defaults)

```bash
helm install opendirectory ./deploy/helm/opendirectory \
  --namespace opendirectory \
  --create-namespace \
  --set postgresql.auth.password=<db-password> \
  --set rabbitmq.auth.password=<rabbitmq-password>
```

### Recommended: use a values override file

Create `values.prod.yaml` (do not commit this file — it contains secrets):

```yaml
global:
  domain: opendirectory.example.com

postgresql:
  auth:
    password: "strong-database-password"

rabbitmq:
  auth:
    password: "strong-rabbitmq-password"

ingress:
  enabled: true
  className: nginx
  hostname: opendirectory.example.com
  tls:
    enabled: true
    secretName: opendirectory-tls
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod

auth:
  replicaCount: 2
  env:
    JWT_SECRET: "your-jwt-secret-minimum-32-chars"
    ENCRYPTION_KEY: "your-32-hex-char-key"
    LLDAP_JWT_SECRET: "your-lldap-jwt-secret"
    LLDAP_ADMIN_PASSWORD: "your-lldap-admin-password"
    NODE_ENV: production
    CORS_ORIGIN: "https://opendirectory.example.com"

apiGateway:
  replicaCount: 2
  env:
    ADMIN_USERNAME: admin
    ADMIN_PASSWORD: "your-admin-password"
    NODE_ENV: production
```

Then install:

```bash
helm install opendirectory ./deploy/helm/opendirectory \
  --namespace opendirectory \
  --create-namespace \
  --values values.prod.yaml \
  --wait \
  --timeout 15m
```

### Verify the deployment

```bash
kubectl get pods -n opendirectory
kubectl get services -n opendirectory
kubectl get ingress -n opendirectory
kubectl get pvc -n opendirectory
```

All pods should reach `Running` status within 5 minutes on a well-provisioned cluster.

---

## Helm Values Reference

All values can be overridden in your `values.prod.yaml`. The full defaults are in `deploy/helm/opendirectory/values.yaml`.

### Global

| Key | Default | Description |
|---|---|---|
| `global.image.registry` | `ghcr.io/opendirectory` | Container image registry |
| `global.image.tag` | `1.0.0` | Image tag for all services |
| `global.image.pullPolicy` | `IfNotPresent` | Kubernetes image pull policy |
| `global.imagePullSecrets` | `[]` | Image pull secrets for private registries |
| `global.nameOverride` | `""` | Override the chart name |
| `global.fullnameOverride` | `""` | Override the full release name |

### Namespace

| Key | Default | Description |
|---|---|---|
| `namespace.create` | `true` | Create the namespace if it does not exist |
| `namespace.name` | `opendirectory` | Namespace to deploy into |

### Per-Service Values

Each service has the same value structure. The table below shows the pattern; replace `<service>` with any of: `auth`, `identity`, `device`, `policy`, `monitoring`, `mdm`, `backup`, `notification`, `appStore`, `certAuthority`, `certNetwork`, `configuration`, `enterpriseDirectory`, `licenseManagement`, `networkInfra`, `oauth`, `printer`, `remoteControl`, `updateManagement`, `conditionalAccess`, `antivirus`, `auditService`, `autoRemediation`, `complianceEngine`, `deviceLifecycle`, `mobileMgmt`, `policySimulator`, `securityScanner`, `apiGateway`, `eventBus`.

| Key | Default | Description |
|---|---|---|
| `<service>.replicaCount` | `1` or `2` | Number of pod replicas |
| `<service>.image.name` | varies | Docker image name (appended to `global.image.registry`) |
| `<service>.service.type` | `ClusterIP` | Kubernetes service type |
| `<service>.service.port` | `80` | Service port (external) |
| `<service>.service.appPort` | varies | Container port the application listens on |
| `<service>.service.grpcPort` | `50051` | gRPC port (where applicable) |
| `<service>.resources.requests.cpu` | `100m` | CPU request |
| `<service>.resources.requests.memory` | `128Mi` | Memory request |
| `<service>.resources.limits.cpu` | `500m` | CPU limit |
| `<service>.resources.limits.memory` | `512Mi` | Memory limit |
| `<service>.env` | `{}` | Additional environment variables injected into the container |

Service-specific defaults:

| Service key | Default appPort | Default replicaCount |
|---|---|---|
| `apiGateway` | `3000` | `2` |
| `auth` | `3001` | `2` |
| `identity` | `3002` | `2` |
| `device` | `3003` | `1` |
| `policy` | `3004` | `1` |
| `monitoring` | `3005` | `1` |
| `mdm` | `3006` | `1` |
| `conditionalAccess` | `3007` | `1` |
| `enterpriseDirectory` | `3008` | `1` |
| `certAuthority` | `3010` | `1` |
| `certNetwork` | `3011` | `1` |
| `configuration` | `3012` | `1` |
| `licenseManagement` | `3013` | `1` |
| `networkInfra` | `3014` | `1` |
| `oauth` | `3015` | `1` |
| `printer` | `3016` | `1` |
| `remoteControl` | `3017` | `1` |
| `updateManagement` | `3018` | `1` |
| `notification` | `3020` | `1` |
| `auditService` | `3021` | `1` |
| `autoRemediation` | `3022` | `1` |
| `complianceEngine` | `3023` | `1` |
| `deviceLifecycle` | `3024` | `1` |
| `mobileMgmt` | `3025` | `1` |
| `policySimulator` | `3026` | `1` |
| `securityScanner` | `3027` | `1` |
| `appStore` | `3906` | `1` |

### Ingress

| Key | Default | Description |
|---|---|---|
| `ingress.enabled` | `true` | Deploy an Ingress resource |
| `ingress.className` | `nginx` | Ingress controller class |
| `ingress.hostname` | `opendirectory.local` | Hostname for the Ingress rule |
| `ingress.tls.enabled` | `false` | Enable TLS on the Ingress |
| `ingress.tls.secretName` | `opendirectory-tls` | Kubernetes Secret containing the TLS certificate |
| `ingress.annotations` | `{}` | Additional Ingress annotations (e.g. cert-manager, rate limiting) |

### PostgreSQL (bundled)

| Key | Default | Description |
|---|---|---|
| `postgresql.enabled` | `true` | Deploy PostgreSQL as part of the chart |
| `postgresql.image` | `postgres:15-alpine` | PostgreSQL container image |
| `postgresql.database` | `opendirectory` | Default database name |
| `postgresql.username` | `opendirectory` | Database username |
| `postgresql.auth.password` | — | **Required.** Database password |
| `postgresql.storageSize` | `10Gi` | PVC size for the data volume |
| `postgresql.storageClass` | `""` | StorageClass name; empty uses the cluster default |

### RabbitMQ (bundled)

| Key | Default | Description |
|---|---|---|
| `rabbitmq.enabled` | `true` | Deploy RabbitMQ as part of the chart |
| `rabbitmq.storageSize` | `5Gi` | PVC size for the RabbitMQ data volume |
| `rabbitmq.auth.username` | `opendirectory` | RabbitMQ username |
| `rabbitmq.auth.password` | `changeme` | **Override in production.** |

### Event Bus

| Key | Default | Description |
|---|---|---|
| `eventBus.transport` | `rabbitmq` | Transport: `rabbitmq`, `grpc`, or `memory` |
| `eventBus.grpcAddress` | `event-bus:50050` | gRPC server address |
| `eventBus.grpcServerPort` | `50050` | gRPC listen port |
| `eventBus.exchange` | `opendirectory.events` | RabbitMQ exchange name |
| `eventBus.prefetch` | `10` | RabbitMQ prefetch count per consumer |
| `eventBus.reconnectDelayMs` | `2000` | Reconnect delay on connection loss |
| `eventBus.replicaCount` | `1` | Event bus service replicas |

### Persistence

| Key | Default | Description |
|---|---|---|
| `persistence.enabled` | `true` | Enable PVCs for stateful services |
| `persistence.storageClass` | `""` | Default StorageClass; empty uses the cluster default |
| `persistence.backupStorageSize` | `50Gi` | PVC size for the backup service |
| `appStore.persistence.size` | `20Gi` | PVC size for app store packages |

### Autoscaling

Autoscaling is disabled by default. Enable it globally or override per-service.

| Key | Default | Description |
|---|---|---|
| `autoscaling.enabled` | `false` | Enable HorizontalPodAutoscaler for all services |
| `autoscaling.minReplicas` | `1` | Minimum replicas per HPA |
| `autoscaling.maxReplicas` | `10` | Maximum replicas per HPA |
| `autoscaling.targetCPUUtilizationPercentage` | `70` | CPU target for scale-out |
| `autoscaling.targetMemoryUtilizationPercentage` | `80` | Memory target for scale-out |

To enable HPA for specific services only:

```yaml
autoscaling:
  enabled: false     # keep global off

auth:
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 8
    targetCPUUtilizationPercentage: 60
```

### Pod Disruption Budget

| Key | Default | Description |
|---|---|---|
| `podDisruptionBudget.enabled` | `true` | Create PodDisruptionBudgets for critical services |

---

## Using an External PostgreSQL

To use a managed PostgreSQL service (Amazon RDS, Google Cloud SQL, Azure Database for PostgreSQL):

```yaml
postgresql:
  enabled: false   # do not deploy the bundled PostgreSQL

# Set the external connection details via service environment variables
auth:
  env:
    DB_HOST: "my-postgres.region.rds.amazonaws.com"
    DB_PORT: "5432"
    DB_NAME: "opendirectory"
    DB_USER: "opendirectory"
    DB_PASSWORD: "your-rds-password"

device:
  env:
    DB_HOST: "my-postgres.region.rds.amazonaws.com"
    DB_PASSWORD: "your-rds-password"
# ... repeat for each service that uses PostgreSQL
```

For easier management across services, use an external secrets operator (e.g. External Secrets Operator with AWS Secrets Manager) to inject the password into a Kubernetes Secret and reference it from all service definitions.

---

## Configuring Ingress with TLS

### Using cert-manager (Let's Encrypt)

Install cert-manager first:

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
```

Create a ClusterIssuer:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
      - http01:
          ingress:
            class: nginx
```

Then in `values.prod.yaml`:

```yaml
ingress:
  enabled: true
  className: nginx
  hostname: opendirectory.example.com
  tls:
    enabled: true
    secretName: opendirectory-tls
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
```

### Using a pre-existing TLS Secret

```bash
kubectl create secret tls opendirectory-tls \
  --cert=path/to/cert.pem \
  --key=path/to/key.pem \
  -n opendirectory
```

Then set `ingress.tls.enabled=true` and `ingress.tls.secretName=opendirectory-tls`.

---

## Resource Requests and Limits Guidance

The chart ships conservative defaults suitable for a development cluster. For production, tune based on observed usage.

**Recommended production minimums:**

| Tier | Service examples | CPU request | Memory request | CPU limit | Memory limit |
|---|---|---|---|---|---|
| High traffic | api-gateway, auth, device | `200m` | `256Mi` | `1000m` | `1Gi` |
| Medium | policy, compliance-engine, audit | `100m` | `128Mi` | `500m` | `512Mi` |
| Low | printer, license, network | `50m` | `64Mi` | `200m` | `256Mi` |
| Databases | postgresql, rabbitmq | `250m` | `512Mi` | `1000m` | `2Gi` |

Set resources in `values.prod.yaml`:

```yaml
auth:
  resources:
    requests:
      cpu: "200m"
      memory: "256Mi"
    limits:
      cpu: "1000m"
      memory: "1Gi"
```

---

## Persistent Volume Claims

The chart creates the following PVCs:

| PVC name | Default size | Used by |
|---|---|---|
| `postgresql-data` | `10Gi` | PostgreSQL data directory |
| `rabbitmq-data` | `5Gi` | RabbitMQ messages and exchange config |
| `app-store-data` | `20Gi` | Enterprise app store packages |
| `backup-data` | `50Gi` | Backup service archives |

To change the storage class for all PVCs:

```yaml
persistence:
  storageClass: "fast-ssd"
```

---

## Horizontal Pod Autoscaler

Enable HPA globally to allow the cluster to scale all services automatically:

```yaml
autoscaling:
  enabled: true
  minReplicas: 1
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
```

Verify HPAs after installation:

```bash
kubectl get hpa -n opendirectory
```

The Metrics Server must be installed in the cluster for HPA to function:

```bash
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
```

---

## Upgrading

```bash
helm upgrade opendirectory ./deploy/helm/opendirectory \
  --namespace opendirectory \
  --values values.prod.yaml \
  --wait
```

Helm performs a rolling update by default — each Deployment's pods are replaced one at a time. Services with `replicaCount: 1` will have a brief downtime window; increase replicas before upgrading if this is unacceptable.

---

## Uninstalling

```bash
# Remove the release (keeps PVCs by default)
helm uninstall opendirectory --namespace opendirectory

# Delete PVCs to free storage (destructive — all data is lost)
kubectl delete pvc --all -n opendirectory

# Delete the namespace
kubectl delete namespace opendirectory
```

---

## Troubleshooting

### Pod is in CrashLoopBackOff

```bash
kubectl logs <pod-name> -n opendirectory --previous
kubectl describe pod <pod-name> -n opendirectory
```

Common causes: missing required environment variable (especially `DB_PASSWORD`, `JWT_SECRET`, or `ENCRYPTION_KEY`); PostgreSQL or RabbitMQ not yet ready (add `initContainers` with a `pg_isready` check if needed).

### Ingress returns 404

```bash
kubectl describe ingress opendirectory -n opendirectory
kubectl logs -n ingress-nginx deployment/ingress-nginx-controller
```

Verify the `ingress.className` matches your installed controller.

### PVC stuck in Pending

```bash
kubectl describe pvc <pvc-name> -n opendirectory
```

The most common cause is no StorageClass defined in the cluster. Set `persistence.storageClass` to an existing class name.
