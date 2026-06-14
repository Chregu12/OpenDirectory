# Installation

This guide covers three ways to install OpenDirectory: Docker Compose (recommended for evaluation and small deployments), Kubernetes with Helm (recommended for production), and local development mode.

## Prerequisites

| Requirement | Minimum | Notes |
|---|---|---|
| Docker | 20.10+ | Required for Docker Compose and building images |
| Docker Compose | 2.0+ | Bundled with Docker Desktop |
| Node.js | 18+ | Required for local development only |
| Kubernetes | 1.25+ | Required for Helm install |
| Helm | 3.10+ | Required for Kubernetes install |
| CPU | 4 cores | 8 recommended for full stack |
| RAM | 8 GB | 16 GB recommended |
| Disk | 20 GB | More if running the app store or backup service |

---

## Option A: Docker Compose

Docker Compose is the fastest path to a running system. All services, databases, and the message broker start from a single command.

### 1. Clone the repository

```bash
git clone https://github.com/Chregu12/OpenDirectory
cd OpenDirectory
```

### 2. Create your environment file

```bash
cp .env.example .env
```

Open `.env` and set every variable that has no default. At a minimum you must supply:

```bash
# Generate strong passwords — do not reuse these examples
DB_PASSWORD=$(openssl rand -base64 32)
MONGO_PASSWORD=$(openssl rand -base64 32)
REDIS_PASSWORD=$(openssl rand -base64 32)
RABBITMQ_PASSWORD=$(openssl rand -base64 32)
LLDAP_JWT_SECRET=$(openssl rand -base64 64)
LLDAP_ADMIN_PASSWORD=$(openssl rand -base64 32)
JWT_SECRET=$(openssl rand -base64 64)
ENCRYPTION_KEY=$(openssl rand -hex 16)   # must be exactly 32 hex chars
ADMIN_PASSWORD=$(openssl rand -base64 24)
```

You can run the above in a shell and paste the output into `.env`, or use `openssl rand` to generate individual values.

### 3. Start the stack

```bash
docker compose up -d
```

First-time startup takes 3–5 minutes because Docker pulls all images and PostgreSQL initialises its schemas.

### 4. Verify services are healthy

```bash
docker compose ps
```

All containers should show `healthy` or `running`. If any service is restarting, check logs:

```bash
docker compose logs <service-name> --tail 50
```

### 5. Access the platform

| Interface | URL | Notes |
|---|---|---|
| Frontend UI | http://localhost:3000 | Next.js app |
| API Gateway | http://localhost:8080 | All REST APIs |
| RabbitMQ Management | http://localhost:15672 | User: `opendirectory` |
| PostgreSQL | localhost:5432 | User: `opendirectory` |

Log in to the UI with the `ADMIN_USERNAME` and `ADMIN_PASSWORD` values from your `.env`.

### Stopping and restarting

```bash
# Stop services (preserve volumes)
docker compose down

# Stop and delete all data
docker compose down -v
```

---

## Option B: Kubernetes with Helm

The Helm chart deploys all 30+ services as Kubernetes Deployments in the `opendirectory` namespace, along with PostgreSQL, RabbitMQ, and the required PVCs.

### 1. Add the Helm repository or use the local chart

The chart is included in the repository under `deploy/helm/opendirectory/`.

```bash
git clone https://github.com/Chregu12/OpenDirectory
cd OpenDirectory
```

### 2. Create a values override file

Create `values.prod.yaml` to override secrets and domain settings. Do not commit this file.

```yaml
# values.prod.yaml
global:
  domain: opendirectory.example.com

postgresql:
  auth:
    password: "your-strong-db-password"

rabbitmq:
  auth:
    password: "your-strong-rabbitmq-password"

ingress:
  enabled: true
  className: nginx
  hostname: opendirectory.example.com
  tls:
    enabled: true
    secretName: opendirectory-tls

# Increase replicas for high-availability
auth:
  replicaCount: 3
apiGateway:
  replicaCount: 3
```

### 3. Create the namespace and install

```bash
kubectl create namespace opendirectory

helm install opendirectory ./deploy/helm/opendirectory \
  --namespace opendirectory \
  --values values.prod.yaml \
  --wait \
  --timeout 10m
```

### 4. Verify the deployment

```bash
# Check all pods are running
kubectl get pods -n opendirectory

# Check services
kubectl get services -n opendirectory

# Check ingress
kubectl get ingress -n opendirectory
```

### 5. Access the platform

If TLS is enabled in ingress, the UI is available at `https://opendirectory.example.com`. For a quick test without DNS:

```bash
kubectl port-forward service/api-gateway 8080:80 -n opendirectory &
kubectl port-forward service/frontend 3000:80 -n opendirectory &
```

Then open http://localhost:3000.

### Upgrading

```bash
helm upgrade opendirectory ./deploy/helm/opendirectory \
  --namespace opendirectory \
  --values values.prod.yaml
```

### Uninstalling

```bash
helm uninstall opendirectory --namespace opendirectory
# Delete PVCs if you want to remove all data
kubectl delete pvc --all -n opendirectory
```

---

## Option C: Local Development

Running services individually is useful for contributing to or debugging a specific service.

### 1. Install dependencies

```bash
# Install all workspace dependencies
npm install
```

### 2. Start infrastructure

You need PostgreSQL, Redis, MongoDB, and RabbitMQ running locally. The easiest approach is to start only the infrastructure containers with Docker Compose:

```bash
docker compose up -d postgres redis mongodb rabbitmq lldap
```

### 3. Configure environment

Copy `.env.example` to `.env` and set the database passwords to match whatever Docker Compose started with. The service URLs should point to `localhost`.

### 4. Start a service

```bash
cd services/core/authentication-service
npm run dev
```

Or start multiple services from the repo root with npm workspaces:

```bash
npm run dev --workspace=services/core/authentication-service
npm run dev --workspace=services/core/device-service
```

### 5. Start the frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend runs on http://localhost:3000 and proxies API requests to the API gateway at http://localhost:8080.

---

## Post-Install Checklist

After completing any of the installation options above, work through this checklist before putting the system into production use:

- [ ] **Change default passwords** — Update `ADMIN_PASSWORD`, database passwords, and `RABBITMQ_PASSWORD` from their defaults
- [ ] **Set `JWT_SECRET`** — Must be at least 32 characters; use `openssl rand -base64 64`
- [ ] **Configure `DOMAIN_NAME`** — Set the Active Directory realm (default `OPENDIRECTORY.LOCAL`); this must match your DNS
- [ ] **Set `ENCRYPTION_KEY`** — Required for encrypting secrets at rest; must be exactly 32 hex characters
- [ ] **Configure TLS** — Set up a TLS certificate for your domain; in Kubernetes update `ingress.tls`
- [ ] **Restrict CORS** — Set `CORS_ORIGIN` to your frontend hostname; default `*` is insecure
- [ ] **Set `NODE_ENV=production`** — Enables secure HTTP headers and disables debug output
- [ ] **Review ROADMAP.md** — The quick-actions service (port 3950) currently has no authentication; do not expose it to untrusted networks
- [ ] **Import existing users** — If migrating from another directory, use the LDAP import endpoint at `POST /api/directory/import` on enterprise-directory
- [ ] **Configure email (SMTP)** — Set `SMTP_HOST`, `SMTP_USER`, and `SMTP_PASSWORD` for password-reset and PIM approval notifications
- [ ] **Set up monitoring** — Prometheus scrapes all `/metrics` endpoints; configure Grafana dashboards against those endpoints
