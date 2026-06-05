# OpenDirectory Helm Chart

Deploys the full OpenDirectory Enterprise Identity & Device Management platform on Kubernetes.

## Quick Start

```bash
# Install with defaults
helm install opendirectory ./deploy/helm/opendirectory

# Install with production overrides
helm install opendirectory ./deploy/helm/opendirectory \
  -f deploy/helm/opendirectory/values.yaml \
  -f deploy/helm/opendirectory/values.prod.yaml \
  --set ingress.hostname=opendirectory.example.com

# Upgrade
helm upgrade opendirectory ./deploy/helm/opendirectory -f values.prod.yaml
```

## Components

| Component          | Default Port | Default Replicas |
|--------------------|-------------|-----------------|
| api-gateway        | 3000        | 2               |
| authentication     | 3001        | 2               |
| identity           | 3002        | 2               |
| device             | 3003        | 1               |
| policy             | 3004        | 1               |
| monitoring         | 3005        | 1               |
| mdm                | 3006        | 1               |
| backup             | 3011        | 1               |
| postgresql         | 5432        | 1 (StatefulSet) |

## Configuration

Key values to override for production:

```yaml
global:
  image:
    registry: your-registry.example.com
    tag: "1.2.3"

ingress:
  hostname: opendirectory.example.com
  tls:
    enabled: true
    secretName: opendirectory-tls

postgresql:
  storageSize: "100Gi"
  storageClass: "fast-ssd"

autoscaling:
  enabled: true
```

## Secrets

The chart ships placeholder secrets. Before deploying to production:

1. Replace values in `templates/secret.yaml`, or
2. Use [External Secrets Operator](https://external-secrets.io/) / [Sealed Secrets](https://sealed-secrets.netlify.app/) to inject real credentials.

## Monitoring

All pods expose `/metrics` on port 9090. Enable Prometheus scraping:

```yaml
prometheusAnnotations:
  enabled: true
```
