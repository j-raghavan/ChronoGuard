# ChronoGuard Kubernetes Deployment

This directory contains production-ready Kubernetes manifests for deploying ChronoGuard.

## Quick Start

### Prerequisites

- Kubernetes cluster (v1.24+)
- `kubectl` configured with cluster access
- Persistent volume provisioner
- Ingress controller (Nginx or Traefik)

### 1. Generate Secrets

```bash
# Navigate to the project root
cd ../../

# Run the secret generation script
./scripts/generate-k8s-secrets.sh

# Or manually create secrets from templates:
cd deployments/kubernetes/secrets/
cp database-secrets.yaml.template database-secrets.yaml
cp app-secrets.yaml.template app-secrets.yaml
cp tls-secrets.yaml.template tls-secrets.yaml

# Edit each file and replace CHANGEME values
# Then apply:
kubectl apply -f database-secrets.yaml
kubectl apply -f app-secrets.yaml
kubectl apply -f tls-secrets.yaml
```

### 2. Update Image References

Edit the following files to reference your container registry:

- `deployments/api.yaml` - Line 46, 63: Replace `<YOUR_REGISTRY>/chronoguard-api:latest`
- `deployments/dashboard.yaml` - Line 18: Replace `<YOUR_REGISTRY>/chronoguard-dashboard:latest`

### 3. Deploy with Kustomize (Recommended)

```bash
# Deploy all resources at once
kubectl apply -k deployments/kubernetes/

# Verify deployment
kubectl get pods -n chronoguard
kubectl get svc -n chronoguard
```

### 4. Deploy Manually (Alternative)

```bash
cd deployments/kubernetes/

# Apply in order:
kubectl apply -f namespace.yaml
kubectl apply -f secrets/  # (after creating from templates)
kubectl apply -f configmaps/
kubectl apply -f storage/
kubectl apply -f deployments/
kubectl apply -f services/
kubectl apply -f ingress/nginx-ingress.yaml  # or traefik-ingress.yaml
```

### 5. Access the Dashboard

```bash
# Get the ingress address
kubectl get ingress -n chronoguard

# Or use port-forwarding for testing:
kubectl port-forward -n chronoguard svc/dashboard-service 3000:80

# Access at: http://localhost:3000
```

## Directory Structure

```
kubernetes/
├── README.md                    # This file
├── namespace.yaml               # Namespace definition
├── kustomization.yaml           # Kustomize deployment config
├── configmaps/                  # Configuration files
│   ├── envoy-config.yaml
│   ├── opa-config.yaml
│   ├── opa-policies.yaml
│   └── nginx-config.yaml
├── secrets/                     # Secret templates
│   ├── database-secrets.yaml.template
│   ├── app-secrets.yaml.template
│   └── tls-secrets.yaml.template
├── storage/                     # Persistent volumes
│   ├── postgres-pvc.yaml
│   └── redis-pvc.yaml
├── deployments/                 # Workload definitions
│   ├── postgres.yaml            # StatefulSet
│   ├── redis.yaml
│   ├── opa.yaml
│   ├── api.yaml
│   ├── envoy.yaml
│   └── dashboard.yaml
├── services/                    # Service definitions
│   └── services.yaml            # All 6 services
└── ingress/                     # Ingress examples
    ├── nginx-ingress.yaml
    └── traefik-ingress.yaml
```

## Service Architecture

```
┌─────────────────────────────────────────────────┐
│                 External Traffic                │
│            (Agents with mTLS certs)             │
└──────────────┬──────────────────────────────────┘
               │
               ↓ port 8080
     ┌─────────────────────┐
     │   envoy-service     │ (LoadBalancer)
     │   (Envoy Proxy)     │
     └──────────┬──────────┘
                │
        ┌───────┴───────┬──────────────────┐
        │               │                  │
        ↓               ↓                  ↓
  ┌──────────┐   ┌──────────┐      ┌──────────┐
  │ opa-svc  │   │ api-svc  │      │dash-svc  │
  │ (OPA)    │   │(FastAPI) │      │(Nginx)   │
  └──────────┘   └─────┬────┘      └──────────┘
                       │
           ┌───────────┴──────────┐
           │                      │
           ↓                      ↓
    ┌──────────┐          ┌──────────┐
    │postgres  │          │  redis   │
    │ -service │          │ -service │
    └──────────┘          └──────────┘
```

## Configuration

### Resource Requirements

| Service | CPU Request | Memory Request | CPU Limit | Memory Limit |
|---------|-------------|----------------|-----------|--------------|
| Postgres | 500m | 1Gi | 2000m | 4Gi |
| Redis | 100m | 256Mi | 500m | 512Mi |
| OPA | 100m | 128Mi | 500m | 512Mi |
| API | 200m | 256Mi | 1000m | 1Gi |
| Envoy | 200m | 128Mi | 1000m | 512Mi |
| Dashboard | 50m | 64Mi | 200m | 256Mi |

### Scaling

```bash
# Scale API backend
kubectl scale deployment api -n chronoguard --replicas=3

# Scale Envoy proxy
kubectl scale deployment envoy -n chronoguard --replicas=3

# Scale OPA policy engine
kubectl scale deployment opa -n chronoguard --replicas=2
```

## Troubleshooting

### Check Pod Status
```bash
kubectl get pods -n chronoguard
kubectl describe pod <pod-name> -n chronoguard
kubectl logs <pod-name> -n chronoguard
```

### Check Service Endpoints
```bash
kubectl get endpoints -n chronoguard
```

### Test Database Connectivity
```bash
kubectl exec -it postgres-0 -n chronoguard -- psql -U chronoguard -d chronoguard -c "SELECT version();"
```

### Test API Health
```bash
kubectl port-forward -n chronoguard svc/api-service 8000:8000
curl http://localhost:8000/health
```

### Common Issues

1. **Pods stuck in Pending**: Check PVC binding and node resources
2. **ImagePullBackOff**: Verify image registry access and image names
3. **CrashLoopBackOff**: Check logs and ensure secrets are properly configured
4. **Service not accessible**: Verify ingress controller is installed and configured

## External Database

To use a managed PostgreSQL database (RDS, Cloud SQL, etc.):

1. Remove the `postgres` deployment and service
2. Remove the `postgres-pvc` storage
3. Update the API deployment environment variables:
   ```yaml
   - name: CHRONOGUARD_DB_HOST
     value: "your-rds-endpoint.amazonaws.com"
   ```

## Security Considerations

- **Secrets Management**: Consider using external secret managers (Vault, AWS Secrets Manager, etc.)
- **Network Policies**: Implement network policies to restrict pod-to-pod communication
- **RBAC**: Configure proper role-based access control
- **TLS**: Enable TLS for ingress (production requirement)
- **Pod Security**: Enable Pod Security Standards (restricted profile recommended)

## Monitoring

### Prometheus Integration

All services expose Prometheus metrics:

```yaml
# Add to your Prometheus scrape config
- job_name: 'chronoguard'
  kubernetes_sd_configs:
  - role: pod
    namespaces:
      names:
      - chronoguard
  relabel_configs:
  - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
    action: keep
    regex: true
```

### Health Checks

All deployments include readiness and liveness probes:

- Postgres: `pg_isready`
- Redis: `redis-cli ping`
- OPA: `GET /health`
- API: `GET /health`
- Envoy: `GET /ready`
- Dashboard: `GET /`

## Further Documentation

For detailed deployment guide with production considerations, see:
[docs/guides/kubernetes-deployment.md](../../docs/guides/kubernetes-deployment.md)

## Support

For issues or questions:
- GitHub Issues: https://github.com/j-raghavan/ChronoGuard/issues
- Documentation: ../../docs/
