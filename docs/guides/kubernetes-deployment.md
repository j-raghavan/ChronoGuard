# Kubernetes Deployment Guide

Complete guide for deploying ChronoGuard on Kubernetes clusters.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Detailed Deployment Steps](#detailed-deployment-steps)
4. [Configuration](#configuration)
5. [Production Considerations](#production-considerations)
6. [Monitoring and Observability](#monitoring-and-observability)
7. [Troubleshooting](#troubleshooting)
8. [Upgrade Guide](#upgrade-guide)

## Prerequisites

### Cluster Requirements

- Kubernetes 1.24 or higher
- At least 4 CPU cores and 8GB RAM available across nodes
- Persistent volume provisioner (for database storage)
- Ingress controller (Nginx or Traefik)

### Tools Required

```bash
# Check versions
kubectl version --client
helm version  # optional, for cert-manager

# Verify cluster access
kubectl cluster-info
kubectl get nodes
```

### Ingress Controller Installation

**Nginx Ingress:**
```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.1/deploy/static/provider/cloud/deploy.yaml

# Verify installation
kubectl get pods -n ingress-nginx
```

**Traefik Ingress:**
```bash
helm repo add traefik https://traefik.github.io/charts
helm install traefik traefik/traefik -n traefik --create-namespace

# Verify installation
kubectl get pods -n traefik
```

## Quick Start

### 1. Generate Secrets

```bash
cd /path/to/ChronoGuard
./scripts/generate-k8s-secrets.sh
```

This interactive script will:
- Generate strong random passwords
- Create Kubernetes secret manifests
- Encode TLS certificates (if provided)

### 2. Build and Push Container Images

```bash
# Build API image
cd backend
docker build -t your-registry.com/chronoguard-api:latest .
docker push your-registry.com/chronoguard-api:latest

# Build Dashboard image
cd ../frontend
docker build -t your-registry.com/chronoguard-dashboard:latest .
docker push your-registry.com/chronoguard-dashboard:latest
```

### 3. Update Image References

Edit these files to use your images:
- `deployments/kubernetes/deployments/api.yaml` (lines 46, 63)
- `deployments/kubernetes/deployments/dashboard.yaml` (line 18)

### 4. Deploy with Kustomize

```bash
kubectl apply -k deployments/kubernetes/
```

### 5. Verify Deployment

```bash
# Check pods
kubectl get pods -n chronoguard

# Check services
kubectl get svc -n chronoguard

# Check ingress
kubectl get ingress -n chronoguard
```

## Detailed Deployment Steps

### Step 1: Create Namespace

```bash
kubectl apply -f deployments/kubernetes/namespace.yaml
```

### Step 2: Create Secrets

```bash
# Generate from templates
cd deployments/kubernetes/secrets/

# Database secrets
cp database-secrets.yaml.template database-secrets.yaml
# Edit and set CHRONOGUARD_DB_PASSWORD

# App secrets
cp app-secrets.yaml.template app-secrets.yaml
# Edit and set CHRONOGUARD_SECURITY_SECRET_KEY and CHRONOGUARD_INTERNAL_SECRET

# TLS secrets (for Envoy mTLS)
cp tls-secrets.yaml.template tls-secrets.yaml
# Add your base64-encoded certificates

# Apply secrets
kubectl apply -f database-secrets.yaml
kubectl apply -f app-secrets.yaml
kubectl apply -f tls-secrets.yaml
```

**Generating Secrets:**
```bash
# Database password (32+ chars)
openssl rand -base64 32

# JWT secret key (43+ chars)
python3 -c "import secrets; print(secrets.token_urlsafe(43))"

# Internal secret (32+ chars)
openssl rand -base64 32
```

### Step 3: Deploy Storage

```bash
kubectl apply -f deployments/kubernetes/storage/
```

**Verify PVC binding:**
```bash
kubectl get pvc -n chronoguard
# STATUS should show "Bound"
```

### Step 4: Deploy ConfigMaps

```bash
kubectl apply -f deployments/kubernetes/configmaps/
```

### Step 5: Deploy Database (PostgreSQL)

```bash
kubectl apply -f deployments/kubernetes/deployments/postgres.yaml

# Wait for ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=database -n chronoguard --timeout=300s
```

### Step 6: Deploy Redis

```bash
kubectl apply -f deployments/kubernetes/deployments/redis.yaml

# Wait for ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=cache -n chronoguard --timeout=120s
```

### Step 7: Deploy OPA Policy Engine

```bash
kubectl apply -f deployments/kubernetes/deployments/opa.yaml

# Wait for ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=policy-engine -n chronoguard --timeout=120s
```

### Step 8: Deploy FastAPI Backend

```bash
kubectl apply -f deployments/kubernetes/deployments/api.yaml

# Wait for ready (migrations run in init container)
kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=api -n chronoguard --timeout=300s
```

**Check migrations:**
```bash
# View init container logs
kubectl logs -n chronoguard <api-pod-name> -c db-migrations
```

### Step 9: Deploy Envoy Proxy

```bash
kubectl apply -f deployments/kubernetes/deployments/envoy.yaml

# Wait for ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=proxy -n chronoguard --timeout=120s
```

### Step 10: Deploy Dashboard

```bash
kubectl apply -f deployments/kubernetes/deployments/dashboard.yaml

# Wait for ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=dashboard -n chronoguard --timeout=120s
```

### Step 11: Deploy Services

```bash
kubectl apply -f deployments/kubernetes/services/services.yaml
```

### Step 12: Deploy Ingress

```bash
# For Nginx Ingress
kubectl apply -f deployments/kubernetes/ingress/nginx-ingress.yaml

# OR for Traefik Ingress
kubectl apply -f deployments/kubernetes/ingress/traefik-ingress.yaml
```

**Update host:**
Edit the ingress file and replace `chronoguard.example.com` with your actual domain.

## Configuration

### Environment-Specific Configuration

Use Kustomize overlays for different environments:

```bash
# Create environment-specific directory
mkdir -p deployments/kubernetes/overlays/production

# Create kustomization.yaml
cat > deployments/kubernetes/overlays/production/kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

bases:
  - ../../

# Override replicas for production
replicas:
  - name: api
    count: 3
  - name: opa
    count: 2
  - name: envoy
    count: 3

# Production-specific patches
patchesStrategicMerge:
  - production-resources.yaml
EOF

# Deploy production config
kubectl apply -k deployments/kubernetes/overlays/production/
```

### Resource Tuning

Edit deployment manifests to adjust CPU/memory:

```yaml
resources:
  requests:
    cpu: "500m"
    memory: "512Mi"
  limits:
    cpu: "2000m"
    memory: "2Gi"
```

### Storage Class

Specify storage class in PVC manifests:

```yaml
spec:
  storageClassName: fast-ssd  # your storage class
```

## Production Considerations

### 1. High Availability

**Database:**
- Use managed PostgreSQL (AWS RDS, GCP Cloud SQL, Azure Database)
- Or deploy PostgreSQL with replication using operators (Zalando, CrunchyData)

**Redis:**
- Use managed Redis (AWS ElastiCache, GCP Memorystore, Azure Cache)
- Or deploy Redis Sentinel/Cluster

**Replicas:**
```bash
# Scale services
kubectl scale deployment api -n chronoguard --replicas=3
kubectl scale deployment opa -n chronoguard --replicas=2
kubectl scale deployment envoy -n chronoguard --replicas=3
kubectl scale deployment dashboard -n chronoguard --replicas=2
```

### 2. TLS/SSL Configuration

**Option 1: cert-manager with Let's Encrypt**

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create ClusterIssuer
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: your-email@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF

# Update ingress with annotation:
# cert-manager.io/cluster-issuer: "letsencrypt-prod"
```

**Option 2: Bring Your Own Certificate**

```bash
kubectl create secret tls chronoguard-tls \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key \
  -n chronoguard
```

### 3. Network Policies

Restrict pod-to-pod communication:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-network-policy
  namespace: chronoguard
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: api
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app.kubernetes.io/component: dashboard
    - podSelector:
        matchLabels:
          app.kubernetes.io/component: policy-engine
    ports:
    - protocol: TCP
      port: 8000
  egress:
  - to:
    - podSelector:
        matchLabels:
          app.kubernetes.io/component: database
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - podSelector:
        matchLabels:
          app.kubernetes.io/component: cache
    ports:
    - protocol: TCP
      port: 6379
```

### 4. Pod Security

Enable Pod Security Standards:

```bash
kubectl label namespace chronoguard \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

### 5. Resource Quotas

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: chronoguard-quota
  namespace: chronoguard
spec:
  hard:
    requests.cpu: "10"
    requests.memory: "20Gi"
    limits.cpu: "20"
    limits.memory: "40Gi"
    persistentvolumeclaims: "5"
```

### 6. Backup and Disaster Recovery

**Database Backups:**

```bash
# Manual backup
kubectl exec postgres-0 -n chronoguard -- \
  pg_dump -U chronoguard chronoguard | gzip > backup.sql.gz

# Restore
gunzip < backup.sql.gz | \
  kubectl exec -i postgres-0 -n chronoguard -- \
  psql -U chronoguard chronoguard
```

**Automated Backups with CronJob:**

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgres-backup
  namespace: chronoguard
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: postgres:15
            command:
            - /bin/bash
            - -c
            - pg_dump -h postgres-service -U chronoguard chronoguard | gzip > /backup/backup-$(date +%Y%m%d-%H%M%S).sql.gz
            env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: chronoguard-db-secret
                  key: CHRONOGUARD_DB_PASSWORD
            volumeMounts:
            - name: backup-storage
              mountPath: /backup
          volumes:
          - name: backup-storage
            persistentVolumeClaim:
              claimName: backup-pvc
          restartPolicy: OnFailure
```

## Monitoring and Observability

### Prometheus Metrics

All services expose `/metrics` endpoints. Add ServiceMonitors:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: chronoguard
  namespace: chronoguard
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: chronoguard
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
```

### Grafana Dashboards

Import pre-built dashboards:
- FastAPI metrics: Dashboard ID 16250
- PostgreSQL: Dashboard ID 9628
- Redis: Dashboard ID 11835
- Envoy: Dashboard ID 11021

### Logging

**Fluentd/Fluent Bit:**

```bash
# Deploy Fluent Bit as DaemonSet
helm repo add fluent https://fluent.github.io/helm-charts
helm install fluent-bit fluent/fluent-bit \
  --namespace logging --create-namespace
```

**Elasticsearch + Kibana:**

```bash
# Deploy EFK stack
helm repo add elastic https://helm.elastic.co
helm install elasticsearch elastic/elasticsearch -n logging
helm install kibana elastic/kibana -n logging
```

### Distributed Tracing

**Jaeger:**

```bash
kubectl create namespace observability
kubectl apply -f https://github.com/jaegertracing/jaeger-operator/releases/download/v1.47.0/jaeger-operator.yaml -n observability

# Deploy Jaeger instance
cat <<EOF | kubectl apply -f -
apiVersion: jaegertracing.io/v1
kind: Jaeger
metadata:
  name: jaeger
  namespace: chronoguard
spec:
  strategy: production
  storage:
    type: elasticsearch
EOF
```

## Troubleshooting

### Common Issues

#### 1. Pods Stuck in Pending

```bash
# Check events
kubectl describe pod <pod-name> -n chronoguard

# Common causes:
# - Insufficient cluster resources
# - PVC not binding (check storage class)
# - Image pull issues
```

#### 2. ImagePullBackOff

```bash
# Check image pull errors
kubectl describe pod <pod-name> -n chronoguard

# Solutions:
# - Verify image exists: docker pull <image>
# - Check registry credentials
# - Create image pull secret if private registry
```

#### 3. CrashLoopBackOff

```bash
# Check logs
kubectl logs <pod-name> -n chronoguard

# For init containers:
kubectl logs <pod-name> -n chronoguard -c <init-container-name>

# Common causes:
# - Missing or incorrect secrets
# - Database connection failure
# - Application configuration errors
```

#### 4. Service Not Accessible

```bash
# Test service connectivity from within cluster
kubectl run test-pod --image=curlimages/curl -i --rm --restart=Never -- \
  curl http://api-service.chronoguard.svc.cluster.local:8000/health

# Check endpoints
kubectl get endpoints -n chronoguard
```

#### 5. Database Connection Issues

```bash
# Test database connectivity
kubectl exec -it <api-pod> -n chronoguard -- \
  pg_isready -h postgres-service -U chronoguard

# Check database logs
kubectl logs postgres-0 -n chronoguard
```

### Health Check Commands

```bash
# API health
kubectl port-forward -n chronoguard svc/api-service 8000:8000
curl http://localhost:8000/health

# OPA health
kubectl port-forward -n chronoguard svc/opa-service 8181:8181
curl http://localhost:8181/health

# Envoy admin
kubectl port-forward -n chronoguard svc/envoy-service 9901:9901
curl http://localhost:9901/ready

# Database
kubectl exec postgres-0 -n chronoguard -- \
  psql -U chronoguard -d chronoguard -c "SELECT version();"

# Redis
kubectl exec <redis-pod> -n chronoguard -- redis-cli ping
```

## Upgrade Guide

### Rolling Updates

```bash
# Update image tag
kubectl set image deployment/api \
  api=your-registry.com/chronoguard-api:v0.2.0 \
  -n chronoguard

# Check rollout status
kubectl rollout status deployment/api -n chronoguard

# Rollback if needed
kubectl rollout undo deployment/api -n chronoguard
```

### Database Migrations

```bash
# Migrations run automatically in init container
# To run manually:
kubectl exec -it <api-pod> -n chronoguard -- \
  alembic upgrade head
```

### Zero-Downtime Upgrades

1. **Update API and Dashboard** (stateless):
   ```bash
   kubectl set image deployment/api api=new-image:tag -n chronoguard
   kubectl set image deployment/dashboard dashboard=new-image:tag -n chronoguard
   ```

2. **Update OPA** (rolling update):
   ```bash
   kubectl set image deployment/opa opa=openpolicyagent/opa:latest-envoy -n chronoguard
   ```

3. **Update Database** (requires downtime for major versions):
   - Backup database first
   - Scale down dependent services
   - Perform upgrade
   - Run migrations
   - Scale up services

## Best Practices

1. **Use Namespaces**: Isolate environments (dev, staging, prod)
2. **Resource Limits**: Always set requests and limits
3. **Health Checks**: Configure readiness and liveness probes
4. **Secrets Management**: Use external secret managers in production
5. **Monitoring**: Set up alerts for pod restarts, high CPU/memory
6. **Backups**: Automate database backups with retention policy
7. **Documentation**: Maintain runbooks for common operations
8. **Testing**: Test deployments in staging before production
9. **GitOps**: Use ArgoCD or Flux for declarative deployments
10. **Security Scanning**: Scan images for vulnerabilities

## Cloud-Specific Notes

### AWS EKS

```yaml
# Use gp3 storage class
storageClassName: gp3

# Use Network Load Balancer for Envoy
annotations:
  service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
```

### GCP GKE

```yaml
# Use pd-ssd storage class
storageClassName: pd-ssd

# Use Internal Load Balancer
annotations:
  cloud.google.com/load-balancer-type: "Internal"
```

### Azure AKS

```yaml
# Use managed-premium storage class
storageClassName: managed-premium

# Use Standard Load Balancer
annotations:
  service.beta.kubernetes.io/azure-load-balancer-internal: "false"
```

## Support

For additional help:
- GitHub Issues: https://github.com/j-raghavan/ChronoGuard/issues
- Documentation: ../../docs/
- Community: GitHub Discussions
