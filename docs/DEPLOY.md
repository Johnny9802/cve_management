# DEPLOY

Two supported targets: **docker-compose** (the default — one host,
single replica each) and **Kubernetes** (the multi-replica path the
Sprint 4 work is built for).

## docker-compose (single host)

The repo's `docker-compose.yml` is the canonical local + portfolio
deployment. After cloning:

```bash
cp .env.example .env
# fill in: POSTGRES_PASSWORD, REDIS_PASSWORD, JWT_SECRET,
# WEBHOOK_ENC_KEY, ADMIN_EMAIL, ADMIN_PASSWORD
docker compose up -d --build
docker compose logs -f backend  # watch the lifespan
```

What you get:

* `cve-postgres` (Postgres 16) on host port 5433
* `cve-valkey` (Redis 7) on host port 6380, password-protected,
  256 MB cap, `allkeys-lru` eviction
* `cve-backend` (FastAPI) on host port 3011, JWT auth on every
  mutating route, Prometheus on `/metrics`
* `cve-frontend` (Next.js standalone) on host port 3010, AuthGate
  redirects anonymous visitors to `/login`

`docker compose up` is idempotent: alembic runs at startup
(`AUTO_MIGRATE=true`) and the admin user is seeded on a fresh
database when `ADMIN_EMAIL` + `ADMIN_PASSWORD` are set.

### Backups (compose)

Add this to host crontab:

```cron
15 3 * * * cd /path/to/repo && BACKUP_DIR=/srv/cve-backups bash scripts/backup.sh >> /var/log/cve-backup.log 2>&1
```

Restore: see `RUNBOOK.md` §6.

## Kubernetes (multi-replica)

> **Note.** The repo doesn't ship k8s manifests because they can't be
> tested without a target cluster. What follows is the deployment
> shape Sprint 4 unlocked — drop it into your IaC of choice. ADR
> 0002 will lift this into a manifests directory once a cluster is
> available.

### Backend

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: cve-backend }
spec:
  replicas: 3
  selector: { matchLabels: { app: cve-backend } }
  template:
    metadata: { labels: { app: cve-backend } }
    spec:
      containers:
        - name: backend
          image: ghcr.io/<org>/cve-management/backend:<sha>
          env:
            - { name: ENVIRONMENT, value: production }
            - { name: AUTO_MIGRATE, value: "false" }
            - name: DATABASE_URL
              valueFrom: { secretKeyRef: { name: cve-secrets, key: DATABASE_URL } }
            - name: REDIS_URL
              valueFrom: { secretKeyRef: { name: cve-secrets, key: REDIS_URL } }
            - name: JWT_SECRET
              valueFrom: { secretKeyRef: { name: cve-secrets, key: JWT_SECRET } }
            - name: WEBHOOK_ENC_KEY
              valueFrom: { secretKeyRef: { name: cve-secrets, key: WEBHOOK_ENC_KEY } }
            - name: SENTRY_DSN
              valueFrom: { secretKeyRef: { name: cve-secrets, key: SENTRY_DSN, optional: true } }
            # ALLOWED_ORIGIN, VULNCHECK_API_KEY, etc. as needed.
          ports: [{ containerPort: 8000 }]
          readinessProbe:
            httpGet: { path: /api/health/ready, port: 8000 }
            periodSeconds: 5
          livenessProbe:
            httpGet: { path: /api/health/ready, port: 8000 }
            periodSeconds: 30
          resources:
            requests: { cpu: 250m, memory: 256Mi }
            limits:   { cpu: 500m, memory: 512Mi }
      initContainers:
        - name: migrate
          image: ghcr.io/<org>/cve-management/backend:<sha>
          command: ["/opt/venv/bin/alembic", "-c", "/app/alembic.ini", "upgrade", "head"]
          env:
            - name: DATABASE_URL
              valueFrom: { secretKeyRef: { name: cve-secrets, key: DATABASE_URL } }
```

Key points:

* `replicas: 3` is safe — Sprint 4's leader election ensures cron
  jobs run on exactly one replica; the rest tick the schedule and
  skip.
* `AUTO_MIGRATE=false` paired with the `migrate` init container
  (`scripts/migrate.sh` is the docker-compose equivalent) avoids the
  multi-replica race on `alembic_version` LOCKs that's blocker R2.
* Secrets via `Secret`; never inline. Rotation is a `kubectl
  rollout restart deployment/cve-backend` after the secret update.

### Frontend

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: cve-frontend }
spec:
  replicas: 2
  selector: { matchLabels: { app: cve-frontend } }
  template:
    metadata: { labels: { app: cve-frontend } }
    spec:
      containers:
        - name: frontend
          image: ghcr.io/<org>/cve-management/frontend:<sha>
          env:
            - { name: NEXT_PUBLIC_API_URL, value: "https://api.example.com" }
            - name: NEXT_PUBLIC_SENTRY_DSN
              valueFrom: { secretKeyRef: { name: cve-secrets, key: NEXT_PUBLIC_SENTRY_DSN, optional: true } }
          ports: [{ containerPort: 3000 }]
          readinessProbe:
            httpGet: { path: /, port: 3000 }
            periodSeconds: 10
          resources:
            requests: { cpu: 100m, memory: 128Mi }
            limits:   { cpu: 250m, memory: 256Mi }
```

### Service & ingress (sketch)

```yaml
apiVersion: v1
kind: Service
metadata: { name: cve-backend }
spec:
  selector: { app: cve-backend }
  ports: [{ port: 80, targetPort: 8000 }]

# An Ingress / Gateway in front handles TLS, the WAF, and the
# /api → backend / / → frontend split. Let the platform team pick
# nginx-ingress vs Traefik vs Gateway API.
```

### HPA

CPU 60% target works because the hot path is async I/O bound:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: { name: cve-backend }
spec:
  scaleTargetRef: { apiVersion: apps/v1, kind: Deployment, name: cve-backend }
  minReplicas: 2
  maxReplicas: 8
  metrics:
    - type: Resource
      resource: { name: cpu, target: { type: Utilization, averageUtilization: 60 } }
```

### Scraping Prometheus

The backend exposes `/metrics` (no auth, no `/api` prefix). A
typical `ServiceMonitor`:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata: { name: cve-backend }
spec:
  selector: { matchLabels: { app: cve-backend } }
  endpoints: [{ port: http, path: /metrics, interval: 30s }]
```

Alert rules go in `monitoring/alerts.yml` once a Prometheus is
available (S4.11 — punted by Sprint 4).
