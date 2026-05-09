# Performance baseline (Sprint 4 — S4.12)

`tests/perf/baseline.js` is the production sign-off load profile.

## Quick start

```bash
# 1. boot the stack
docker compose up -d

# 2. run k6 (local install)
k6 run \
  -e BASE_URL=http://localhost:3011 \
  -e ADMIN_EMAIL=admin@example.com \
  -e ADMIN_PASSWORD=admin \
  tests/perf/baseline.js

# 3. or via the official k6 image (no host install needed)
docker run --rm \
  --network cve-management-network \
  -v "$PWD/tests/perf:/scripts" \
  -e BASE_URL=http://backend:8000 \
  -e ADMIN_EMAIL=admin@example.com \
  -e ADMIN_PASSWORD=admin \
  grafana/k6 run /scripts/baseline.js
```

## What it asserts

| Path | p95 budget | Why |
|---|---|---|
| GET `/api/cves` | 500 ms | Hottest read path, paginated 20 rows |
| GET `/api/findings?status=open` | 500 ms | Triage page primary call |
| GET `/api/dashboard/triage` | 800 ms | Aggregator query, joins findings + cves |
| PATCH `/api/findings/{pid}/{cve}` | 700 ms | Includes auth + 3 inserts (UPDATE + history + audit) |
| Error rate | < 1 % | Excludes 404s (most VUs hit unseeded ids by design) |

The thresholds are budget for a single-replica `docker compose up` on
a developer laptop. In production with the same hardware they should
be 2–3× faster thanks to the connection pool warmup and the absence
of the dev `--reload` overhead.

## Profile shape

15s warm-up to 10 VUs → 60s ramp to 50 VUs → 120s sustain → 15s ramp
down. ~3 min total. Tweak `options.scenarios.baseline.stages` for a
heavier / lighter run.

## Rate limiting & the load test

The production rate limiter caps each client IP at 200 req/min — by
design, so a runaway browser tab can't take the API down. A k6 run
from a single host hits that ceiling within seconds and most
requests come back 429.

For an honest latency baseline, **drop the limiter for the duration
of the run** by flushing the slowapi keys in Redis before the test:

```bash
docker compose exec valkey valkey-cli -a "$REDIS_PASSWORD" \
  --scan --pattern 'LIMITS:*' \
  | xargs -r docker compose exec -T valkey valkey-cli -a "$REDIS_PASSWORD" DEL
```

Or temporarily relax the default in `app/core/rate_limit.py`
(`default_limits=["10000/minute"]`) and rebuild the backend. Both
approaches keep the limiter in place for production code paths;
they only affect the synthetic profile.

A k6 run executed *with* the live limiter is still useful as a
back-pressure smoke test: the app must answer 429 in single-digit
milliseconds (it does — ~5 ms p95 on the rejected calls).

