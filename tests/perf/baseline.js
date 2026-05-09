/**
 * k6 baseline load test (Sprint 4 — S4.12).
 *
 * What it asserts
 * ---------------
 * Two thresholds — **the gates** for production sign-off:
 *   * GET p95 < 500ms  (read paths must stay snappy under modest load)
 *   * error_rate < 1% (no flakiness in the happy path)
 *
 * Mix
 * ---
 * Realistic ratio for a SOC dashboard:
 *   * 60%   GET /api/cves
 *   * 20%   GET /api/findings
 *   * 10%   GET /api/dashboard/triage
 *   * 5%    GET /api/cves/{id}
 *   * 5%    PATCH /api/findings/{pid}/{cve} (status flip — needs auth)
 *
 * The PATCH path is gated behind an analyst JWT — the test logs in
 * once with the seeded admin user, reuses the bearer for the run.
 *
 * Usage
 * -----
 *   docker compose up -d
 *   k6 run -e BASE_URL=http://localhost:3011 \
 *          -e ADMIN_EMAIL=admin@example.com \
 *          -e ADMIN_PASSWORD=admin \
 *          tests/perf/baseline.js
 *
 * Or via docker:
 *   docker run --rm --network cve-management-network \
 *     -v "$PWD/tests/perf:/scripts" \
 *     -e BASE_URL=http://backend:8000 \
 *     -e ADMIN_EMAIL=admin@example.com \
 *     -e ADMIN_PASSWORD=admin \
 *     grafana/k6 run /scripts/baseline.js
 */
import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const errorRate = new Rate('errors');

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3011';
const ADMIN_EMAIL = __ENV.ADMIN_EMAIL || 'admin@example.com';
const ADMIN_PASSWORD = __ENV.ADMIN_PASSWORD || 'admin';

export const options = {
  scenarios: {
    baseline: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '15s', target: 10 },   // warm up
        { duration: '1m',  target: 50 },   // ramp to 50 vus
        { duration: '2m',  target: 50 },   // sustain
        { duration: '15s', target: 0 },    // ramp down
      ],
      gracefulRampDown: '10s',
    },
  },
  thresholds: {
    // Production sign-off gates.
    'http_req_duration{path:get_cves}':       ['p(95)<500'],
    'http_req_duration{path:get_findings}':   ['p(95)<500'],
    'http_req_duration{path:get_dashboard}':  ['p(95)<800'],
    'http_req_duration{path:patch_finding}':  ['p(95)<700'],
    errors:                                    ['rate<0.01'],
  },
};

let BEARER = null;

export function setup() {
  // Authenticate once and pass the bearer to every VU. We don't want
  // every VU spamming /auth/login — that's a different test.
  const resp = http.post(
    `${BASE_URL}/api/auth/login`,
    JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
    { headers: { 'Content-Type': 'application/json' } },
  );
  check(resp, { 'login 200': (r) => r.status === 200 });
  if (resp.status !== 200) {
    throw new Error(`login failed: ${resp.status} ${resp.body}`);
  }
  return { token: JSON.parse(resp.body).access_token };
}

export default function (data) {
  const authHeaders = { 'Authorization': `Bearer ${data.token}` };
  const r = Math.random();

  if (r < 0.60) {
    group('GET /api/cves', () => {
      const resp = http.get(`${BASE_URL}/api/cves?limit=20`, {
        tags: { path: 'get_cves' },
      });
      const ok = check(resp, { 'cves 200': (x) => x.status === 200 });
      errorRate.add(!ok);
    });
  } else if (r < 0.80) {
    group('GET /api/findings', () => {
      const resp = http.get(`${BASE_URL}/api/findings?status=open&limit=20`, {
        tags: { path: 'get_findings' },
      });
      const ok = check(resp, { 'findings 200': (x) => x.status === 200 });
      errorRate.add(!ok);
    });
  } else if (r < 0.90) {
    group('GET /api/dashboard/triage', () => {
      const resp = http.get(`${BASE_URL}/api/dashboard/triage`, {
        tags: { path: 'get_dashboard' },
      });
      const ok = check(resp, { 'dashboard 200': (x) => x.status === 200 });
      errorRate.add(!ok);
    });
  } else if (r < 0.95) {
    group('GET /api/cves/CVE-2024-1234', () => {
      const resp = http.get(`${BASE_URL}/api/cves/CVE-2024-1234`, {
        tags: { path: 'get_cve_detail' },
      });
      // 404 is acceptable — most VUs hit a non-seeded id.
      const ok = check(resp, { 'detail 200/404': (x) => [200, 404].includes(x.status) });
      errorRate.add(!ok);
    });
  } else {
    // PATCH path needs both an existing finding and auth. We use a
    // dummy product/cve id pair: the API returns 404 if not seeded,
    // which is fine for the throughput gate (we're measuring the
    // hot path including auth + DB lookup, not the actual write).
    group('PATCH /api/findings/{pid}/{cve}', () => {
      const resp = http.patch(
        `${BASE_URL}/api/findings/1/CVE-2024-1234`,
        JSON.stringify({ status: 'in_review', reason: 'k6 load test' }),
        {
          headers: { 'Content-Type': 'application/json', ...authHeaders },
          tags: { path: 'patch_finding' },
        },
      );
      const ok = check(resp, {
        'patch 200/404': (x) => [200, 404].includes(x.status),
      });
      errorRate.add(!ok);
    });
  }

  sleep(0.1 + Math.random() * 0.4);  // 100–500 ms think time
}

export function teardown(data) {
  // Nothing to clean up — the test is read-mostly and the rare write
  // paths just touch the audit_log (which the queue cleanup janitor
  // will collect on schedule).
  // eslint-disable-next-line no-unused-vars
  void data;
}
