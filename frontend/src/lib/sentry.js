/**
 * Frontend Sentry init (Sprint 3 — S3.6).
 *
 * Mirrors the backend posture (app/core/sentry.py): the SDK is a
 * no-op when ``NEXT_PUBLIC_SENTRY_DSN`` is empty. Errors caught by
 * the page-level ErrorBoundary are forwarded here so a single
 * configuration switches both the FastAPI side and the Next.js side
 * to "sentry on".
 *
 * PII posture:
 *   * we never call ``setUser`` with email or username;
 *   * the optional user context only carries id+role from the JWT.
 *
 * Init is idempotent — safe to call from multiple modules.
 */
import * as Sentry from '@sentry/browser';

let _ready = false;

export function initSentry() {
  if (_ready) return _ready;
  if (typeof window === 'undefined') return false;
  const dsn = process.env.NEXT_PUBLIC_SENTRY_DSN;
  if (!dsn) {
    return false;
  }
  Sentry.init({
    dsn,
    environment: process.env.NEXT_PUBLIC_ENVIRONMENT || 'development',
    sendDefaultPii: false,
    // No tracing on the browser by default — performance metrics for the
    // dashboard live on the backend's /metrics endpoint.
    tracesSampleRate: 0,
    beforeSend(event) {
      // Drop request bodies and Authorization headers belt-and-brace.
      if (event.request) {
        delete event.request.data;
        delete event.request.cookies;
        const h = event.request.headers;
        if (h && typeof h === 'object') {
          for (const k of Object.keys(h)) {
            if (/authorization|cookie|x-api-key/i.test(k)) {
              h[k] = '[scrubbed]';
            }
          }
        }
      }
      return event;
    },
  });
  _ready = true;
  return _ready;
}

export function captureError(err, ctx) {
  if (!_ready) return;
  Sentry.captureException(err, ctx ? { extra: ctx } : undefined);
}

export function setUserContext(user) {
  if (!_ready || !user) return;
  Sentry.setUser({ id: String(user.id), role: user.role });
}

export function clearUserContext() {
  if (!_ready) return;
  Sentry.setUser(null);
}
