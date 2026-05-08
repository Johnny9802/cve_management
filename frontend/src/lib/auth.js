/**
 * Token store for the JWT auth flow (Sprint 1 — S1-FE).
 *
 * Trade-off: tokens live in `localStorage`, not an httpOnly cookie.
 * The decision is documented in docs/adr/0001-auth-strategy.md.
 * Reasoning in one line: the strict CSP shipped in S1.6 makes XSS
 * the only realistic exfil vector, and the platform never renders
 * user-controlled HTML, so the trade-off favours zero-CSRF surface
 * and a static Next.js standalone build that doesn't need server
 * sessions.
 *
 * If we ever add user-generated HTML, switch to an httpOnly Secure
 * SameSite=Strict cookie — the rest of this module is the only thing
 * that needs to change.
 */
const ACCESS_KEY = 'cve.access_token';
const REFRESH_KEY = 'cve.refresh_token';
const USER_KEY = 'cve.user';

function safeStorage() {
  // SSR / Next.js server components have no window; calls must no-op.
  if (typeof window === 'undefined') return null;
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

export function getAccessToken() {
  return safeStorage()?.getItem(ACCESS_KEY) ?? null;
}

export function getRefreshToken() {
  return safeStorage()?.getItem(REFRESH_KEY) ?? null;
}

export function getCurrentUser() {
  const raw = safeStorage()?.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function setSession({ access_token, refresh_token, user }) {
  const s = safeStorage();
  if (!s) return;
  if (access_token) s.setItem(ACCESS_KEY, access_token);
  if (refresh_token) s.setItem(REFRESH_KEY, refresh_token);
  if (user) s.setItem(USER_KEY, JSON.stringify(user));
}

export function clearSession() {
  const s = safeStorage();
  if (!s) return;
  s.removeItem(ACCESS_KEY);
  s.removeItem(REFRESH_KEY);
  s.removeItem(USER_KEY);
}

export function isAuthenticated() {
  return Boolean(getAccessToken());
}
