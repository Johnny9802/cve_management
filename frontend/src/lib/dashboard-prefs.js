'use client';

/**
 * Dashboard preference helpers.
 *
 * Stores the user's preferred default dashboard in localStorage so the
 * hub at /dashboards can offer one-click jump and (optionally) auto-redirect.
 *
 * Single key, no PII, no PII-equivalent identifier — fine to live
 * client-side until a real auth model is introduced.
 */
const KEY = 'cve.dashboard.default';

export const VALID_KEYS = ['triage', 'remediation', 'exposure', 'executive'];

export function getDefaultDashboard() {
  if (typeof window === 'undefined') return null;
  try {
    const v = window.localStorage.getItem(KEY);
    return VALID_KEYS.includes(v) ? v : null;
  } catch {
    return null;
  }
}

export function setDefaultDashboard(key) {
  if (typeof window === 'undefined') return;
  try {
    if (key && VALID_KEYS.includes(key)) {
      window.localStorage.setItem(KEY, key);
    } else {
      window.localStorage.removeItem(KEY);
    }
  } catch {
    /* ignore quota / privacy mode */
  }
}
