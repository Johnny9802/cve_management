'use client';

/**
 * URL state helpers for dashboards.
 *
 * Filters live in `?key=value` query params so:
 *   - browser back/forward works,
 *   - the URL is shareable,
 *   - refresh preserves state.
 *
 * useUrlState({ kev: '', severity: '' })
 *   → returns [state, setState] where setState merges patch and pushes
 *     a new URL via Next router.
 *
 * Empty values are dropped from the URL (so a "no filter" default URL
 * is short and clean).
 */
import { useCallback, useMemo } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';

export function useUrlState(defaults = {}) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();

  const state = useMemo(() => {
    const out = { ...defaults };
    for (const k of Object.keys(defaults)) {
      const v = params.get(k);
      if (v != null && v !== '') out[k] = v;
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);

  const setState = useCallback(
    (patch) => {
      const next = new URLSearchParams(params.toString());
      for (const [k, v] of Object.entries(patch)) {
        if (v == null || v === '' || v === defaults[k]) {
          next.delete(k);
        } else {
          next.set(k, String(v));
        }
      }
      const qs = next.toString();
      router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [params, pathname, router]
  );

  const reset = useCallback(() => {
    router.replace(pathname, { scroll: false });
  }, [pathname, router]);

  return [state, setState, reset];
}

/**
 * Returns true if any value in `state` differs from `defaults`.
 * Useful to gate a "Reset" button without re-implementing the predicate.
 */
export function hasActiveState(state, defaults) {
  for (const k of Object.keys(defaults)) {
    const cur = state[k];
    const def = defaults[k];
    if (cur == null || cur === '') continue;
    if (cur !== def) return true;
  }
  return false;
}
