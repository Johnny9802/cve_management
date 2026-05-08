'use client';

/**
 * Client-side route guard (Sprint 1 — S1-FE).
 *
 * Wrap a layout or page in <AuthGate> to redirect anonymous visitors
 * to /login. The guard runs only on the client, so SSR/static export
 * still works — the first paint may briefly show nothing while the
 * effect fires, hence the placeholder.
 *
 * Note: this is *not* a security boundary. Server-side authorization
 * is enforced by the backend's Depends(require_role(...)). The gate
 * exists purely to keep the UX clean (no blank dashboards behind a
 * password prompt the user hasn't seen yet).
 */
import { useEffect, useState } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { isAuthenticated } from '../../lib/auth';

export default function AuthGate({ children }) {
  const router = useRouter();
  const pathname = usePathname();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (!isAuthenticated()) {
      const next = encodeURIComponent(pathname || '/dashboards');
      router.replace(`/login?next=${next}`);
      return;
    }
    setReady(true);
  }, [router, pathname]);

  if (!ready) {
    return (
      <main className="min-h-screen bg-gray-950 flex items-center justify-center">
        <div className="text-xs text-gray-600">Verifica sessione…</div>
      </main>
    );
  }

  return children;
}
