'use client';

/**
 * Login page (Sprint 1 — S1-FE).
 *
 * Uses raw axios via `lib/api.login()` so the bearer interceptor
 * isn't triggered (no token to attach yet, and a 401 on login must
 * stay 401 — no refresh-then-retry attempt).
 *
 * After success: tokens stored in localStorage via setSession, user
 * profile fetched via /api/auth/me (so the role and id are
 * authoritative — never trust a value that came back inside
 * `/login`'s body for authorization decisions), then we navigate to
 * the `next` query param if present, else `/dashboards`.
 *
 * The form is wrapped in <Suspense> because `useSearchParams()` would
 * otherwise force the whole page out of static prerender in Next.js
 * 14 / 15.
 */
import { Suspense, useState, useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { fetchMe, login } from '../../lib/api';
import { isAuthenticated, setSession } from '../../lib/auth';

export default function LoginPage() {
  return (
    <Suspense fallback={<LoginShell><div className="text-xs text-gray-600 text-center">…</div></LoginShell>}>
      <LoginForm />
    </Suspense>
  );
}

function LoginForm() {
  const router = useRouter();
  const search = useSearchParams();
  const next = search.get('next') || '/dashboards';

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  // If a session is already present, don't show the form — bounce.
  useEffect(() => {
    if (isAuthenticated()) router.replace(next);
  }, [router, next]);

  async function onSubmit(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      const tokens = await login(email.trim().toLowerCase(), password);
      setSession(tokens);
      const me = await fetchMe();
      setSession({ user: me });
      router.replace(next);
    } catch (err) {
      const status = err?.response?.status;
      if (status === 401) setError('Email o password errate.');
      else if (status === 429) setError('Troppi tentativi. Riprova tra un minuto.');
      else setError(err?.response?.data?.detail || err?.message || 'Errore di rete.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <LoginShell>
      <form
        onSubmit={onSubmit}
        className="space-y-4"
        aria-describedby={error ? 'login-error' : undefined}
      >
          <div>
            <label htmlFor="email" className="block text-xs text-gray-400 mb-1">
              Email
            </label>
            <input
              id="email"
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={busy}
              className="w-full bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 disabled:opacity-60"
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-xs text-gray-400 mb-1">
              Password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              minLength={1}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={busy}
              className="w-full bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 disabled:opacity-60"
            />
          </div>

          {error && (
            <p
              id="login-error"
              role="alert"
              className="text-xs text-red-400 bg-red-950/30 border border-red-900/50 rounded px-2 py-1.5"
            >
              {error}
            </p>
          )}

        <button
          type="submit"
          disabled={busy || !email || !password}
          className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-800 disabled:text-gray-500 text-white text-sm font-semibold py-2 rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:ring-offset-2 focus:ring-offset-gray-900"
        >
          {busy ? 'Accesso in corso…' : 'Accedi'}
        </button>
      </form>
    </LoginShell>
  );
}

function LoginShell({ children }) {
  return (
    <main className="min-h-screen bg-gray-950 flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-6">
          <h1 className="text-xl font-bold text-white">CVE Management</h1>
          <p className="text-xs text-gray-500 mt-1">Accedi per continuare</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
          {children}
        </div>
        <p className="text-[11px] text-gray-600 mt-4 text-center">
          Sessione locale · token JWT 60 min · refresh 7 giorni
        </p>
      </div>
    </main>
  );
}
