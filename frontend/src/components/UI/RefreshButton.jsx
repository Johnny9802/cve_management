'use client';
import { useState } from 'react';

/**
 * Refresh button with loading state, accessible label and a busy
 * indicator. Wraps an async onRefresh handler; resolves disabled state
 * automatically.
 */
export default function RefreshButton({ onRefresh, label = 'Aggiorna', className = '' }) {
  const [busy, setBusy] = useState(false);

  async function handleClick() {
    if (busy) return;
    setBusy(true);
    try {
      await onRefresh?.();
    } finally {
      setBusy(false);
    }
  }

  return (
    <button
      type="button"
      onClick={handleClick}
      disabled={busy}
      aria-label={label}
      aria-busy={busy}
      title={busy ? 'Aggiornamento in corso…' : label}
      className={`text-xs text-gray-400 hover:text-white border border-gray-700 px-3 py-1.5 rounded-lg transition disabled:opacity-50 inline-flex items-center gap-1 ${className}`}
    >
      <span aria-hidden className={busy ? 'inline-block animate-spin' : 'inline-block'}>↻</span>
      <span className="hidden sm:inline">{busy ? 'Aggiornamento…' : label}</span>
    </button>
  );
}
