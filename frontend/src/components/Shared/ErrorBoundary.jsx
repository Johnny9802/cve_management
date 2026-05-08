'use client';

/**
 * Page-level error boundary (Sprint 2 — S2.7).
 *
 * Wraps a dashboard subtree so a render error in one panel doesn't
 * blank the whole page. Class component because React error boundaries
 * still need ``componentDidCatch`` / ``getDerivedStateFromError`` —
 * those have no hook equivalent.
 *
 * The fallback shows the error message + a "ricarica" button. We
 * intentionally do not display the stack to the user — stacks go to
 * the console (and, in Sprint 3, Sentry).
 */
import { Component } from 'react';

export default class ErrorBoundary extends Component {
  state = { error: null };

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // eslint-disable-next-line no-console
    console.error('[ErrorBoundary]', error, info?.componentStack);
    if (typeof this.props.onError === 'function') {
      try {
        this.props.onError(error, info);
      } catch {
        /* swallow — don't error inside the error handler */
      }
    }
  }

  reset = () => this.setState({ error: null });

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    if (this.props.fallback) {
      return typeof this.props.fallback === 'function'
        ? this.props.fallback({ error, reset: this.reset })
        : this.props.fallback;
    }

    return (
      <div
        role="alert"
        className="bg-red-950/30 border border-red-800 rounded-xl p-4 text-sm text-red-200"
      >
        <p className="font-semibold mb-1">Si è verificato un errore in questa sezione.</p>
        <p className="text-xs text-red-300 mb-3 break-words">
          {error.message || 'Errore non identificato'}
        </p>
        <button
          type="button"
          onClick={this.reset}
          className="text-xs bg-red-900/50 hover:bg-red-800 text-red-100 border border-red-800 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-red-400"
        >
          Riprova
        </button>
      </div>
    );
  }
}
