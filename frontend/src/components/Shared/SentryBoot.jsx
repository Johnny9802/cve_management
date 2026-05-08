'use client';

/**
 * Mount-once side-effect component that boots Sentry on the client.
 * Placed in the root layout so the SDK is ready before any page
 * mounts; runs once per browser session.
 *
 * Renders nothing.
 */
import { useEffect } from 'react';
import { initSentry, setUserContext } from '../../lib/sentry';
import { getCurrentUser } from '../../lib/auth';

export default function SentryBoot() {
  useEffect(() => {
    if (initSentry()) {
      setUserContext(getCurrentUser());
    }
  }, []);
  return null;
}
