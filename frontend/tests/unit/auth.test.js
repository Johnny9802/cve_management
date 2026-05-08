import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  clearSession,
  getAccessToken,
  getCurrentUser,
  getRefreshToken,
  isAuthenticated,
  setSession,
} from '../../src/lib/auth';

describe('auth token store', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });
  afterEach(() => {
    clearSession();
  });

  it('starts unauthenticated', () => {
    expect(isAuthenticated()).toBe(false);
    expect(getAccessToken()).toBeNull();
    expect(getRefreshToken()).toBeNull();
    expect(getCurrentUser()).toBeNull();
  });

  it('setSession + isAuthenticated round-trip', () => {
    setSession({
      access_token: 'a.b.c',
      refresh_token: 'r1',
      user: { id: 1, email: 'a@b.c', role: 'admin' },
    });
    expect(isAuthenticated()).toBe(true);
    expect(getAccessToken()).toBe('a.b.c');
    expect(getRefreshToken()).toBe('r1');
    expect(getCurrentUser()).toMatchObject({
      id: 1,
      email: 'a@b.c',
      role: 'admin',
    });
  });

  it('clearSession wipes everything', () => {
    setSession({
      access_token: 'a',
      refresh_token: 'r',
      user: { id: 9, role: 'viewer' },
    });
    clearSession();
    expect(isAuthenticated()).toBe(false);
    expect(getCurrentUser()).toBeNull();
  });

  it('partial updates only overwrite the keys they pass', () => {
    setSession({
      access_token: 'a1',
      refresh_token: 'r1',
      user: { id: 1, role: 'admin' },
    });
    setSession({ user: { id: 1, role: 'analyst' } });
    expect(getAccessToken()).toBe('a1');     // unchanged
    expect(getCurrentUser()?.role).toBe('analyst');
  });

  it('survives malformed user JSON', () => {
    window.localStorage.setItem('cve.user', 'not-json');
    expect(getCurrentUser()).toBeNull();
  });
});
