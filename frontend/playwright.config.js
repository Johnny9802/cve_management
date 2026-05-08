/**
 * Playwright config (Sprint 3 — S3.2).
 *
 * Single-browser smoke (chromium) against a live stack. Tests assume:
 *   * frontend on http://localhost:3010 (or PLAYWRIGHT_BASE_URL),
 *   * backend on http://localhost:3011 (proxied via Next rewrite),
 *   * an admin user seeded with the credentials in PLAYWRIGHT_ADMIN_*.
 *
 * Trace + screenshot only on failure to keep the artifact small.
 *
 * In CI: kicked off only after a separate "install browsers" step, so
 * a normal lint/test run doesn't pull the 200MB chromium tarball.
 */
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 30_000,
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:3010',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
});
