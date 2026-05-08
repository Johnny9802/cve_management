/**
 * E2E smoke + a11y (Sprint 3 — S3.2 / S3.3).
 *
 * Covers the happy-path login flow + asserts axe-core finds no
 * "serious" or "critical" a11y violations on the public surfaces.
 *
 * Configurable via env vars (default to the local docker-compose
 * stack):
 *   PLAYWRIGHT_BASE_URL       — http://localhost:3010 by default
 *   PLAYWRIGHT_ADMIN_EMAIL    — admin@example.com
 *   PLAYWRIGHT_ADMIN_PASSWORD — admin
 */
import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const ADMIN_EMAIL = process.env.PLAYWRIGHT_ADMIN_EMAIL || 'admin@example.com';
const ADMIN_PASSWORD = process.env.PLAYWRIGHT_ADMIN_PASSWORD || 'admin';

const SEVERE = ['serious', 'critical'];

async function expectNoSevereA11yViolations(page, label) {
  const results = await new AxeBuilder({ page })
    .disableRules([
      // FastAPI's /api/docs HTML uses a few `tabindex=-1` patterns we
      // don't control; recharts emits SVG with implicit roles. Both
      // produce false positives on rules we don't enforce.
      'scrollable-region-focusable',
    ])
    .analyze();
  const blocking = results.violations.filter((v) => SEVERE.includes(v.impact));
  if (blocking.length > 0) {
    // Print a compact summary so the CI log shows what failed.
    /* eslint-disable no-console */
    console.log(`\n[axe ${label}] ${blocking.length} severe violation(s):`);
    for (const v of blocking) {
      console.log(`  • ${v.id} (${v.impact}) — ${v.help} :: ${v.nodes.length} node(s)`);
    }
    /* eslint-enable no-console */
  }
  expect(blocking, `axe (${label}) found severe violations`).toEqual([]);
}

test.describe('CVE Management — smoke', () => {
  test('login page renders and passes axe', async ({ page }) => {
    await page.goto('/login');
    await expect(page.getByRole('heading', { name: /CVE Management/i })).toBeVisible();
    await expect(page.getByLabel(/email/i)).toBeVisible();
    await expect(page.getByLabel(/password/i)).toBeVisible();
    await expectNoSevereA11yViolations(page, 'login');
  });

  test('admin login lands on /dashboards and topbar shows the role', async ({ page }) => {
    await page.goto('/login');
    await page.getByLabel(/email/i).fill(ADMIN_EMAIL);
    await page.getByLabel(/password/i).fill(ADMIN_PASSWORD);
    await page.getByRole('button', { name: /accedi/i }).click();

    // Either /dashboards (hub) or whatever /dashboards lands on.
    await page.waitForURL(/\/dashboards/);
    await expect(page.locator('header')).toContainText(ADMIN_EMAIL);
    await expect(page.locator('header')).toContainText(/admin/i);

    await expectNoSevereA11yViolations(page, 'dashboards');
  });

  test('Findings page is reachable and accessible', async ({ page }) => {
    // Reuse the storage state from the previous test would be nicer;
    // for the smoke we just log in fresh.
    await page.goto('/login');
    await page.getByLabel(/email/i).fill(ADMIN_EMAIL);
    await page.getByLabel(/password/i).fill(ADMIN_PASSWORD);
    await page.getByRole('button', { name: /accedi/i }).click();
    await page.waitForURL(/\/dashboards/);

    await page.goto('/findings');
    await expect(page.getByRole('tab', { name: /^open$/i })).toBeVisible();
    await expectNoSevereA11yViolations(page, 'findings');
  });
});
