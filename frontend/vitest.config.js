/**
 * Vitest config (Sprint 3 — S3.1).
 *
 * jsdom environment so React Testing Library can render components,
 * a small setup file that wires @testing-library/jest-dom matchers
 * and stubs out browser APIs we don't have in jsdom (matchMedia +
 * ResizeObserver — recharts touches both).
 *
 * Globs intentionally exclude E2E tests so `npm test` doesn't try to
 * spin up Playwright when we want fast unit feedback.
 */
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./tests/vitest.setup.js'],
    include: ['tests/unit/**/*.{test,spec}.{js,jsx}'],
    exclude: ['tests/e2e/**', 'node_modules/**'],
    css: false,
  },
});
