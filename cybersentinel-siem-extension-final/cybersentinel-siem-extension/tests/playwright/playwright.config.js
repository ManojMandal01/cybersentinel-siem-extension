import { defineConfig } from '@playwright/test';

// MV3 extensions can only be exercised in a real (non-headless) Chromium
// instance launched with --load-extension, so this config intentionally
// does not use Playwright's default browser fixtures. See fixtures.js.
export default defineConfig({
  testDir: '.',
  testMatch: '*.spec.js',
  timeout: 30_000,
  retries: process.env.CI ? 1 : 0,
  workers: 1, // extension tests share one persistent browser profile
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  use: {
    trace: 'retain-on-failure'
  }
});
