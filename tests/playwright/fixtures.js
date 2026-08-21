import { test as base, chromium } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EXTENSION_PATH = path.resolve(__dirname, '../../');

/**
 * Extends Playwright's `test` with a persistent Chromium context that has
 * the unpacked CyberSentinel extension loaded, plus the resolved
 * extension id and its MV3 service worker handle.
 *
 * MV3 extensions require headed Chromium (headless: false / "new" headless
 * modes do not reliably expose extension service workers as of Chromium
 * 128), and must be loaded via --load-extension on a persistent profile
 * rather than through context.addInitScript or a normal browser launch.
 */
export const test = base.extend({
  context: async ({}, use) => {
    const userDataDir = mkdtempSync(path.join(tmpdir(), 'cybersentinel-pw-'));
    const context = await chromium.launchPersistentContext(userDataDir, {
      headless: false,
      args: [
        `--disable-extensions-except=${EXTENSION_PATH}`,
        `--load-extension=${EXTENSION_PATH}`,
        '--no-first-run'
      ]
    });
    await use(context);
    await context.close();
  },
  extensionId: async ({ context }, use) => {
    let [worker] = context.serviceWorkers();
    if (!worker) worker = await context.waitForEvent('serviceworker', { timeout: 15_000 });
    const extensionId = worker.url().split('/')[2];
    await use(extensionId);
  },
  serviceWorker: async ({ context }, use) => {
    let [worker] = context.serviceWorkers();
    if (!worker) worker = await context.waitForEvent('serviceworker', { timeout: 15_000 });
    await use(worker);
  }
});

export const expect = base.expect;
