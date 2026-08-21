import { test, expect } from './fixtures.js';

test.describe('CyberSentinel extension bootstrap', () => {
  test('service worker registers and exposes a stable extension id', async ({ extensionId }) => {
    expect(extensionId).toMatch(/^[a-p]{32}$/);
  });

  test('service worker responds to GET_CONFIG without throwing', async ({ serviceWorker }) => {
    const config = await serviceWorker.evaluate(async () => {
      return await new Promise((resolve) => chrome.runtime.sendMessage({ type: 'GET_CONFIG' }, resolve));
    });
    expect(config).toBeTruthy();
    expect(config.detection).toBeDefined();
  });
});

test.describe('SOC dashboard', () => {
  test('dashboard loads with all primary views reachable', async ({ context, extensionId }) => {
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/dashboard/dashboard.html`);
    await expect(page.locator('.brand')).toContainText('CyberSentinel');

    for (const view of ['executive', 'analyst', 'timeline', 'hunting', 'iocs', 'incidentgraph', 'settings']) {
      await page.click(`.nav-link[data-view="${view}"]`);
      await expect(page.locator(`#view-${view}`)).toHaveClass(/active/);
    }
  });

  test('MITRE heatmap renders technique cells', async ({ context, extensionId }) => {
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/dashboard/dashboard.html`);
    await page.click('.nav-link[data-view="analyst"]');
    await expect(page.locator('#mitreHeatmap .heatmap-cell').first()).toBeVisible({ timeout: 10_000 });
    const cellCount = await page.locator('#mitreHeatmap .heatmap-cell').count();
    expect(cellCount).toBeGreaterThan(0);
  });

  test('IOC Explorer search and filters are present and interactive', async ({ context, extensionId }) => {
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/dashboard/dashboard.html`);
    await page.click('.nav-link[data-view="iocs"]');
    await expect(page.locator('#iocSearch')).toBeVisible();
    await page.fill('#iocSearch', 'nonexistent-value-zzz');
    await expect(page.locator('#iocTable')).toContainText('No data', { timeout: 5000 });
    await page.fill('#iocSearch', '');
  });

  test('Incident Graph view renders without a stored incident (empty state)', async ({ context, extensionId }) => {
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/dashboard/dashboard.html`);
    await page.click('.nav-link[data-view="incidentgraph"]');
    await expect(page.locator('#incidentGraph')).toBeVisible();
  });
});
