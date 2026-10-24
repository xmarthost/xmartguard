import { afterAll, beforeAll, expect, it } from 'vitest';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';

// A real browser (Playwright's Chromium, where installed): the ALTCHA box
// waits for a person's click; a script ticking it is refused.
const PW = process.env.PLAYWRIGHT_PATH ?? '/opt/node-tools/node_modules/playwright/index.js';
const browserTest = existsSync(PW) ? it : it.skip;
import { Client, startHarness, type Harness } from './helpers.js';

let h: Harness;
let serverId = '';
const passes: unknown[] = [];
beforeAll(async () => {
  h = await startHarness({ trustProxy: false });
  const { rows: acc } = await h.pool.query('SELECT id FROM accounts LIMIT 1');
  const { rows } = await h.pool.query("INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, 'web-e2e', 'x') RETURNING id", [acc[0].id]);
  serverId = rows[0].id;
  h.hub.isOnline = () => true;
  h.hub.command = async (_id: string, action: string, params: unknown) => {
    if (action === 'captcha.pass') passes.push(params);
    if (action === 'captcha.host') return { hosted: true };
    return { ok: true };
  };
  const admin = new Client(h.url);
  await admin.login();
  await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '', secret_key: '', minutes: 60, provider: 'altcha' });
});
afterAll(async () => h.close());

browserTest('ALTCHA waits for a real tick', async () => {
  const { chromium } = createRequire(import.meta.url)(PW);
  const b = await chromium.launch();
  const page = await b.newPage();
  await page.goto(`${h.url}/v?s=${serverId}&ip=127.0.0.1&h=shop.example.com&u=/wp-login.php`);
  await page.waitForTimeout(4000);
  expect(passes).toHaveLength(0);
  const status = (await page.textContent('#status')) ?? '';
  expect(status).toContain('Tick the box');
  await page.mouse.move(100, 100);
  await page.mouse.move(200, 220, { steps: 5 });
  await page.locator('altcha-widget label').click();
  await page.waitForFunction(() => document.getElementById('status')?.className.includes('ok') || document.getElementById('status')?.className.includes('err'), null, { timeout: 20000 });
  expect(await page.textContent('#status')).toContain('Verified');
  expect(passes).toHaveLength(1);
  // A script ticking the box (no real click) is refused.
  const bot = await b.newPage();
  await bot.goto(`${h.url}/v?s=${serverId}&ip=127.0.0.2&h=shop.example.com&u=/wp-login.php`);
  await bot.waitForSelector('altcha-widget');
  await bot.waitForTimeout(1500);
  await bot.evaluate(() => (document.querySelector('altcha-widget') as any).shadowRoot?.querySelector('input[type=checkbox]')?.click() ?? (document.querySelector('altcha-widget input[type=checkbox]') as HTMLInputElement).click());
  await bot.waitForFunction(() => /ok|err/.test(document.getElementById('status')?.className ?? ''), null, { timeout: 20000 });
  expect(await bot.textContent('#status')).toContain('tick the box yourself');
  expect(passes).toHaveLength(1);
  await b.close();
}, 60_000);
