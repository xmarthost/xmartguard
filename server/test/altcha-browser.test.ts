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
  h = await startHarness({ trustProxy: false, captchaUrl: 'https://captcha.test' });
  const { rows: acc } = await h.pool.query('SELECT id FROM accounts LIMIT 1');
  const { rows } = await h.pool.query("INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, 'web-e2e', 'x') RETURNING id", [acc[0].id]);
  serverId = rows[0].id;
  h.hub.isOnline = () => true;
  h.hub.command = async (_id: string, action: string, params: unknown) => {
    if (action === 'captcha.pass' || action === 'captcha.ticket') passes.push(params);
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

// A phone: one tap on the box, no pointer movement (Safari on iPhones
// behind iCloud Private Relay failed the first try before 0.23.15).
browserTest('ALTCHA passes a single tap on a phone', async () => {
  const { chromium } = createRequire(import.meta.url)(PW);
  const b = await chromium.launch();
  const ctx = await b.newContext({ hasTouch: true, isMobile: true, viewport: { width: 390, height: 844 } });
  const page = await ctx.newPage();
  await page.goto(`${h.url}/v?s=${serverId}&ip=127.0.0.1&h=shop.example.com&u=/`);
  await page.locator('altcha-widget label').waitFor();
  await page.waitForTimeout(1200);
  const before = passes.length;
  await page.locator('altcha-widget label').tap();
  await page.waitForFunction(() => /ok|err/.test(document.getElementById('status')?.className ?? ''), null, { timeout: 20000 });
  expect(await page.textContent('#status')).toContain('Verified');
  expect(passes.length).toBe(before + 1);
  await b.close();
}, 60_000);

// Site mode ("the website's own address"): the server's page on the
// website frames this page; the tick happens inside the frame and the
// frame tells the website's page (postMessage), which sets the pass.
browserTest('ALTCHA waits for a real tick inside the frame on the website (site mode)', async () => {
  const { chromium } = createRequire(import.meta.url)(PW);
  const b = await chromium.launch();
  const ctx = await b.newContext({ ignoreHTTPSErrors: true });
  const nonce = '0123456789abcdef0123456789abcdef';
  const src = `https://captcha.test/v?s=${serverId}&ip=127.0.0.1&h=shop.example.com&n=${nonce}&frame=1&k=fw&u=/`;
  // The website's page (as the server serves it, simplified) and this
  // portal behind an https address, as in production.
  await ctx.route('https://shop.example.com:7743/**', (r: any) =>
    r.fulfill({ contentType: 'text/html', body: `<!doctype html><body style="margin:0"><iframe id="f" src="${src}" style="border:0;width:100vw;height:100vh"></iframe><script>window.got=[];addEventListener('message',function(e){window.got.push(e.data)})</script></body>` }),
  );
  await ctx.route('https://captcha.test/**', async (r: any) => {
    const u = new URL(r.request().url());
    // The CAPTCHA host is the only one a website may frame.
    const res = await r.fetch({ url: h.url + u.pathname + u.search, headers: { ...r.request().headers(), host: 'captcha.test' } });
    await r.fulfill({ response: res });
  });
  const page = await ctx.newPage();
  await page.goto('https://shop.example.com:7743/.xpguard/gate');
  const frame = page.frameLocator('#f');
  await frame.locator('altcha-widget label').waitFor();
  await page.waitForTimeout(3000);
  const before = passes.length;
  expect(await frame.locator('#status').textContent()).toContain('Tick the box');
  // Glowing while it waits.
  expect(await frame.locator('.altcha').evaluate((e: Element) => getComputedStyle(e).animationName)).toBe('xglow');
  await page.mouse.move(100, 100);
  await page.mouse.move(400, 300, { steps: 6 });
  await frame.locator('altcha-widget label').click();
  await page.waitForFunction(() => (window as any).got.length > 0, null, { timeout: 20000 });
  expect(await page.evaluate(() => (window as any).got)).toEqual([{ xg: 'pass', n: nonce }]);
  expect(passes.slice(before)).toEqual([{ ip: '127.0.0.1', host: 'shop.example.com', nonce }]);
  expect(await frame.locator('.altcha').evaluate((e: Element) => getComputedStyle(e).animationName)).toBe('none');
  // Recorded as an IPDB / firewall visitor.
  const { rows } = await h.pool.query("SELECT result, method, source FROM captcha_events WHERE host = 'shop.example.com' ORDER BY id DESC LIMIT 1");
  expect(rows[0]).toEqual({ result: 'passed', method: 'altcha', source: 'firewall' });
  await b.close();
}, 60_000);

// Site mode: the portal's page first checks that the browser reaches the
// website's CAPTCHA port. Reached: on to the check on the website's own
// address. Not (a VPN or network that only opens 80 and 443, Cloudflare):
// the check here, and the report says why.
browserTest('site mode goes to the website when its port answers, and records why it did not', async () => {
  const { chromium } = createRequire(import.meta.url)(PW);
  const b = await chromium.launch();
  const ctx = await b.newContext({ ignoreHTTPSErrors: true });
  await ctx.route('https://captcha.test/**', async (r: any) => {
    const u = new URL(r.request().url());
    const res = await r.fetch({ url: h.url + u.pathname + u.search, headers: { ...r.request().headers(), host: 'captcha.test' } });
    await r.fulfill({ response: res });
  });
  let reachable = true;
  const gif = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
  await ctx.route('https://shop.example.com:7743/**', (r: any) => {
    const u = new URL(r.request().url());
    if (!reachable) return r.abort('connectionrefused');
    if (u.pathname === '/.xpguard/ping.gif') return r.fulfill({ contentType: 'image/gif', body: gif });
    return r.fulfill({ contentType: 'text/html', body: '<p id="gate">gate on the website</p>' });
  });
  const link = `https://captcha.test/v?s=${serverId}&ip=127.0.0.1&h=shop.example.com&g=7743&u=/wp-login.php`;
  const page = await ctx.newPage();
  await page.goto(link);
  await page.waitForURL((u: URL) => u.href.startsWith('https://shop.example.com:7743/.xpguard/gate'), { timeout: 10000 });
  expect(page.url()).toBe('https://shop.example.com:7743/.xpguard/gate?back=/wp-login.php');
  // The port does not answer: the check here.
  reachable = false;
  await page.goto(link);
  await page.waitForURL((u: URL) => u.searchParams.get('pf') === 'e', { timeout: 10000 });
  await page.locator('altcha-widget label').waitFor();
  await page.waitForTimeout(800);
  await page.mouse.move(100, 100);
  await page.mouse.move(300, 300, { steps: 5 });
  await page.locator('altcha-widget label').click();
  await page.waitForFunction(() => /ok|err/.test(document.getElementById('status')?.className ?? ''), null, { timeout: 20000 });
  expect(await page.textContent('#status')).toContain('Verified');
  const { rows } = await h.pool.query("SELECT result, via FROM captcha_events WHERE host = 'shop.example.com' ORDER BY id DESC LIMIT 1");
  expect(rows[0]).toEqual({ result: 'passed', via: 'port-refused' });
  await b.close();
}, 60_000);
