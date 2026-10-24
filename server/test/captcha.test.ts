import crypto from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';
import { envelopeMessage } from '../src/agent-sign.js';
import { allowOtherAddress, altchaAllowed, humanTick, altchaKeysFor, egressNetwork, hostingCheck, noteAltchaPass, offlineWait, parseParams, sameNetwork, shownIP, turnstile } from '../src/routes/captcha.js';

let h: Harness;
let admin: Client;
let serverId = '';
const keys = crypto.generateKeyPairSync('ed25519');
const pub = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
const passes: unknown[] = [];
let online = true;
let agentError = '';
// What the server answers to "is this website yours?" (undefined: an agent without the command).
let hostAnswer: (host: string) => boolean | undefined = (host) => host !== 'paypal.com';
let realVerify: typeof turnstile.verify;

beforeAll(async () => {
  h = await startHarness({ captchaUrl: 'https://captcha.example.org', trustProxy: true });
  const { rows: acc } = await h.pool.query('SELECT id FROM accounts LIMIT 1');
  const { rows } = await h.pool.query("INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, 'web-captcha', $2) RETURNING id", [acc[0].id, pub]);
  serverId = rows[0].id;
  admin = new Client(h.url);
  await admin.login();
  h.hub.isOnline = () => online;
  h.hub.command = async (_id: string, action: string, params: unknown) => {
    if (action === 'captcha.pass') {
      if (agentError) throw new Error(agentError);
      passes.push(params);
    }
    if (action === 'captcha.host') {
      const hosted = hostAnswer((params as { host: string }).host);
      return hosted === undefined ? { ok: true } : { hosted };
    }
    return { ok: true };
  };
  realVerify = turnstile.verify.bind(turnstile);
  turnstile.verify = async (_secret: string, token: string) => token === 'good-token';
});

afterAll(async () => {
  await h.close();
});

async function agent(path: string, payload: unknown) {
  const raw = JSON.stringify(payload);
  const ts = String(Math.floor(Date.now() / 1000));
  const signature = crypto.sign(null, Buffer.from(envelopeMessage(serverId, ts, raw)), keys.privateKey).toString('base64');
  const r = await fetch(h.url + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ server_id: serverId, ts, signature, payload: raw }) });
  return { status: r.status, body: await r.json() };
}

// A person's tick on the ALTCHA box (see humanTick).
const HU = JSON.stringify({ t: 1500, m: 12, k: 0, tr: true, tc: false });

const link = () => `/v?s=${serverId}&ip=203.0.113.5&h=shop.example.com&u=/wp-login.php?redirect_to=/wp-admin/&reauth=1`;

async function verify(body: Record<string, string>, ip = '203.0.113.5') {
  const r = await h.app.inject({ method: 'POST', url: '/v/verify', headers: { 'x-forwarded-for': ip }, payload: body });
  return { status: r.statusCode, body: r.json() };
}

describe('CAPTCHA page for suspicious visitors', () => {
  it('reads the page the WAF appends unescaped', () => {
    expect(parseParams('/v?s=a&ip=1.2.3.4&h=x.org&u=/wp-login.php?redirect_to=/a&b=c')).toEqual({ s: 'a', ip: '1.2.3.4', h: 'x.org', u: '/wp-login.php?redirect_to=/a&b=c', preview: false, n: '', frame: false, k: '', g: 0, design: undefined });
    expect(parseParams('/v?s=a&ip=1.2.3.4&h=X.ORG').u).toBe('/');
  });

  it('is off until the Turnstile keys are saved', async () => {
    const g = await admin.req('GET', '/api/captcha');
    expect(g.body.config).toEqual({ enabled: false, site_key: '', secret_set: false, minutes: 720, provider: 'auto', strict_ip: false, design: 'classic', countdown: 5, site_servers: [], ipdb_captcha: '' });
    expect(g.body.url).toBe('https://captcha.example.org/v');
    const page = await h.app.inject({ method: 'GET', url: link() });
    expect(page.statusCode).toBe(503);
    expect(page.body).toContain('not available right now');
    const noKeys = await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '', secret_key: '', minutes: 720, provider: 'turnstile' });
    expect(noKeys.status).toBe(400);
    expect((await agent('/api/agent/captcha/config', { version: 0 })).body.unchanged).toBe(true);
  });

  it('saves the keys (secret never shown) and gives servers the setting', async () => {
    const put = await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '0x4AAAAAAAtestSiteKey', secret_key: '0x4AAAAAAAsecret', minutes: 60 });
    expect(put.status).toBe(200);
    expect(put.body.version).toBe(1);
    const g = await admin.req('GET', '/api/captcha');
    expect(g.body.config).toEqual({ enabled: true, site_key: '0x4AAAAAAAtestSiteKey', secret_set: true, minutes: 60, provider: 'auto', strict_ip: false, design: 'classic', countdown: 5, site_servers: [], ipdb_captcha: '' });
    expect(JSON.stringify(g.body)).not.toContain('0x4AAAAAAAsecret');
    // Saving without a secret keeps the saved one.
    expect((await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '0x4AAAAAAAtestSiteKey', secret_key: '', minutes: 60 })).status).toBe(200);
    const a = await agent('/api/agent/captcha/config', { version: 0 });
    expect(a.body.config).toEqual({ version: 2, enabled: true, url: 'https://captcha.example.org/v', minutes: 60, mode: '' });
  });

  it('shows the branded page with the site, the address and the check', async () => {
    const page = await h.app.inject({ method: 'GET', url: link(), headers: { 'x-forwarded-for': '203.0.113.5' } });
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain('shop.example.com');
    expect(page.body).toContain('is protected by <b>xPGuard</b>');
    expect(page.body).toContain('Your IP address is <b>203.0.113.5</b>');
    expect(page.body).toContain('0x4AAAAAAAtestSiteKey');
    expect(page.body).not.toContain('0x4AAAAAAAsecret');
    expect(page.headers['content-security-policy']).toContain('challenges.cloudflare.com');
    expect(page.headers['x-robots-tag']).toContain('noindex');
    // Bad links: no check.
    for (const bad of [`/v?s=${serverId}&ip=x&h=shop.example.com&u=/`, `/v?s=${serverId}&ip=1.2.3.4&h=<script>&u=/`, `/v?s=${serverId}&ip=1.2.3.4&h=a.org&u=evil.com`, '/v?s=nope&ip=1.2.3.4&h=a.org&u=/']) {
      const r = await h.app.inject({ method: 'GET', url: bad });
      expect(r.statusCode, bad).toBe(400);
      expect(r.body).not.toContain('<script>&');
    }
  });

  it('keeps one slash for pages opened with a double slash (site.com//wp-admin/)', async () => {
    const r = await h.app.inject({ method: 'GET', url: `/v?s=${serverId}&ip=203.0.113.5&h=shop.example.com&u=//blog/wp-includes/wlwmanifest.xml`, headers: { 'x-forwarded-for': '203.0.113.5' } });
    expect(r.statusCode).toBe(200);
    expect(r.body).toContain('/blog/wp-includes/wlwmanifest.xml');
    expect(r.body).not.toContain('//blog/');
  });

  it('limits the page per visitor, not per proxy in front of it', async () => {
    // Behind Cloudflare and a front proxy every visitor arrives from the same
    // address; 70 visitors in a row must all get the page.
    for (let i = 1; i <= 70; i++) {
      const r = await h.app.inject({ method: 'GET', url: link(), headers: { 'x-forwarded-for': `198.18.0.${i}` } });
      expect(r.statusCode, `visitor ${i}`).toBe(200);
    }
    // One visitor reloading it over and over is still limited.
    let last = 0;
    for (let i = 0; i < 61; i++) last = (await h.app.inject({ method: 'GET', url: link(), headers: { 'x-forwarded-for': '198.18.1.1' } })).statusCode;
    expect(last).toBe(429);
  });

  it('passes a solved check to the server and sends the visitor back', async () => {
    const p = { s: serverId, ip: '203.0.113.5', h: 'shop.example.com', u: '/wp-login.php?redirect_to=/wp-admin/&reauth=1' };
    // Strict: only the address the website saw may solve the check.
    await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '0x4AAAAAAAtestSiteKey', secret_key: '', minutes: 60, strict_ip: true });
    expect((await verify({ ...p, token: 'bad-token' })).status).toBe(403);
    // Another IPv4 address may not use the link.
    expect((await verify({ ...p, token: 'good-token' }, '198.51.100.9')).status).toBe(403);
    expect(passes).toHaveLength(0);
    const ok = await verify({ ...p, token: 'good-token' });
    expect(ok.status).toBe(200);
    expect(ok.body.redirect).toBe('https://shop.example.com/wp-login.php?redirect_to=/wp-admin/&reauth=1');
    expect(passes).toEqual([{ ip: '203.0.113.5', host: 'shop.example.com', also: '' }]);
    // A dual-stack visitor reaching this page over IPv6 is fine; the server
    // lets both addresses through (mobile networks change the address too).
    expect((await verify({ ...p, token: 'good-token' }, '2001:db8::5')).status).toBe(200);
    expect(passes[1]).toEqual({ ip: '203.0.113.5', host: 'shop.example.com', also: '2001:db8::5' });
    // The server refuses a site it does not host.
    agentError = 'evil.example is not a website on this server';
    expect((await verify({ ...p, h: 'evil.example', token: 'good-token' })).status).toBe(403);
    agentError = '';
    online = false;
    offlineWait.ms = 1500;
    expect((await verify({ ...p, token: 'good-token' })).status).toBe(503);
    online = true;
    const g = await admin.req('GET', '/api/captcha');
    expect(g.body.last24h).toMatchObject({ passed: 2, failed: 1, rejected: 2, offline: 1 });
    const ev = await admin.req('GET', '/api/captcha/events?limit=25');
    expect(ev.body.total).toBe(6);
    expect(ev.body.events[0]).toMatchObject({ server: 'web-captcha' });
    // Filter, pages, search.
    expect((await admin.req('GET', '/api/captcha/events?result=passed')).body.total).toBe(2);
    expect((await admin.req('GET', '/api/captcha/events?q=evil.example')).body.total).toBe(1);
    const p2 = await admin.req('GET', '/api/captcha/events?limit=25&offset=5');
    expect(p2.body.events).toHaveLength(1);
    expect((await admin.req('GET', '/api/captcha/events?limit=7')).status).toBe(400);
    // Delete chosen rows.
    const del = await admin.req('DELETE', '/api/captcha/events', { ids: [ev.body.events[0].id, ev.body.events[1].id] });
    expect(del.body.deleted).toBe(2);
    expect((await admin.req('GET', '/api/captcha/events')).body.total).toBe(4);
  });

  it('previews: tests only the check, asks no server, records nothing', async () => {
    const before = passes.length;
    const page = await h.app.inject({ method: 'GET', url: `/v?s=${serverId}&preview=1`, headers: { 'x-forwarded-for': '198.51.100.20' } });
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain('Preview of the page visitors see');
    expect(page.body).toContain('"preview":true');
    const p = { s: serverId, ip: '198.51.100.20', h: 'example.com', u: '/wp-login.php', preview: true };
    const r = await h.app.inject({ method: 'POST', url: '/v/verify', headers: { 'x-forwarded-for': '198.51.100.20' }, payload: { ...p, token: 'good-token' } });
    expect(r.json()).toEqual({ ok: true, preview: true });
    expect((await h.app.inject({ method: 'POST', url: '/v/verify', headers: { 'x-forwarded-for': '198.51.100.20' }, payload: { ...p, token: 'bad' } })).statusCode).toBe(403);
    expect(passes.length).toBe(before);
    const g = await admin.req('GET', '/api/captcha');
    expect(g.status).toBe(200);
    const ev = await admin.req('GET', '/api/captcha/events?q=example.com&limit=200');
    expect(ev.body.events.some((x: { host: string }) => x.host === 'example.com')).toBe(false);
    // Clearing the list.
    expect((await admin.req('DELETE', '/api/captcha/events')).body.deleted).toBeGreaterThan(0);
    expect((await admin.req('GET', '/api/captcha/events')).body.total).toBe(0);
  });

  it('has three looks and a countdown, chosen in the portal and tried in previews', async () => {
    expect((await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '0x4AAAAAAAtestSiteKey', secret_key: '', minutes: 60, design: 'neon', countdown: 5 })).status).toBe(400);
    expect((await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '0x4AAAAAAAtestSiteKey', secret_key: '', minutes: 60, design: 'minimal', countdown: 99 })).status).toBe(400);
    expect((await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '0x4AAAAAAAtestSiteKey', secret_key: '', minutes: 60, design: 'minimal', countdown: 10 })).status).toBe(200);
    expect((await admin.req('GET', '/api/captcha')).body.config).toMatchObject({ design: 'minimal', countdown: 10 });
    const hdr = { 'x-forwarded-for': '198.51.100.20' };
    const page = await h.app.inject({ method: 'GET', url: `/v?s=${serverId}&ip=198.51.100.20&h=shop.example.com&u=/wp-login.php`, headers: hdr });
    expect(page.body).toContain('<body class="d-minimal">');
    expect(page.body).toContain('WAIT=10');
    expect(page.body).toContain('id="badge"');
    // A preview may show another look; a visitor's link may not.
    expect((await h.app.inject({ method: 'GET', url: `/v?s=${serverId}&preview=1&d=midnight`, headers: hdr })).body).toContain('<body class="d-midnight">');
    expect((await h.app.inject({ method: 'GET', url: `/v?s=${serverId}&ip=198.51.100.20&h=shop.example.com&d=midnight&u=/x`, headers: hdr })).body).toContain('<body class="d-minimal">');
    // Configurations saved before the looks existed get the defaults.
    await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '0x4AAAAAAAtestSiteKey', secret_key: '', minutes: 60 });
    expect((await admin.req('GET', '/api/captcha')).body.config).toMatchObject({ design: 'classic', countdown: 5 });
  });

  it('shows the IPv4 address first; an IPv6 one fits a phone screen', async () => {
    expect(shownIP('2404:3100:19fc:6fcd:18db:6195:dd34:1', '203.0.113.5')).toBe('203.0.113.5');
    expect(shownIP('::ffff:198.51.100.2', '2001:db8::1')).toBe('198.51.100.2');
    expect(shownIP('2001:db8::2', '2001:db8::1')).toBe('2001:db8::2');
    // Reached over IPv6, the website saw IPv4: the page shows the IPv4 one.
    const page = await h.app.inject({ method: 'GET', url: link(), headers: { 'x-forwarded-for': '2404:3100:19fc:6fcd:18db:6195:dd34:1' } });
    expect(page.body).toContain('Your IP address is <b>203.0.113.5</b>');
    const v6 = await h.app.inject({ method: 'GET', url: `/v?s=${serverId}&ip=2001:db8::7&h=shop.example.com&u=/`, headers: { 'x-forwarded-for': '2001:db8::7' } });
    expect(v6.body).toContain('<p class="ip v6">Your IP address is <b>2001:<wbr>db8:<wbr>:<wbr>7</b>');
  });

  it('never names a website its server does not confirm', async () => {
    // A made-up link for a site that is not on the server: refused, the name not shown.
    const spoof = await h.app.inject({ method: 'GET', url: `/v?s=${serverId}&ip=203.0.113.5&h=paypal.com&u=/signin`, headers: { 'x-forwarded-for': '203.0.113.5' } });
    expect(spoof.statusCode).toBe(404);
    expect(spoof.body).not.toContain('paypal.com');
    // An older agent that cannot answer: the check works, the page says "this website".
    hostAnswer = () => undefined;
    try {
      const old = await h.app.inject({ method: 'GET', url: `/v?s=${serverId}&ip=203.0.113.5&h=old-agent.example.com&u=/`, headers: { 'x-forwarded-for': '203.0.113.5' } });
      expect(old.statusCode).toBe(200);
      expect(old.body).not.toContain('<h1 class="site">old-agent.example.com');
      expect(old.body).toContain('this website');
    } finally {
      hostAnswer = (host) => host !== 'paypal.com';
    }
  });

  it('keeps the CAPTCHA host out of search results', async () => {
    const r = await h.app.inject({ method: 'GET', url: '/robots.txt', headers: { host: 'captcha.example.org' } });
    expect(r.statusCode).toBe(200);
    expect(r.headers['content-type']).toContain('text/plain');
    const front = await h.app.inject({ method: 'GET', url: '/', headers: { host: 'captcha.example.org' } });
    expect(front.headers['x-robots-tag']).toContain('noindex');
    expect(front.body).toContain('name="robots" content="noindex');
  });

  it('shows only the service page on the CAPTCHA host', async () => {
    const r = await h.app.inject({ method: 'GET', url: '/api/captcha', headers: { host: 'captcha.example.org' } });
    expect(r.statusCode).toBe(200);
    expect(r.headers['content-type']).toContain('text/html');
    expect(r.body).toContain('xPGuard verification service');
  });
});

describe('CAPTCHA page: other addresses and ALTCHA', () => {
  const p = () => ({ s: serverId, ip: '203.0.113.77', h: 'shop.example.com', u: '/wp-login.php' });

  it('lets a visitor on a network with changing addresses pass, a few addresses per hour', async () => {
    await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '0x4AAAAAAAtestSiteKey', secret_key: '', minutes: 60, provider: 'auto', strict_ip: false });
    passes.length = 0;
    // The website saw 203.0.113.7x, the portal sees 198.51.100.44 (mobile NAT).
    for (const ip of ['203.0.113.77', '203.0.113.78', '203.0.113.79']) {
      expect((await verify({ ...p(), ip, token: 'good-token' }, '198.51.100.44')).status).toBe(200);
    }
    expect(passes.map((x) => (x as { ip: string }).ip)).toEqual(['203.0.113.77', '203.0.113.78', '203.0.113.79']);
    // The same address again is fine; a fourth one in the hour is not.
    expect((await verify({ ...p(), token: 'good-token' }, '198.51.100.44')).status).toBe(200);
    const fourth = await verify({ ...p(), ip: '203.0.113.80', token: 'good-token' }, '198.51.100.44');
    expect(fourth.status).toBe(403);
    expect(fourth.body.error).toContain('Too many checks');
  });

  it('answers a retried check with the first answer while the website is still letting the visitor in', async () => {
    // The website's server takes a while (LiteSpeed reload); a front proxy
    // sends the same request again meanwhile.
    let release = () => {};
    const slow = new Promise<void>((r) => (release = r));
    const before = h.hub.command;
    let calls = 0;
    h.hub.command = async (id: string, action: string, params: unknown) => {
      if (action === 'captcha.pass') {
        calls++;
        await slow;
      }
      return before(id, action, params);
    };
    try {
      const first = verify({ ...p('198.51.100.61'), token: 'good-token' }, '198.51.100.61');
      await new Promise((r) => setTimeout(r, 50));
      const retry = verify({ ...p('198.51.100.61'), token: 'good-token' }, '198.51.100.61');
      await new Promise((r) => setTimeout(r, 50));
      release();
      const [a, b] = await Promise.all([first, retry]);
      expect(a.status).toBe(200);
      expect(b.status).toBe(200);
      expect(b.body.redirect).toBe(a.body.redirect);
      expect(calls).toBe(1);
    } finally {
      h.hub.command = before;
    }
  });

  it('checks ALTCHA solutions itself: once, and only where ALTCHA is allowed', async () => {
    const { solveChallenge } = await import('altcha-lib');
    const { deriveKey } = await import('altcha-lib/algorithms/pbkdf2');
    const solve = async () => {
      const c = await h.app.inject({ method: 'GET', url: '/v/altcha/challenge' });
      expect(c.statusCode).toBe(200);
      const challenge = c.json();
      const solution = await solveChallenge({ challenge, deriveKey } as never);
      return Buffer.from(JSON.stringify({ challenge, solution })).toString('base64');
    };
    const js = await h.app.inject({ method: 'GET', url: '/v/altcha.js' });
    expect(js.statusCode).toBe(200);
    expect(js.headers['content-type']).toContain('javascript');
    passes.length = 0;
    // A correct answer without a person's tick (the page used to solve by
    // itself on load, a script posts one) is refused, and does not use up
    // the answer.
    const a = await solve();
    for (const hu of [undefined, '{}', JSON.stringify({ t: 1500, m: 12, tr: false }), JSON.stringify({ t: 200, m: 12, tr: true }), JSON.stringify({ t: 1500, m: 0, k: 0, tr: true }), 'not json']) {
      const r = await verify({ ...p(), altcha: a, ...(hu === undefined ? {} : { hu }) }, '203.0.113.77');
      expect(r.status).toBe(403);
      expect(r.body.error).toContain('tick the box yourself');
    }
    const { rows } = await h.pool.query("SELECT reason FROM captcha_events WHERE ip = '203.0.113.77' ORDER BY id DESC LIMIT 1");
    expect(rows[0].reason).toBe('box not ticked by a person');
    // A touch or a key press (keyboard users) counts as a person too.
    expect(humanTick(JSON.stringify({ t: 900, m: 0, tr: true, tc: true }))).toBe(true);
    expect(humanTick(JSON.stringify({ t: 900, m: 0, k: 1, tr: true }))).toBe(true);
    expect((await verify({ ...p(), altcha: a, hu: HU }, '203.0.113.77')).status).toBe(200);
    expect(passes).toHaveLength(1);
    // A solution works once.
    expect((await verify({ ...p(), altcha: a, hu: HU }, '203.0.113.77')).status).toBe(403);
    expect((await verify({ ...p(), altcha: 'eyJ4IjoxfQ==', hu: HU }, '203.0.113.77')).status).toBe(403);
    // Turnstile only: ALTCHA is not accepted, the page shows Turnstile.
    await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '0x4AAAAAAAtestSiteKey', secret_key: '', minutes: 60, provider: 'turnstile' });
    expect((await verify({ ...p(), altcha: await solve(), hu: HU }, '203.0.113.77')).status).toBe(403);
    let page = await h.app.inject({ method: 'GET', url: link() });
    expect(page.body).toContain('MODE="turnstile"');
    // The ALTCHA box waits for the visitor's tick (no auto-start).
    expect(page.body).not.toContain("'auto','onload'");
    expect(page.body).toContain('hu:JSON.stringify(hs)');
    // ALTCHA only: works without Turnstile keys; no Cloudflare on the page.
    await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '', secret_key: '', minutes: 60, provider: 'altcha' });
    page = await h.app.inject({ method: 'GET', url: link() });
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain('MODE="altcha"');
    expect(page.headers['content-security-policy']).toContain("worker-src 'self' blob:");
    expect((await verify({ ...p(), token: 'good-token' }, '203.0.113.77')).status).toBe(403);
    expect((await verify({ ...p(), altcha: await solve(), hu: HU }, '203.0.113.77')).status).toBe(200);
  }, 60_000);
});

describe('CAPTCHA page: no passing bots through', () => {
  const p = (ip: string) => ({ s: serverId, ip, h: 'shop.example.com', u: '/wp-login.php' });
  const solve = async () => {
    const { solveChallenge } = await import('altcha-lib');
    const { deriveKey } = await import('altcha-lib/algorithms/pbkdf2');
    const challenge = (await h.app.inject({ method: 'GET', url: '/v/altcha/challenge' })).json();
    const solution = await solveChallenge({ challenge, deriveKey } as never);
    return Buffer.from(JSON.stringify({ challenge, solution })).toString('base64');
  };

  it('counts an address of the other family as another address', async () => {
    await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '0x4AAAAAAAtestSiteKey', secret_key: '', minutes: 60, provider: 'auto' });
    passes.length = 0;
    // One IPv6 visitor solving the page for IPv4 addresses the WAF sent: a few, not any number.
    for (const ip of ['192.0.2.11', '192.0.2.12', '192.0.2.13']) {
      expect((await verify({ ...p(ip), token: 'good-token' }, '2001:db8::99')).status).toBe(200);
    }
    expect((await verify({ ...p('192.0.2.14'), token: 'good-token' }, '2001:db8::99')).status).toBe(403);
    expect(passes).toHaveLength(3);
    // The log names the address that solved it, and the check used.
    const ev = await admin.req('GET', '/api/captcha/events?q=2001:db8::99&limit=25');
    expect(ev.body.total).toBe(4);
    expect(ev.body.events[0]).toMatchObject({ ip: '192.0.2.14', solver_ip: '2001:db8::99', method: 'turnstile', result: 'rejected' });
  });

  it('takes ALTCHA, where Turnstile is the check, only for the own network, a few times a day, for an hour', async () => {
    passes.length = 0;
    // Not for an address of another network (cloud solvers passing bots).
    expect((await verify({ ...p('192.0.2.21'), altcha: await solve(), hu: HU }, '198.51.100.120')).status).toBe(403);
    expect(passes).toHaveLength(0);
    for (let i = 0; i < 3; i++) {
      expect((await verify({ ...p('192.0.2.22'), altcha: await solve(), hu: HU }, '192.0.2.22')).status).toBe(200);
    }
    expect(passes[0]).toEqual({ ip: '192.0.2.22', host: 'shop.example.com', also: '', minutes: 60 });
    // The fourth in a day is refused; Turnstile still works for that visitor.
    expect((await verify({ ...p('192.0.2.22'), altcha: await solve(), hu: HU }, '192.0.2.22')).status).toBe(403);
    expect((await verify({ ...p('192.0.2.22'), token: 'good-token' }, '192.0.2.22')).status).toBe(200);
    expect(passes[3]).toEqual({ ip: '192.0.2.22', host: 'shop.example.com', also: '' });
    const ev = await admin.req('GET', '/api/captcha/events?q=192.0.2.22&result=passed&limit=25');
    expect(ev.body.events.map((x: { method: string }) => x.method).sort()).toEqual(['altcha', 'altcha', 'altcha', 'turnstile']);
    // Carrier-grade NAT (a neighbouring address) and Cloudflare WARP / iCloud Private Relay are the visitor's own network.
    expect((await verify({ ...p('203.0.113.229'), altcha: await solve(), hu: HU }, '203.0.113.228')).status).toBe(200);
    expect((await verify({ ...p('104.29.10.1'), altcha: await solve(), hu: HU }, '104.29.20.2')).status).toBe(200);
  }, 60_000);

  it('knows the own network', () => {
    expect(sameNetwork('198.51.100.229', '198.51.100.228')).toBe(true);
    expect(sameNetwork('104.29.10.1', '104.28.30.3')).toBe(true);
    expect(sameNetwork('203.0.113.74', '198.51.100.35')).toBe(false);
    expect(sameNetwork('198.18.100.74', '198.18.104.138')).toBe(false);
    expect(sameNetwork('2001:db8:4f77:25b9::3c2:25', '2001:db8:4f77::1')).toBe(true);
    expect(sameNetwork('2001:db8:4f77::1', '2001:db8:4f78::1')).toBe(false);
    expect(sameNetwork('192.0.2.1', '2001:db8::1')).toBe(false);
    // iCloud Private Relay and WARP: the site over IPv4, the check over IPv6
    // (oxannebradley.org: 104.29.202.184 solved from 2606:54c1:1:2c0::3c0:2f).
    expect(sameNetwork('104.29.202.184', '2606:54c1:1:2c0::3c0:2f')).toBe(true);
    expect(sameNetwork('2a09:bac5:a7b8:25a5::3c0:5e', '104.28.213.42')).toBe(true);
    // Meta's agent browsers (Muse): 57.141.20.x solving from 2a03:2880::.
    expect(sameNetwork('57.141.20.52', '2a03:2880:16ff:4d::')).toBe(true);
    // Different operators stay different networks.
    expect(sameNetwork('57.141.20.52', '104.28.1.1')).toBe(false);
    expect(sameNetwork('104.29.202.184', '2001:db8::1')).toBe(false);
    expect(egressNetwork('57.141.0.2')).toBe('meta');
    expect(egressNetwork('192.0.2.1')).toBe('');
  });

  it('keeps the daily ALTCHA allowance per website on shared egress networks', () => {
    expect(altchaKeysFor('198.51.100.7', '198.51.100.7', 'a.example')).toEqual(['s:198.51.100.7', 't:198.51.100.7']);
    expect(altchaKeysFor('2606:54c1:1:2c0::3c0:2f', '104.29.202.184', 'oxannebradley.org')).toEqual([
      's:2606:54c1:1:2c0::3c0:2f|oxannebradley.org',
      't:104.29.202.184|oxannebradley.org',
    ]);
    // Strangers on the same relay address using up the allowance on other
    // sites do not touch this site's.
    const now = Date.now();
    const busy = altchaKeysFor('104.29.202.184', '104.29.202.184', 'busy.example');
    for (let i = 0; i < 10; i++) noteAltchaPass(busy, now);
    expect(altchaAllowed(busy, 'altcha', now)).toBe(false);
    expect(altchaAllowed(altchaKeysFor('104.29.202.184', '104.29.202.184', 'oxannebradley.org'), 'altcha', now)).toBe(true);
    // Elsewhere one address's allowance is for all sites.
    const home = altchaKeysFor('198.51.100.8', '198.51.100.8', 'busy.example');
    for (let i = 0; i < 10; i++) noteAltchaPass(home, now);
    expect(altchaAllowed(altchaKeysFor('198.51.100.8', '198.51.100.8', 'oxannebradley.org'), 'altcha', now)).toBe(false);
  });

  it('does not count a shared egress network as another address', () => {
    // One Meta IPv6 address solved for 16 Meta IPv4 addresses in an hour:
    // many people behind one network, not one solver passing bots.
    for (let i = 1; i <= 16; i++) expect(allowOtherAddress('2a03:2880:16ff:5e::', `57.141.20.${i}`)).toBe(true);
    // Elsewhere the limit of 3 other addresses an hour stays.
    for (let i = 1; i <= 3; i++) expect(allowOtherAddress('198.51.100.7', `203.0.113.${i}`)).toBe(true);
    // Also for neighbours in the solver's own /24 (a hosting network of bots).
    for (let i = 1; i <= 3; i++) expect(allowOtherAddress('192.0.2.200', `192.0.2.${i}`)).toBe(true);
    expect(allowOtherAddress('192.0.2.200', '192.0.2.9')).toBe(false);
    expect(allowOtherAddress('198.51.100.7', '203.0.113.9')).toBe(false);
    // A shared egress solver passing addresses outside its network still counts.
    for (let i = 1; i <= 3; i++) expect(allowOtherAddress('2a03:2880:16ff:77::', `203.0.113.${20 + i}`)).toBe(true);
    expect(allowOtherAddress('2a03:2880:16ff:77::', '203.0.113.99')).toBe(false);
    // Per website there (roxannebradley.org: 104.29.x solving for 87.81.x,
    // its allowance used up by strangers on the same relay address), and
    // still 3 an hour for one website.
    for (let i = 1; i <= 3; i++) expect(allowOtherAddress('104.29.193.195', `198.51.100.${40 + i}`, Date.now(), 'busy.example')).toBe(true);
    expect(allowOtherAddress('104.29.193.195', '87.81.235.109', Date.now(), 'roxannebradley.org')).toBe(true);
    expect(allowOtherAddress('104.29.193.195', '198.51.100.99', Date.now(), 'busy.example')).toBe(false);
  });

  it('refuses the ALTCHA fallback from hosting and cloud networks (AbuseIPDB usage type)', async () => {
    const old = hostingCheck.lookup;
    await h.pool.query("INSERT INTO ipdb_abuseipdb (id, api_key) VALUES (1, 'test-key') ON CONFLICT (id) DO UPDATE SET api_key = 'test-key'");
    hostingCheck.lookup = async (_key: string, ip: string) => ip === '192.0.2.31';
    try {
      passes.length = 0;
      const dc = await verify({ ...p('192.0.2.31'), altcha: await solve(), hu: HU }, '192.0.2.31');
      expect(dc.status).toBe(403);
      expect(dc.body.error).toContain('hosting or cloud network');
      // Turnstile still decides for that address; a home address passes ALTCHA.
      expect((await verify({ ...p('192.0.2.31'), token: 'good-token' }, '192.0.2.31')).status).toBe(200);
      expect((await verify({ ...p('192.0.2.32'), altcha: await solve(), hu: HU }, '192.0.2.32')).status).toBe(200);
      expect(passes).toHaveLength(2);
      // Why it was refused is recorded.
      const { rows } = await h.pool.query("SELECT reason FROM captcha_events WHERE ip = '192.0.2.31' AND result = 'rejected' ORDER BY id DESC LIMIT 1");
      expect(rows[0].reason).toBe('ALTCHA from a hosting network');
    } finally {
      hostingCheck.lookup = old;
      await h.pool.query("UPDATE ipdb_abuseipdb SET api_key = '' WHERE id = 1");
    }
  }, 60_000);

  it('lets privacy relays use ALTCHA, and refuses data centres solving for other addresses', async () => {
    const old = hostingCheck.lookup;
    await h.pool.query("INSERT INTO ipdb_abuseipdb (id, api_key) VALUES (1, 'test-key') ON CONFLICT (id) DO UPDATE SET api_key = 'test-key'");
    // AbuseIPDB calls both data centres: iCloud Private Relay (Apple's IPv6
    // range, the website saw 87.81.x) and a CAPTCHA farm's server.
    hostingCheck.lookup = async () => true;
    try {
      passes.length = 0;
      const relay = await verify({ ...p('87.81.235.80'), altcha: await solve(), hu: HU }, '2606:54c1:1:eff::50c:3d');
      expect(relay.status).toBe(200);
      const farm = await verify({ ...p('198.51.100.148'), token: 'good-token' }, '203.0.113.123');
      expect(farm.status).toBe(403);
      expect(farm.body.error).toContain('hosting or cloud network');
      const { rows } = await h.pool.query("SELECT reason FROM captcha_events WHERE ip = '198.51.100.148' ORDER BY id DESC LIMIT 1");
      expect(rows[0].reason).toBe('solved from a hosting network for another address');
      expect(passes).toHaveLength(1);
    } finally {
      hostingCheck.lookup = old;
      await h.pool.query("UPDATE ipdb_abuseipdb SET api_key = '' WHERE id = 1");
    }
  }, 60_000);

  it('refuses a Turnstile token solved on another site', async () => {
    const http = await import('node:http');
    let host = 'captcha.example.org';
    const srv = http.createServer((_q, r) => r.end(JSON.stringify({ success: true, hostname: host })));
    await new Promise<void>((ok) => srv.listen(0, '127.0.0.1', ok));
    const old = turnstile.url;
    turnstile.url = `http://127.0.0.1:${(srv.address() as { port: number }).port}/`;
    try {
      expect(await realVerify('s', 't', '192.0.2.1', ['captcha.example.org'])).toBe(true);
      host = 'evil.example';
      expect(await realVerify('s', 't', '192.0.2.1', ['captcha.example.org'])).toBe(false);
    } finally {
      turnstile.url = old;
      srv.close();
    }
  });
});

describe('CAPTCHA on the website’s own address', () => {
  const nonce = '0123456789abcdef0123456789abcdef';
  it('turns on per server and tells the server (both ways of getting the setting)', async () => {
    const commands: { action: string; params: any }[] = [];
    const before = h.hub.command;
    h.hub.command = async (id: string, action: string, params: unknown) => {
      commands.push({ action, params });
      return before(id, action, params);
    };
    try {
      const put = await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '0x4AAAAAAAtestSiteKey', secret_key: '', minutes: 60, site_servers: [serverId, '00000000-0000-4000-8000-000000000009'] });
      expect(put.status).toBe(200);
      const g = await admin.req('GET', '/api/captcha');
      // A server this account does not have is dropped.
      expect(g.body.config.site_servers).toEqual([serverId]);
      expect(commands.find((c) => c.action === 'captcha.central')?.params.mode).toBe('site');
      const a = await agent('/api/agent/captcha/config', { version: 0 });
      expect(a.body.config.mode).toBe('site');
    } finally {
      h.hub.command = before;
    }
  });

  it('goes to the CAPTCHA port only when the browser reaches it (site mode)', async () => {
    const url = `/v?s=${serverId}&ip=203.0.113.88&h=shop.example.com&g=7743&u=/wp-admin/?x=1`;
    const page = await h.app.inject({ method: 'GET', url, headers: { host: 'captcha.example.org', 'x-forwarded-for': '203.0.113.88' } });
    expect(page.statusCode).toBe(200);
    // A pixel from the port, on to the gate there, or the check here.
    expect(page.body).toContain('"https://shop.example.com:7743/.xpguard/ping.gif?"');
    expect(page.body).toContain('"https://shop.example.com:7743/.xpguard/gate?back=/wp-admin/?x=1"');
    expect(page.body).toContain(`"https://captcha.example.org/v?s=${serverId}&ip=203.0.113.88&h=shop.example.com&u=/wp-admin/?x=1"`);
    expect(page.headers['content-security-policy']).toContain('img-src https://shop.example.com:7743;');
    expect(page.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    // The fallback is the check itself.
    const check = await h.app.inject({ method: 'GET', url: `/v?s=${serverId}&ip=203.0.113.88&h=shop.example.com&u=/wp-admin/?x=1`, headers: { host: 'captcha.example.org', 'x-forwarded-for': '203.0.113.88' } });
    expect(check.body).not.toContain('ping.gif');
    // A website its server does not confirm gets no redirect to any port.
    const evil = await h.app.inject({ method: 'GET', url: `/v?s=${serverId}&ip=203.0.113.88&h=paypal.com&g=443&u=/`, headers: { host: 'captcha.example.org', 'x-forwarded-for': '203.0.113.88' } });
    expect(evil.statusCode).toBe(404);
    expect(evil.body).not.toContain('paypal.com:443');
    expect(parseParams(`/v?s=x&g=99999&u=/`).g).toBe(0);
    expect(parseParams(`/v?s=x&g=7743&u=/`).g).toBe(7743);
  });

  it('may be framed by that website only, and gives the server a ticket instead of a reload', async () => {
    const url = `/v?s=${serverId}&ip=203.0.113.88&h=shop.example.com&n=${nonce}&frame=1&u=/wp-login.php`;
    const page = await h.app.inject({ method: 'GET', url, headers: { host: 'captcha.example.org', 'x-forwarded-for': '203.0.113.88' } });
    const body = page.body;
    expect(page.statusCode).toBe(200);
    expect(page.headers['x-frame-options']).toBeUndefined();
    expect(page.headers['content-security-policy']).toContain('frame-ancestors https://shop.example.com:* https://shop.example.com');
    expect(body).toContain('FRAME=true');
    expect(body).toContain(`"n":"${nonce}"`);
    // Audit A7 F4: the framing page's message text is never shown, and
    // messages are set as text, not markup.
    expect(body).not.toContain('e.data.error');
    expect(body).toContain('st.textContent=t');
    expect(body).not.toContain('st.innerHTML');
    // The portal's own host never lets a website frame the page.
    const onPortal = await fetch(h.url + url, { headers: { 'x-forwarded-for': '203.0.113.88' } });
    expect(onPortal.headers.get('x-frame-options')).toBe('DENY');
    expect(onPortal.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    expect(await onPortal.text()).toContain('FRAME=false');
    // Without the frame parameters: no one may frame it.
    const plain = await fetch(h.url + `/v?s=${serverId}&ip=203.0.113.88&h=shop.example.com&u=/wp-login.php`, { headers: { 'x-forwarded-for': '203.0.113.88' } });
    expect(plain.headers.get('x-frame-options')).toBe('DENY');
    expect(plain.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    // A site its server does not confirm is never framed.
    const evil = await fetch(h.url + `/v?s=${serverId}&ip=203.0.113.88&h=paypal.com&n=${nonce}&frame=1&u=/`);
    expect(evil.status).toBe(404);
    expect(evil.headers.get('x-frame-options')).toBe('DENY');

    const commands: { action: string; params: any }[] = [];
    const before = h.hub.command;
    h.hub.command = async (id: string, action: string, params: unknown) => {
      commands.push({ action, params });
      return before(id, action, params);
    };
    try {
      const r = await verify({ s: serverId, ip: '203.0.113.88', h: 'shop.example.com', u: '/wp-login.php', n: nonce, token: 'good-token' }, '203.0.113.88');
      expect(r.status).toBe(200);
      expect(r.body.frame).toBe(true);
      expect(commands.map((c) => c.action)).toEqual(['captcha.ticket']);
      expect(commands[0].params).toEqual({ ip: '203.0.113.88', host: 'shop.example.com', nonce });
      // Recorded like any other check.
      const ev = await admin.req('GET', '/api/captcha/events?q=203.0.113.88');
      expect(ev.body.events[0]).toMatchObject({ ip: '203.0.113.88', result: 'passed', method: 'turnstile' });
    } finally {
      h.hub.command = before;
    }
  });

  it('waits for a server that is reconnecting instead of failing the solved check', async () => {
    online = false;
    offlineWait.ms = 3000;
    setTimeout(() => (online = true), 600);
    try {
      const r = await verify({ s: serverId, ip: '203.0.113.89', h: 'shop.example.com', u: '/wp-login.php', n: nonce, token: 'good-token' }, '203.0.113.89');
      expect(r.status).toBe(200);
    } finally {
      online = true;
    }
  });

  it('sets the IPDB CAPTCHA for all servers, or leaves each server its own', async () => {
    const commands: { action: string; params: any }[] = [];
    const before = h.hub.command;
    h.hub.command = async (id: string, action: string, params: unknown) => {
      commands.push({ action, params });
      return before(id, action, params);
    };
    const base = { enabled: true, site_key: '0x4AAAAAAAtestSiteKey', secret_key: '', minutes: 60, site_servers: [serverId] };
    try {
      for (const [v, want] of [['on', true], ['off', false], ['', undefined]] as const) {
        commands.length = 0;
        expect((await admin.req('PUT', '/api/captcha', { ...base, ipdb_captcha: v })).status).toBe(200);
        expect((await admin.req('GET', '/api/captcha')).body.config.ipdb_captcha).toBe(v);
        const pushed = commands.find((c) => c.action === 'captcha.central')?.params;
        const pulled = (await agent('/api/agent/captcha/config', { version: 0 })).body.config;
        for (const c of [pushed, pulled]) {
          if (want === undefined) expect(c).not.toHaveProperty('ipdb_captcha');
          else expect(c.ipdb_captcha).toBe(want);
        }
      }
      expect((await admin.req('PUT', '/api/captcha', { ...base, ipdb_captcha: 'maybe' })).status).toBe(400);
    } finally {
      h.hub.command = before;
    }
  });

  it('tells IPDB and firewall visitors apart from login pages in the reports (a label only)', async () => {
    const page = await h.app.inject({ method: 'GET', url: `/v?s=${serverId}&ip=198.51.100.77&h=shop.example.com&k=fw&u=/`, headers: { host: 'captcha.example.org', 'x-forwarded-for': '198.51.100.77' } });
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain('"k":"fw"');
    expect(parseParams('/v?s=x&k=evil&u=/').k).toBe('');
    const fw = await verify({ s: serverId, ip: '198.51.100.77', h: 'shop.example.com', u: '/', k: 'fw', token: 'good-token' }, '198.51.100.77');
    expect(fw.status).toBe(200);
    const login = await verify({ s: serverId, ip: '198.51.100.78', h: 'shop.example.com', u: '/wp-login.php', token: 'good-token' }, '198.51.100.78');
    expect(login.status).toBe(200);
    // Any other kind is refused, not recorded under a made-up source.
    expect((await verify({ s: serverId, ip: '198.51.100.79', h: 'shop.example.com', u: '/', k: 'x', token: 'good-token' }, '198.51.100.79')).status).toBe(400);
    const f = await admin.req('GET', '/api/captcha/events?source=firewall&q=198.51.100.7');
    expect(f.body.events.map((e: any) => [e.ip, e.source])).toEqual([['198.51.100.77', 'firewall']]);
    const l = await admin.req('GET', '/api/captcha/events?source=login&q=198.51.100.78');
    expect(l.body.events.map((e: any) => [e.ip, e.source])).toEqual([['198.51.100.78', '']]);
    expect((await admin.req('GET', '/api/captcha/events?source=other')).status).toBe(400);
  });

  it('shows the checks of customers’ servers to the master account', async () => {
    const { rows: acc } = await h.pool.query("INSERT INTO accounts (name) VALUES ('Customer Co') RETURNING id");
    const { rows: srv } = await h.pool.query("INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, 'cust-1', 'x') RETURNING id", [acc[0].id]);
    await h.pool.query("INSERT INTO captcha_events (account_id, server_id, ip, host, result, method) VALUES ($1, $2, '198.51.100.201', 'customer-site.example', 'failed', 'altcha')", [acc[0].id, srv[0].id]);
    const ev = await admin.req('GET', '/api/captcha/events?q=customer-site.example');
    expect(ev.body.total).toBe(1);
    expect(ev.body.events[0]).toMatchObject({ server: 'cust-1', result: 'failed' });
    const g = await admin.req('GET', '/api/captcha');
    expect(g.body.last24h.failed).toBeGreaterThan(0);
  });
});
