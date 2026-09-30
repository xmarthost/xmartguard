import crypto from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';
import { envelopeMessage } from '../src/agent-sign.js';
import { parseParams, turnstile } from '../src/routes/captcha.js';

let h: Harness;
let admin: Client;
let serverId = '';
const keys = crypto.generateKeyPairSync('ed25519');
const pub = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
const passes: unknown[] = [];
let online = true;
let agentError = '';

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
    return { ok: true };
  };
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

const link = () => `/v?s=${serverId}&ip=203.0.113.5&h=shop.example.com&u=/wp-login.php?redirect_to=/wp-admin/&reauth=1`;

async function verify(body: Record<string, string>, ip = '203.0.113.5') {
  const r = await h.app.inject({ method: 'POST', url: '/v/verify', headers: { 'cf-connecting-ip': ip }, payload: body });
  return { status: r.statusCode, body: r.json() };
}

describe('CAPTCHA page for suspicious visitors', () => {
  it('reads the page the WAF appends unescaped', () => {
    expect(parseParams('/v?s=a&ip=1.2.3.4&h=x.org&u=/wp-login.php?redirect_to=/a&b=c')).toEqual({ s: 'a', ip: '1.2.3.4', h: 'x.org', u: '/wp-login.php?redirect_to=/a&b=c', preview: false });
    expect(parseParams('/v?s=a&ip=1.2.3.4&h=X.ORG').u).toBe('/');
  });

  it('is off until the Turnstile keys are saved', async () => {
    const g = await admin.req('GET', '/api/captcha');
    expect(g.body.config).toEqual({ enabled: false, site_key: '', secret_set: false, minutes: 720 });
    expect(g.body.url).toBe('https://captcha.example.org/v');
    const page = await h.app.inject({ method: 'GET', url: link() });
    expect(page.statusCode).toBe(503);
    expect(page.body).toContain('not available right now');
    const noKeys = await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '', secret_key: '', minutes: 720 });
    expect(noKeys.status).toBe(400);
    expect((await agent('/api/agent/captcha/config', { version: 0 })).body.unchanged).toBe(true);
  });

  it('saves the keys (secret never shown) and gives servers the setting', async () => {
    const put = await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '0x4AAAAAAAtestSiteKey', secret_key: '0x4AAAAAAAsecret', minutes: 60 });
    expect(put.status).toBe(200);
    expect(put.body.version).toBe(1);
    const g = await admin.req('GET', '/api/captcha');
    expect(g.body.config).toEqual({ enabled: true, site_key: '0x4AAAAAAAtestSiteKey', secret_set: true, minutes: 60 });
    expect(JSON.stringify(g.body)).not.toContain('0x4AAAAAAAsecret');
    // Saving without a secret keeps the saved one.
    expect((await admin.req('PUT', '/api/captcha', { enabled: true, site_key: '0x4AAAAAAAtestSiteKey', secret_key: '', minutes: 60 })).status).toBe(200);
    const a = await agent('/api/agent/captcha/config', { version: 0 });
    expect(a.body.config).toEqual({ version: 2, enabled: true, url: 'https://captcha.example.org/v', minutes: 60 });
  });

  it('shows the branded page with the site, the address and the check', async () => {
    const page = await h.app.inject({ method: 'GET', url: link(), headers: { 'cf-connecting-ip': '203.0.113.5' } });
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain('shop.example.com');
    expect(page.body).toContain('is protected by <b>xPGuard</b>');
    expect(page.body).toContain('Your IP address is <b>203.0.113.5</b>');
    expect(page.body).toContain('0x4AAAAAAAtestSiteKey');
    expect(page.body).not.toContain('0x4AAAAAAAsecret');
    expect(page.headers['content-security-policy']).toContain('challenges.cloudflare.com');
    // Bad links: no check.
    for (const bad of [`/v?s=${serverId}&ip=x&h=shop.example.com&u=/`, `/v?s=${serverId}&ip=1.2.3.4&h=<script>&u=/`, `/v?s=${serverId}&ip=1.2.3.4&h=a.org&u=//evil.com`, '/v?s=nope&ip=1.2.3.4&h=a.org&u=/']) {
      const r = await h.app.inject({ method: 'GET', url: bad });
      expect(r.statusCode, bad).toBe(400);
      expect(r.body).not.toContain('<script>&');
    }
  });

  it('passes a solved check to the server and sends the visitor back', async () => {
    const p = { s: serverId, ip: '203.0.113.5', h: 'shop.example.com', u: '/wp-login.php?redirect_to=/wp-admin/&reauth=1' };
    expect((await verify({ ...p, token: 'bad-token' })).status).toBe(403);
    // Another IPv4 address may not use the link.
    expect((await verify({ ...p, token: 'good-token' }, '198.51.100.9')).status).toBe(403);
    expect(passes).toHaveLength(0);
    const ok = await verify({ ...p, token: 'good-token' });
    expect(ok.status).toBe(200);
    expect(ok.body.redirect).toBe('https://shop.example.com/wp-login.php?redirect_to=/wp-admin/&reauth=1');
    expect(passes).toEqual([{ ip: '203.0.113.5', host: 'shop.example.com' }]);
    // A dual-stack visitor reaching this page over IPv6 is fine.
    expect((await verify({ ...p, token: 'good-token' }, '2001:db8::5')).status).toBe(200);
    // The server refuses a site it does not host.
    agentError = 'evil.example is not a website on this server';
    expect((await verify({ ...p, h: 'evil.example', token: 'good-token' })).status).toBe(403);
    agentError = '';
    online = false;
    expect((await verify({ ...p, token: 'good-token' })).status).toBe(503);
    online = true;
    const g = await admin.req('GET', '/api/captcha');
    expect(g.body.last24h).toMatchObject({ passed: 2, failed: 1, rejected: 2, offline: 1 });
    expect(g.body.recent[0]).toMatchObject({ server: 'web-captcha' });
  });

  it('previews: tests only the check, asks no server, records nothing', async () => {
    const before = passes.length;
    const page = await h.app.inject({ method: 'GET', url: `/v?s=${serverId}&preview=1`, headers: { 'cf-connecting-ip': '198.51.100.20' } });
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain('Preview of the page visitors see');
    expect(page.body).toContain('"preview":true');
    const p = { s: serverId, ip: '198.51.100.20', h: 'example.com', u: '/wp-login.php', preview: true };
    const r = await h.app.inject({ method: 'POST', url: '/v/verify', headers: { 'cf-connecting-ip': '198.51.100.20' }, payload: { ...p, token: 'good-token' } });
    expect(r.json()).toEqual({ ok: true, preview: true });
    expect((await h.app.inject({ method: 'POST', url: '/v/verify', headers: { 'cf-connecting-ip': '198.51.100.20' }, payload: { ...p, token: 'bad' } })).statusCode).toBe(403);
    expect(passes.length).toBe(before);
    const g = await admin.req('GET', '/api/captcha');
    expect(g.body.recent.some((x: { host: string }) => x.host === 'example.com')).toBe(false);
    // Clearing the list.
    expect((await admin.req('DELETE', '/api/captcha/events')).body.deleted).toBeGreaterThan(0);
    expect((await admin.req('GET', '/api/captcha')).body.recent).toHaveLength(0);
  });

  it('shows only the service page on the CAPTCHA host', async () => {
    const r = await h.app.inject({ method: 'GET', url: '/api/captcha', headers: { host: 'captcha.example.org' } });
    expect(r.statusCode).toBe(200);
    expect(r.headers['content-type']).toContain('text/html');
    expect(r.body).toContain('xPGuard verification service');
  });
});
