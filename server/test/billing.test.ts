import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import { Client, OWNER, startHarness, type Harness } from './helpers.js';

const SECRET = 'test-billing-secret-0123456789';
let h: Harness;
let owner: Client;

function signed(path: string, payload: unknown, opts: { secret?: string; ts?: number } = {}) {
  const p = JSON.stringify(payload);
  const ts = String(opts.ts ?? Math.floor(Date.now() / 1000));
  const sig = crypto.createHmac('sha256', opts.secret ?? SECRET).update(`${ts}.${path}.${p}`).digest('hex');
  return { body: { payload: p }, headers: { 'x-xg-timestamp': ts, 'x-xg-signature': sig } };
}
async function call(path: string, payload: unknown, opts?: { secret?: string; ts?: number }) {
  const s = signed(path, { ...(payload as object), nonce: crypto.randomUUID() }, opts);
  return new Client(h.url).req('POST', path, s.body, s.headers);
}
const inAYear = () => new Date(Date.now() + 365 * 86400_000).toISOString();

beforeAll(async () => {
  h = await startHarness({ billingSecret: SECRET, billingSiteUrl: 'https://shop.example.com' });
  owner = new Client(h.url);
  await owner.login();
});
afterAll(async () => h.close());

describe('billing API (website -> portal)', () => {
  it('accepts only fresh requests signed with the shared secret, once', async () => {
    const pl = { email: 'nobody@example.com' };
    expect((await new Client(h.url).req('POST', '/api/billing/usage', { payload: JSON.stringify(pl) })).status).toBe(401);
    expect((await call('/api/billing/usage', pl, { secret: 'wrong' })).status).toBe(401);
    expect((await call('/api/billing/usage', pl, { ts: Math.floor(Date.now() / 1000) - 3600 })).status).toBe(401);
    const s = signed('/api/billing/usage', pl);
    expect((await new Client(h.url).req('POST', '/api/billing/usage', s.body, s.headers)).status).toBe(404); // valid, unknown customer
    expect((await new Client(h.url).req('POST', '/api/billing/usage', s.body, s.headers)).status).toBe(409); // replayed
  });

  it('makes a customer account with a licence; the customer sets a password and signs in', async () => {
    const r = await call('/api/billing/provision', { email: 'Ali@Example.com', name: 'Ali Raza', plan: 'pro', plan_name: 'Pro', max_servers: 1, period_end: inAYear(), customer_ref: 'C-1' });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ created: true });
    const token = new URL(r.body.set_password_url).searchParams.get('token')!;
    // No password works before one is set.
    expect((await new Client(h.url).req('POST', '/api/auth/login', { email: 'ali@example.com', password: '' })).status).toBe(400);
    const c = new Client(h.url);
    expect((await c.req('GET', `/api/auth/set-password?token=${token}`)).body.email).toBe('ali@example.com');
    expect((await c.req('POST', '/api/auth/set-password', { token, password: 'short' })).status).toBe(400);
    expect((await c.req('POST', '/api/auth/set-password', { token, password: 'a-good-long-password' })).status).toBe(200);
    expect((await c.req('POST', '/api/auth/set-password', { token, password: 'a-good-long-password' })).status).toBe(404); // used
    expect((await c.req('GET', '/api/auth/me')).body.user).toMatchObject({ email: 'ali@example.com', role: 'owner', platform: false });
    await new Client(h.url).login('ali@example.com', 'a-good-long-password');
    // Provisioning again updates the licence, no new account.
    const again = await call('/api/billing/provision', { email: 'ali@example.com', plan: 'pro', max_servers: 3, period_end: inAYear() });
    expect(again.body).toMatchObject({ created: false, set_password_url: null });
    const lic = await c.req('GET', '/api/license');
    expect(lic.body).toMatchObject({ unlimited: false, platform: false, servers_used: 0, buy_url: 'https://shop.example.com/account/add-servers' });
    expect(lic.body.license).toMatchObject({ plan: 'pro', max_servers: 3, status: 'active' });
    // The platform's own account has no limit.
    expect((await owner.req('GET', '/api/license')).body).toMatchObject({ unlimited: true, platform: true });
    // The operator's email cannot be sold a licence.
    expect((await call('/api/billing/provision', { email: OWNER.email, plan: 'pro', max_servers: 1, period_end: null })).status).toBe(409);
  });

  it('signs a customer in from the website with a one-time link', async () => {
    const r = await call('/api/billing/login-link', { email: 'ali@example.com' });
    expect(r.status).toBe(200);
    const u = new URL(r.body.url);
    const res = await fetch(h.url + u.pathname + u.search, { redirect: 'manual' });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/');
    const cookies = res.headers.getSetCookie();
    const cookie = cookies[0].split(';')[0];
    // A month-long session, and the browser is marked as a client's.
    expect(cookies[0]).toMatch(/Max-Age=2592000/);
    expect(cookies.some((c) => c.startsWith('xg_client=1'))).toBe(true);
    const me = await fetch(h.url + '/api/auth/me', { headers: { cookie } });
    expect((await me.json()).user.email).toBe('ali@example.com');
    // A used link sends the customer back to the client area's sign-in.
    const twice = await fetch(h.url + u.pathname + u.search, { redirect: 'manual' });
    expect(twice.headers.get('location')).toBe('https://shop.example.com/login?next=%2Faccount%2Fpanel');
    expect((await new Client(h.url).req('GET', '/api/auth/options')).body).toEqual({
      client_login_url: 'https://shop.example.com/login?next=%2Faccount%2Fpanel',
      client_area_url: 'https://shop.example.com/account',
    });
  });

  it('keeps customers to the servers they paid for', async () => {
    await call('/api/billing/provision', { email: 'sara@example.com', plan: 'pro', max_servers: 1, period_end: inAYear() });
    const link = await call('/api/billing/password-link', { email: 'sara@example.com' });
    const c = new Client(h.url);
    await c.req('POST', '/api/auth/set-password', { token: new URL(link.body.url).searchParams.get('token'), password: 'another-long-password' });
    const t1 = await c.req('POST', '/api/enrollment-tokens', { label: 'one' });
    expect(t1.status).toBe(200);
    const t2 = await c.req('POST', '/api/enrollment-tokens', { label: 'two' });
    expect(t2.status).toBe(402);
    expect(t2.body).toMatchObject({ limit: true, buy_url: 'https://shop.example.com/account/add-servers' });
    // The first token enrols a server; then the limit holds at enrolment too.
    const key = () => crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
    const enroll = (token: string) => new Client(h.url).req('POST', '/api/agent/enroll', { token, public_key: key(), agent_version: '0.21.9', inventory: { hostname: 'cust1.example.com' } });
    expect((await enroll(t1.body.token)).status).toBe(200);
    expect((await c.req('GET', '/api/license')).body.servers_used).toBe(1);
    // More licences bought: a token again; down to 1 before it is used: refused at enrolment.
    await call('/api/billing/provision', { email: 'sara@example.com', plan: 'pro', max_servers: 2, period_end: inAYear() });
    const t3 = await c.req('POST', '/api/enrollment-tokens', { label: 'three' });
    expect(t3.status).toBe(200);
    await call('/api/billing/provision', { email: 'sara@example.com', plan: 'pro', max_servers: 1, period_end: inAYear() });
    expect((await enroll(t3.body.token)).status).toBe(402);
    // An expired subscription adds nothing; the connected server stays.
    await call('/api/billing/provision', { email: 'sara@example.com', plan: 'pro', max_servers: 5, period_end: new Date(Date.now() - 86400_000).toISOString() });
    const exp = await c.req('POST', '/api/enrollment-tokens', { label: 'four' });
    expect(exp.status).toBe(402);
    expect(exp.body.error).toMatch(/not active/);
    const usage = await call('/api/billing/usage', { email: 'sara@example.com' });
    expect(usage.body).toMatchObject({ servers_used: 1, needs_password: false });
    expect(usage.body.servers[0].hostname).toBe('cust1.example.com');
    // The platform account is never limited.
    expect((await owner.req('POST', '/api/enrollment-tokens', { label: 'mine' })).status).toBe(200);
  });

  it('gives each server one free trial, and shows unused tokens again', async () => {
    const key = () => crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
    const customer = async (email: string) => {
      await call('/api/billing/provision', { email, plan: 'free-trial', plan_name: 'Free Trial', max_servers: 1, period_end: inAYear(), trial: true });
      const link = await call('/api/billing/password-link', { email });
      const c = new Client(h.url);
      await c.req('POST', '/api/auth/set-password', { token: new URL(link.body.url).searchParams.get('token'), password: 'trial-long-password' });
      return c;
    };
    const a = await customer('trial-a@example.com');
    const t = await a.req('POST', '/api/enrollment-tokens', { label: 'trial box' });
    // The token and its command are still there after a reload.
    const pending = await a.req('GET', '/api/enrollment-tokens/pending');
    expect(pending.body.tokens[0]).toMatchObject({ id: t.body.id, token: t.body.token, label: 'trial box' });
    expect(pending.body.tokens[0].install_command).toContain(t.body.token);
    const inv = { hostname: 'box.example.com', primary_ip: '203.0.113.50', ips: ['203.0.113.50', '10.0.0.5'] };
    expect((await new Client(h.url).req('POST', '/api/agent/enroll', { token: t.body.token, public_key: key(), agent_version: '0.21.9', inventory: inv })).status).toBe(200);
    // Used: gone from the list, and its plain text is no longer stored.
    expect((await a.req('GET', '/api/enrollment-tokens/pending')).body.tokens).toHaveLength(0);
    // Another account's trial cannot install on the same server.
    const b = await customer('trial-b@example.com');
    const tb = await b.req('POST', '/api/enrollment-tokens', { label: 'same box' });
    const again = await new Client(h.url).req('POST', '/api/agent/enroll', { token: tb.body.token, public_key: key(), agent_version: '0.21.9', inventory: inv });
    expect(again.status).toBe(402);
    expect(again.body.error).toMatch(/203\.0\.113\.50\) already used its xPGuard free trial/);
    // The same account's next trial (a new trial period) cannot reuse the server either.
    await call('/api/billing/provision', { email: 'trial-a@example.com', plan: 'free-trial', max_servers: 2, period_end: new Date(Date.now() + 60 * 86400_000).toISOString(), trial: true });
    const ta2 = await a.req('POST', '/api/enrollment-tokens', { label: 'second trial' });
    const reuse = await new Client(h.url).req('POST', '/api/agent/enroll', { token: ta2.body.token, public_key: key(), agent_version: '0.21.9', inventory: inv });
    expect(reuse.status).toBe(402);
    // A paid licence installs there without trouble.
    await call('/api/billing/provision', { email: 'trial-b@example.com', plan: 'pro', max_servers: 1, period_end: inAYear(), trial: false });
    expect((await new Client(h.url).req('POST', '/api/agent/enroll', { token: tb.body.token, public_key: key(), agent_version: '0.21.9', inventory: inv })).status).toBe(200);
  });

  it('keeps master settings to the platform account', async () => {
    const c = new Client(h.url);
    await c.login('ali@example.com', 'a-good-long-password');
    for (const [m, p, b] of [
      ['GET', '/api/captcha', undefined],
      ['PUT', '/api/appearance', { theme: 'navy', mode: 'light' }],
      ['GET', '/api/ai/providers', undefined],
      ['GET', '/api/waf/rulesets', undefined],
      ['GET', '/api/waf/intel', undefined],
      ['GET', '/api/mail-protection', undefined],
      ['GET', '/api/domain-reputation', undefined],
      ['GET', '/api/trusted', undefined],
      ['POST', '/api/ipdb/entries', { cidr: '203.0.113.9' }],
      ['POST', '/api/signatures/sync', {}],
    ] as const) {
      const r = await c.req(m, p, b);
      expect(r.status, `${m} ${p}`).toBe(403);
    }
    // Signed for another path: refused.
    const other = signed('/api/billing/usage', { email: 'ali@example.com' });
    expect((await new Client(h.url).req('POST', '/api/billing/login-link', other.body, other.headers)).status).toBe(401);
    // The platform keeps them.
    expect((await owner.req('GET', '/api/captcha')).status).toBe(200);
    // Customers see the platform's look.
    await owner.req('PUT', '/api/appearance', { theme: 'emerald', mode: 'light' });
    expect((await c.req('GET', '/api/appearance')).body.appearance.theme).toBe('emerald');
  });
});
