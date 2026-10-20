import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, OWNER, startHarness, type Harness } from './helpers.js';
import { safePageLink } from '../src/routes/notifications.js';

let h: Harness;
let c: Client;
beforeAll(async () => {
  h = await startHarness();
  c = new Client(h.url);
});
afterAll(async () => h.close());

describe('own profile', () => {
  it('changes the name freely and the email only with the current password', async () => {
    await c.login();
    let r = await c.req('PUT', '/api/auth/profile', { name: 'Shoaib', email: OWNER.email });
    expect(r.status).toBe(200);
    expect(r.body.user.name).toBe('Shoaib');
    expect((await c.req('PUT', '/api/auth/profile', { name: 'Shoaib', email: 'new@example.com' })).status).toBe(403);
    expect((await c.req('PUT', '/api/auth/profile', { name: 'Shoaib', email: 'new@example.com', current_password: 'wrong-password' })).status).toBe(403);
    expect((await c.req('PUT', '/api/auth/profile', { name: 'Shoaib', email: 'not an email', current_password: OWNER.password })).status).toBe(400);
    r = await c.req('PUT', '/api/auth/profile', { name: 'Shoaib', email: 'new@example.com', current_password: OWNER.password });
    expect(r.status).toBe(200);
    expect((await c.req('GET', '/api/auth/me')).body.user.email).toBe('new@example.com');
    // The new email is the login now.
    const fresh = new Client(h.url);
    await fresh.login('new@example.com', OWNER.password);
    // Put it back for other tests.
    await c.req('PUT', '/api/auth/profile', { name: '', email: OWNER.email, current_password: OWNER.password });
  });
});

describe('notifications (header bell)', () => {
  it('lists offline servers, all of them or just one', async () => {
    await c.login();
    const { rows: acc } = await h.pool.query('SELECT id FROM accounts LIMIT 1');
    const ids: string[] = [];
    for (const host of ['bell-a', 'bell-b']) {
      const { rows } = await h.pool.query("INSERT INTO servers (account_id, hostname, public_key, status) VALUES ($1, $2, $3, 'active') RETURNING id", [acc[0].id, host, `key-${host}`]);
      ids.push(String(rows[0].id));
    }
    expect((await new Client(h.url).req('GET', '/api/notifications')).status).toBe(401);
    const all = await c.req('GET', '/api/notifications');
    expect(all.status).toBe(200);
    const mine = all.body.items.filter((n: { hostname: string }) => n.hostname.startsWith('bell-'));
    expect(mine).toHaveLength(2);
    expect(mine[0]).toMatchObject({ level: 'danger', text: expect.stringContaining('offline') });
    const one = await c.req('GET', `/api/notifications?server=${ids[1]}`);
    expect(one.body.items).toHaveLength(1);
    expect(one.body.items[0]).toMatchObject({ server_id: ids[1], hostname: 'bell-b' });
    // The master opens a customer's server: its bell shows that server's alerts.
    const { rows: cust } = await h.pool.query("INSERT INTO accounts (name) VALUES ('Bell Customer') RETURNING id");
    const { rows: cs } = await h.pool.query("INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, 'bell-cust', 'key-bell-cust') RETURNING id", [cust[0].id]);
    const theirs = await c.req('GET', `/api/notifications?server=${cs[0].id}`);
    expect(theirs.body.items).toEqual([expect.objectContaining({ server_id: String(cs[0].id), text: expect.stringContaining('offline') })]);
  });
});

describe('notification links from agents', () => {
  it('pass only pages of that server', () => {
    for (const ok of ['scanner-logs', 'scanner-logs?paused=1', 'domain-reputation', 'settings', 'waf-logs']) expect(safePageLink(ok)).toBe(ok);
    for (const bad of ['https://evil.example/x', '//evil.example', '/admin', '../../settings', 'javascript:alert(1)', 'a b', 'x?u=//evil.example', 7]) expect(safePageLink(bad)).toBe('');
  });
});

describe('password guessing against one account', () => {
  it('locks the email after many failures from any addresses, with the same answer', async () => {
    // Ten failures already recorded for the owner (from many addresses).
    await h.pool.query(
      "INSERT INTO audit_events (action, detail, ip) SELECT 'auth.login_failed', jsonb_build_object('email', $1::text), '198.51.100.' || g FROM generate_series(1, 10) g",
      [OWNER.email.toUpperCase()],
    );
    const r = await new Client(h.url).req('POST', '/api/auth/login', { email: OWNER.email, password: OWNER.password });
    expect(r.status).toBe(401);
    expect(r.body.error).toBe('invalid email or password');
    // After the window the right password works again.
    await h.pool.query("UPDATE audit_events SET created_at = now() - interval '1 hour' WHERE action = 'auth.login_failed'");
    expect((await new Client(h.url).req('POST', '/api/auth/login', { email: OWNER.email, password: OWNER.password })).status).toBe(200);
  });

  it('has indexes for the hourly prunes and lookups', async () => {
    const { rows } = await h.pool.query("SELECT indexname FROM pg_indexes WHERE indexname = ANY($1)", [['server_metrics_ts_idx', 'captcha_events_at_idx', 'ai_kb_match_idx', 'audit_login_failed_idx']]);
    expect(rows).toHaveLength(4);
  });
});
