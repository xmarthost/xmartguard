import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, OWNER, startHarness, type Harness } from './helpers.js';

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
  });
});
