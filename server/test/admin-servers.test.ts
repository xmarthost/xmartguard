import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';
import { createOwner } from '../src/routes/users.js';

let h: Harness;
let master: Client;
let cust: Client;
let customerServer = '';

beforeAll(async () => {
  h = await startHarness();
  master = new Client(h.url);
  await master.login();
  const { rows: own } = await h.pool.query('SELECT id FROM accounts WHERE platform');
  for (let i = 1; i <= 25; i++) {
    await h.pool.query("INSERT INTO servers (account_id, hostname, public_key, primary_ip) VALUES ($1, $2, $3, $4)", [
      own[0].id,
      `node${String(i).padStart(2, '0')}.example.net`,
      `k${i}`,
      `198.51.100.${i}`,
    ]);
  }
  await createOwner(h.pool, 'trial@example.com', 'trial-password-123', 'Trial Co');
  const { rows: acc } = await h.pool.query("SELECT account_id FROM users WHERE email = 'trial@example.com'");
  await h.pool.query("INSERT INTO account_licenses (account_id, plan, max_servers, status, trial) VALUES ($1, 'trial', 1, 'active', true)", [acc[0].account_id]);
  const { rows } = await h.pool.query(
    "INSERT INTO servers (account_id, hostname, public_key, primary_ip) VALUES ($1, 'shop.customer.test', 'kc', '203.0.113.50') RETURNING id",
    [acc[0].account_id],
  );
  customerServer = rows[0].id;
  cust = new Client(h.url);
  await cust.login('trial@example.com', 'trial-password-123');
});

afterAll(async () => h.close());

describe('master: all servers', () => {
  it('lists every account\'s servers 20 per page', async () => {
    const r = await master.req('GET', '/api/admin/servers');
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ page: 1, per: 20, total: 26, pages: 2, counts: { all: 26, customer: 1, trial: 1, paid: 0 } });
    expect(r.body.servers).toHaveLength(20);
    const p2 = await master.req('GET', '/api/admin/servers?page=2');
    expect(p2.body.servers).toHaveLength(6);
    const shop = p2.body.servers.find((s: { id: string }) => s.id === customerServer);
    expect(shop.account).toMatchObject({ owner_email: 'trial@example.com', trial: true, platform: false, name: 'Trial Co' });
  });

  it('searches by hostname, IP, owner email and filters', async () => {
    const one = async (qs: string) => (await master.req('GET', '/api/admin/servers?' + qs)).body;
    expect((await one('q=node07')).servers.map((s: { hostname: string }) => s.hostname)).toEqual(['node07.example.net']);
    expect((await one('q=203.0.113.50')).total).toBe(1);
    expect((await one('q=trial%40example')).servers[0].id).toBe(customerServer);
    expect((await one('filter=trial')).total).toBe(1);
    expect((await one('filter=platform')).total).toBe(25);
    expect((await master.req('GET', '/api/admin/servers?filter=bogus')).status).toBe(400);
  });

  it('gives the master full access to customer servers, never the other way', async () => {
    expect((await master.req('GET', `/api/servers/${customerServer}`)).status).toBe(200);
    expect((await master.req('PATCH', `/api/servers/${customerServer}`, { tags: ['vip'] })).status).toBe(200);
    // Agent commands reach the server (offline here, so 409 rather than 404).
    expect((await master.req('POST', `/api/servers/${customerServer}/agent/fw.list`, {})).status).toBe(409);
    expect((await cust.req('GET', '/api/admin/servers')).status).toBe(403);
    const { rows } = await h.pool.query("SELECT id FROM servers WHERE hostname = 'node01.example.net'");
    expect((await cust.req('GET', `/api/servers/${rows[0].id}`)).status).toBe(404);
    expect((await cust.req('POST', `/api/servers/${rows[0].id}/agent/fw.list`, {})).status).toBe(404);
    expect((await cust.req('GET', `/api/servers/${customerServer}`)).status).toBe(200);
  });
});
