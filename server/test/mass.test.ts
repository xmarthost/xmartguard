import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';
import { createOwner } from '../src/routes/users.js';
import { parseAddrs } from '../src/routes/mass.js';

let h: Harness;
let c: Client;
let serverIds: string[] = [];

beforeAll(async () => {
  h = await startHarness();
  c = new Client(h.url);
  await c.login();
  const { rows: acc } = await h.pool.query('SELECT id FROM accounts LIMIT 1');
  for (const name of ['web1', 'web2']) {
    const { rows } = await h.pool.query(
      "INSERT INTO servers (account_id, hostname, public_key, agent_version) VALUES ($1, $2, $3, '0.4.0') RETURNING id",
      [acc[0].id, name, 'key-' + name],
    );
    serverIds.push(rows[0].id);
  }
});

afterAll(async () => h.close());

describe('mass operations', () => {
  it('lists operations filtered by role', async () => {
    const r = await c.req('GET', '/api/mass/operations');
    expect(r.status).toBe(200);
    const ids = r.body.operations.map((o: { id: string }) => o.id);
    expect(ids).toEqual(expect.arrayContaining(['quick_scan', 'block_ip', 'waf_on', 'update_agent']));
    await c.req('POST', '/api/users', { email: 'op@example.com', password: 'operator-password-1', role: 'operator' });
    const op = new Client(h.url);
    await op.login('op@example.com', 'operator-password-1');
    const ro = await op.req('GET', '/api/mass/operations');
    const opIds = ro.body.operations.map((o: { id: string }) => o.id);
    expect(opIds).toContain('block_ip');
    expect(opIds).not.toContain('waf_on'); // settings changes need admin
    expect((await op.req('POST', '/api/mass/run', { op: 'waf_on', server_ids: serverIds })).status).toBe(403);
  });

  it('validates input', async () => {
    expect((await c.req('POST', '/api/mass/run', { op: 'nope', server_ids: serverIds })).status).toBe(400);
    expect((await c.req('POST', '/api/mass/run', { op: 'block_ip', server_ids: serverIds, params: { addr: 'x; rm' } })).status).toBe(400);
    expect((await c.req('POST', '/api/mass/run', { op: 'quick_scan', server_ids: [] })).status).toBe(400);
  });

  it('reports per-server results and audits the run', async () => {
    const r = await c.req('POST', '/api/mass/run', { op: 'block_ip', server_ids: serverIds, params: { addrs: '203.0.113.9\n203.0.113.10', reason: 'abuse' } });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ total: 2, ok: 0 });
    expect(r.body.results.map((x: { hostname: string; error: string }) => [x.hostname, x.error])).toEqual([
      ['web1', 'server is offline'],
      ['web2', 'server is offline'],
    ]);
    const { rows } = await h.pool.query("SELECT detail FROM audit_events WHERE action = 'mass.block_ip'");
    expect(rows[0].detail).toMatchObject({ servers: 2, ok: 0, params: { kind: 'deny', mode: 'add', count: 2, reason: 'abuse' } });
  });

  it('reads IP lists one per line', async () => {
    const p = parseAddrs('203.0.113.9\n  198.51.100.0/24 , 2001:db8::1\n# office\n203.0.113.9\n\n10.0.0.1 # vpn');
    expect(p).toEqual({ addrs: ['203.0.113.9', '198.51.100.0/24', '2001:db8::1', '10.0.0.1'], errors: [] });
    expect(parseAddrs('1.2.3.4\nabc\n1.2.3.4/33\n::1/129').errors).toEqual([
      'line 2: "abc" is not an IP address or CIDR',
      'line 3: "1.2.3.4/33" is not an IP address or CIDR',
      'line 4: "::1/129" is not an IP address or CIDR',
    ]);
    const bad = await c.req('POST', '/api/mass/run', { op: 'allow_ip', server_ids: serverIds, params: { addrs: '203.0.113.9\nnope' } });
    expect(bad).toMatchObject({ status: 400, body: { error: 'line 2: "nope" is not an IP address or CIDR' } });
    expect((await c.req('POST', '/api/mass/run', { op: 'allow_ip', server_ids: serverIds, params: { addrs: ' \n' } })).status).toBe(400);
    const many = Array.from({ length: 1001 }, (_, i) => `10.${i >> 8}.${i & 255}.1`).join('\n');
    expect((await c.req('POST', '/api/mass/run', { op: 'allow_ip', server_ids: serverIds, params: { addrs: many } })).status).toBe(400);
    // Unblock only deletes.
    expect((await c.req('POST', '/api/mass/run', { op: 'unblock_ip', server_ids: serverIds, params: { addrs: '203.0.113.9', mode: 'add' } })).status).toBe(400);
    const ops = (await c.req('GET', '/api/mass/operations')).body.operations;
    expect(ops.find((o: { id: string }) => o.id === 'ignore_ip')).toMatchObject({ ip_list: true, modes: ['add', 'delete'] });
  });

  it('keeps customers to their own servers; the master reaches all', async () => {
    await createOwner(h.pool, 'customer@example.com', 'customer-password-1', 'Customer');
    const { rows: acc } = await h.pool.query("SELECT account_id FROM users WHERE email = 'customer@example.com'");
    const { rows } = await h.pool.query(
      "INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, 'foreign', 'key-foreign') RETURNING id",
      [acc[0].account_id],
    );
    const cust = new Client(h.url);
    await cust.login('customer@example.com', 'customer-password-1');
    expect((await cust.req('POST', '/api/mass/run', { op: 'quick_scan', server_ids: serverIds })).body).toMatchObject({ total: 0, results: [] });
    expect((await cust.req('POST', '/api/mass/run', { op: 'quick_scan', server_ids: [rows[0].id] })).body).toMatchObject({ total: 1 });
    expect((await c.req('POST', '/api/mass/run', { op: 'quick_scan', server_ids: [rows[0].id] })).body).toMatchObject({ total: 1 });
  });
});
