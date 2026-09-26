import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';

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
    const r = await c.req('POST', '/api/mass/run', { op: 'block_ip', server_ids: serverIds, params: { addr: '203.0.113.9' } });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ total: 2, ok: 0 });
    expect(r.body.results.map((x: { hostname: string; error: string }) => [x.hostname, x.error])).toEqual([
      ['web1', 'server is offline'],
      ['web2', 'server is offline'],
    ]);
    const { rows } = await h.pool.query("SELECT detail FROM audit_events WHERE action = 'mass.block_ip'");
    expect(rows[0].detail).toMatchObject({ servers: 2, ok: 0 });
  });

  it('never touches servers of another account', async () => {
    const { rows: acc } = await h.pool.query("INSERT INTO accounts (name) VALUES ('other') RETURNING id");
    const { rows } = await h.pool.query(
      "INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, 'foreign', 'key-foreign') RETURNING id",
      [acc[0].id],
    );
    const r = await c.req('POST', '/api/mass/run', { op: 'quick_scan', server_ids: [rows[0].id] });
    expect(r.body).toMatchObject({ total: 0, ok: 0, results: [] });
  });
});
