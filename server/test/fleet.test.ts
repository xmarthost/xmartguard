import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';

let h: Harness;
let admin: Client;
const ids: string[] = [];
const rollbacks: string[] = [];

beforeAll(async () => {
  h = await startHarness({});
  const { rows: acc } = await h.pool.query('SELECT id FROM accounts LIMIT 1');
  for (const [host, metrics] of [['web-a', { cpu_percent: 12, disk_used: 98, disk_total: 100 }], ['web-b', { cpu_percent: 5, disk_used: 10, disk_total: 100 }]] as const) {
    const { rows } = await h.pool.query(
      "INSERT INTO servers (account_id, hostname, public_key, agent_version, last_metrics) VALUES ($1, $2, $3, '0.21.34', $4) RETURNING id",
      [acc[0].id, host, 'key-' + host, JSON.stringify(metrics)],
    );
    ids.push(String(rows[0].id));
  }
  await h.pool.query(`INSERT INTO waf_server_status (server_id, status) VALUES ($1, '{"error":"Apache refused the rules"}')`, [ids[1]]);
  admin = new Client(h.url);
  await admin.login();
  h.hub.isOnline = (id: string) => id === ids[0] || id === ids[1];
  h.hub.command = async (id: string, action: string) => {
    if (action === 'alerts.get') return { alerts: id === ids[0] ? [{ level: 'danger', text: 'Firewall is not working: ipset missing' }] : [] };
    if (action === 'settings.rollback') {
      rollbacks.push(id);
      if (id === ids[1]) throw new Error('no settings change to undo in that time');
      return { settings: {} };
    }
    throw new Error('unexpected ' + action);
  };
});

afterAll(async () => {
  await h.close();
});

describe('fleet health', () => {
  it('lists what needs fixing on each server', async () => {
    const r = await admin.req('GET', '/api/fleet/health');
    expect(r.status).toBe(200);
    const a = r.body.servers.find((s: { hostname: string }) => s.hostname === 'web-a');
    const b = r.body.servers.find((s: { hostname: string }) => s.hostname === 'web-b');
    expect(a.problems.map((p: { fix: string }) => p.fix)).toEqual(expect.arrayContaining(['monitoring', 'dashboard']));
    expect(b.problems[0]).toMatchObject({ level: 'danger', fix: 'waf' });
    expect(r.body.summary).toMatchObject({ total: 2, offline: 0, problems: 2 });
  });

  it('rolls settings back on every server', async () => {
    const r = await admin.req('POST', '/api/fleet/rollback', { before: 1_700_000_000 });
    expect(r.status).toBe(200);
    expect(rollbacks.sort()).toEqual([...ids].sort());
    expect(r.body.results.filter((x: { ok: boolean }) => x.ok).length).toBe(1);
    expect((await admin.req('POST', '/api/fleet/rollback', {})).status).toBe(400);
  });
});
