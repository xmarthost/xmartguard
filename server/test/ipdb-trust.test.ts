import crypto from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { startHarness, type Harness } from './helpers.js';
import { IPDBService, PROTECTED_PER_SERVER } from '../src/ipdb/service.js';
import { GeoDB } from '../src/ipdb/geo.js';
import type { AgentHub } from '../src/agents/hub.js';

// What each server's agent answers to ipdb.sync (any agent may lie: its
// owner has root on it).
const answers = new Map<string, Record<string, unknown>>();
const hub = {
  command: async (serverId: string, action: string) => (action === 'ipdb.sync' ? (answers.get(serverId) ?? {}) : {}),
  connections: () => [],
} as unknown as AgentHub;

let h: Harness;
let ipdb: IPDBService;
let master = '';
const key = () => crypto.randomBytes(32).toString('base64');

async function server(accountId: string, inventory: Record<string, unknown> = {}): Promise<string> {
  const { rows } = await h.pool.query(
    'INSERT INTO servers (account_id, hostname, public_key, inventory, primary_ip) VALUES ($1, $2, $3, $4, $5) RETURNING id',
    [accountId, 'srv', key(), JSON.stringify(inventory), String(inventory.primary_ip ?? '')],
  );
  return rows[0].id;
}
async function customer(name: string): Promise<string> {
  return (await h.pool.query('INSERT INTO accounts (name) VALUES ($1) RETURNING id', [name])).rows[0].id;
}
let nextId = 1;
const reports = (ip: string, n: number) => Array.from({ length: n }, () => ({ id: nextId++, ip, source: 'waf', reason: 'test', at: Date.now() / 1000 }));

beforeAll(async () => {
  h = await startHarness();
  master = (await h.pool.query('SELECT id FROM accounts WHERE platform')).rows[0].id;
  ipdb = new IPDBService(h.pool, h.cfg, hub, new GeoDB(), h.app.log);
});
afterAll(async () => {
  ipdb.stop();
  await h.close();
});

describe("IPDB: one customer's agent cannot change the fleet's list", () => {
  it('lists an address one customer server reports only when another account agrees', async () => {
    const a = await server(await customer('Cust A'));
    const b = await server(await customer('Cust B'));
    const own = await server(master);
    answers.set(a, { reports: [...reports('198.51.100.20', 10), ...reports('198.51.100.21', 1)] });
    answers.set(own, { reports: reports('198.51.100.22', 3) });
    await ipdb.syncServer(a);
    await ipdb.syncServer(own);
    await ipdb.rebuild();
    expect(ipdb.entries).not.toContain('198.51.100.20');
    expect(ipdb.entries).toContain('198.51.100.22');
    // A second, independent account reports the same address: listed.
    answers.set(b, { reports: reports('198.51.100.21', 1) });
    await ipdb.syncServer(b);
    await ipdb.rebuild();
    expect(ipdb.entries).toContain('198.51.100.21');
    expect(ipdb.entries).not.toContain('198.51.100.20');
  });

  it("takes CAPTCHA clearings from the platform's servers only", async () => {
    await h.pool.query("INSERT INTO ipdb_entries (cidr, source, reason, note) VALUES ('198.51.100.30', 'feed', 'test feed', 'test'), ('198.51.100.31', 'feed', 'test feed', 'test')");
    const a = await server(await customer('Cust C'));
    const own = await server(master);
    answers.set(a, { solved: [{ ip: '198.51.100.30', at: Date.now() / 1000 }] });
    answers.set(own, { solved: [{ ip: '198.51.100.31', at: Date.now() / 1000 }] });
    await ipdb.syncServer(a);
    await ipdb.syncServer(own);
    await ipdb.rebuild();
    expect(ipdb.entries).toContain('198.51.100.30');
    expect(ipdb.entries).not.toContain('198.51.100.31');
  });

  it("protects only a few addresses a customer's inventory names", async () => {
    const many = Array.from({ length: 1000 }, (_, i) => `203.0.113.${i % 250}`).map((ip, i) => (i < 250 ? ip : `198.18.${Math.floor(i / 250)}.${i % 250}`));
    await server(await customer('Cust D'), { primary_ip: '192.0.2.10', ips: many });
    await server(master, { primary_ip: '192.0.2.20', ips: ['192.0.2.21', '192.0.2.22', ...Array.from({ length: 20 }, (_, i) => `192.0.2.${100 + i}`)] });
    const prot = await ipdb.protectedIPs();
    expect(prot).toContain('192.0.2.10');
    expect(prot.filter((ip) => ip.startsWith('203.0.113.') || ip.startsWith('198.18.')).length).toBeLessThan(PROTECTED_PER_SERVER);
    expect(prot).toContain('192.0.2.119');
  });

  it('moves the cursor on past rows the database cannot take', async () => {
    const own = await server(master);
    const first = nextId;
    answers.set(own, {
      reports: [
        { id: nextId++, ip: '198.51.100.40', source: 'waf', reason: 'nul \u0000 byte', at: 1e300 },
        { id: nextId++, ip: '198.51.100.41', source: 'waf', reason: 'ok', at: Date.now() / 1000 },
      ],
      hits: [{ entry: '198.51.100.40', country: 'NL', hits: Infinity, last_seen: 1e300 }, { entry: '198.51.100.41', country: 'NL', hits: 1e20, last_seen: -1e300 }],
    });
    await ipdb.syncServer(own);
    const cur = (await h.pool.query('SELECT ipdb_cursor FROM servers WHERE id = $1', [own])).rows[0].ipdb_cursor;
    expect(Number(cur)).toBe(first + 1);
    const { rows } = await h.pool.query('SELECT host(ip) AS ip, reason FROM ipdb_reports WHERE server_id = $1 ORDER BY ip', [own]);
    expect(rows).toEqual([{ ip: '198.51.100.40', reason: 'nul  byte' }, { ip: '198.51.100.41', reason: 'ok' }]);
    expect((await h.pool.query('SELECT hits FROM ipdb_hits WHERE server_id = $1', [own])).rows).toEqual([{ hits: '1000000000' }]);
  });

  it('forgets the one-shot timers of agent connections once they ran', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      for (let i = 0; i < 20; i++) ipdb.onConnect(crypto.randomUUID(), '0.22.0');
      expect(ipdb.pendingTimers()).toBeGreaterThan(0);
      vi.advanceTimersByTime(10_000);
      expect(ipdb.pendingTimers()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});
