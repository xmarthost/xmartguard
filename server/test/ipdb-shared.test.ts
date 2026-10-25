import crypto from 'node:crypto';
import http from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startHarness, type Harness } from './helpers.js';
import { IPDBService } from '../src/ipdb/service.js';
import { GeoDB } from '../src/ipdb/geo.js';
import { SharedEgress, parseRelayCSV } from '../src/ipdb/shared.js';
import type { AgentHub } from '../src/agents/hub.js';

const answers = new Map<string, Record<string, unknown>>();
const hub = {
  command: async (serverId: string, action: string) => (action === 'ipdb.sync' ? (answers.get(serverId) ?? {}) : {}),
  connections: () => [],
} as unknown as AgentHub;

let h: Harness;
let ipdb: IPDBService;
let srv: http.Server;
let csv = '';
let nextId = 1;
const reports = (ip: string, n: number) => Array.from({ length: n }, () => ({ id: nextId++, ip, source: 'waf', reason: 'test', at: Date.now() / 1000 }));

// An Apple-style list: range,country,region,city, (1,200 ranges).
function appleCSV(extra: string[]): string {
  const lines = [...extra];
  for (let i = 0; lines.length < 1200; i++) lines.push(`172.225.${i >> 4}.${(i & 15) * 16}/28,GB,GB-EN,London,`);
  return lines.join('\n') + '\n';
}

beforeAll(async () => {
  h = await startHarness();
  ipdb = new IPDBService(h.pool, h.cfg, hub, new GeoDB(), h.app.log);
  srv = http.createServer((_q, r) => r.end(csv));
  await new Promise<void>((ok) => srv.listen(0, '127.0.0.1', ok));
  ipdb.relayURL = `http://127.0.0.1:${(srv.address() as { port: number }).port}/egress.csv`;
});
afterAll(async () => {
  ipdb.stop();
  srv.close();
  await h.close();
});

describe('IPDB: shared egress networks stay off the fleet list', () => {
  it('looks up addresses and networks in the ranges', () => {
    const s = new SharedEgress(['104.29.197.0/24', '2606:54c1:1:cd8::/64']);
    expect(s.relayRanges).toBe(2);
    expect(s.has('104.29.197.208')).toBe(true);
    expect(s.has('104.29.197.0/25')).toBe(true);
    expect(s.has('104.29.196.0/23')).toBe(false); // only partly inside
    expect(s.has('104.29.198.1')).toBe(false);
    expect(s.has('2606:54c1:1:cd8::499:65')).toBe(true);
    expect(s.has('2606:54c1:1:cd9::1')).toBe(false);
    // Meta's own networks always.
    expect(s.has('57.141.20.7')).toBe(true);
    expect(s.has('2a03:2880:16ff:5e::')).toBe(true);
    expect(s.has('not an address')).toBe(false);
    expect(parseRelayCSV('172.224.226.0/27,GB,GB-EN,London,\n\nbad,XX\n2a02:26f7:b3c0:4000::/64,GB,GB-EN,London,\n')).toEqual([
      '172.224.226.0/27',
      '2a02:26f7:b3c0:4000::/64',
    ]);
  });

  it("keeps iCloud Private Relay and Meta addresses off the list, but not Cloudflare WARP's", async () => {
    // Website owners on Private Relay banned by mistake (business200,
    // 2026-10-25: 104.29.x) were reported by several servers.
    const servers: string[] = [];
    for (let i = 0; i < 2; i++) {
      const { rows } = await h.pool.query(
        "INSERT INTO servers (account_id, hostname, public_key) VALUES ((SELECT id FROM accounts WHERE platform), 'srv', $1) RETURNING id",
        [crypto.randomBytes(32).toString('base64')],
      );
      servers.push(rows[0].id);
    }
    const ips = ['104.29.197.208', '2606:54c1:1:cd8::499:65', '57.141.20.7', '104.28.1.1', '198.51.100.77'];
    for (const s of servers) {
      answers.set(s, { reports: ips.flatMap((ip) => reports(ip, 3)) });
      await ipdb.syncServer(s);
    }
    csv = appleCSV(['104.29.197.0/24,GB,GB-EN,London,', '2606:54c1:1:cd8::/64,GB,GB-EN,London,']);
    expect(await ipdb.refreshRelay()).toBe(1200);
    await ipdb.rebuild();
    for (const ip of ['104.29.197.208', '2606:54c1:1:cd8::499:65', '57.141.20.7']) expect(ipdb.entries).not.toContain(ip);
    // Cloudflare's WARP (a free VPN on Cloudflare's ranges) and others: listed.
    expect(ipdb.entries).toContain('104.28.1.1');
    expect(ipdb.entries).toContain('198.51.100.77');

    // The operator can still list one by hand.
    await h.pool.query("INSERT INTO ipdb_entries (cidr, source, reason) VALUES ('104.29.197.9', 'manual', 'test')");
    await ipdb.rebuild();
    expect(ipdb.entries).toContain('104.29.197.9');

    // A short or failed download keeps the saved list, also after a restart.
    csv = '<html>error</html>';
    await expect(ipdb.refreshRelay()).rejects.toThrow(/only 0 ranges/);
    const again = new IPDBService(h.pool, h.cfg, hub, new GeoDB(), h.app.log);
    await again.rebuild();
    expect(again.entries).not.toContain('104.29.197.208');
    expect(again.entries).toContain('104.28.1.1');
    again.stop();
  }, 60_000);

  it('checks a large list quickly', () => {
    const ranges: string[] = [];
    for (let i = 0; i < 300_000; i++) ranges.push(`${10 + (i >> 16)}.${(i >> 8) & 255}.${i & 255}.0/28`);
    const s = new SharedEgress(ranges);
    const t = Date.now();
    let n = 0;
    for (let i = 0; i < 200_000; i++) if (s.has(`${10 + (i % 5)}.${i & 255}.${(i >> 8) & 255}.5`)) n++;
    expect(n).toBeGreaterThan(0);
    expect(Date.now() - t).toBeLessThan(3000);
  });
});
