import crypto from 'node:crypto';
import net from 'node:net';
import type { FastifyBaseLogger } from 'fastify';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';
import type { AgentHub } from '../agents/hub.js';
import { versionLess } from '../agents/release.js';
import type { GeoDB } from './geo.js';

/** Agents older than this do not implement the ipdb.* commands. */
export const IPDB_MIN_AGENT = '0.3.0';

// Addresses that are never reported or listed.
const reserved = new net.BlockList();
for (const [a, p] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.168.0.0', 16], ['224.0.0.0', 3],
] as const) reserved.addSubnet(a, p, 'ipv4');
for (const [a, p] of [['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]] as const) {
  reserved.addSubnet(a, p, 'ipv6');
}

/** True for a public unicast IP address. */
export function reportable(ip: string): boolean {
  const fam = net.isIP(ip);
  if (!fam) return false;
  return !reserved.check(ip, fam === 4 ? 'ipv4' : 'ipv6');
}

/** Validates "IP" or "IP/len" (not too broad) and returns canonical text, or null. */
export function parseCidr(s: string): string | null {
  const [addr, len, extra] = s.trim().split('/');
  if (extra !== undefined) return null;
  const fam = net.isIP(addr);
  if (!fam) return null;
  const max = fam === 4 ? 32 : 128;
  if (len === undefined) return addr.toLowerCase();
  if (!/^\d{1,3}$/.test(len)) return null;
  const n = Number(len);
  if (n > max || n < (fam === 4 ? 8 : 16)) return null;
  return n === max ? addr.toLowerCase() : `${addr.toLowerCase()}/${n}`;
}

/** Postgres cidr text -> list entry ("1.2.3.4" for host routes). */
export function entryText(cidr: string): string {
  return cidr.replace(/\/(32|128)$/, '');
}

interface SyncResult {
  enabled?: boolean;
  version?: string;
  reports?: { id: number; ip: string; source: string; reason: string; at: number }[];
  hits?: { entry: string; country: string; hits: number; last_seen: number }[];
}

/**
 * The IPDB: aggregates automatic bans reported by every agent, merges public
 * feeds and manual entries, and distributes the resulting list to agents.
 */
export class IPDBService {
  version = '';
  entries: string[] = [];
  builtAt = 0;
  private dirty = true;
  private timers: NodeJS.Timeout[] = [];
  private syncing = new Set<string>();
  private building: Promise<void> | null = null;

  constructor(
    private pool: Pool,
    private cfg: Config,
    private hub: AgentHub,
    readonly geo: GeoDB,
    private log: FastifyBaseLogger,
  ) {}

  markDirty(): void {
    this.dirty = true;
  }

  start(): void {
    if (!this.cfg.ipdbSync) return;
    const tick = async () => {
      try {
        if (this.dirty || Date.now() - this.builtAt > 10 * 60_000) await this.rebuild();
        await this.syncAll();
      } catch (err) {
        this.log.error({ err }, 'ipdb tick failed');
      }
    };
    this.timers.push(setInterval(tick, 60_000));
    this.timers.push(setTimeout(tick, 5_000));
    const feeds = () => this.refreshFeeds().catch((err) => this.log.error({ err }, 'ipdb feeds failed'));
    this.timers.push(setTimeout(feeds, 30_000));
    this.timers.push(setInterval(feeds, 12 * 3600_000));
  }

  stop(): void {
    for (const t of this.timers) clearTimeout(t);
    this.timers = [];
  }

  /** Called when an agent connects so it gets the list quickly. */
  onConnect(serverId: string, agentVersion: string): void {
    if (!this.cfg.ipdbSync || versionLess(agentVersion, IPDB_MIN_AGENT)) return;
    const t = setTimeout(() => {
      this.ensureBuilt()
        .then(() => this.syncServer(serverId))
        .catch((err) => this.log.warn({ serverId, err: (err as Error).message }, 'ipdb sync failed'));
    }, 5_000);
    this.timers.push(t);
  }

  async ensureBuilt(): Promise<void> {
    if (!this.builtAt || this.dirty) await this.rebuild();
  }

  /** Recomputes community entries and the distributed list. */
  rebuild(): Promise<void> {
    if (!this.building) {
      this.building = this.doRebuild().finally(() => {
        this.building = null;
      });
    }
    return this.building;
  }

  private async doRebuild(): Promise<void> {
    this.dirty = false;
    const c = this.cfg;
    const { rows: agg } = await this.pool.query(
      `SELECT ip::cidr::text AS cidr, count(DISTINCT server_id)::int AS reporters, count(*)::int AS reports,
              min(created_at) AS first_seen, max(created_at) AS last_seen,
              (array_agg(reason ORDER BY id DESC))[1] AS reason
         FROM ipdb_reports
        WHERE created_at > now() - make_interval(days => $1)
        GROUP BY ip
       HAVING count(DISTINCT server_id) >= $2 OR count(*) >= $3`,
      [c.ipdbWindowDays, c.ipdbMinReporters, c.ipdbMinReports],
    );
    if (agg.length) {
      await this.pool.query(
        `INSERT INTO ipdb_entries (cidr, source, country, reporters, reports, reason, first_seen, last_seen, expires_at)
         SELECT x.cidr, 'community', x.cc, x.reporters, x.reports, x.reason, x.first_seen, x.last_seen,
                x.last_seen + make_interval(days => $8)
           FROM unnest($1::cidr[], $2::text[], $3::int[], $4::int[], $5::text[], $6::timestamptz[], $7::timestamptz[])
                AS x(cidr, cc, reporters, reports, reason, first_seen, last_seen)
         ON CONFLICT (cidr) DO UPDATE SET
           reporters = excluded.reporters, reports = excluded.reports, reason = excluded.reason,
           last_seen = excluded.last_seen,
           expires_at = CASE WHEN ipdb_entries.source = 'community' THEN excluded.expires_at ELSE ipdb_entries.expires_at END`,
        [
          agg.map((r) => r.cidr),
          agg.map((r) => this.geo.lookup(r.cidr)),
          agg.map((r) => r.reporters),
          agg.map((r) => r.reports),
          agg.map((r) => String(r.reason ?? '').slice(0, 200)),
          agg.map((r) => r.first_seen),
          agg.map((r) => r.last_seen),
          c.ipdbTtlDays,
        ],
      );
    }
    await this.pool.query('DELETE FROM ipdb_entries WHERE expires_at IS NOT NULL AND expires_at < now()');
    await this.pool.query("DELETE FROM ipdb_reports WHERE created_at < now() - interval '90 days'");
    await this.pool.query("DELETE FROM ipdb_hits WHERE day < current_date - 90");

    // Fill in countries once the GeoIP database is available.
    if (this.geo.size) {
      const { rows: missing } = await this.pool.query("SELECT cidr::text AS cidr FROM ipdb_entries WHERE country = '' LIMIT 20000");
      const upd = missing.map((r) => ({ cidr: r.cidr as string, cc: this.geo.lookup(r.cidr) })).filter((x) => x.cc);
      if (upd.length) {
        await this.pool.query(
          `UPDATE ipdb_entries e SET country = x.cc FROM unnest($1::cidr[], $2::text[]) AS x(cidr, cc) WHERE e.cidr = x.cidr`,
          [upd.map((x) => x.cidr), upd.map((x) => x.cc)],
        );
      }
    }

    const { rows } = await this.pool.query(
      `SELECT e.cidr::text AS cidr, e.country FROM ipdb_entries e
        WHERE NOT EXISTS (SELECT 1 FROM ipdb_whitelist w WHERE w.cidr >>= e.cidr OR e.cidr >>= w.cidr)
          AND NOT (e.cidr >>= ANY($1::inet[]))
        ORDER BY (e.source = 'manual') DESC, e.last_seen DESC
        LIMIT $2`,
      [await this.protectedIPs(), c.ipdbMaxEntries],
    );
    const lines = rows.map((r) => `${entryText(r.cidr)} ${r.country || ''}`.trim()).sort();
    this.entries = lines;
    this.version = crypto.createHash('sha256').update(lines.join('\n')).digest('hex').slice(0, 16);
    this.builtAt = Date.now();
  }

  /** Every enrolled server's addresses: never listed. */
  async protectedIPs(): Promise<string[]> {
    const { rows } = await this.pool.query("SELECT primary_ip, inventory->'ips' AS ips FROM servers WHERE status = 'active'");
    const out = new Set<string>();
    for (const r of rows) {
      for (const ip of [r.primary_ip, ...(Array.isArray(r.ips) ? r.ips : [])]) {
        if (typeof ip === 'string' && net.isIP(ip)) out.add(ip);
      }
    }
    return [...out];
  }

  private async syncAll(): Promise<void> {
    const conns = this.hub.connections().filter((c) => !versionLess(c.version, IPDB_MIN_AGENT));
    for (let i = 0; i < conns.length; i += 5) {
      await Promise.all(
        conns.slice(i, i + 5).map((c) =>
          this.syncServer(c.serverId).catch((err) =>
            this.log.warn({ serverId: c.serverId, err: (err as Error).message }, 'ipdb sync failed'),
          ),
        ),
      );
    }
    if (this.dirty) await this.rebuild();
  }

  /** Pulls reports and hits from one agent and pushes the list if it is stale. */
  async syncServer(serverId: string): Promise<void> {
    if (this.syncing.has(serverId)) return;
    this.syncing.add(serverId);
    try {
      const { rows } = await this.pool.query(
        "SELECT account_id, ipdb_cursor, ipdb_version FROM servers WHERE id = $1 AND status = 'active'",
        [serverId],
      );
      const srv = rows[0];
      if (!srv) return;
      const data = (await this.hub.command(serverId, 'ipdb.sync', { since: Number(srv.ipdb_cursor) }, 60_000)) as SyncResult;
      const reports = (data.reports ?? []).filter((r) => typeof r?.id === 'number' && reportable(String(r.ip)));
      let cursor = Number(srv.ipdb_cursor);
      for (const r of data.reports ?? []) if (typeof r?.id === 'number' && r.id > cursor) cursor = r.id;
      if (reports.length) {
        await this.pool.query(
          `INSERT INTO ipdb_reports (ip, server_id, account_id, source, reason, reported_at)
           SELECT x.ip, $1, $2, x.source, x.reason, to_timestamp(x.at)
             FROM unnest($3::inet[], $4::text[], $5::text[], $6::float8[]) AS x(ip, source, reason, at)`,
          [
            serverId,
            srv.account_id,
            reports.map((r) => r.ip),
            reports.map((r) => String(r.source ?? '').slice(0, 30)),
            reports.map((r) => String(r.reason ?? '').slice(0, 200)),
            reports.map((r) => (Number.isFinite(r.at) ? r.at : Date.now() / 1000)),
          ],
        );
        this.dirty = true;
      }
      const hits = (data.hits ?? []).filter((h) => h && parseCidr(String(h.entry)) && Number(h.hits) > 0);
      if (hits.length) {
        await this.pool.query(
          `INSERT INTO ipdb_hits (server_id, entry, day, country, hits, last_seen)
           SELECT $1, x.entry, to_timestamp(x.ts)::date, x.cc, x.hits, to_timestamp(x.ts)
             FROM unnest($2::text[], $3::text[], $4::bigint[], $5::float8[]) AS x(entry, cc, hits, ts)
           ON CONFLICT (server_id, entry, day) DO UPDATE SET
             hits = ipdb_hits.hits + excluded.hits, last_seen = greatest(ipdb_hits.last_seen, excluded.last_seen),
             country = CASE WHEN excluded.country <> '' THEN excluded.country ELSE ipdb_hits.country END`,
          [
            serverId,
            hits.map((h) => String(h.entry)),
            hits.map((h) => (/^[A-Z]{2}$/.test(String(h.country)) ? h.country : this.geo.lookup(String(h.entry)))),
            hits.map((h) => Math.floor(Number(h.hits))),
            hits.map((h) => (Number.isFinite(h.last_seen) ? h.last_seen : Date.now() / 1000)),
          ],
        );
      }
      await this.pool.query('UPDATE servers SET ipdb_cursor = $2, ipdb_synced_at = now() WHERE id = $1', [serverId, cursor]);
      if (data.enabled && this.version && data.version !== this.version) {
        await this.hub.command(serverId, 'ipdb.apply', { version: this.version, entries: this.entries }, 180_000);
        await this.pool.query('UPDATE servers SET ipdb_version = $2 WHERE id = $1', [serverId, this.version]);
      } else if (data.version && data.version !== srv.ipdb_version) {
        await this.pool.query('UPDATE servers SET ipdb_version = $2 WHERE id = $1', [serverId, data.version]);
      }
    } finally {
      this.syncing.delete(serverId);
    }
  }

  /** Downloads the configured public feeds and merges them as 'feed' entries. */
  async refreshFeeds(): Promise<Record<string, number>> {
    const result: Record<string, number> = {};
    for (const url of this.cfg.ipdbFeeds) {
      try {
        const res = await fetch(url, { signal: AbortSignal.timeout(60_000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const text = (await res.text()).slice(0, 20 << 20);
        const cidrs = parseFeed(text);
        result[url] = cidrs.length;
        if (!cidrs.length) continue; // never wipe a feed on an empty/odd response
        await this.pool.query(
          `DELETE FROM ipdb_entries WHERE source = 'feed' AND note = $1
              AND NOT (cidr = ANY(ARRAY(SELECT network(t::inet) FROM unnest($2::text[]) AS t)))`,
          [url, cidrs],
        );
        await this.pool.query(
          `INSERT INTO ipdb_entries (cidr, source, country, reason, note)
           SELECT DISTINCT ON (network(x.c::inet)) network(x.c::inet), 'feed', x.cc, 'public blocklist', $3
             FROM unnest($1::text[], $2::text[]) AS x(c, cc)
           ON CONFLICT (cidr) DO UPDATE SET last_seen = now() WHERE ipdb_entries.source = 'feed'`,
          [cidrs, cidrs.map((c) => this.geo.lookup(c)), url],
        );
        this.dirty = true;
      } catch (err) {
        result[url] = -1;
        this.log.warn({ url, err: (err as Error).message }, 'ipdb feed download failed');
      }
    }
    return result;
  }
}

/** Accepts NDJSON ({"cidr": ...}) or plain lists (one IP/CIDR per line, ; or # comments). */
export function parseFeed(text: string): string[] {
  const out = new Set<string>();
  for (let line of text.split('\n')) {
    line = line.trim();
    if (!line) continue;
    let cand = '';
    if (line.startsWith('{')) {
      try {
        const o = JSON.parse(line);
        cand = typeof o.cidr === 'string' ? o.cidr : typeof o.ip === 'string' ? o.ip : '';
      } catch {
        continue;
      }
    } else {
      cand = line.split(/[;#\s]/)[0];
    }
    const c = cand && parseCidr(cand);
    if (c && reportable(c.split('/')[0])) out.add(c);
  }
  return [...out];
}
