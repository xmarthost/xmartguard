import crypto from 'node:crypto';
import net from 'node:net';
import type { FastifyBaseLogger } from 'fastify';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';
import type { AgentHub } from '../agents/hub.js';
import { versionLess } from '../agents/release.js';
import type { GeoDB } from './geo.js';
import {
  ABUSEIPDB_CHECK_DAYS,
  ABUSEIPDB_CHECK_NOTE,
  ABUSEIPDB_CHECK_SHARE,
  ABUSEIPDB_NOTE,
  checkAbuseIPDB,
  downloadEveryMs,
  fetchAbuseIPDB,
  loadAbuseIPDB,
} from './abuseipdb.js';
import { MAIL_MIN_AGENT, syncMail } from '../routes/mail.js';
import { eachLimit, single } from '../agents/limit.js';
import { platformAccount } from '../tenancy.js';

/** Agents older than this do not implement the ipdb.* commands. */
export const IPDB_MIN_AGENT = '0.3.0';
/** Agents that take the list in parts, and the entries per part (well under 4 MB). */
export const IPDB_PARTS_AGENT = '0.21.20';
export const IPDB_PART_SIZE = 50_000;
/** Shortest time between automatic list rebuilds (each one is sent to every server). */
export const REBUILD_EVERY_MS = 5 * 60_000;
/** Agents that take the fleet whitelist (fleet.set). */
export const FLEET_MIN_AGENT = '0.16.2';

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

/**
 * Days a CAPTCHA-solved address stays off the shared list at most (any new
 * attack report ends it sooner). A day, not longer: on shared servers a
 * check can be solved once by a paid solving service, and the list is the
 * fleet's first defence.
 */
export const CLEARED_DAYS = 1;

/**
 * Most entries taken from one ipdb.sync answer (what an agent sends at
 * most); an agent is a customer's machine and may send anything.
 */
export const SYNC_MAX = { reports: 1000, probes: 2000, hits: 2000, solved: 500 };
/** Addresses of a customer's server that are never listed (its inventory is the customer's word). */
export const PROTECTED_PER_SERVER = 8;

/** Text from an agent that Postgres can store (no NUL), at most `max` characters. */
function text(v: unknown, max: number): string {
  return String(v ?? '').replace(/\u0000/g, '').slice(0, max);
}

/** A Unix time from an agent, kept between 90 days ago and an hour ahead (now when invalid). */
export function agentTime(v: unknown): number {
  const now = Date.now() / 1000;
  const n = Number(v);
  if (!Number.isFinite(n)) return now;
  return Math.min(now + 3600, Math.max(now - 90 * 86400, n));
}

interface SyncResult {
  enabled?: boolean;
  version?: string;
  reports?: { id: number; ip: string; source: string; reason: string; at: number }[];
  /** Scanners the agent's WAF refused (0.21.17 agents), with their own cursor. */
  probes?: { id: number; ip: string; source: string; reason: string; at: number }[];
  probe_cursor?: number;
  hits?: { entry: string; country: string; hits: number; last_seen: number }[];
  /** IPDB-listed addresses whose visitor solved the CAPTCHA (0.21.17 agents). */
  solved?: { ip: string; at: number }[];
}

/**
 * The IPDB: aggregates automatic bans reported by every agent, merges public
 * feeds and manual entries, and distributes the resulting list to agents.
 */
export class IPDBService {
  version = '';
  /** The version before the current one: servers holding it are still protected (they get the new one within minutes). */
  prevVersion = '';
  entries: string[] = [];
  builtAt = 0;
  private dirty = true;
  private timers: NodeJS.Timeout[] = [];
  /** One-shot timers of agent connections (removed when they run). */
  private once = new Set<NodeJS.Timeout>();
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
    // Every server whitelists the other servers of its account.
    // (single: with hundreds of servers a run can outlast the interval.)
    const fleet = single(() => this.syncFleetAll().catch((err) => this.log.warn({ err }, 'fleet sync failed')));
    this.timers.push(setInterval(fleet, 10 * 60_000));
    if (!this.cfg.ipdbSync) return;
    const tick = single(async () => {
      try {
        // New reports change the list all the time: it is rebuilt (and sent
        // to every server) at most every REBUILD_EVERY_MS; operator changes
        // rebuild at once through their own routes.
        const age = Date.now() - this.builtAt;
        if ((this.dirty && age > REBUILD_EVERY_MS) || age > 10 * 60_000) await this.rebuild();
        await this.syncAll();
      } catch (err) {
        this.log.error({ err }, 'ipdb tick failed');
      }
    });
    this.timers.push(setInterval(tick, 60_000));
    this.timers.push(setTimeout(tick, 5_000));
    const feeds = () => this.refreshFeeds().catch((err) => this.log.error({ err }, 'ipdb feeds failed'));
    this.timers.push(setTimeout(feeds, 30_000));
    // Attacker feeds change by the hour (blocklist.de keeps 48 hours).
    this.timers.push(setInterval(feeds, 2 * 3600_000));
    // AbuseIPDB: checked often, downloaded every ABUSEIPDB_EVERY_HOURS.
    // AbuseIPDB: checked often, downloaded as the plan allows; new attackers
    // checked every 15 minutes (96 rounds a day share the daily checks).
    const abuse = single(async () => {
      await this.refreshAbuseIPDB().catch((err) => this.log.error({ err: (err as Error).message }, 'abuseipdb failed'));
      await this.checkAbuseIPDBSuspects(96).catch((err) => this.log.error({ err: (err as Error).message }, 'abuseipdb checks failed'));
    });
    this.timers.push(setTimeout(abuse, 45_000));
    this.timers.push(setInterval(abuse, 15 * 60_000));
  }

  stop(): void {
    for (const t of this.timers) clearTimeout(t);
    this.timers = [];
    for (const t of this.once) clearTimeout(t);
    this.once.clear();
  }

  /** Runs fn once after ms; forgotten once it ran (agents reconnect all the time). */
  private later(ms: number, fn: () => void): void {
    const t = setTimeout(() => {
      this.once.delete(t);
      fn();
    }, ms);
    this.once.add(t);
  }

  /** Pending one-shot timers (tests). */
  pendingTimers(): number {
    return this.once.size;
  }

  /** Called when an agent connects so it gets the list quickly. */
  onConnect(serverId: string, agentVersion: string): void {
    if (!versionLess(agentVersion, MAIL_MIN_AGENT)) {
      this.later(4_000, () => {
        syncMail(this.pool, this.hub, serverId).catch((err) => this.log.warn({ serverId, err: (err as Error).message }, 'mail settings sync failed'));
      });
    }
    if (!versionLess(agentVersion, FLEET_MIN_AGENT)) {
      this.later(3_000, () => {
        this.syncFleet(serverId).catch((err) => this.log.warn({ serverId, err: (err as Error).message }, 'fleet sync failed'));
      });
    }
    if (!this.cfg.ipdbSync || versionLess(agentVersion, IPDB_MIN_AGENT)) return;
    this.later(5_000, () => {
      this.ensureBuilt()
        .then(() => this.syncServer(serverId))
        .catch((err) => this.log.warn({ serverId, err: (err as Error).message }, 'ipdb sync failed'));
    });
  }

  async ensureBuilt(): Promise<void> {
    // Built once; later changes wait for the next scheduled rebuild.
    if (!this.builtAt) await this.rebuild();
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
    // Reports from the platform's own servers list an address on the usual
    // threshold. A customer controls their server and can report anyone (a
    // competitor, a payment gateway), so customers' reports count only when
    // servers of at least two different accounts agree.
    const { rows: agg } = await this.pool.query(
      `SELECT ip::cidr::text AS cidr, count(DISTINCT server_id)::int AS reporters, count(*)::int AS reports,
              min(created_at) AS first_seen, max(created_at) AS last_seen,
              (array_agg(reason ORDER BY id DESC))[1] AS reason
         FROM ipdb_reports
        WHERE created_at > now() - make_interval(days => $1)
        GROUP BY ip
       HAVING count(DISTINCT server_id) FILTER (WHERE $4::uuid IS NULL OR account_id = $4) >= $2
           OR count(*) FILTER (WHERE $4::uuid IS NULL OR account_id = $4) >= $3
           OR (count(DISTINCT account_id) >= 2 AND count(DISTINCT server_id) >= $2)`,
      [c.ipdbWindowDays, c.ipdbMinReporters, c.ipdbMinReports, await platformAccount(this.pool)],
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
    await this.pool.query('DELETE FROM ipdb_cleared WHERE until < now()');
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
          -- Solved the CAPTCHA (single addresses; manual entries stay): off
          -- the list until the clearing ends (CLEARED_DAYS) or a server
          -- reports a new attack from it, whatever listed it (feeds too).
          AND NOT EXISTS (SELECT 1 FROM ipdb_cleared k WHERE k.ip::cidr = e.cidr AND e.source <> 'manual' AND k.until > now()
                            AND NOT EXISTS (SELECT 1 FROM ipdb_reports r WHERE r.ip = k.ip AND r.reported_at > k.cleared_at))
        ORDER BY (e.source = 'manual') DESC, e.last_seen DESC
        LIMIT $2`,
      [await this.protectedIPs(), c.ipdbMaxEntries],
    );
    const lines = rows.map((r) => `${entryText(r.cidr)} ${r.country || ''}`.trim()).sort();
    this.entries = lines;
    const version = crypto.createHash('sha256').update(lines.join('\n')).digest('hex').slice(0, 16);
    if (version !== this.version) this.prevVersion = this.version;
    this.version = version;
    this.builtAt = Date.now();
  }

  /** The servers of an account with their addresses (the fleet whitelist). */
  async fleet(accountId: string): Promise<{ ip: string; host: string }[]> {
    const { rows } = await this.pool.query(
      "SELECT hostname, primary_ip, inventory->'ips' AS ips FROM servers WHERE status = 'active' AND account_id = $1",
      [accountId],
    );
    const out = new Map<string, string>();
    for (const r of rows) {
      for (const ip of [r.primary_ip, ...(Array.isArray(r.ips) ? r.ips : [])]) {
        if (typeof ip === 'string' && reportable(ip) && !out.has(ip)) out.set(ip, String(r.hostname ?? ''));
      }
    }
    return [...out].map(([ip, host]) => ({ ip, host })).sort((a, b) => a.ip.localeCompare(b.ip));
  }

  /** Sends one server the addresses of its account's servers. */
  async syncFleet(serverId: string): Promise<void> {
    const { rows } = await this.pool.query("SELECT account_id FROM servers WHERE id = $1 AND status = 'active'", [serverId]);
    if (!rows[0]) return;
    await this.hub.command(serverId, 'fleet.set', { servers: await this.fleet(rows[0].account_id) }, 60_000);
  }

  private async syncFleetAll(): Promise<void> {
    const conns = this.hub.connections().filter((c) => !versionLess(c.version, FLEET_MIN_AGENT));
    await eachLimit(conns, 10, async (c) => {
      await this.syncFleet(c.serverId).catch(() => undefined);
      if (!versionLess(c.version, MAIL_MIN_AGENT)) await syncMail(this.pool, this.hub, c.serverId).catch(() => undefined);
    });
  }

  /**
   * Every enrolled server's addresses: never listed. A customer's server
   * names its own addresses, so it protects at most PROTECTED_PER_SERVER
   * (else one inventory could keep any attacker off the fleet's list).
   */
  async protectedIPs(): Promise<string[]> {
    const platform = await platformAccount(this.pool);
    const { rows } = await this.pool.query("SELECT account_id, primary_ip, inventory->'ips' AS ips FROM servers WHERE status = 'active'");
    const out = new Set<string>();
    for (const r of rows) {
      const own = platform === null || String(r.account_id) === platform;
      let n = 0;
      for (const ip of [r.primary_ip, ...(Array.isArray(r.ips) ? r.ips : [])]) {
        if (typeof ip !== 'string' || !net.isIP(ip)) continue;
        if (!own && ++n > PROTECTED_PER_SERVER) break;
        out.add(ip);
      }
    }
    return [...out];
  }

  private async syncAll(): Promise<void> {
    const conns = this.hub.connections().filter((c) => !versionLess(c.version, IPDB_MIN_AGENT));
    await eachLimit(conns, 8, (c) =>
      this.syncServer(c.serverId).catch((err) => this.log.warn({ serverId: c.serverId, err: (err as Error).message }, 'ipdb sync failed')),
    );
  }

  /**
   * Sends the list to one agent. An agent message is at most 4 MB, so agents
   * that take parts (IPDB_PARTS_AGENT) get it IPDB_PART_SIZE entries at a time.
   */
  private async pushList(serverId: string): Promise<void> {
    const version = this.version;
    const entries = this.entries;
    const agent = this.hub.connections().find((c) => c.serverId === serverId)?.version ?? '';
    if (entries.length <= IPDB_PART_SIZE || versionLess(agent, IPDB_PARTS_AGENT)) {
      // An older agent drops its connection on a message over 4 MB (and then
      // could not update itself either): it keeps its list until it updates.
      const bytes = entries.reduce((n, e) => n + e.length + 3, 64);
      if (bytes > 3_800_000) throw new Error(`agent ${agent || '?'} cannot take a list this large; it gets it after updating`);
      await this.hub.command(serverId, 'ipdb.apply', { version, entries }, 180_000);
      return;
    }
    const parts = Math.ceil(entries.length / IPDB_PART_SIZE);
    for (let part = 0; part < parts; part++) {
      await this.hub.command(serverId, 'ipdb.apply', { version, part, parts, entries: entries.slice(part * IPDB_PART_SIZE, (part + 1) * IPDB_PART_SIZE) }, 180_000);
    }
  }

  /** Pulls reports and hits from one agent and pushes the list if it is stale. */
  async syncServer(serverId: string): Promise<void> {
    if (this.syncing.has(serverId)) return;
    this.syncing.add(serverId);
    try {
      const { rows } = await this.pool.query(
        "SELECT account_id, ipdb_cursor, ipdb_probe_cursor, ipdb_version FROM servers WHERE id = $1 AND status = 'active'",
        [serverId],
      );
      const srv = rows[0];
      if (!srv) return;
      const data = (await this.hub.command(
        serverId,
        'ipdb.sync',
        { since: Number(srv.ipdb_cursor), since_probe: Number(srv.ipdb_probe_cursor) },
        60_000,
      )) as SyncResult;
      const valid = (r: { id?: unknown; ip?: unknown }) => typeof r?.id === 'number' && reportable(String(r.ip));
      const reports = [...(data.reports ?? []).slice(0, SYNC_MAX.reports).filter(valid), ...(data.probes ?? []).slice(0, SYNC_MAX.probes).filter(valid)];
      let cursor = Number(srv.ipdb_cursor);
      for (const r of data.reports ?? []) if (typeof r?.id === 'number' && Number.isSafeInteger(r.id) && r.id > cursor) cursor = r.id;
      const probeCursor = Number.isSafeInteger(data.probe_cursor) ? Math.max(Number(data.probe_cursor), Number(srv.ipdb_probe_cursor)) : Number(srv.ipdb_probe_cursor);
      // One bad row must not stop this server's sync for good: the cursor
      // moves on and the list is still pushed when an insert fails.
      const keep = async (what: string, fn: () => Promise<unknown>) => {
        try {
          await fn();
        } catch (err) {
          this.log.warn({ serverId, err: (err as Error).message }, `ipdb ${what} from the agent dropped`);
        }
      };
      if (reports.length) {
        await keep('reports', () =>
          this.pool.query(
            `INSERT INTO ipdb_reports (ip, server_id, account_id, source, reason, reported_at)
             SELECT x.ip, $1, $2, x.source, x.reason, to_timestamp(x.at)
               FROM unnest($3::inet[], $4::text[], $5::text[], $6::float8[]) AS x(ip, source, reason, at)`,
            [
              serverId,
              srv.account_id,
              reports.map((r) => r.ip),
              reports.map((r) => text(r.source, 30)),
              reports.map((r) => text(r.reason, 200)),
              reports.map((r) => agentTime(r.at)),
            ],
          ),
        );
        this.dirty = true;
      }
      const hits = (data.hits ?? []).slice(0, SYNC_MAX.hits).filter((h) => h && parseCidr(String(h.entry)) && Number.isFinite(Number(h.hits)) && Number(h.hits) > 0);
      if (hits.length) {
        await keep('hits', () =>
          this.pool.query(
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
              hits.map((h) => Math.min(1e9, Math.max(1, Math.floor(Number(h.hits))))),
              hits.map((h) => agentTime(h.last_seen)),
            ],
          ),
        );
      }
      // A person proved they are behind the address: it leaves the list
      // for CLEARED_DAYS at most, until a server reports it again.
      // Taken from the platform's own servers only: a customer's agent could
      // name any address (an attacker's) to take it off every server's list.
      const solved = (await this.trusted(srv.account_id)) ? (data.solved ?? []).slice(0, SYNC_MAX.solved).filter((s) => s && reportable(String(s.ip))) : [];
      if (solved.length) {
        await keep('solved', () =>
          this.pool.query(
            `INSERT INTO ipdb_cleared (ip, server_id, cleared_at, until)
             SELECT x.ip, $1, to_timestamp(x.at), to_timestamp(x.at) + make_interval(days => $4)
               FROM unnest($2::inet[], $3::float8[]) AS x(ip, at)
             ON CONFLICT (ip) DO UPDATE SET server_id = excluded.server_id, cleared_at = excluded.cleared_at, until = excluded.until`,
            [serverId, solved.map((s) => String(s.ip)), solved.map((s) => Math.min(agentTime(s.at), Date.now() / 1000)), CLEARED_DAYS],
          ),
        );
        this.dirty = true;
      }
      await this.pool.query('UPDATE servers SET ipdb_cursor = $2, ipdb_probe_cursor = $3, ipdb_synced_at = now() WHERE id = $1', [serverId, cursor, probeCursor]);
      if (data.enabled && this.version && data.version !== this.version) {
        await this.pushList(serverId);
        await this.pool.query('UPDATE servers SET ipdb_version = $2 WHERE id = $1', [serverId, this.version]);
      } else if (data.version && data.version !== srv.ipdb_version) {
        await this.pool.query('UPDATE servers SET ipdb_version = $2 WHERE id = $1', [serverId, data.version]);
      }
    } finally {
      this.syncing.delete(serverId);
    }
  }

  /** Whether an account's servers may change the fleet's list on their own word. */
  private async trusted(accountId: string): Promise<boolean> {
    const p = await platformAccount(this.pool);
    return p === null || String(accountId) === p;
  }

  /** Makes one feed's entries exactly `cidrs` (note = the feed's name). */
  private async replaceFeed(note: string, cidrs: string[], reason: string): Promise<void> {
    await this.pool.query(
      `DELETE FROM ipdb_entries WHERE source = 'feed' AND note = $1
          AND NOT (cidr = ANY(ARRAY(SELECT network(t::inet) FROM unnest($2::text[]) AS t)))`,
      [note, cidrs],
    );
    if (cidrs.length) {
      await this.pool.query(
        `INSERT INTO ipdb_entries (cidr, source, country, reason, note)
         SELECT DISTINCT ON (network(x.c::inet)) network(x.c::inet), 'feed', x.cc, $4, $3
           FROM unnest($1::text[], $2::text[]) AS x(c, cc)
         ON CONFLICT (cidr) DO UPDATE SET last_seen = now() WHERE ipdb_entries.source = 'feed'`,
        [cidrs, cidrs.map((c) => this.geo.lookup(c)), note, reason],
      );
    }
    this.dirty = true;
  }

  /**
   * AbuseIPDB blacklist (the operator's API key), as often as the plan's
   * daily downloads allow (downloadEveryMs), or now when forced. The last download time is kept in the database, so
   * portal restarts never use up the daily downloads. A removed or disabled
   * key takes its addresses off the list.
   */
  async refreshAbuseIPDB(force = false): Promise<{ count: number; error?: string; skipped?: boolean }> {
    const c = await loadAbuseIPDB(this.pool);
    if (!c.api_key || !c.enabled) {
      const { rowCount } = await this.pool.query("DELETE FROM ipdb_entries WHERE source = 'feed' AND note IN ($1, $2)", [ABUSEIPDB_NOTE, ABUSEIPDB_CHECK_NOTE]);
      if (rowCount) this.dirty = true;
      return { count: 0, skipped: true };
    }
    if (!force && c.last_fetch_at && Date.now() - new Date(c.last_fetch_at).getTime() < downloadEveryMs(c.blacklist_limit)) {
      return { count: c.last_count, skipped: true };
    }
    const got = await fetchAbuseIPDB(c.api_key, c.confidence, c.max_ips);
    if (got.limit && got.limit !== c.blacklist_limit) {
      await this.pool.query('UPDATE ipdb_abuseipdb SET blacklist_limit = $1 WHERE id = 1', [got.limit]);
    }
    const cidrs = got.error ? [] : parseFeed(got.ips.join('\n'));
    if (got.error || !cidrs.length) {
      const error = got.error ?? 'AbuseIPDB returned an empty list';
      // A failed download keeps the previous list; it is retried next round.
      await this.pool.query('UPDATE ipdb_abuseipdb SET last_fetch_at = now(), last_error = $1 WHERE id = 1', [error]);
      this.log.warn({ err: error }, 'abuseipdb download failed');
      return { count: 0, error };
    }
    await this.replaceFeed(ABUSEIPDB_NOTE, cidrs, `AbuseIPDB (confidence ${c.confidence}%+)`);
    await this.pool.query("UPDATE ipdb_abuseipdb SET last_fetch_at = now(), last_count = $1, last_error = '' WHERE id = 1", [cidrs.length]);
    return { count: cidrs.length };
  }

  /**
   * Checks attackers our servers reported in the last day that are not
   * listed yet (an address reported once or by one server waits for more
   * reports otherwise). One scoring at least check_min joins the list for
   * ABUSEIPDB_CHECK_DAYS. Uses ABUSEIPDB_CHECK_SHARE of the plan's daily
   * checks, spread over the day; an address is checked again after 3 days.
   */
  async checkAbuseIPDBSuspects(runsPerDay = 96): Promise<{ checked: number; listed: number; error?: string }> {
    const c = await loadAbuseIPDB(this.pool);
    if (!c.api_key || !c.enabled || !c.check_enabled) {
      const { rowCount } = await this.pool.query("DELETE FROM ipdb_entries WHERE source = 'feed' AND note = $1", [ABUSEIPDB_CHECK_NOTE]);
      if (rowCount) this.dirty = true;
      return { checked: 0, listed: 0 };
    }
    const today = new Date().toISOString().slice(0, 10);
    let used = c.checks_day === today ? c.checks_today : 0;
    const daily = Math.floor(c.check_limit * ABUSEIPDB_CHECK_SHARE);
    const budget = Math.min(daily - used, Math.max(1, Math.ceil(daily / runsPerDay)));
    if (budget <= 0) return { checked: 0, listed: 0 };
    const { rows } = await this.pool.query(
      `SELECT host(r.ip) AS ip FROM ipdb_reports r
        WHERE r.created_at > now() - interval '1 day'
          AND NOT EXISTS (SELECT 1 FROM ipdb_entries e WHERE e.cidr = r.ip::cidr)
          AND NOT EXISTS (SELECT 1 FROM ipdb_abuse_checks k WHERE k.ip = r.ip AND k.checked_at > now() - interval '3 days')
          AND NOT EXISTS (SELECT 1 FROM ipdb_whitelist w WHERE w.cidr >>= r.ip)
          AND NOT (r.ip <<= ANY($2::inet[]))
        GROUP BY r.ip ORDER BY count(*) DESC, max(r.created_at) DESC LIMIT $1`,
      [budget, await this.protectedIPs()],
    );
    let checked = 0;
    let listed = 0;
    let error: string | undefined;
    let limit = c.check_limit;
    for (const { ip } of rows) {
      const r = await checkAbuseIPDB(c.api_key, ip);
      if (r.limit) limit = r.limit;
      if (r.error) {
        error = r.error;
        if (r.exhausted) {
          used = daily; // nothing more today
          break;
        }
        continue;
      }
      checked++;
      await this.pool.query(
        'INSERT INTO ipdb_abuse_checks (ip, score) VALUES ($1, $2) ON CONFLICT (ip) DO UPDATE SET score = excluded.score, checked_at = now()',
        [ip, r.score],
      );
      if (!r.whitelisted && (r.score ?? 0) >= c.check_min) {
        const { rowCount } = await this.pool.query(
          `INSERT INTO ipdb_entries (cidr, source, country, reason, note, expires_at)
           VALUES ($1::inet::cidr, 'feed', $2, $3, $4, now() + make_interval(days => $5))
           ON CONFLICT (cidr) DO NOTHING`,
          [ip, r.country || this.geo.lookup(ip), `AbuseIPDB score ${r.score}% (attacked our servers)`, ABUSEIPDB_CHECK_NOTE, ABUSEIPDB_CHECK_DAYS],
        );
        if (rowCount) listed++;
      }
    }
    await this.pool.query(
      `UPDATE ipdb_abuseipdb SET checks_day = $1::date, checks_today = $2, check_limit = $3 WHERE id = 1`,
      [today, Math.min(used + checked, daily), limit],
    );
    await this.pool.query("DELETE FROM ipdb_abuse_checks WHERE checked_at < now() - interval '30 days'");
    if (listed) this.dirty = true;
    if (error) this.log.warn({ err: error }, 'abuseipdb check failed');
    return { checked, listed, error };
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
        await this.replaceFeed(url, cidrs, 'public blocklist');
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
