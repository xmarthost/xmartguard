import type { FastifyBaseLogger } from 'fastify';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';
import type { AgentHub } from '../agents/hub.js';

/**
 * New WordPress plugin, theme and core vulnerabilities for the whole fleet,
 * fast: the full scan (and its plugin inventory) runs every 72 hours, but an
 * exploited plugin must be patched within hours (owner, 2026-11-12). Every
 * few hours (and when Wordfence's webhook says something changed) the portal
 * reads Wordfence Intelligence's free production feed (free API key, set in
 * Master » Plugin Vulnerabilities; WORDFENCE_API_KEY also works), keeps one row per affected
 * component, numbers new and changed rows (seq) and asks the online agents
 * to fetch what is new; each agent matches its last inventory, without a new
 * scan, and updates, shields or deactivates the affected plugin.
 */

export interface VulnRange {
  from: string; // '' or '*' = any
  from_inc: boolean;
  to: string; // '' or '*' = any
  to_inc: boolean;
}

export interface VulnItem {
  id: string;
  kind: 'plugin' | 'theme' | 'core';
  slug: string;
  title: string;
  cvss: number;
  ranges: VulnRange[];
  patched: string[];
  published: string | null;
  seq?: number;
}

/** One site's outcome for one advisory, as an agent reports it. */
export interface AgentResult {
  at: number;
  advisory: string;
  title?: string;
  cvss: number;
  path: string;
  domain?: string;
  user?: string;
  kind: string;
  slug: string;
  version: string;
  action: string;
  to_version?: string;
  detail?: string;
}

type WFSoftware = {
  type?: string;
  slug?: string;
  affected_versions?: Record<string, { from_version?: string; from_inclusive?: boolean; to_version?: string; to_inclusive?: boolean }>;
  patched_versions?: string[];
};
type WFVuln = {
  id?: string;
  title?: string;
  software?: WFSoftware[];
  informational?: boolean;
  cvss?: { score?: number | string } | null;
  published?: string | null;
  updated?: string | null;
};

/** Parses the feed (an object keyed by id, or an array) into one item per component. */
export function parseFeed(raw: unknown): { item: VulnItem; updated: string }[] {
  const list: WFVuln[] = Array.isArray(raw) ? raw : raw && typeof raw === 'object' ? Object.values(raw as Record<string, WFVuln>) : [];
  const out: { item: VulnItem; updated: string }[] = [];
  for (const v of list) {
    if (!v || typeof v !== 'object' || !v.id || v.informational) continue;
    const cvss = Number(v.cvss?.score ?? 0) || 0;
    for (const s of v.software ?? []) {
      const kind = s.type === 'plugin' || s.type === 'theme' || s.type === 'core' ? s.type : null;
      const slug = String(s.slug ?? '').toLowerCase().trim();
      if (!kind || (kind !== 'core' && !/^[a-z0-9][a-z0-9._-]{0,120}$/.test(slug))) continue;
      const ranges: VulnRange[] = Object.values(s.affected_versions ?? {})
        .map((r) => ({ from: String(r.from_version ?? '*'), from_inc: r.from_inclusive !== false, to: String(r.to_version ?? '*'), to_inc: r.to_inclusive !== false }))
        .slice(0, 50);
      if (!ranges.length) continue;
      out.push({
        item: {
          id: `${v.id}:${kind}:${kind === 'core' ? 'wordpress' : slug}`,
          kind,
          slug: kind === 'core' ? 'wordpress' : slug,
          title: String(v.title ?? '').slice(0, 300),
          cvss,
          ranges,
          patched: (s.patched_versions ?? []).map(String).slice(0, 20),
          published: v.published ? (/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/.test(v.published) ? `${v.published.replace(' ', 'T')}Z` : v.published) : null,
        },
        updated: String(v.updated ?? v.published ?? ''),
      });
    }
  }
  return out;
}

/**
 * The records of the feed's top-level object (or array), read from the
 * response one at a time: only the current record is held in memory.
 */
export async function* feedRecords(body: ReadableStream<Uint8Array>): AsyncGenerator<unknown> {
  const dec = new TextDecoder();
  let buf = '';
  let depth = 0;
  let inStr = false;
  let esc = false;
  let start = -1;
  let i = 0;
  const reader = body.getReader();
  for (;;) {
    const { value, done } = await reader.read();
    buf += done ? dec.decode() : dec.decode(value, { stream: true });
    for (; i < buf.length; i++) {
      const c = buf[i];
      if (inStr) {
        if (esc) esc = false;
        else if (c === '\\') esc = true;
        else if (c === '"') inStr = false;
        continue;
      }
      if (c === '"') inStr = true;
      else if (c === '{' || c === '[') {
        depth++;
        if (depth === 2 && c === '{') start = i;
      } else if (c === '}' || c === ']') {
        if (depth === 2 && start >= 0 && c === '}') {
          const rec = buf.slice(start, i + 1);
          start = -1;
          try {
            yield JSON.parse(rec);
          } catch {
            // a broken record is skipped
          }
        }
        depth--;
      }
    }
    // Keep only the record being read.
    const keep = start >= 0 ? start : buf.length;
    buf = buf.slice(keep);
    i -= keep;
    if (start >= 0) start = 0;
    if (done) break;
  }
}

export class VulnFeedService {
  private timer: NodeJS.Timeout | null = null;
  private running = false;
  lastError = '';
  syncedAt: Date | null = null;

  constructor(
    private pool: Pool,
    private cfg: Config,
    private hub: AgentHub,
    private log: FastifyBaseLogger,
  ) {}

  start(): void {
    // Checked every 10 minutes; a download only when the last attempt is
    // older than the interval and Wordfence's limit has passed (both kept in
    // the database: a restart does not download again).
    const tick = () =>
      void this.due()
        .then((d) => (d ? this.sync() : 0))
        .catch(() => undefined);
    setTimeout(tick, 5 * 60_000).unref();
    this.timer = setInterval(tick, 10 * 60_000);
    this.timer.unref();
  }

  private async due(): Promise<boolean> {
    const { rows } = await this.pool.query('SELECT api_key, retry_at, last_attempt_at FROM vuln_feed_config WHERE id = 1');
    const r = rows[0];
    if (!r?.api_key && !this.cfg.wordfenceApiKey) return false;
    if (r?.retry_at && new Date(r.retry_at).getTime() > Date.now()) return false;
    return !r?.last_attempt_at || Date.now() - new Date(r.last_attempt_at).getTime() >= Math.max(1, this.cfg.vulnFeedHours) * 3600_000;
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
  }

  /** The operator's settings (the env key when none is saved). */
  async config(): Promise<{ api_key: string; webhook_secret: string; last_sync_at: Date | null; last_changed: number; last_error: string; last_webhook_at: Date | null; last_webhook_ok: boolean | null }> {
    const { rows } = await this.pool.query('SELECT * FROM vuln_feed_config WHERE id = 1');
    const r = rows[0] ?? { api_key: '', webhook_secret: '', last_sync_at: null, last_changed: 0, last_error: '', last_webhook_at: null, last_webhook_ok: null };
    return { ...r, api_key: r.api_key || this.cfg.wordfenceApiKey };
  }

  /** Wordfence's usage limit: no feed request before this time (ms). */
  retryAt = 0;

  /**
   * Downloads the full feed: one request (the feed endpoint takes no
   * parameters and its usage limit is low, so a key is never "tested"
   * separately: a test is a download).
   */
  private async download(key: string): Promise<ReadableStream<Uint8Array>> {
    const { rows } = await this.pool.query('SELECT retry_at FROM vuln_feed_config WHERE id = 1');
    const until = Math.max(this.retryAt, rows[0]?.retry_at ? new Date(rows[0].retry_at).getTime() : 0);
    if (Date.now() < until) {
      throw new Error(`Wordfence limits feed downloads: next try after ${new Date(until).toISOString().slice(11, 16)} UTC`);
    }
    await this.pool.query(
      'INSERT INTO vuln_feed_config (id, last_attempt_at) VALUES (1, now()) ON CONFLICT (id) DO UPDATE SET last_attempt_at = now()',
    );
    const res = await fetch(this.cfg.wordfenceFeedUrl, {
      headers: { authorization: `Bearer ${key}`, 'user-agent': 'xPGuard' },
      signal: AbortSignal.timeout(600_000),
    });
    if (res.status === 429) {
      const after = Number(res.headers.get('retry-after'));
      this.retryAt = Date.now() + (Number.isFinite(after) && after > 0 ? Math.min(after, 86_400) : 3600) * 1000;
      await this.pool.query('UPDATE vuln_feed_config SET retry_at = $1 WHERE id = 1', [new Date(this.retryAt)]);
      throw new Error(`Wordfence: too many feed downloads; next try after ${new Date(this.retryAt).toISOString().slice(11, 16)} UTC`);
    }
    if (res.status === 401 || res.status === 403) throw new Error('Wordfence refused the API key (check it in Account » Integrations)');
    if (!res.ok || !res.body) throw new Error(`Wordfence feed: HTTP ${res.status}`);
    return res.body;
  }

  /** Reads the feed (with key, else the saved one), stores new and changed items; returns how many changed. */
  async sync(raw?: unknown, key?: string): Promise<number> {
    if (this.running) throw new Error('a feed download is already running');
    this.running = true;
    try {
      const conf = await this.config();
      // Until a full download succeeded once, everything in it is backlog
      // (webhook deliveries before it do not count).
      const backlog = !conf.last_sync_at;
      // Records go to the database in batches, read one at a time from
      // the response (the whole feed in memory, over 100 MB of JSON, made
      // the portal slow or killed it), all with seq 0; the changed ones get
      // their numbers at the end, unless it was a backlog.
      let records: AsyncIterable<unknown> | unknown[];
      if (raw === undefined) {
        key ||= conf.api_key;
        if (!key) return 0; // not set up: the feature is off
        records = feedRecords(await this.download(key));
      } else {
        records = Array.isArray(raw) ? raw : raw && typeof raw === 'object' ? Object.values(raw as Record<string, unknown>) : [];
      }
      const changedIds: string[] = [];
      let unseen = 0;
      let batch: { item: VulnItem; updated: string }[] = [];
      const flush = async () => {
        if (!batch.length) return;
        const r = await this.storeBatch(batch);
        changedIds.push(...r.changed);
        unseen += r.unseen;
        batch = [];
        await new Promise((res) => setImmediate(res)); // let requests in
      };
      for await (const rec of records) {
        batch.push(...parseFeed([rec]));
        if (batch.length >= 500) await flush();
      }
      await flush();
      // A download that brings more than a thousand records never seen is
      // a backlog too (a database emptied or restored): sending them all as
      // new would update and deactivate plugins across the fleet at once.
      const bulk = !backlog && unseen > 1000;
      if (bulk) this.log.warn({ unseen }, 'vulnerability feed: too many unseen records, stored as backlog');
      const changed = backlog || bulk ? 0 : await this.number(changedIds);
      this.syncedAt = new Date();
      this.lastError = '';
      await this.pool.query(
        `INSERT INTO vuln_feed_config (id, last_sync_at, last_changed, last_error) VALUES (1, now(), $1, '')
         ON CONFLICT (id) DO UPDATE SET last_sync_at = now(), last_changed = $1, last_error = ''`,
        [changed],
      );
      if (changed > 0) {
        this.log.info({ changed }, 'new plugin vulnerabilities: agents notified');
        await this.notify();
      }
      return changed;
    } catch (err) {
      this.lastError = (err as Error).message;
      this.log.warn({ err: this.lastError }, 'vulnerability feed sync failed');
      await this.pool
        .query(`INSERT INTO vuln_feed_config (id, last_error) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET last_error = $1`, [this.lastError.slice(0, 300)])
        .catch(() => undefined);
      throw err;
    } finally {
      this.running = false;
    }
  }

  /**
   * Stores a batch with seq 0; returns the ids that were new or changed and
   * how many were new.
   */
  async storeBatch(items: { item: VulnItem; updated: string }[]): Promise<{ changed: string[]; unseen: number }> {
    const by = new Map<string, { item: VulnItem; updated: string }>();
    for (const x of items) by.set(x.item.id, x); // one row per id in a statement
    const list = [...by.values()];
    if (!list.length) return { changed: [], unseen: 0 };
    const date = (v: string | null) => (v && !Number.isNaN(Date.parse(v)) ? v : null);
    const { rows: seen } = await this.pool.query('SELECT count(*)::int AS n FROM vuln_feed WHERE id = ANY($1::text[])', [list.map((x) => x.item.id)]);
    const { rows } = await this.pool.query(
      `INSERT INTO vuln_feed (id, kind, slug, title, cvss, ranges, patched, published, updated, seq)
       SELECT x.id, x.kind, x.slug, x.title, x.cvss, x.ranges::jsonb, x.patched::jsonb, x.published::timestamptz, x.updated, 0
       FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::real[], $6::text[], $7::text[], $8::text[], $9::text[])
         AS x(id, kind, slug, title, cvss, ranges, patched, published, updated)
       ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, cvss = EXCLUDED.cvss, ranges = EXCLUDED.ranges,
         patched = EXCLUDED.patched, published = EXCLUDED.published, updated = EXCLUDED.updated, seq = 0
       WHERE vuln_feed.updated IS DISTINCT FROM EXCLUDED.updated
       RETURNING id`,
      [
        list.map((x) => x.item.id),
        list.map((x) => x.item.kind),
        list.map((x) => x.item.slug),
        list.map((x) => x.item.title),
        list.map((x) => x.item.cvss),
        list.map((x) => JSON.stringify(x.item.ranges)),
        list.map((x) => JSON.stringify(x.item.patched)),
        list.map((x) => date(x.item.published)),
        list.map((x) => x.updated),
      ],
    );
    return { changed: rows.map((r) => String(r.id)), unseen: list.length - seen[0].n };
  }

  /** Gives changed rows their numbers: the agents fetch them as new. Records the dispatch. */
  private async number(ids: string[], source = 'feed', note = ''): Promise<number> {
    let n = 0;
    let lo = Infinity;
    let hi = 0;
    for (let i = 0; i < ids.length; i += 1000) {
      const { rows } = await this.pool.query(
        "UPDATE vuln_feed SET seq = nextval('vuln_feed_seq') WHERE id = ANY($1::text[]) RETURNING seq",
        [ids.slice(i, i + 1000)],
      );
      for (const r of rows) {
        const q = Number(r.seq);
        lo = Math.min(lo, q);
        hi = Math.max(hi, q);
      }
      n += rows.length;
    }
    if (n > 0) await this.dispatch(source, note, lo, hi, n);
    return n;
  }

  private async dispatch(source: string, note: string, from: number, to: number, count: number): Promise<void> {
    await this.pool.query('INSERT INTO vuln_dispatch (source, note, seq_from, seq_to, count) VALUES ($1, $2, $3, $4, $5)', [source, note, from, to, count]);
  }

  /**
   * Stores what a server did with the advisories it received: the sites it
   * acted on (results) and, with receipt, which advisories reached it.
   */
  async results(serverId: string, results: AgentResult[], receipt?: { seqs: number[]; sites: number }): Promise<number> {
    if (receipt && receipt.seqs.length > 0) {
      await this.pool.query(
        `INSERT INTO vuln_receipts (server_id, dispatch_id, advisories, sites)
         SELECT $1, d.id, count(*)::int, $3 FROM unnest($2::bigint[]) AS s(seq)
           JOIN vuln_dispatch d ON s.seq BETWEEN d.seq_from AND d.seq_to
         GROUP BY d.id
         ON CONFLICT (server_id, dispatch_id) DO UPDATE SET received_at = now(),
           advisories = GREATEST(vuln_receipts.advisories, EXCLUDED.advisories), sites = vuln_receipts.sites + EXCLUDED.sites`,
        [serverId, receipt.seqs, receipt.sites],
      );
    }
    if (results.length === 0) return 0;
    const col = <K extends keyof AgentResult>(k: K) => results.map((r) => r[k]);
    const r = await this.pool.query(
      `INSERT INTO vuln_results (dispatch_id, server_id, advisory_id, kind, slug, title, cvss, site_path, domain, account, version, action, to_version, detail, at)
       SELECT (SELECT d.id FROM vuln_dispatch d WHERE f.seq BETWEEN d.seq_from AND d.seq_to ORDER BY d.id DESC LIMIT 1),
              $1, x.advisory, x.kind, x.slug, coalesce(nullif(x.title, ''), f.title, ''), coalesce(nullif(x.cvss, 0), f.cvss, 0),
              x.path, x.domain, x.account, x.version, x.action, x.to_version, x.detail, to_timestamp(x.at)
       FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::real[], $7::text[], $8::text[], $9::text[], $10::text[], $11::text[], $12::text[], $13::text[], $14::bigint[])
         AS x(advisory, kind, slug, title, cvss, path, domain, account, version, action, to_version, detail, at)
       LEFT JOIN vuln_feed f ON f.id = x.advisory
       ON CONFLICT (server_id, advisory_id, site_path, version) DO UPDATE SET
         action = EXCLUDED.action, to_version = EXCLUDED.to_version, detail = EXCLUDED.detail, at = EXCLUDED.at,
         dispatch_id = coalesce(vuln_results.dispatch_id, EXCLUDED.dispatch_id)`,
      [
        serverId, col('advisory'), col('kind'), col('slug'), col('title'), col('cvss'), col('path'),
        col('domain').map((v) => v ?? ''), col('user').map((v) => v ?? ''), col('version'), col('action'),
        col('to_version').map((v) => v ?? ''), col('detail').map((v) => v ?? ''), col('at'),
      ],
    );
    return r.rowCount ?? 0;
  }

  /**
   * Sends the advisories published since a date to the agents again, as if
   * they were new (owner, 2026-11-13: the first download is backlog, the
   * holes of the last weeks were never acted on). The agents act once per
   * site and advisory, so a repeat does nothing twice. Returns how many.
   */
  async replay(from: Date): Promise<number> {
    const { rows } = await this.pool.query(
      `WITH r AS (
         UPDATE vuln_feed SET seq = nextval('vuln_feed_seq')
         WHERE published >= $1 AND published > now() - interval '90 days'
         RETURNING seq)
       SELECT count(*)::int AS n, min(seq)::bigint AS lo, max(seq)::bigint AS hi FROM r`,
      [from],
    );
    const n = Number(rows[0].n);
    if (n > 0) {
      await this.dispatch('resend', `published since ${from.toISOString().slice(0, 10)}`, Number(rows[0].lo), Number(rows[0].hi), n);
      await this.notify();
    }
    return n;
  }

  /** Stores items and numbers the changed ones (webhook deliveries). */
  async storeItems(items: { item: VulnItem; updated: string }[]): Promise<number> {
    const r = await this.storeBatch(items);
    return this.number(r.changed, 'webhook');
  }

  /**
   * A Wordfence webhook delivery ({vulnerabilities: {created, replaced,
   * deleted}}, the full records): stored at once, agents nudged. Returns how
   * many items changed.
   */
  async applyWebhook(body: unknown): Promise<number> {
    const v = (body as { vulnerabilities?: { created?: unknown[]; replaced?: unknown[]; deleted?: unknown[] } })?.vulnerabilities;
    if (!v || typeof v !== 'object') return 0;
    const items = parseFeed([...(Array.isArray(v.created) ? v.created : []), ...(Array.isArray(v.replaced) ? v.replaced : [])]);
    const changed = await this.storeItems(items);
    for (const id of Array.isArray(v.deleted) ? v.deleted : []) {
      if (typeof id === 'string' && /^[0-9a-f-]{8,64}$/i.test(id)) await this.pool.query('DELETE FROM vuln_feed WHERE id LIKE $1', [`${id}:%`]);
    }
    if (changed > 0) {
      this.log.info({ changed }, 'Wordfence webhook: new plugin vulnerabilities, agents notified');
      await this.notify();
    }
    return changed;
  }

  /** Asks every online server to fetch the new items now. */
  async notify(): Promise<number> {
    const { rows } = await this.pool.query("SELECT id FROM servers WHERE status = 'active'");
    let n = 0;
    for (const r of rows) {
      const id = String(r.id);
      if (!this.hub.isOnline(id)) continue;
      n++;
      void this.hub.command(id, 'cms.vuln_sync', {}, 120_000).catch(() => undefined);
    }
    return n;
  }

  /** Items after the agent's cursor (published in the last 90 days). since < 0: only the cursor. */
  async since(since: number): Promise<{ items: VulnItem[]; cursor: number }> {
    const { rows: m } = await this.pool.query('SELECT coalesce(max(seq), 0)::bigint AS c FROM vuln_feed');
    const max = Number(m[0].c);
    if (since < 0) return { items: [], cursor: max };
    const { rows } = await this.pool.query(
      `SELECT id, kind, slug, title, cvss, ranges, patched, published, seq FROM vuln_feed
       WHERE seq > $1 AND (published IS NULL OR published > now() - interval '90 days') ORDER BY seq LIMIT 2000`,
      [since],
    );
    const items = rows.map((r) => ({
      id: r.id, kind: r.kind, slug: r.slug, title: r.title, cvss: Number(r.cvss), ranges: r.ranges, patched: r.patched, seq: Number(r.seq),
      published: r.published ? new Date(r.published).toISOString() : null,
    }));
    const cursor = rows.length === 2000 ? Number(rows[rows.length - 1].seq) : max;
    return { items, cursor };
  }
}
