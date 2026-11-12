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
          published: v.published ?? null,
        },
        updated: String(v.updated ?? v.published ?? ''),
      });
    }
  }
  return out;
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
    const tick = () => void this.sync().catch(() => undefined);
    setTimeout(tick, 60_000).unref();
    this.timer = setInterval(tick, Math.max(1, this.cfg.vulnFeedHours) * 3600_000);
    this.timer.unref();
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

  /** Checks a key: Wordfence answers the feed request (the body is not read). */
  async testKey(key: string): Promise<{ ok: boolean; error?: string }> {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 30_000);
    try {
      const res = await fetch(this.cfg.wordfenceFeedUrl, { headers: { authorization: `Bearer ${key}`, 'user-agent': 'xPGuard' }, signal: ctl.signal });
      ctl.abort(); // only the status is needed
      if (res.ok) return { ok: true };
      if (res.status === 401 || res.status === 403) return { ok: false, error: 'Wordfence refused the key (check it in Account » Integrations)' };
      if (res.status === 429) return { ok: false, error: 'Wordfence: too many requests, try again in a few minutes' };
      return { ok: false, error: `Wordfence answered HTTP ${res.status}` };
    } catch (err) {
      return { ok: false, error: `Wordfence not reachable: ${(err as Error).message}` };
    } finally {
      clearTimeout(t);
    }
  }

  /** Reads the feed, stores new and changed items; returns how many changed. */
  async sync(raw?: unknown): Promise<number> {
    if (this.running) return 0;
    this.running = true;
    try {
      if (raw === undefined) {
        const key = (await this.config()).api_key;
        if (!key) return 0; // not set up: the feature is off
        const res = await fetch(this.cfg.wordfenceFeedUrl, {
          headers: { authorization: `Bearer ${key}`, 'user-agent': 'xPGuard' },
          signal: AbortSignal.timeout(300_000),
        });
        if (!res.ok) throw new Error(`Wordfence feed: HTTP ${res.status}`);
        raw = await res.json();
      }
      const { rows } = await this.pool.query('SELECT count(*)::int AS n FROM vuln_feed');
      const changed = await this.storeItems(parseFeed(raw), rows[0].n === 0);
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
   * Stores items; returns how many are new or changed. The first import is
   * the backlog (handled by the nightly checks): seq 0, never sent as new.
   */
  async storeItems(items: { item: VulnItem; updated: string }[], backlog: boolean): Promise<number> {
    let changed = 0;
    for (const { item, updated } of items) {
      const r = await this.pool.query(
        `INSERT INTO vuln_feed (id, kind, slug, title, cvss, ranges, patched, published, updated, seq)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CASE WHEN $10 THEN 0 ELSE nextval('vuln_feed_seq') END)
         ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, cvss = EXCLUDED.cvss, ranges = EXCLUDED.ranges,
           patched = EXCLUDED.patched, published = EXCLUDED.published, updated = EXCLUDED.updated, seq = nextval('vuln_feed_seq')
         WHERE vuln_feed.updated IS DISTINCT FROM EXCLUDED.updated`,
        [item.id, item.kind, item.slug, item.title, item.cvss, JSON.stringify(item.ranges), JSON.stringify(item.patched), item.published, updated, backlog],
      );
      if (!backlog) changed += r.rowCount ?? 0;
    }
    return changed;
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
    const changed = await this.storeItems(items, false);
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
      id: r.id, kind: r.kind, slug: r.slug, title: r.title, cvss: Number(r.cvss), ranges: r.ranges, patched: r.patched,
      published: r.published ? new Date(r.published).toISOString() : null,
    }));
    const cursor = rows.length === 2000 ? Number(rows[rows.length - 1].seq) : max;
    return { items, cursor };
  }
}
