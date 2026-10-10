import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import net from 'node:net';
import { z } from 'zod';
import type { Pool } from '../db.js';
import { audit, hasRole, requireRole, type SessionUser } from '../auth.js';
import { entryText, parseCidr, type IPDBService } from '../ipdb/service.js';
import { ABUSEIPDB_EVERY_HOURS, keyHint, loadAbuseIPDB, testAbuseIPDB } from '../ipdb/abuseipdb.js';
import { signedPayload } from '../agent-sign.js';

const Paging = z.object({
  q: z.string().max(100).default(''),
  source: z.enum(['', 'community', 'manual', 'feed']).default(''),
  limit: z.coerce.number().int().min(1).max(500).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

const AddEntry = z.object({
  cidr: z.string().max(60),
  note: z.string().max(200).default(''),
  days: z.number().int().min(0).max(3650).default(0), // 0 = permanent
});

const AddWhite = z.object({ cidr: z.string().max(60), note: z.string().max(200).default('') });

/**
 * The IPDB is shared by the whole portal. Its list is managed by the
 * platform operator: owners/admins of the first account created on the
 * portal. Everyone else can view it and see the traffic it drops on their
 * own servers.
 */
export function ipdbRoutes(app: FastifyInstance, pool: Pool, ipdb: IPDBService): void {
  const viewer = { preHandler: requireRole('viewer') };

  // The platform account's administrators manage the shared IPDB.
  async function isOperator(user: SessionUser): Promise<boolean> {
    return hasRole(user, 'admin') && user.platform;
  }

  async function requireOperator(req: FastifyRequest, reply: FastifyReply): Promise<boolean> {
    if (!req.user) {
      reply.code(401).send({ error: 'authentication required' });
      return false;
    }
    if (!(await isOperator(req.user))) {
      reply.code(403).send({ error: 'only the portal operator can change the IPDB' });
      return false;
    }
    return true;
  }

  app.get('/api/ipdb/summary', viewer, async (req) => {
    const user = req.user!;
    await ipdb.ensureBuilt();
    const [sources, reports, hitsToday, countries, daily, servers, top] = await Promise.all([
      pool.query('SELECT source, count(*)::int AS n FROM ipdb_entries GROUP BY source'),
      pool.query(`SELECT count(*)::int AS reports_24h, count(DISTINCT ip)::int AS ips_24h,
                         count(DISTINCT server_id)::int AS reporters_24h
                    FROM ipdb_reports WHERE created_at > now() - interval '24 hours'`),
      pool.query(
        `SELECT coalesce(sum(h.hits),0)::bigint AS n FROM ipdb_hits h JOIN servers s ON s.id = h.server_id
          WHERE s.account_id = $1 AND h.day = current_date`,
        [user.accountId],
      ),
      pool.query(
        `SELECT h.country, sum(h.hits)::bigint AS hits, count(DISTINCT h.entry)::int AS ips
           FROM ipdb_hits h JOIN servers s ON s.id = h.server_id
          WHERE s.account_id = $1 AND h.day > current_date - 30
          GROUP BY h.country ORDER BY hits DESC`,
        [user.accountId],
      ),
      pool.query(
        `SELECT to_char(d, 'YYYY-MM-DD') AS day, coalesce(sum(h.hits),0)::bigint AS hits
           FROM generate_series(current_date - 29, current_date, interval '1 day') d
           LEFT JOIN (SELECT h.day, h.hits FROM ipdb_hits h JOIN servers s ON s.id = h.server_id WHERE s.account_id = $1) h
             ON h.day = d::date
          GROUP BY d ORDER BY d`,
        [user.accountId],
      ),
      pool.query(
        `SELECT id, hostname, agent_version, connected, ipdb_version, ipdb_synced_at FROM servers
          WHERE account_id = $1 AND status = 'active' ORDER BY hostname`,
        [user.accountId],
      ),
      pool.query(
        `SELECT h.entry, max(h.country) AS country, sum(h.hits)::bigint AS hits, max(h.last_seen) AS last_seen,
                count(DISTINCT h.server_id)::int AS servers
           FROM ipdb_hits h JOIN servers s ON s.id = h.server_id
          WHERE s.account_id = $1 AND h.day > current_date - 30
          GROUP BY h.entry ORDER BY hits DESC LIMIT 15`,
        [user.accountId],
      ),
    ]);
    const bySource: Record<string, number> = { community: 0, manual: 0, feed: 0 };
    for (const r of sources.rows) bySource[r.source] = r.n;
    return {
      version: ipdb.version,
      listed: ipdb.entries.length,
      sources: bySource,
      ...reports.rows[0],
      hits_today: Number(hitsToday.rows[0].n),
      countries: countries.rows.map((r) => ({ country: r.country, hits: Number(r.hits), ips: r.ips })),
      daily: daily.rows.map((r) => ({ day: r.day, hits: Number(r.hits) })),
      top: top.rows.map((r) => ({ ...r, hits: Number(r.hits) })),
      servers: servers.rows.map((r) => ({ ...r, synced: r.ipdb_version === ipdb.version && !!ipdb.version })),
      geoip: ipdb.geo.size > 0,
      can_manage: await isOperator(user),
    };
  });

  /** Most recent drops on this account's servers (polled by the live monitor). */
  app.get('/api/ipdb/live', viewer, async (req) => {
    const { rows } = await pool.query(
      `SELECT h.entry, h.country, h.hits, h.last_seen, s.id AS server_id, s.hostname
         FROM ipdb_hits h JOIN servers s ON s.id = h.server_id
        WHERE s.account_id = $1 AND h.day >= current_date - 1
        ORDER BY h.last_seen DESC LIMIT 60`,
      [req.user!.accountId],
    );
    return { events: rows.map((r) => ({ ...r, hits: Number(r.hits) })) };
  });

  app.get('/api/ipdb/entries', viewer, async (req, reply) => {
    const p = Paging.safeParse(req.query);
    if (!p.success) return reply.code(400).send({ error: 'invalid query' });
    const { q, source, limit, offset } = p.data;
    const where: string[] = ['true'];
    const args: unknown[] = [];
    if (q) {
      args.push(q);
      const i = args.length;
      where.push(net.isIP(q)
        ? `cidr >>= $${i}::inet`
        : `(cidr::text ILIKE '%' || $${i} || '%' OR country ILIKE $${i} OR reason ILIKE '%' || $${i} || '%' OR note ILIKE '%' || $${i} || '%')`);
    }
    if (source) {
      args.push(source);
      where.push(`source = $${args.length}`);
    }
    const cond = where.join(' AND ');
    const total = await pool.query(`SELECT count(*)::int AS n FROM ipdb_entries WHERE ${cond}`, args);
    const { rows } = await pool.query(
      `SELECT cidr::text AS cidr, source, country, reporters, reports, reason, note, first_seen, last_seen, expires_at
         FROM ipdb_entries WHERE ${cond} ORDER BY last_seen DESC LIMIT $${args.length + 1} OFFSET $${args.length + 2}`,
      [...args, limit, offset],
    );
    return { total: total.rows[0].n, entries: rows.map((r) => ({ ...r, cidr: entryText(r.cidr) })) };
  });

  /** Country codes for a batch of addresses (flags in log tables). */
  app.post('/api/geo/lookup', viewer, async (req, reply) => {
    const b = z.object({ ips: z.array(z.string().max(64)).max(500) }).safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: 'invalid request' });
    const out: Record<string, string> = {};
    for (const raw of b.data.ips) {
      const ip = raw.split('/')[0].trim();
      if (net.isIP(ip)) out[raw] = ipdb.geo.lookup(ip) || '';
    }
    return { countries: out };
  });

  /** A country's networks for an agent's country whitelist/block, from the
   *  same GeoIP database the portal shows countries with. */
  app.post('/api/agent/geo/zone', { bodyLimit: 16 * 1024 }, async (req, reply) => {
    const r = await signedPayload(pool, req.body, z.object({ cc: z.string().regex(/^[A-Za-z]{2}$/) }), reply);
    if (!r) return;
    if (!ipdb.geo.size) return reply.code(503).send({ error: 'the GeoIP database is not loaded yet' });
    return { cc: r.data.cc.toUpperCase(), source: 'db-ip', loaded_at: ipdb.geo.loadedAt, cidrs: ipdb.geo.cidrs(r.data.cc) };
  });

  /** The address the portal sees for this browser (the globe button of IP fields). */
  app.get('/api/geo/me', viewer, async (req) => {
    const ip = req.ip;
    return { ip, country: net.isIP(ip) ? ipdb.geo.lookup(ip) || '' : '' };
  });

  /** What the IPDB knows about one address. */
  app.get('/api/ipdb/check', viewer, async (req, reply) => {
    const ip = String((req.query as Record<string, string>).ip ?? '').trim();
    if (!net.isIP(ip)) return reply.code(400).send({ error: 'invalid IP address' });
    const [entries, white, reports] = await Promise.all([
      pool.query(
        `SELECT cidr::text AS cidr, source, country, reporters, reports, reason, note, last_seen, expires_at
           FROM ipdb_entries WHERE cidr >>= $1::inet ORDER BY masklen(cidr) DESC`,
        [ip],
      ),
      pool.query('SELECT cidr::text AS cidr, note FROM ipdb_whitelist WHERE cidr >>= $1::inet', [ip]),
      pool.query(
        `SELECT count(*)::int AS reports, count(DISTINCT server_id)::int AS reporters, max(created_at) AS last_report
           FROM ipdb_reports WHERE ip = $1::inet AND created_at > now() - interval '30 days'`,
        [ip],
      ),
    ]);
    return {
      ip,
      country: ipdb.geo.lookup(ip),
      listed: entries.rows.length > 0 && white.rows.length === 0,
      entries: entries.rows.map((r) => ({ ...r, cidr: entryText(r.cidr) })),
      whitelisted: white.rows.map((r) => ({ ...r, cidr: entryText(r.cidr) })),
      ...reports.rows[0],
    };
  });

  app.post('/api/ipdb/entries', async (req, reply) => {
    if (!(await requireOperator(req, reply))) return;
    const p = AddEntry.safeParse(req.body);
    const cidr = p.success ? parseCidr(p.data.cidr) : null;
    if (!p.success || !cidr) return reply.code(400).send({ error: 'enter a valid IP address or network (/8 or smaller)' });
    const prot = await ipdb.protectedIPs();
    const { rows: hit } = await pool.query('SELECT 1 FROM unnest($1::inet[]) AS p WHERE network($2::inet) >>= p', [prot, cidr]);
    if (hit.length) return reply.code(400).send({ error: `${cidr} contains one of your servers and cannot be listed` });
    await pool.query(
      `INSERT INTO ipdb_entries (cidr, source, country, reason, note, expires_at, created_by)
       VALUES (network($1::inet), 'manual', $2, 'added by the operator', $3,
               CASE WHEN $4::int > 0 THEN now() + make_interval(days => $4::int) END, $5)
       ON CONFLICT (cidr) DO UPDATE SET source = 'manual', note = excluded.note, expires_at = excluded.expires_at,
             last_seen = now(), created_by = excluded.created_by`,
      [cidr, ipdb.geo.lookup(cidr), p.data.note, p.data.days, req.user!.id],
    );
    await pool.query('DELETE FROM ipdb_whitelist WHERE cidr = network($1::inet)', [cidr]);
    await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, action: 'ipdb.add', detail: { cidr, note: p.data.note }, ip: req.ip });
    await ipdb.rebuild();
    return { ok: true, cidr };
  });

  app.delete('/api/ipdb/entries', async (req, reply) => {
    if (!(await requireOperator(req, reply))) return;
    const cidr = parseCidr(String((req.query as Record<string, string>).cidr ?? ''));
    if (!cidr) return reply.code(400).send({ error: 'invalid address' });
    const { rowCount } = await pool.query('DELETE FROM ipdb_entries WHERE cidr = network($1::inet)', [cidr]);
    if (!rowCount) return reply.code(404).send({ error: `${cidr} is not in the IPDB` });
    // Forget its reports too, so it is not re-listed from the same evidence.
    await pool.query('DELETE FROM ipdb_reports WHERE network($1::inet) >>= ip', [cidr]);
    await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, action: 'ipdb.remove', detail: { cidr }, ip: req.ip });
    await ipdb.rebuild();
    return { ok: true };
  });

  app.get('/api/ipdb/whitelist', viewer, async () => {
    const { rows } = await pool.query('SELECT cidr::text AS cidr, note, created_at FROM ipdb_whitelist ORDER BY created_at DESC');
    return { whitelist: rows.map((r) => ({ ...r, cidr: entryText(r.cidr) })) };
  });

  app.post('/api/ipdb/whitelist', async (req, reply) => {
    if (!(await requireOperator(req, reply))) return;
    const p = AddWhite.safeParse(req.body);
    const cidr = p.success ? parseCidr(p.data.cidr) : null;
    if (!p.success || !cidr) return reply.code(400).send({ error: 'enter a valid IP address or network' });
    await pool.query(
      `INSERT INTO ipdb_whitelist (cidr, note, created_by) VALUES (network($1::inet), $2, $3)
       ON CONFLICT (cidr) DO UPDATE SET note = excluded.note`,
      [cidr, p.data.note, req.user!.id],
    );
    await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, action: 'ipdb.whitelist', detail: { cidr }, ip: req.ip });
    await ipdb.rebuild();
    return { ok: true, cidr };
  });

  app.delete('/api/ipdb/whitelist', async (req, reply) => {
    if (!(await requireOperator(req, reply))) return;
    const cidr = parseCidr(String((req.query as Record<string, string>).cidr ?? ''));
    if (!cidr) return reply.code(400).send({ error: 'invalid address' });
    await pool.query('DELETE FROM ipdb_whitelist WHERE cidr = network($1::inet)', [cidr]);
    await ipdb.rebuild();
    return { ok: true };
  });

  // AbuseIPDB (Master » IPDB): the operator's key; its blacklist goes to
  // every server through the shared list. The key itself never leaves the
  // portal and is shown only as a hint.
  const abuseState = async () => {
    const c = await loadAbuseIPDB(pool);
    const { rows } = await pool.query("SELECT count(*)::int AS n FROM ipdb_entries WHERE source = 'feed' AND note = 'abuseipdb'");
    return {
      key_set: c.api_key !== '',
      key_hint: keyHint(c.api_key),
      enabled: c.enabled,
      confidence: c.confidence,
      max_ips: c.max_ips,
      last_fetch_at: c.last_fetch_at,
      last_count: c.last_count,
      last_error: c.last_error,
      listed: rows[0].n,
      every_hours: ABUSEIPDB_EVERY_HOURS,
    };
  };
  const AbuseKey = z.string().trim().regex(/^[A-Za-z0-9]{40,120}$/, 'an AbuseIPDB API key is 80 letters and digits');

  app.get('/api/ipdb/abuseipdb', async (req, reply) => {
    if (!(await requireOperator(req, reply))) return;
    return abuseState();
  });

  app.put('/api/ipdb/abuseipdb', async (req, reply) => {
    if (!(await requireOperator(req, reply))) return;
    const b = z
      .object({
        api_key: z.union([AbuseKey, z.literal('')]).optional(), // omitted = keep, '' = remove
        enabled: z.boolean().optional(),
        confidence: z.number().int().min(25).max(100).optional(),
        max_ips: z.number().int().min(1000).max(500_000).optional(),
      })
      .safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: b.error.issues[0]?.message ?? 'invalid request' });
    const cur = await loadAbuseIPDB(pool);
    const next = { ...cur, ...b.data };
    const keyChanged = b.data.api_key !== undefined && b.data.api_key !== cur.api_key;
    if (keyChanged && next.api_key) {
      // A new key is saved only once AbuseIPDB accepts it.
      const t = await testAbuseIPDB(next.api_key);
      if (!t.ok) return reply.code(400).send({ error: `AbuseIPDB: ${t.error}` });
    }
    const listChanged = keyChanged || next.enabled !== cur.enabled || next.confidence !== cur.confidence || next.max_ips !== cur.max_ips;
    await pool.query(
      `INSERT INTO ipdb_abuseipdb (id, api_key, enabled, confidence, max_ips) VALUES (1, $1, $2, $3, $4)
       ON CONFLICT (id) DO UPDATE SET api_key = $1, enabled = $2, confidence = $3, max_ips = $4, updated_at = now(),
         last_fetch_at = CASE WHEN $5 THEN NULL ELSE ipdb_abuseipdb.last_fetch_at END,
         last_error = CASE WHEN $5 THEN '' ELSE ipdb_abuseipdb.last_error END`,
      [next.api_key, next.enabled, next.confidence, next.max_ips, listChanged],
    );
    await audit(pool, {
      accountId: req.user!.accountId,
      userId: req.user!.id,
      action: 'ipdb.abuseipdb',
      detail: { key: keyChanged ? (next.api_key ? 'set' : 'removed') : 'kept', enabled: next.enabled, confidence: next.confidence, max_ips: next.max_ips },
      ip: req.ip,
    });
    // Download (or drop) the list in the background; servers get it on their next sync.
    if (listChanged) void ipdb.refreshAbuseIPDB(true).then(() => ipdb.rebuild()).catch(() => undefined);
    return abuseState();
  });

  /** Tests a key (the one typed, else the saved one) without saving it. */
  app.post('/api/ipdb/abuseipdb/test', async (req, reply) => {
    if (!(await requireOperator(req, reply))) return;
    const b = z.object({ api_key: z.union([AbuseKey, z.literal('')]).default('') }).safeParse(req.body ?? {});
    if (!b.success) return reply.code(400).send({ error: b.error.issues[0]?.message ?? 'invalid request' });
    const key = b.data.api_key || (await loadAbuseIPDB(pool)).api_key;
    if (!key) return reply.code(400).send({ error: 'enter an API key first' });
    return testAbuseIPDB(key);
  });

  /** Downloads the AbuseIPDB list now (uses one of the daily downloads). */
  app.post('/api/ipdb/abuseipdb/refresh', async (req, reply) => {
    if (!(await requireOperator(req, reply))) return;
    const r = await ipdb.refreshAbuseIPDB(true);
    await ipdb.rebuild();
    return { ...r, state: await abuseState() };
  });

  /** Operator: re-download the public feeds now. */
  app.post('/api/ipdb/feeds/refresh', async (req, reply) => {
    if (!(await requireOperator(req, reply))) return;
    const result = await ipdb.refreshFeeds();
    await ipdb.rebuild();
    return { feeds: result };
  });
}
