import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import net from 'node:net';
import { z } from 'zod';
import type { Pool } from '../db.js';
import { audit, hasRole, requireRole, type SessionUser } from '../auth.js';
import { entryText, parseCidr, type IPDBService } from '../ipdb/service.js';

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
  let operatorAccount: string | null = null;

  async function isOperator(user: SessionUser): Promise<boolean> {
    if (!hasRole(user, 'admin')) return false;
    if (!operatorAccount) {
      const { rows } = await pool.query('SELECT id FROM accounts ORDER BY created_at, id LIMIT 1');
      operatorAccount = rows[0]?.id ?? null;
    }
    return user.accountId === operatorAccount;
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

  /** Operator: re-download the public feeds now. */
  app.post('/api/ipdb/feeds/refresh', async (req, reply) => {
    if (!(await requireOperator(req, reply))) return;
    const result = await ipdb.refreshFeeds();
    await ipdb.rebuild();
    return { feeds: result };
  });
}
