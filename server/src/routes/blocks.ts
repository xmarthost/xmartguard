import type { FastifyInstance } from 'fastify';
import net from 'node:net';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { AgentHub } from '../agents/hub.js';
import { audit, requirePlatform, requireRole } from '../auth.js';
import { scopeAccounts } from '../tenancy.js';

/**
 * "Why is it blocked?": find an address or website in the WAF logs and
 * firewalls of every server at once, and the unblock requests visitors
 * send from the portal's public page. The fixes (unblock, allow on a site)
 * are the servers' own actions, called from the page.
 */

const Host = z
  .string()
  .trim()
  .toLowerCase()
  .max(253)
  .regex(/^[a-z0-9.-]*$/, 'a website name like example.com');

const Lookup = z.object({
  ip: z.string().trim().max(45).default(''),
  host: Host.default(''),
  hours: z.coerce.number().int().min(1).max(720).default(72),
});

interface WafEvent { id: number; at: number; ip: string; method: string; host: string; uri: string; rule_id: number; msg: string; category: string; action: string; user: string; detail?: string }

export function blockRoutes(app: FastifyInstance, pool: Pool, hub: AgentHub): void {
  app.get('/api/blocks/lookup', { preHandler: requireRole('viewer') }, async (req, reply) => {
    const p = Lookup.safeParse(req.query);
    if (!p.success) return reply.code(400).send({ error: p.error.issues[0]?.message ?? 'invalid search' });
    const { ip, host, hours } = p.data;
    if (ip && !net.isIP(ip)) return reply.code(400).send({ error: 'not an IP address' });
    if (!ip && !host) return reply.code(400).send({ error: 'enter an IP address or a website' });
    const { rows: servers } = await pool.query<{ id: string; hostname: string }>(
      "SELECT id, hostname FROM servers WHERE account_id = ANY($1::uuid[]) AND status = 'active' ORDER BY hostname",
      [await scopeAccounts(pool, req.user!.accountId)],
    );
    const online = servers.filter((s) => hub.isOnline(String(s.id)));
    const since = Math.floor(Date.now() / 1000) - hours * 3600;
    const found: { server_id: string; server: string; firewall: unknown; waf: WafEvent[]; waf_total: number }[] = [];
    const failed: string[] = [];
    let next = 0;
    const worker = async () => {
      for (;;) {
        const srv = online[next++];
        if (!srv) return;
        const id = String(srv.id);
        try {
          const [w, fw] = await Promise.all([
            hub.command(id, 'waf.events', { ip, host, since, limit: 25 }, 20_000) as Promise<{ events: WafEvent[] | null; total: number }>,
            ip ? (hub.command(id, 'fw.check', { ip }, 20_000) as Promise<{ status: string; found?: string[] | null }>) : Promise.resolve(null),
          ]);
          const listed = fw && fw.status !== 'none' && fw.status !== 'allowed' && fw.status !== 'ignored';
          if ((w.total ?? 0) > 0 || listed) found.push({ server_id: id, server: srv.hostname, firewall: fw, waf: w.events ?? [], waf_total: w.total ?? 0 });
        } catch {
          failed.push(srv.hostname);
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(10, online.length) }, worker));
    found.sort((a, b) => a.server.localeCompare(b.server));
    return { ip, host, hours, servers: servers.length, online: online.length, failed, found };
  });

  // ---- public: a visitor asks to be unblocked.
  app.get('/api/unblock/whoami', async (req) => ({ ip: req.ip }));

  const Request = z.object({
    site: Host.refine((v) => v.includes('.'), 'the website you could not open, like example.com'),
    email: z.string().trim().max(200).email().or(z.literal('')).default(''),
    message: z.string().trim().max(1000).default(''),
    // Left empty by people; bots fill every field.
    website: z.string().max(0).optional(),
  });
  app.post('/api/unblock', { config: { rateLimit: { max: 5, timeWindow: '1 hour' } } }, async (req, reply) => {
    const b = Request.safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: b.error.issues[0]?.message ?? 'invalid request' });
    const { rows } = await pool.query("SELECT count(*)::int AS n FROM unblock_requests WHERE ip = $1 AND created_at > now() - interval '1 day'", [req.ip]);
    if (rows[0].n >= 5) return reply.code(429).send({ error: 'You already sent requests today; we will look at them.' });
    await pool.query('INSERT INTO unblock_requests (ip, site, email, message) VALUES ($1, $2, $3, $4)', [req.ip, b.data.site, b.data.email, b.data.message]);
    return { ok: true, ip: req.ip };
  });

  // ---- the provider's list of requests.
  app.get('/api/unblock-requests', { preHandler: requirePlatform('viewer') }, async (req) => {
    const status = (req.query as { status?: string }).status === 'all' ? null : 'open';
    const { rows } = await pool.query(
      `SELECT id, host(ip) AS ip, site, email, message, status, created_at, updated_at FROM unblock_requests
        WHERE ($1::text IS NULL OR status = $1) ORDER BY created_at DESC LIMIT 200`,
      [status],
    );
    const { rows: c } = await pool.query("SELECT count(*)::int AS n FROM unblock_requests WHERE status = 'open'");
    return { requests: rows, open: c[0].n };
  });

  const Handle = z.object({ status: z.enum(['open', 'done', 'rejected']) });
  app.post('/api/unblock-requests/:id', { preHandler: requirePlatform('operator') }, async (req, reply) => {
    const b = Handle.safeParse(req.body);
    const id = Number((req.params as { id: string }).id);
    if (!b.success || !Number.isInteger(id)) return reply.code(400).send({ error: 'invalid request' });
    const r = await pool.query('UPDATE unblock_requests SET status = $1, handled_by = $2, updated_at = now() WHERE id = $3', [b.data.status, req.user!.id, id]);
    if (!r.rowCount) return reply.code(404).send({ error: 'not found' });
    await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, action: 'unblock.request', detail: { id, status: b.data.status }, ip: req.ip });
    return { ok: true };
  });
}
