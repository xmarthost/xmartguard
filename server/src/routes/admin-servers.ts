import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { AgentHub } from '../agents/hub.js';
import { requirePlatform } from '../auth.js';

const Query = z.object({
  q: z.string().trim().max(100).default(''),
  page: z.coerce.number().int().min(1).max(100_000).default(1),
  per: z.coerce.number().int().min(1).max(500).default(20),
  // all | platform | customer | trial | paid | online | offline
  filter: z.enum(['all', 'platform', 'customer', 'trial', 'paid', 'online', 'offline']).default('all'),
});

/**
 * Master access: every server of every account (the platform's own,
 * customers on a trial or a paid plan), searchable, a page at a time. The
 * server dashboard opens any of them (see serverInScope).
 */
export function adminServerRoutes(app: FastifyInstance, pool: Pool, hub: AgentHub): void {
  app.get('/api/admin/servers', { preHandler: requirePlatform('viewer') }, async (req, reply) => {
    const p = Query.safeParse(req.query);
    if (!p.success) return reply.code(400).send({ error: 'invalid request' });
    const { q, page, per, filter } = p.data;
    const where = ["s.status = 'active'"];
    const args: unknown[] = [];
    if (q) {
      args.push(q);
      const n = `$${args.length}`;
      where.push(`(s.hostname ILIKE '%' || ${n} || '%' OR s.primary_ip ILIKE '%' || ${n} || '%' OR a.name ILIKE '%' || ${n} || '%'
        OR o.email ILIKE '%' || ${n} || '%' OR l.customer_ref = ${n} OR ${n} = ANY(s.tags) OR s.id::text = ${n})`);
    }
    if (filter === 'platform') where.push('a.platform');
    if (filter === 'customer') where.push('NOT a.platform');
    if (filter === 'trial') where.push('l.trial');
    if (filter === 'paid') where.push('NOT a.platform AND l.account_id IS NOT NULL AND NOT l.trial');
    if (filter === 'online') where.push('s.connected');
    if (filter === 'offline') where.push('NOT s.connected');
    const from = `FROM servers s JOIN accounts a ON a.id = s.account_id
      LEFT JOIN account_licenses l ON l.account_id = a.id
      LEFT JOIN LATERAL (SELECT email, name FROM users u WHERE u.account_id = a.id ORDER BY (u.role = 'owner') DESC, u.created_at LIMIT 1) o ON true
      WHERE ${where.join(' AND ')}`;
    const total = (await pool.query(`SELECT count(*)::int AS n ${from}`, args)).rows[0].n as number;
    const { rows } = await pool.query(
      `SELECT s.id, s.hostname, s.primary_ip, s.os_name, s.control_panel, s.agent_version, s.tags, s.last_seen_at, s.created_at,
              s.last_metrics->'security' AS security,
              a.id AS account_id, a.name AS account_name, a.platform,
              o.email AS owner_email, o.name AS owner_name,
              l.plan, l.plan_name, l.trial, l.status AS licence_status, l.period_end, l.max_servers
         ${from}
        ORDER BY a.platform DESC, s.hostname, s.created_at
        LIMIT ${per} OFFSET ${(page - 1) * per}`,
      args,
    );
    const counts = (
      await pool.query(
        `SELECT count(*)::int AS all,
                count(*) FILTER (WHERE NOT a.platform)::int AS customer,
                count(*) FILTER (WHERE l.trial)::int AS trial,
                count(*) FILTER (WHERE NOT a.platform AND l.account_id IS NOT NULL AND NOT l.trial)::int AS paid,
                count(*) FILTER (WHERE s.connected)::int AS online
           FROM servers s JOIN accounts a ON a.id = s.account_id LEFT JOIN account_licenses l ON l.account_id = a.id
          WHERE s.status = 'active'`,
      )
    ).rows[0];
    return {
      page,
      per,
      total,
      pages: Math.max(1, Math.ceil(total / per)),
      counts,
      servers: rows.map((r) => ({
        id: r.id,
        hostname: r.hostname,
        primary_ip: r.primary_ip,
        os_name: r.os_name,
        control_panel: r.control_panel,
        agent_version: r.agent_version,
        tags: r.tags ?? [],
        last_seen_at: r.last_seen_at,
        created_at: r.created_at,
        online: hub.isOnline(r.id),
        security: r.security ?? null,
        account: {
          id: r.account_id,
          name: r.account_name,
          platform: !!r.platform,
          owner_email: r.owner_email ?? '',
          owner_name: r.owner_name ?? '',
          plan: r.platform ? 'platform' : (r.plan ?? 'none'),
          plan_name: r.plan_name ?? '',
          trial: !!r.trial,
          licence_status: r.licence_status ?? null,
          period_end: r.period_end,
          max_servers: r.max_servers ?? null,
        },
      })),
    };
  });
}
