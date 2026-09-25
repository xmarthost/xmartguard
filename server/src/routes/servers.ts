import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';
import { CommandError, type AgentHub } from '../agents/hub.js';
import { audit, requireRole } from '../auth.js';
import { enrollmentToken, sha256 } from '../security.js';
import { currentRelease } from '../agents/release.js';

const IdParams = z.object({ id: z.string().uuid() });
const RANGES: Record<string, { interval: string; bucket: number }> = {
  '1h': { interval: '1 hour', bucket: 60 },
  '4h': { interval: '4 hours', bucket: 300 },
  '24h': { interval: '24 hours', bucket: 900 },
  '7d': { interval: '7 days', bucket: 3600 },
  '30d': { interval: '30 days', bucket: 4 * 3600 },
};

const SERVER_COLUMNS = `id, hostname, primary_ip, os_name, control_panel, web_server, agent_version, tags,
  connected, last_seen_at, created_at, inventory, last_metrics`;

function shape(r: Record<string, any>, online: boolean) {
  return {
    id: r.id,
    hostname: r.hostname,
    primary_ip: r.primary_ip,
    os_name: r.os_name,
    control_panel: r.control_panel,
    web_server: r.web_server,
    agent_version: r.agent_version,
    tags: r.tags,
    online,
    last_seen_at: r.last_seen_at,
    created_at: r.created_at,
    inventory: r.inventory,
    last_metrics: r.last_metrics,
  };
}

export function installCommand(cfg: Config, token: string): string {
  return `curl -fsSL ${cfg.publicUrl}/install.sh | bash -s -- --token ${token}`;
}

export function serverRoutes(app: FastifyInstance, pool: Pool, cfg: Config, hub: AgentHub): void {
  const viewer = { preHandler: requireRole('viewer') };
  const operator = { preHandler: requireRole('operator') };
  const admin = { preHandler: requireRole('admin') };

  async function load(accountId: string, id: string) {
    const { rows } = await pool.query(
      `SELECT ${SERVER_COLUMNS} FROM servers WHERE id = $1 AND account_id = $2 AND status = 'active'`,
      [id, accountId],
    );
    return rows[0];
  }

  function params(req: { params: unknown }, reply: FastifyReply): string | null {
    const p = IdParams.safeParse(req.params);
    if (!p.success) {
      reply.code(404).send({ error: 'server not found' });
      return null;
    }
    return p.data.id;
  }

  function commandError(reply: FastifyReply, err: unknown) {
    if (err instanceof CommandError) return reply.code(409).send({ error: err.message });
    throw err;
  }

  app.get('/api/overview', viewer, async (req) => {
    const { rows } = await pool.query(
      `SELECT id, hostname, primary_ip, os_name, control_panel FROM servers
        WHERE account_id = $1 AND status = 'active' ORDER BY hostname`,
      [req.user!.accountId],
    );
    const online = rows.filter((r) => hub.isOnline(r.id)).length;
    const sec = await pool.query(
      `SELECT last_metrics->'security' AS s, last_metrics->>'ts' AS ts FROM servers WHERE account_id = $1 AND status = 'active'`,
      [req.user!.accountId],
    );
    const totals = { threats_30d: 0, quarantined: 0, open_findings: 0, blocks_30d: 0, active_blocks: 0, blacklisted_ips: 0, servers_with_alerts: 0 };
    for (const r of sec.rows) {
      const s = r.s || {};
      totals.threats_30d += s.scanner?.threats_30d ?? 0;
      totals.quarantined += s.scanner?.quarantined ?? 0;
      totals.open_findings += s.scanner?.open_findings ?? 0;
      totals.blocks_30d += s.firewall?.blocks_30d ?? 0;
      totals.active_blocks += s.firewall?.active_blocks ?? 0;
      totals.blacklisted_ips += s.blacklisted_ips ?? 0;
      if ((s.scanner?.open_findings ?? 0) > 0 || (s.blacklisted_ips ?? 0) > 0) totals.servers_with_alerts++;
    }
    return {
      security: totals,
      servers_total: rows.length,
      servers_online: online,
      servers_offline: rows.length - online,
      quick_access: rows.slice(0, 12).map((r) => ({ ...r, online: hub.isOnline(r.id) })),
    };
  });

  app.get('/api/servers', viewer, async (req) => {
    const q = req.query as { q?: string };
    const filter = (q.q || '').trim().slice(0, 100);
    const { rows } = await pool.query(
      `SELECT ${SERVER_COLUMNS} FROM servers
        WHERE account_id = $1 AND status = 'active'
          AND ($2 = '' OR hostname ILIKE '%' || $2 || '%' OR primary_ip ILIKE '%' || $2 || '%'
               OR $2 = ANY(tags))
        ORDER BY hostname, created_at`,
      [req.user!.accountId, filter],
    );
    return { servers: rows.map((r) => shape(r, hub.isOnline(r.id))) };
  });

  app.get('/api/servers/:id', viewer, async (req, reply) => {
    const id = params(req, reply);
    if (!id) return;
    const r = await load(req.user!.accountId, id);
    if (!r) return reply.code(404).send({ error: 'server not found' });
    const conn = hub.get(id);
    return {
      server: { ...shape(r, !!conn), last_metrics: conn?.lastMetrics ?? r.last_metrics },
      latest_agent_version: currentRelease(cfg.downloadsDir)?.version ?? null,
    };
  });

  app.get('/api/servers/:id/metrics', viewer, async (req, reply) => {
    const id = params(req, reply);
    if (!id) return;
    const range = RANGES[(req.query as { range?: string }).range || '4h'] ?? RANGES['4h'];
    if (!(await load(req.user!.accountId, id))) return reply.code(404).send({ error: 'server not found' });
    const { rows } = await pool.query(
      `SELECT extract(epoch FROM to_timestamp(floor(extract(epoch FROM ts) / $3) * $3))::bigint AS t,
              round(avg(cpu)::numeric, 1)::float AS cpu,
              round(avg(load1)::numeric, 2)::float AS load1,
              round(avg(load5)::numeric, 2)::float AS load5,
              round(avg(load15)::numeric, 2)::float AS load15,
              round(avg(mem_used::float / nullif(mem_total, 0) * 100)::numeric, 1)::float AS mem_pct,
              round(avg(disk_used::float / nullif(disk_total, 0) * 100)::numeric, 1)::float AS disk_pct,
              round(avg(connections))::int AS connections
         FROM server_metrics
        WHERE server_id = $1 AND ts > now() - $2::interval
        GROUP BY 1 ORDER BY 1`,
      [id, range.interval, range.bucket],
    );
    return { points: rows.map((r) => ({ ...r, t: Number(r.t) })) };
  });

  app.post('/api/servers/:id/live', viewer, async (req, reply) => {
    const id = params(req, reply);
    if (!id) return;
    if (!(await load(req.user!.accountId, id))) return reply.code(404).send({ error: 'server not found' });
    try {
      return await hub.command(id, 'live', { seconds: 120 }, 10_000);
    } catch (err) {
      return commandError(reply, err);
    }
  });

  app.post('/api/servers/:id/ping', operator, async (req, reply) => {
    const id = params(req, reply);
    if (!id) return;
    if (!(await load(req.user!.accountId, id))) return reply.code(404).send({ error: 'server not found' });
    const started = Date.now();
    try {
      const data = await hub.command(id, 'ping', {}, 10_000);
      return { ok: true, rtt_ms: Date.now() - started, data };
    } catch (err) {
      return commandError(reply, err);
    }
  });

  const TagsBody = z.object({ tags: z.array(z.string().trim().min(1).max(40)).max(20) });
  app.patch('/api/servers/:id', operator, async (req, reply) => {
    const id = params(req, reply);
    if (!id) return;
    const body = TagsBody.safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: 'invalid tags' });
    const tags = [...new Set(body.data.tags)];
    const { rowCount } = await pool.query(
      "UPDATE servers SET tags = $3 WHERE id = $1 AND account_id = $2 AND status = 'active'",
      [id, req.user!.accountId, tags],
    );
    if (!rowCount) return reply.code(404).send({ error: 'server not found' });
    return { tags };
  });

  app.delete('/api/servers/:id', admin, async (req, reply) => {
    const id = params(req, reply);
    if (!id) return;
    const { rowCount } = await pool.query(
      `UPDATE servers SET status = 'revoked', revoked_at = now(), connected = false
        WHERE id = $1 AND account_id = $2 AND status = 'active'`,
      [id, req.user!.accountId],
    );
    if (!rowCount) return reply.code(404).send({ error: 'server not found' });
    hub.revoke(id);
    await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, serverId: id, action: 'server.removed', ip: req.ip });
    return { ok: true };
  });

  const TokenBody = z.object({ label: z.string().max(100).default('') });
  app.post('/api/enrollment-tokens', admin, async (req, reply) => {
    const body = TokenBody.safeParse(req.body ?? {});
    if (!body.success) return reply.code(400).send({ error: 'invalid request' });
    const token = enrollmentToken();
    const { rows } = await pool.query(
      `INSERT INTO enrollment_tokens (account_id, token_hash, label, created_by, expires_at)
       VALUES ($1, $2, $3, $4, now() + make_interval(hours => $5)) RETURNING id, expires_at`,
      [req.user!.accountId, sha256(token), body.data.label, req.user!.id, cfg.enrollTokenTtlHours],
    );
    await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, action: 'enrollment_token.created', ip: req.ip });
    return {
      id: rows[0].id,
      token,
      expires_at: rows[0].expires_at,
      install_command: installCommand(cfg, token),
      uninstall_command: `curl -fsSL ${cfg.publicUrl}/uninstall.sh | bash`,
    };
  });

  app.get('/api/enrollment-tokens', admin, async (req) => {
    const { rows } = await pool.query(
      `SELECT t.id, t.label, t.created_at, t.expires_at, t.used_at, s.hostname AS server_hostname
         FROM enrollment_tokens t LEFT JOIN servers s ON s.id = t.server_id
        WHERE t.account_id = $1 ORDER BY t.created_at DESC LIMIT 50`,
      [req.user!.accountId],
    );
    return { tokens: rows };
  });

  app.delete('/api/enrollment-tokens/:id', admin, async (req, reply) => {
    const p = IdParams.safeParse(req.params);
    if (!p.success) return reply.code(404).send({ error: 'token not found' });
    await pool.query(
      'DELETE FROM enrollment_tokens WHERE id = $1 AND account_id = $2 AND used_at IS NULL',
      [p.data.id, req.user!.accountId],
    );
    return { ok: true };
  });

  app.get('/api/audit', admin, async (req) => {
    const { rows } = await pool.query(
      `SELECT a.id, a.action, a.detail, a.ip, a.created_at, u.email AS user_email, s.hostname AS server_hostname
         FROM audit_events a
         LEFT JOIN users u ON u.id = a.user_id
         LEFT JOIN servers s ON s.id = a.server_id
        WHERE a.account_id = $1 ORDER BY a.created_at DESC LIMIT 200`,
      [req.user!.accountId],
    );
    return { events: rows };
  });
}
