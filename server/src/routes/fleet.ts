import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';
import type { AgentHub } from '../agents/hub.js';
import { audit, requireRole } from '../auth.js';
import { scopeAccounts } from '../tenancy.js';
import { currentRelease, versionLess } from '../agents/release.js';
import { eachLimit } from '../agents/limit.js';
import { serverAlerts } from './notifications.js';

/**
 * Fleet health: one row per server with what needs fixing (offline, old
 * agent, WAF errors, high load, full disk, service problems), and the
 * fleet-wide settings rollback.
 */

interface Metrics { cpu_percent?: number; load1?: number; cpu_cores?: number; mem_used?: number; mem_total?: number; disk_used?: number; disk_total?: number }

export function fleetRoutes(app: FastifyInstance, pool: Pool, cfg: Config, hub: AgentHub): void {
  app.get('/api/fleet/health', { preHandler: requireRole('viewer') }, async (req) => {
    const { rows } = await pool.query(
      `SELECT s.id, s.hostname, s.agent_version, s.last_seen_at, s.last_metrics, s.control_panel, w.status AS waf
         FROM servers s LEFT JOIN waf_server_status w ON w.server_id = s.id
        WHERE s.account_id = ANY($1::uuid[]) AND s.status = 'active' ORDER BY s.hostname`,
      [await scopeAccounts(pool, req.user!.accountId)],
    );
    const latest = currentRelease(cfg.downloadsDir)?.version ?? null;
    const out = await eachLimit(rows, 16, async (r) => {
      const id = String(r.id);
      const online = hub.isOnline(id);
      const m: Metrics = r.last_metrics ?? {};
      const problems: { level: 'danger' | 'warning'; text: string; fix: 'update' | 'waf' | 'dashboard' | 'install' | 'monitoring' }[] = [];
      const version = String(r.agent_version ?? '');
      if (!online) problems.push({ level: 'danger', text: 'Offline: the agent is not connected', fix: 'install' });
      if (latest && version && versionLess(version.replace(/-dev$/, ''), latest)) problems.push({ level: 'warning', text: `Agent ${version}, ${latest} is available`, fix: 'update' });
      const waf = r.waf ?? {};
      if (waf.error) problems.push({ level: 'danger', text: `WAF: ${String(waf.error).slice(0, 160)}`, fix: 'waf' });
      const disk = m.disk_total ? (m.disk_used ?? 0) / m.disk_total : 0;
      if (disk >= 0.9) problems.push({ level: disk >= 0.97 ? 'danger' : 'warning', text: `Disk ${Math.round(disk * 100)}% full`, fix: 'monitoring' });
      if ((m.cpu_percent ?? 0) >= 90) problems.push({ level: 'warning', text: `CPU ${Math.round(m.cpu_percent!)}%`, fix: 'monitoring' });
      let alerts = 0;
      if (online) {
        try {
          for (const a of await serverAlerts(hub, id, version)) {
            if (a.level !== 'danger' && a.level !== 'warning') continue;
            alerts++;
            if (/not working|paused|stuck/i.test(String(a.text))) problems.push({ level: a.level, text: String(a.text).slice(0, 160), fix: 'dashboard' });
          }
        } catch {
          /* counted as no answer */
        }
      }
      // The most serious first.
      problems.sort((x, y) => (x.level === y.level ? 0 : x.level === 'danger' ? -1 : 1));
      return {
        id,
        hostname: r.hostname,
        online,
        last_seen_at: r.last_seen_at,
        agent_version: version,
        control_panel: r.control_panel,
        cpu: m.cpu_percent ?? null,
        load1: m.load1 ?? null,
        mem: m.mem_total ? (m.mem_used ?? 0) / m.mem_total : null,
        disk: m.disk_total ? disk : null,
        alerts,
        problems,
      };
    });
    const rank = (x: (typeof out)[0]) => (x.problems.some((p) => p.level === 'danger') ? 0 : x.problems.length ? 1 : 2);
    out.sort((a, b) => rank(a) - rank(b) || String(a.hostname).localeCompare(String(b.hostname)));
    return {
      latest_agent_version: latest,
      servers: out,
      summary: {
        total: out.length,
        offline: out.filter((x) => !x.online).length,
        outdated: out.filter((x) => x.problems.some((p) => p.fix === 'update')).length,
        problems: out.filter((x) => x.problems.length).length,
      },
    };
  });

  // Undo every settings change made since a time, on every online server.
  const Rollback = z.object({ before: z.number().int().min(1), servers: z.array(z.string().uuid()).max(1000).optional() });
  app.post('/api/fleet/rollback', { preHandler: requireRole('admin') }, async (req, reply) => {
    const b = Rollback.safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: 'choose a time' });
    const { rows } = await pool.query<{ id: string; hostname: string }>(
      "SELECT id, hostname FROM servers WHERE account_id = ANY($1::uuid[]) AND status = 'active' AND ($2::uuid[] IS NULL OR id = ANY($2::uuid[])) ORDER BY hostname",
      [await scopeAccounts(pool, req.user!.accountId), b.data.servers ?? null],
    );
    const results = await eachLimit(rows, 10, async (r) => {
      if (!hub.isOnline(String(r.id))) return { server: r.hostname, ok: false, message: 'offline' };
      try {
        await hub.command(String(r.id), 'settings.rollback', { before: b.data.before }, 120_000);
        return { server: r.hostname, ok: true, message: 'rolled back' };
      } catch (err) {
        return { server: r.hostname, ok: false, message: (err as Error).message.slice(0, 200) };
      }
    });
    await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, action: 'fleet.rollback', detail: { before: b.data.before, servers: rows.length }, ip: req.ip });
    return { results };
  });
}
