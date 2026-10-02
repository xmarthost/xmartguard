import type { FastifyInstance } from 'fastify';
import type { Pool } from '../db.js';
import type { AgentHub } from '../agents/hub.js';
import { requireRole } from '../auth.js';
import { versionLess } from '../agents/release.js';
import { eachLimit } from '../agents/limit.js';

/** Agents with the light alerts.get command; older ones answer from dashboard.get. */
export const ALERTS_MIN_AGENT = '0.21.3';

export interface Notification {
  server_id: string;
  hostname: string;
  level: string;
  text: string;
  link: string;
  details: string[];
}

interface AgentAlert {
  level?: string;
  text?: string;
  link?: string;
  details?: string[] | null;
}

const CACHE_MS = 60_000;

/**
 * The header bell: what the servers' dashboards show as alerts, for every
 * server (or one, inside a server), plus servers that are offline.
 */
export function notificationRoutes(app: FastifyInstance, pool: Pool, hub: AgentHub): void {
  const viewer = { preHandler: requireRole('viewer') };
  // Every open portal tab asks each minute; the agents are asked at most once a minute.
  const cache = new Map<string, { at: number; alerts: AgentAlert[] }>();

  async function serverAlerts(id: string, version: string): Promise<AgentAlert[]> {
    const hit = cache.get(id);
    if (hit && Date.now() - hit.at < CACHE_MS) return hit.alerts;
    const r = versionLess(version, ALERTS_MIN_AGENT)
      ? ((await hub.command(id, 'dashboard.get', { days: 7 }, 20_000)) as { alerts?: AgentAlert[] })
      : ((await hub.command(id, 'alerts.get', {}, 15_000)) as { alerts?: AgentAlert[] });
    const alerts = Array.isArray(r?.alerts) ? r.alerts : [];
    cache.set(id, { at: Date.now(), alerts });
    return alerts;
  }

  app.get('/api/notifications', viewer, async (req) => {
    const q = req.query as { server?: string };
    const params: unknown[] = [req.user!.accountId];
    let where = "account_id = $1 AND status = 'active'";
    if (q.server) {
      params.push(q.server);
      where += ' AND id::text = $2';
    }
    const { rows } = await pool.query(`SELECT id, hostname, agent_version FROM servers WHERE ${where} ORDER BY hostname`, params);
    const per = await eachLimit(rows, 16, async (r): Promise<Notification[]> => {
      const base = { server_id: String(r.id), hostname: String(r.hostname) };
      if (!hub.isOnline(r.id)) return [{ ...base, level: 'danger', text: 'Server is offline: the agent is not connected', link: '', details: [] }];
      try {
        const alerts = await serverAlerts(String(r.id), String(r.agent_version ?? ''));
        return alerts.map((a) => ({
          ...base,
          level: a.level === 'danger' || a.level === 'warning' ? a.level : 'info',
          text: String(a.text ?? ''),
          link: String(a.link ?? ''),
          details: Array.isArray(a.details) ? a.details.map(String) : [],
        }));
      } catch (err) {
        return [{ ...base, level: 'warning', text: `Could not read alerts: ${(err as Error).message}`, link: '', details: [] }];
      }
    });
    const items = per.flat();
    const rank = (l: string) => (l === 'danger' ? 0 : l === 'warning' ? 1 : 2);
    items.sort((a, b) => rank(a.level) - rank(b.level) || a.hostname.localeCompare(b.hostname));
    return { items, servers: rows.length };
  });
}
