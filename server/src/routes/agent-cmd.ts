import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';
import { CommandError, type AgentHub } from '../agents/hub.js';
import { audit, hasRole, type Role } from '../auth.js';
import { currentRelease } from '../agents/release.js';

/**
 * Agent actions the portal may proxy, with the minimum role and whether the
 * call changes state (audited). Anything not listed is rejected.
 */
export const ACTIONS: Record<string, { role: Role; mutates: boolean; timeoutMs?: number }> = {
  'stats.get': { role: 'viewer', mutates: false },
  'scan.list': { role: 'viewer', mutates: false },
  'scanner.paths': { role: 'viewer', mutates: false },
  'findings.list': { role: 'viewer', mutates: false },
  'settings.get': { role: 'viewer', mutates: false },
  'fw.list': { role: 'viewer', mutates: false },
  'fw.check': { role: 'viewer', mutates: false },
  'fw.events': { role: 'viewer', mutates: false },
  'reputation.get': { role: 'viewer', mutates: false },
  'ipdb.status': { role: 'viewer', mutates: false },
  'ipdb.live': { role: 'viewer', mutates: false },
  'fw.connections': { role: 'viewer', mutates: false },

  'scan.start': { role: 'operator', mutates: true },
  'scan.stop': { role: 'operator', mutates: true },
  'scan.delete': { role: 'operator', mutates: true },
  'finding.action': { role: 'operator', mutates: true, timeoutMs: 120_000 },
  'fw.add': { role: 'operator', mutates: true },
  'fw.remove': { role: 'operator', mutates: true },
  'fw.unblock': { role: 'operator', mutates: true },
  'reputation.check': { role: 'operator', mutates: true, timeoutMs: 120_000 },

  'settings.set': { role: 'admin', mutates: true, timeoutMs: 120_000 },
  'fw.apply': { role: 'admin', mutates: true, timeoutMs: 120_000 },
};

const Params = z.object({ id: z.string().uuid(), action: z.string().max(40) });

export function agentCommandRoutes(app: FastifyInstance, pool: Pool, cfg: Config, hub: AgentHub): void {
  app.post('/api/servers/:id/agent/:action', async (req, reply) => {
    const user = req.user;
    if (!user) return reply.code(401).send({ error: 'authentication required' });
    const p = Params.safeParse(req.params);
    if (!p.success) return reply.code(404).send({ error: 'not found' });
    const spec = ACTIONS[p.data.action];
    if (!spec) return reply.code(404).send({ error: 'unknown action' });
    if (!hasRole(user, spec.role)) return reply.code(403).send({ error: 'insufficient permissions' });
    const { rowCount } = await pool.query(
      "SELECT 1 FROM servers WHERE id = $1 AND account_id = $2 AND status = 'active'",
      [p.data.id, user.accountId],
    );
    if (!rowCount) return reply.code(404).send({ error: 'server not found' });

    let params: Record<string, unknown> = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, unknown>;
    if (p.data.action === 'scan.start') params = { ...params, initiator: user.email };
    try {
      const data = await hub.command(p.data.id, p.data.action, params, spec.timeoutMs ?? 30_000);
      if (spec.mutates) {
        await audit(pool, {
          accountId: user.accountId,
          userId: user.id,
          serverId: p.data.id,
          action: `agent.${p.data.action}`,
          detail: summarize(params),
          ip: req.ip,
        });
      }
      return data ?? {};
    } catch (err) {
      if (err instanceof CommandError) {
        const msg = err.message.startsWith('unsupported action')
          ? 'This server runs an older agent. Update the agent to use this feature.'
          : err.message;
        return reply.code(409).send({ error: msg });
      }
      throw err;
    }
  });

  /** Pushes the portal's bundled agent release to a server. */
  app.post('/api/servers/:id/update-agent', async (req, reply) => {
    const user = req.user;
    if (!user) return reply.code(401).send({ error: 'authentication required' });
    if (!hasRole(user, 'admin')) return reply.code(403).send({ error: 'insufficient permissions' });
    const id = (req.params as { id: string }).id;
    if (!z.string().uuid().safeParse(id).success) return reply.code(404).send({ error: 'server not found' });
    const { rows } = await pool.query(
      "SELECT inventory FROM servers WHERE id = $1 AND account_id = $2 AND status = 'active'",
      [id, user.accountId],
    );
    if (!rows[0]) return reply.code(404).send({ error: 'server not found' });
    const rel = currentRelease(cfg.downloadsDir);
    if (!rel) return reply.code(409).send({ error: 'no agent release is bundled with this portal' });
    try {
      const data = await hub.command(id, 'agent.update', { sha256: rel.sha256[rows[0].inventory?.arch ?? 'amd64'] ?? '' }, 180_000);
      await audit(pool, { accountId: user.accountId, userId: user.id, serverId: id, action: 'agent.update', detail: { to: rel.version }, ip: req.ip });
      return data;
    } catch (err) {
      if (err instanceof CommandError) {
        const msg = err.message.startsWith('unsupported action')
          ? 'This agent is too old to update itself. Re-install it once with a new token from Add Server.'
          : err.message;
        return reply.code(409).send({ error: msg });
      }
      throw err;
    }
  });
}

/** Keeps audit entries small and free of large payloads. */
function summarize(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) {
    const s = typeof v === 'string' ? v : JSON.stringify(v);
    out[k] = s && s.length > 300 ? s.slice(0, 300) + '…' : v;
  }
  return out;
}
