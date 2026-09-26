import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';
import { CommandError, type AgentHub } from '../agents/hub.js';
import { audit, hasRole, type Role } from '../auth.js';
import { currentRelease } from '../agents/release.js';
import { ACTIONS } from './agent-cmd.js';

/**
 * Operations that can be run on many servers at once. Each maps to one
 * agent action with fixed or validated parameters, so a mass operation can
 * never do more than the same action run server by server.
 */
const OPS: Record<string, { label: string; action: string; params: (p: Record<string, unknown>) => Record<string, unknown> | string }> = {
  quick_scan: { label: 'Start quick scan', action: 'scan.start', params: () => ({ kind: 'quick' }) },
  full_scan: { label: 'Start full scan', action: 'scan.start', params: () => ({ kind: 'full' }) },
  block_ip: {
    label: 'Block IP',
    action: 'fw.add',
    params: (p) => (isAddr(p.addr) ? { kind: 'deny', addr: p.addr, comment: str(p.comment) || 'mass operation' } : 'enter a valid IP address or CIDR'),
  },
  allow_ip: {
    label: 'Whitelist IP',
    action: 'fw.add',
    params: (p) => (isAddr(p.addr) ? { kind: 'allow', addr: p.addr, comment: str(p.comment) || 'mass operation' } : 'enter a valid IP address or CIDR'),
  },
  unblock_ip: { label: 'Unblock IP', action: 'fw.unblock', params: (p) => (isAddr(p.addr) ? { addr: p.addr } : 'enter a valid IP address') },
  cms_scan: { label: 'Scan websites (CMS)', action: 'cms.scan', params: () => ({}) },
  domain_check: { label: 'Check domain reputation', action: 'domainrep.check', params: () => ({}) },
  rbl_check: { label: 'Check IP reputation', action: 'reputation.check', params: () => ({}) },
  waf_on: { label: 'Enable WAF', action: 'settings.set', params: () => ({ waf: { enabled: true } }) },
  waf_off: { label: 'Disable WAF', action: 'settings.set', params: () => ({ waf: { enabled: false } }) },
  ipdb_on: { label: 'Enable IPDB protection', action: 'settings.set', params: () => ({ ipdb: { enabled: true } }) },
  ai_portal: {
    label: 'Use the portal AI model for the AI scanner',
    action: 'settings.set',
    params: () => ({ ai: { enabled: true, provider: 'portal' } }),
  },
  ai_builtin: {
    label: 'Use the built-in AI model for the AI scanner',
    action: 'settings.set',
    params: () => ({ ai: { enabled: true, provider: 'builtin' } }),
  },
  realtime_on: { label: 'Enable realtime scanning', action: 'settings.set', params: () => ({ scanner: { realtime: true } }) },
  quarantine_on: {
    label: 'Quarantine viruses automatically',
    action: 'settings.set',
    params: () => ({ scanner: { virus_action: 'quarantine' } }),
  },
  firewall_apply: { label: 'Reload firewall', action: 'fw.apply', params: () => ({}) },
};

function str(v: unknown): string {
  return typeof v === 'string' ? v.trim().slice(0, 200) : '';
}

function isAddr(v: unknown): v is string {
  return typeof v === 'string' && /^[0-9a-fA-F:.]{3,45}(\/\d{1,3})?$/.test(v.trim());
}

const Body = z.object({
  op: z.string().max(40),
  server_ids: z.array(z.string().uuid()).min(1).max(500),
  params: z.record(z.string(), z.unknown()).default({}),
});

export function massRoutes(app: FastifyInstance, pool: Pool, cfg: Config, hub: AgentHub): void {
  app.get('/api/mass/operations', async (req, reply) => {
    if (!req.user) return reply.code(401).send({ error: 'authentication required' });
    const ops = Object.entries(OPS).map(([id, o]) => ({
      id,
      label: o.label,
      role: ACTIONS[o.action]?.role ?? 'admin',
      needs_addr: ['block_ip', 'allow_ip', 'unblock_ip'].includes(id),
    }));
    ops.push({ id: 'update_agent', label: 'Update agent to the latest version', role: 'admin', needs_addr: false });
    return { operations: ops.filter((o) => hasRole(req.user!, o.role as Role)) };
  });

  app.post('/api/mass/run', async (req, reply) => {
    const user = req.user;
    if (!user) return reply.code(401).send({ error: 'authentication required' });
    const b = Body.safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: 'invalid request' });
    const { op, server_ids, params } = b.data;

    let action: string;
    let actionParams: Record<string, unknown> = {};
    let role: Role;
    let timeoutMs = 60_000;
    const rel = op === 'update_agent' ? currentRelease(cfg.downloadsDir) : null;
    if (op === 'update_agent') {
      if (!rel) return reply.code(409).send({ error: 'no agent release is bundled with this portal' });
      action = 'agent.update';
      role = 'admin';
      timeoutMs = 180_000;
    } else {
      const o = OPS[op];
      if (!o) return reply.code(400).send({ error: 'unknown operation' });
      const spec = ACTIONS[o.action];
      const p = o.params(params);
      if (typeof p === 'string') return reply.code(400).send({ error: p });
      action = o.action;
      actionParams = p;
      role = spec.role;
      timeoutMs = spec.timeoutMs ?? 60_000;
      if (action === 'scan.start') actionParams.initiator = user.email;
    }
    if (!hasRole(user, role)) return reply.code(403).send({ error: 'insufficient permissions' });

    const { rows } = await pool.query(
      "SELECT id, hostname, inventory->>'arch' AS arch FROM servers WHERE account_id = $1 AND status = 'active' AND id = ANY($2::uuid[])",
      [user.accountId, server_ids],
    );
    const servers = rows as { id: string; hostname: string; arch: string | null }[];
    const results: { server_id: string; hostname: string; ok: boolean; error?: string; data?: unknown }[] = [];
    // Run with limited concurrency so a big fleet does not overload the portal.
    let next = 0;
    const worker = async () => {
      while (next < servers.length) {
        const s = servers[next++];
        const params = action === 'agent.update' ? { sha256: rel!.sha256[s.arch ?? 'amd64'] ?? '' } : actionParams;
        try {
          const data = await hub.command(s.id, action, params, timeoutMs);
          results.push({ server_id: s.id, hostname: s.hostname, ok: true, data });
        } catch (err) {
          let msg = err instanceof CommandError ? err.message : 'failed';
          if (msg.startsWith('unsupported action')) msg = 'agent too old for this operation (update the agent)';
          results.push({ server_id: s.id, hostname: s.hostname, ok: false, error: msg });
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(8, servers.length) }, worker));
    results.sort((a, b) => a.hostname.localeCompare(b.hostname));
    await audit(pool, {
      accountId: user.accountId,
      userId: user.id,
      action: `mass.${op}`,
      detail: { servers: servers.length, ok: results.filter((r) => r.ok).length, params: actionParams },
      ip: req.ip,
    });
    return { op, total: servers.length, ok: results.filter((r) => r.ok).length, results };
  });
}
