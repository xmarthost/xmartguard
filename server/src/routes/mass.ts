import type { FastifyInstance } from 'fastify';
import { isIP } from 'node:net';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';
import { CommandError, type AgentHub } from '../agents/hub.js';
import { audit, hasRole, type Role } from '../auth.js';
import { currentRelease } from '../agents/release.js';
import { ACTIONS } from './agent-cmd.js';
import { scopeAccounts } from '../tenancy.js';

/**
 * Operations that can be run on many servers at once. Each maps to one
 * agent action with fixed or validated parameters, so a mass operation can
 * never do more than the same action run server by server.
 */
const OPS: Record<string, { label: string; action: string; params: (p: Record<string, unknown>) => Record<string, unknown> | string }> = {
  quick_scan: { label: 'Start quick scan', action: 'scan.start', params: () => ({ kind: 'quick' }) },
  full_scan: { label: 'Start full scan', action: 'scan.start', params: () => ({ kind: 'full' }) },
  cms_scan: { label: 'Scan websites (CMS)', action: 'cms.scan', params: () => ({}) },
  domain_check: { label: 'Check domain reputation', action: 'domainrep.check', params: () => ({}) },
  rbl_check: { label: 'Check IP reputation', action: 'reputation.check', params: () => ({}) },
  waf_on: { label: 'Enable WAF', action: 'settings.set', params: () => ({ waf: { enabled: true } }) },
  waf_off: { label: 'Disable WAF', action: 'settings.set', params: () => ({ waf: { enabled: false } }) },
  ipdb_on: { label: 'Enable IPDB protection', action: 'settings.set', params: () => ({ ipdb: { enabled: true } }) },
  ai_portal: {
    label: 'AI scanner: use xPGuard AI (free AI APIs), detections only',
    action: 'settings.set',
    params: () => ({ ai: { enabled: true, provider: 'portal', scope: 'suspicious', learn: true } }),
  },
  ai_all: {
    label: 'AI scanner: xPGuard AI checks every new file (self-training)',
    action: 'settings.set',
    params: () => ({ ai: { enabled: true, provider: 'portal', scope: 'all', learn: true } }),
  },
  trim_on: {
    label: 'Trim injected code instead of quarantining (AI)',
    action: 'settings.set',
    params: () => ({ scanner: { trim: true } }),
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

/**
 * IP list operations (Whitelist, Blacklist, Ignore, Unblock): many
 * addresses at once, one per line, added to or deleted from the list on
 * every selected server with one firewall reload per server.
 */
const IP_OPS: Record<string, { label: string; kind: string; modes: ('add' | 'delete')[] }> = {
  allow_ip: { label: 'Whitelist IPs', kind: 'allow', modes: ['add', 'delete'] },
  block_ip: { label: 'Blacklist (block) IPs', kind: 'deny', modes: ['add', 'delete'] },
  ignore_ip: { label: 'Ignore IPs (never blocked automatically)', kind: 'ignore', modes: ['add', 'delete'] },
  unblock_ip: { label: 'Unblock IPs (lift every block)', kind: 'unblock', modes: ['delete'] },
};
export const MAX_ADDRS = 1000;

/**
 * Reads the address list: one per line (commas, semicolons and spaces
 * also separate), "# comments" ignored, duplicates dropped. Each bad
 * entry is reported with its line number.
 */
export function parseAddrs(text: unknown): { addrs: string[]; errors: string[] } {
  const addrs: string[] = [];
  const errors: string[] = [];
  const seen = new Set<string>();
  const lines = (Array.isArray(text) ? text.join('\n') : typeof text === 'string' ? text : '').split(/\r?\n/);
  lines.forEach((raw, i) => {
    for (const v of raw.replace(/#.*/, '').split(/[\s,;]+/)) {
      if (!v) continue;
      if (!isAddr(v)) {
        if (errors.length < 20) errors.push(`line ${i + 1}: "${v.slice(0, 60)}" is not an IP address or CIDR`);
        continue;
      }
      const k = v.toLowerCase();
      if (!seen.has(k)) {
        seen.add(k);
        addrs.push(v);
      }
    }
  });
  return { addrs, errors };
}

type AddrResult = { addr: string; ok: boolean; error?: string };

/** Runs an IP list operation on one server; older agents get one command per address. */
async function runIpOp(
  hub: AgentHub,
  serverId: string,
  kind: string,
  mode: 'add' | 'delete',
  addrs: string[],
  comment: string,
): Promise<AddrResult[]> {
  try {
    const data = (mode === 'add'
      ? await hub.command(serverId, 'fw.add_many', { kind, addrs, comment }, 120_000)
      : await hub.command(serverId, 'fw.remove_many', { kind, addrs }, 120_000)) as { results?: { addr: string; ok: boolean; error?: string }[] };
    return (data?.results ?? []).map((r) => ({ addr: r.addr, ok: r.ok, ...(r.error ? { error: r.error } : {}) }));
  } catch (err) {
    if (!(err instanceof CommandError) || !err.message.startsWith('unsupported action')) throw err;
  }
  const out: AddrResult[] = [];
  for (const addr of addrs) {
    try {
      if (mode === 'add') await hub.command(serverId, 'fw.add', { kind, addr, comment }, 60_000);
      else if (kind === 'unblock') await hub.command(serverId, 'fw.unblock', { addr }, 60_000);
      else await hub.command(serverId, 'fw.remove', { kind, addr }, 60_000);
      out.push({ addr, ok: true });
    } catch (err) {
      if (err instanceof CommandError && err.message.startsWith('unsupported action')) throw err;
      out.push({ addr, ok: false, error: err instanceof CommandError ? err.message : 'failed' });
    }
  }
  return out;
}

function str(v: unknown): string {
  return typeof v === 'string' ? v.trim().slice(0, 200) : '';
}

/** An IPv4/IPv6 address, or a CIDR with a valid prefix length. */
function isAddr(v: unknown): boolean {
  if (typeof v !== 'string') return false;
  const [host, bits, extra] = v.trim().split('/');
  const fam = isIP(host);
  if (!fam || extra !== undefined) return false;
  if (bits === undefined) return true;
  return /^\d{1,3}$/.test(bits) && Number(bits) <= (fam === 4 ? 32 : 128);
}

const Body = z.object({
  op: z.string().max(40),
  server_ids: z.array(z.string().uuid()).min(1).max(500),
  params: z.record(z.string(), z.unknown()).default({}),
});

export function massRoutes(app: FastifyInstance, pool: Pool, cfg: Config, hub: AgentHub): void {
  app.get('/api/mass/operations', async (req, reply) => {
    if (!req.user) return reply.code(401).send({ error: 'authentication required' });
    const ops: { id: string; label: string; role: string; needs_addr: boolean; ip_list?: boolean; modes?: string[] }[] = [
      ...Object.entries(IP_OPS).map(([id, o]) => ({ id, label: o.label, role: 'operator', needs_addr: true, ip_list: true, modes: o.modes })),
      ...Object.entries(OPS).map(([id, o]) => ({ id, label: o.label, role: ACTIONS[o.action]?.role ?? 'admin', needs_addr: false })),
    ];
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
    const ipOp = IP_OPS[op];
    let ip: { mode: 'add' | 'delete'; addrs: string[]; comment: string } | null = null;
    if (ipOp) {
      const mode = params.mode === 'delete' ? 'delete' : 'add';
      if (!ipOp.modes.includes(mode)) return reply.code(400).send({ error: 'this list only supports delete' });
      const { addrs, errors } = parseAddrs(params.addrs ?? params.addr);
      if (errors.length) return reply.code(400).send({ error: errors.join('; ') });
      if (!addrs.length) return reply.code(400).send({ error: 'enter at least one IP address or CIDR (one per line)' });
      if (addrs.length > MAX_ADDRS) return reply.code(400).send({ error: `at most ${MAX_ADDRS} addresses at once` });
      ip = { mode, addrs, comment: str(params.reason ?? params.comment) || 'mass operation' };
      action = mode === 'add' ? 'fw.add_many' : 'fw.remove_many';
      actionParams = { kind: ipOp.kind, mode, count: addrs.length, reason: ip.comment, addrs: addrs.slice(0, 50) };
      role = 'operator';
      timeoutMs = 120_000;
    } else if (op === 'update_agent') {
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
      "SELECT id, hostname, inventory->>'arch' AS arch FROM servers WHERE account_id = ANY($1::uuid[]) AND status = 'active' AND id = ANY($2::uuid[])",
      [await scopeAccounts(pool, user.accountId), server_ids],
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
          if (ip) {
            const addrs = await runIpOp(hub, s.id, ipOp!.kind, ip.mode, ip.addrs, ip.comment);
            const failed = addrs.filter((a) => !a.ok);
            results.push({
              server_id: s.id,
              hostname: s.hostname,
              ok: failed.length === 0,
              ...(failed.length ? { error: `${failed.length} of ${addrs.length} addresses failed` } : {}),
              data: { done: addrs.length - failed.length, total: addrs.length, failed },
            });
            continue;
          }
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
