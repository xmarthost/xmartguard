import type { FastifyInstance } from 'fastify';
import { isIP } from 'node:net';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { AgentHub } from '../agents/hub.js';
import { audit, requireRole } from '../auth.js';
import { signedPayload } from '../agent-sign.js';

/** One CIDR or address; wider than /8 (IPv4) or /16 (IPv6) is refused. */
function validAddr(a: string): boolean {
  const [ip, bits, extra] = a.split('/');
  if (extra !== undefined) return false;
  const v = isIP(ip);
  if (!v) return false;
  if (bits === undefined) return true;
  if (!/^\d{1,3}$/.test(bits)) return false;
  const n = Number(bits);
  return v === 4 ? n >= 8 && n <= 32 : n >= 16 && n <= 128;
}

export const TrustedConfig = z.object({
  enabled: z.boolean(),
  disabled: z.array(z.string().regex(/^[a-z0-9-]{1,40}$/)).max(200),
  custom: z.array(z.string().trim().max(50)).max(500),
});
export type TrustedConfig = z.infer<typeof TrustedConfig>;

const DEFAULT: TrustedConfig = { enabled: true, disabled: [], custom: [] };

async function load(pool: Pool, accountId: string): Promise<{ config: TrustedConfig; version: number; updated_at: string | null }> {
  const { rows } = await pool.query('SELECT config, version, updated_at FROM trusted_services WHERE account_id = $1', [accountId]);
  if (!rows[0]) return { config: DEFAULT, version: 0, updated_at: null };
  const p = TrustedConfig.safeParse(rows[0].config);
  return { config: p.success ? p.data : DEFAULT, version: Number(rows[0].version), updated_at: rows[0].updated_at };
}

/**
 * Trusted services for all servers (Overview » Trusted Services): which
 * crawler, CDN, monitor, payment and vendor lists every server exempts from
 * blocks, plus the administrator's own addresses. Saving pushes the list to
 * every online server; the others fetch it when they reconnect.
 */
export function trustedRoutes(app: FastifyInstance, pool: Pool, hub: AgentHub): void {
  const viewer = { preHandler: requireRole('viewer') };
  const admin = { preHandler: requireRole('admin') };

  async function servers(accountId: string) {
    const { rows } = await pool.query(
      "SELECT id, hostname, agent_version FROM servers WHERE account_id = $1 AND status = 'active' ORDER BY hostname",
      [accountId],
    );
    return rows.map((r) => ({ id: String(r.id), hostname: String(r.hostname), agent_version: String(r.agent_version ?? ''), online: hub.isOnline(r.id) }));
  }

  app.get('/api/trusted', viewer, async (req) => {
    const acc = req.user!.accountId;
    const cur = await load(pool, acc);
    const list = await servers(acc);
    // The service catalog and list sizes come from the agents (they
    // download the lists); the first online server that answers is shown.
    let services: unknown[] = [];
    let source: { id: string; hostname: string } | null = null;
    for (const s of list.filter((x) => x.online).slice(0, 3)) {
      try {
        const r = (await hub.command(s.id, 'trusted.status', {}, 15_000)) as { services?: unknown[] };
        if (Array.isArray(r?.services)) {
          services = r.services;
          source = { id: s.id, hostname: s.hostname };
          break;
        }
      } catch {
        /* try the next server */
      }
    }
    return { ...cur, services, source, servers: list };
  });

  app.put('/api/trusted', admin, async (req, reply) => {
    const b = TrustedConfig.safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: b.error.issues[0]?.message ?? 'invalid configuration' });
    const c = { ...b.data, custom: [...new Set(b.data.custom.filter((x) => x !== ''))], disabled: [...new Set(b.data.disabled)] };
    const bad = c.custom.find((x) => !validAddr(x));
    if (bad) return reply.code(400).send({ error: `${bad} is not an IP address or network (networks wider than /8 are refused)` });
    const acc = req.user!.accountId;
    const { rows } = await pool.query(
      `INSERT INTO trusted_services (account_id, config, version) VALUES ($1, $2, 1)
       ON CONFLICT (account_id) DO UPDATE SET config = EXCLUDED.config, version = trusted_services.version + 1, updated_at = now()
       RETURNING version`,
      [acc, JSON.stringify(c)],
    );
    const version = Number(rows[0].version);
    await audit(pool, { accountId: acc, userId: req.user!.id, action: 'trusted.saved', detail: { version, ...c }, ip: req.ip });
    let pushed = 0;
    let offline = 0;
    for (const s of await servers(acc)) {
      if (!s.online) {
        offline++;
        continue;
      }
      pushed++;
      void hub.command(s.id, 'trusted.apply', { version, ...c }, 120_000).catch(() => undefined);
    }
    return { version, config: c, pushed, offline };
  });

  // Agents fetch the list when it changed (servers that were offline).
  app.post('/api/agent/trusted/config', { bodyLimit: 16 * 1024 }, async (req, reply) => {
    const r = await signedPayload(pool, req.body, z.object({ version: z.number().int().min(0) }), reply);
    if (!r) return;
    const cur = await load(pool, r.accountId);
    // Never saved: every server keeps its own switches.
    if (cur.version === 0 || cur.version === r.data.version) return { unchanged: true };
    return { config: { version: cur.version, ...cur.config } };
  });
}
