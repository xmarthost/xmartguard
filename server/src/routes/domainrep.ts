import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import { masterAccount, scopeAccounts } from '../tenancy.js';
import type { AgentHub } from '../agents/hub.js';
import { audit, requirePlatform, requireRole } from '../auth.js';
import { versionLess } from '../agents/release.js';
import { eachLimit } from '../agents/limit.js';
import { SAFE_BROWSING_MIN_AGENT, SafeBrowsingKey, hint, loadGlobalKeys, syncMail } from './mail.js';

/**
 * Domain reputation for all servers (Overview » Domain Reputation): one
 * Google Safe Browsing key for every server, and each server's state
 * (switched on, which key it uses, listed domains, last check).
 */
export function domainRepRoutes(app: FastifyInstance, pool: Pool, hub: AgentHub): void {
  const viewer = { preHandler: requirePlatform('viewer') };
  const admin = { preHandler: requirePlatform('admin') };

  async function servers(accountId: string) {
    const { rows } = await pool.query(
      "SELECT id, hostname, agent_version FROM servers WHERE account_id = ANY($1::uuid[]) AND status = 'active' ORDER BY hostname",
      [await scopeAccounts(pool, accountId)],
    );
    return rows.map((r) => ({ id: String(r.id), hostname: String(r.hostname), agent_version: String(r.agent_version ?? ''), online: hub.isOnline(r.id) }));
  }

  async function states(accountId: string) {
    return eachLimit(await servers(accountId), 16, async (s): Promise<Record<string, unknown>> => {
      if (!s.online) return { ...s, error: 'offline' };
      const old = versionLess(s.agent_version, SAFE_BROWSING_MIN_AGENT);
      try {
        const r = (await hub.command(s.id, 'domainrep.get', { limit: 1 }, 15_000)) as Record<string, unknown>;
        return { ...s, enabled: r.enabled ?? null, key_source: r.safe_browsing ?? null, summary: r.summary ?? null, last_check: Number(r.last_check) || 0, old, error: '' };
      } catch (err) {
        return { ...s, old, error: (err as Error).message };
      }
    });
  }

  app.get('/api/domain-reputation', viewer, async (req) => {
    const acc = req.user!.accountId;
    const k = (await loadGlobalKeys(pool, acc)).safe_browsing_key;
    return { key_set: k !== '', key_hint: hint(k), min_agent: SAFE_BROWSING_MIN_AGENT, servers: await states(acc) };
  });

  app.put('/api/domain-reputation', admin, async (req, reply) => {
    const b = z.object({ safe_browsing_key: SafeBrowsingKey }).safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: b.error.issues[0]?.message ?? 'invalid key' });
    const acc = req.user!.accountId;
    const key = b.data.safe_browsing_key;
    await pool.query(
      `INSERT INTO account_mail (account_id, safe_browsing_key) VALUES ($1, $2)
       ON CONFLICT (account_id) DO UPDATE SET safe_browsing_key = EXCLUDED.safe_browsing_key, updated_at = now()`,
      [acc, key],
    );
    await audit(pool, { accountId: acc, userId: req.user!.id, action: key ? 'domainrep.key_set' : 'domainrep.key_removed', detail: { key: hint(key) }, ip: req.ip });
    let pushed = 0;
    for (const s of await servers(acc)) {
      if (!s.online || versionLess(s.agent_version, SAFE_BROWSING_MIN_AGENT)) continue;
      pushed++;
      void syncMail(pool, hub, s.id).catch(() => undefined);
    }
    return { key_set: key !== '', key_hint: hint(key), pushed };
  });
}
