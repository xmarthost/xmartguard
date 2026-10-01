import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { AgentHub } from '../agents/hub.js';
import { audit, requireRole } from '../auth.js';
import { versionLess } from '../agents/release.js';

/** Agents that take the account's mail settings (mail.global). */
export const MAIL_MIN_AGENT = '0.19.2';

const DQSKey = z.string().trim().regex(/^(?:[A-Za-z0-9]{20,40})?$/, 'A Spamhaus DQS key is 20-40 letters and digits');

export async function loadDQSKey(pool: Pool, accountId: string): Promise<string> {
  const { rows } = await pool.query('SELECT dqs_key FROM account_mail WHERE account_id = $1', [accountId]);
  return String(rows[0]?.dqs_key ?? '');
}

/** Sends one server its account's mail settings. */
export async function syncMail(pool: Pool, hub: AgentHub, serverId: string): Promise<void> {
  const { rows } = await pool.query("SELECT account_id FROM servers WHERE id = $1 AND status = 'active'", [serverId]);
  if (!rows[0]) return;
  await hub.command(serverId, 'mail.global', { dqs_key: await loadDQSKey(pool, rows[0].account_id) }, 60_000);
}

/** The key is a secret: only its ends are shown. */
function hint(k: string): string {
  return k ? `${k.slice(0, 4)}…${k.slice(-3)}` : '';
}

/**
 * Mail protection for all servers (Overview » Mail Protection): one Spamhaus
 * DQS key for every server's Exim, and each server's blocklist and
 * phishing-filter state, so it shows whether the key works.
 */
export function mailRoutes(app: FastifyInstance, pool: Pool, hub: AgentHub): void {
  const viewer = { preHandler: requireRole('viewer') };
  const admin = { preHandler: requireRole('admin') };

  async function servers(accountId: string) {
    const { rows } = await pool.query(
      "SELECT id, hostname, agent_version FROM servers WHERE account_id = $1 AND status = 'active' ORDER BY hostname",
      [accountId],
    );
    return rows.map((r) => ({ id: String(r.id), hostname: String(r.hostname), agent_version: String(r.agent_version ?? ''), online: hub.isOnline(r.id) }));
  }

  /** Each server's Exim state, asked in batches of 10. */
  async function states(accountId: string, action: 'exim.rbls' | 'exim.guard') {
    const list = await servers(accountId);
    const out: Record<string, unknown>[] = [];
    for (let i = 0; i < list.length; i += 10) {
      out.push(
        ...(await Promise.all(
          list.slice(i, i + 10).map(async (s) => {
            if (!s.online) return { ...s, state: null, error: 'offline' };
            if (versionLess(s.agent_version, MAIL_MIN_AGENT)) return { ...s, state: null, error: `agent ${s.agent_version} is too old (update to ${MAIL_MIN_AGENT} or later)` };
            try {
              const r = (await hub.command(s.id, action, {}, action === 'exim.guard' ? 120_000 : 15_000)) as { guard?: unknown; rbls?: unknown };
              return { ...s, state: r?.guard ?? null, cpanel: Array.isArray(r?.rbls) && r.rbls.length > 0, error: '' };
            } catch (err) {
              return { ...s, state: null, error: (err as Error).message };
            }
          }),
        )),
      );
    }
    return out;
  }

  app.get('/api/mail-protection', viewer, async (req) => {
    const acc = req.user!.accountId;
    const key = await loadDQSKey(pool, acc);
    return { dqs_key_set: key !== '', dqs_key_hint: hint(key), servers: await states(acc, 'exim.rbls') };
  });

  app.put('/api/mail-protection', admin, async (req, reply) => {
    const b = z.object({ dqs_key: DQSKey }).safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: b.error.issues[0]?.message ?? 'invalid key' });
    const acc = req.user!.accountId;
    const key = b.data.dqs_key;
    await pool.query(
      `INSERT INTO account_mail (account_id, dqs_key) VALUES ($1, $2)
       ON CONFLICT (account_id) DO UPDATE SET dqs_key = EXCLUDED.dqs_key, updated_at = now()`,
      [acc, key],
    );
    await audit(pool, { accountId: acc, userId: req.user!.id, action: key ? 'mail.dqs_key_set' : 'mail.dqs_key_removed', detail: { key: hint(key) }, ip: req.ip });
    let pushed = 0;
    for (const s of await servers(acc)) {
      if (!s.online || versionLess(s.agent_version, MAIL_MIN_AGENT)) continue;
      pushed++;
      void hub.command(s.id, 'mail.global', { dqs_key: key }, 60_000).catch(() => undefined);
    }
    return { dqs_key_set: key !== '', dqs_key_hint: hint(key), pushed };
  });

  // Check every server now (the agents test the blocklists again).
  app.post('/api/mail-protection/check', admin, async (req) => ({ servers: await states(req.user!.accountId, 'exim.guard') }));
}
