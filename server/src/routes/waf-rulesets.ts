import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { AgentHub } from '../agents/hub.js';
import { audit, requireRole } from '../auth.js';
import { signedPayload } from '../agent-sign.js';
import { CRSService, DEFAULT_CONFIG, PRESET_REMOTE, PRESET_VENDORS, RuleSetsConfig, linkedTo, loadConfig, usesMalwareExpert, validateCustomRules } from '../waf/rulesets.js';

/**
 * WAF Rule Sets: one ModSecurity configuration for all servers. Saving it
 * pushes "waf.sync" to every online server; the others pick it up within
 * 15 minutes.
 */
export function wafRulesetRoutes(app: FastifyInstance, pool: Pool, hub: AgentHub, crs: CRSService): void {
  const viewer = { preHandler: requireRole('viewer') };
  const admin = { preHandler: requireRole('admin') };

  /** Asks every online server of the account to apply the rule sets now. */
  async function rollout(accountId: string): Promise<{ pushed: number; offline: number }> {
    const { rows } = await pool.query("SELECT id FROM servers WHERE account_id = $1 AND status = 'active'", [accountId]);
    let pushed = 0;
    for (const r of rows) {
      if (!hub.isOnline(r.id)) continue;
      pushed++;
      void hub.command(r.id, 'waf.sync', {}, 300_000).catch(() => undefined);
    }
    return { pushed, offline: rows.length - pushed };
  }

  app.get('/api/waf/rulesets', viewer, async (req) => {
    const acc = req.user!.accountId;
    const cur = await loadConfig(pool, acc);
    // License keys are secrets: only the last 4 characters are shown.
    cur.config = { ...cur.config, remote: cur.config.remote.map((r) => ({ ...r, key: '********' + r.key.slice(-4) })) };
    const servers = await pool.query(
      `SELECT s.id, s.hostname, s.control_panel, s.web_server, s.agent_version, w.version, w.status, w.updated_at
         FROM servers s LEFT JOIN waf_server_status w ON w.server_id = s.id
        WHERE s.account_id = $1 AND s.status = 'active' ORDER BY s.hostname`,
      [acc],
    );
    return {
      ...cur,
      presets: PRESET_VENDORS,
      remote_presets: PRESET_REMOTE,
      crs: { ...(await crs.status()), resolved: cur.config.crs.enabled ? await crs.resolve(cur.config.crs.version) : null },
      servers: servers.rows.map((r) => ({ ...r, version: r.version == null ? null : Number(r.version), online: hub.isOnline(r.id) })),
    };
  });

  app.put('/api/waf/rulesets', admin, async (req, reply) => {
    const prev = await loadConfig(pool, req.user!.accountId);
    // A masked key ("********1234") means "keep the stored key".
    const body = req.body as { remote?: { id?: string; key?: string }[] } | undefined;
    for (const r of body?.remote ?? []) {
      if (typeof r?.key === 'string' && r.key.startsWith('********')) r.key = prev.config.remote.find((p) => p.id === r.id)?.key ?? '';
    }
    const b = RuleSetsConfig.safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: b.error.issues[0]?.message ?? 'invalid configuration' });
    const c = b.data;
    if (c.custom.enabled) {
      const err = validateCustomRules(c.custom.rules);
      if (err) return reply.code(400).send({ error: err });
    }
    // Feeds can only be linked to this account's servers.
    const own = await pool.query('SELECT id FROM servers WHERE account_id = $1', [req.user!.accountId]);
    const ownIds = new Set(own.rows.map((r) => String(r.id)));
    for (const x of [...c.vendors, ...c.remote]) {
      if (x.servers.some((id) => !ownIds.has(id))) return reply.code(400).send({ error: `${x.name}: linked to an unknown server` });
    }
    const rids = new Set<string>();
    for (const r of c.remote) {
      if (rids.has(r.id)) return reply.code(400).send({ error: `feed id ${r.id} is used twice` });
      rids.add(r.id);
    }
    const ids = new Set<string>();
    for (const v of c.vendors) {
      if (ids.has(v.id)) return reply.code(400).send({ error: `vendor id ${v.id} is used twice` });
      ids.add(v.id);
    }
    // A vendor that is not a known preset can load arbitrary rules on every
    // server: only the account owner may add one.
    const presetIds = new Set<string>(PRESET_VENDORS.filter((p) => p.id !== 'custom').map((p) => p.id));
    const prevUrls = new Set(prev.config.vendors.map((v) => v.url));
    if (req.user!.role !== 'owner' && c.vendors.some((v) => !presetIds.has(v.id) && !prevUrls.has(v.url))) {
      return reply.code(403).send({ error: 'only the account owner can add a custom ModSecurity vendor' });
    }
    // Remote rule feeds also run someone else's rules on every server.
    const prevRemote = new Set(prev.config.remote.map((r) => r.url));
    if (req.user!.role !== 'owner' && c.remote.some((r) => !prevRemote.has(r.url))) {
      return reply.code(403).send({ error: 'only the account owner can add a remote rule feed' });
    }
    const { rows } = await pool.query(
      `INSERT INTO waf_rulesets (account_id, config, version, updated_by) VALUES ($1, $2, 1, $3)
       ON CONFLICT (account_id) DO UPDATE SET config = EXCLUDED.config, version = waf_rulesets.version + 1,
         updated_by = EXCLUDED.updated_by, updated_at = now()
       RETURNING version`,
      [req.user!.accountId, JSON.stringify(c), req.user!.id],
    );
    if (c.crs.enabled && !(await crs.resolve(c.crs.version))) {
      // First use: fetch the release now so servers can install it.
      await crs.fetchRelease(c.crs.version).catch((err) => req.log.warn({ err: (err as Error).message }, 'CRS download failed'));
    }
    await audit(pool, {
      accountId: req.user!.accountId,
      userId: req.user!.id,
      action: 'waf.rulesets_saved',
      detail: {
        version: Number(rows[0].version),
        xmartguard: c.xmartguard.enabled,
        crs: c.crs.enabled ? `${c.crs.version} PL${c.crs.paranoia}` : 'off',
        vendors: c.vendors.map((v) => `${v.id}:${v.enabled ? 'on' : 'off'}${v.servers.length ? `@${v.servers.length} server(s)` : ''}`),
        remote: c.remote.map((r) => `${r.id}:${r.enabled ? 'on' : 'off'}${r.servers.length ? `@${r.servers.length} server(s)` : ''}`),
        custom: c.custom.enabled,
      },
      ip: req.ip,
    });
    return { version: Number(rows[0].version), ...(await rollout(req.user!.accountId)) };
  });

  app.post('/api/waf/rulesets/rollout', admin, async (req) => rollout(req.user!.accountId));

  app.post('/api/waf/crs/sync', admin, async (_req, reply) => {
    try {
      return { ...(await crs.sync()), status: await crs.status() };
    } catch (err) {
      return reply.code(502).send({ error: (err as Error).message });
    }
  });

  // ---- agents

  app.post('/api/agent/waf/config', { bodyLimit: 64 * 1024 }, async (req, reply) => {
    const r = await signedPayload(pool, req.body, z.object({ version: z.number().int().min(0), crs_version: z.string().max(20), crs_enabled: z.boolean().optional(), own_replaced_by: z.string().max(60).optional() }), reply);
    if (!r) return;
    const cur = await loadConfig(pool, r.accountId);
    const c = cur.version ? cur.config : DEFAULT_CONFIG;
    // Malware.Expert replaces the OWASP CRS on the servers that use it.
    const meHere = usesMalwareExpert(c, r.serverId);
    const replaced = c.crs.enabled && meHere;
    const crsOn = c.crs.enabled && !replaced;
    const crsVersion = crsOn ? await crs.resolve(c.crs.version) : null;
    // The agent reports the CRS release it runs ('' = none), so a server
    // that must drop CRS (or pick it up again) is resynced.
    // Older agents only report the release.
    const crsState = r.data.crs_enabled === undefined ? crsOn || r.data.crs_version === '' : r.data.crs_enabled === crsOn;
    const crsCurrent = crsState && (!crsOn || !crsVersion || crsVersion === r.data.crs_version);
    // Malware.Expert also replaces xPGuard's own blocking rules there (two
    // rule sets would handle the same attacks). Agents from 0.11.4 report
    // what they run, so a server whose linking changed is resynced.
    const ownReplacedBy = cur.version && meHere ? 'Malware.Expert' : '';
    const ownCurrent = r.data.own_replaced_by === undefined || r.data.own_replaced_by === ownReplacedBy;
    if (cur.version === r.data.version && crsCurrent && ownCurrent) return { unchanged: true };
    const config = {
      version: cur.version,
      // Unset until the account saves its rule sets, so existing per-server
      // WAF switches are left alone.
      xmartguard: cur.version ? { ...c.xmartguard, replaced_by: ownReplacedBy || undefined } : undefined,
      crs: { ...c.crs, enabled: crsOn, version: crsVersion ?? '', replaced_by: replaced ? 'Malware.Expert' : undefined },
      // Licensed feeds go only to the servers they are linked to.
      vendors: c.vendors.filter((v) => linkedTo(v, r.serverId)).map(({ servers: _s, ...v }) => v),
      remote: c.remote.filter((x) => linkedTo(x, r.serverId)).map(({ servers: _s, ...x }) => x),
      custom: c.custom,
    };
    const out: Record<string, unknown> = { config };
    if (crsOn && crsVersion && crsVersion !== r.data.crs_version) {
      out.crs = { version: crsVersion, files: await crs.files(crsVersion) };
    }
    return out;
  });

  app.post('/api/agent/waf/status', { bodyLimit: 512 * 1024 }, async (req, reply) => {
    const r = await signedPayload(pool, req.body, z.object({ version: z.number().int().min(0) }).passthrough(), reply);
    if (!r) return;
    await pool.query(
      `INSERT INTO waf_server_status (server_id, version, status, updated_at) VALUES ($1, $2, $3, now())
       ON CONFLICT (server_id) DO UPDATE SET version = EXCLUDED.version, status = EXCLUDED.status, updated_at = now()`,
      [r.serverId, r.data.version, JSON.stringify(r.data)],
    );
    return { ok: true };
  });
}
