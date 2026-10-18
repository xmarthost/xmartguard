import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { AgentHub } from '../agents/hub.js';
import { audit, requirePlatform } from '../auth.js';
import { masterAccount, scopeAccounts } from '../tenancy.js';
import { signedPayload } from '../agent-sign.js';
import { FIRST_REVIEWED_PATCH, PATCHES, intelFor, learnedNames, loadIntelConfig, nameOK, type IntelConfig } from '../waf/intel.js';

/** WAF fleet intelligence (Overview » WAF Intelligence) and its agent API. */
export function wafIntelRoutes(app: FastifyInstance, pool: Pool, hub: AgentHub): void {
  const viewer = { preHandler: requirePlatform('viewer') };
  const admin = { preHandler: requirePlatform('admin') };

  /** Sends the account's intelligence to its online servers. */
  async function push(accountId: string) {
    const intel = await intelFor(pool, accountId);
    const { rows } = await pool.query("SELECT id FROM servers WHERE account_id = ANY($1::uuid[]) AND status = 'active'", [await scopeAccounts(pool, accountId)]);
    let pushed = 0;
    for (const r of rows) {
      const id = String(r.id);
      if (!hub.isOnline(id)) continue;
      pushed++;
      void hub.command(id, 'waf.intel', intel, 120_000).catch(() => undefined);
    }
    return { pushed, names: intel.names.length, patches: intel.patches.length };
  }

  app.get('/api/waf/intel', viewer, async (req) => {
    const acc = req.user!.accountId;
    const cfg = await loadIntelConfig(pool, acc);
    const names = await learnedNames(pool, acc, cfg);
    const intel = await intelFor(pool, acc);
    return {
      config: cfg,
      names,
      patches: PATCHES.map((p) => ({ ...p, enabled: cfg.enabled && !cfg.disabled_patches.includes(p.id) })),
      active: { names: intel.names.length, patches: intel.patches.length },
    };
  });

  const Config = z.object({
    enabled: z.boolean(),
    min_servers: z.number().int().min(1).max(50),
    disabled_patches: z.array(z.number().int().min(7703000).max(7703999)).max(500),
  });
  app.put('/api/waf/intel/config', admin, async (req, reply) => {
    const b = Config.safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: b.error.issues[0]?.message ?? 'invalid settings' });
    const acc = req.user!.accountId;
    const c: IntelConfig = b.data;
    await pool.query(
      `INSERT INTO waf_intel_config (account_id, config) VALUES ($1, $2)
       ON CONFLICT (account_id) DO UPDATE SET config = EXCLUDED.config, updated_at = now()`,
      [acc, JSON.stringify(c)],
    );
    await audit(pool, { accountId: acc, userId: req.user!.id, action: 'waf.intel.config', detail: c, ip: req.ip });
    return push(acc);
  });

  // Approve, ignore or add a name ('' removes the administrator's decision).
  const Name = z.object({ name: z.string().trim().toLowerCase().max(80), status: z.enum(['approved', 'ignored', 'added', '']) });
  app.post('/api/waf/intel/names', admin, async (req, reply) => {
    const b = Name.safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: 'invalid name' });
    const { name, status } = b.data;
    if (status !== '' && status !== 'ignored' && !nameOK(name)) {
      return reply.code(400).send({ error: `${name} cannot be blocked by name: use a PHP file name that legitimate software does not use (index.php, config.php and similar are never blocked).` });
    }
    const acc = req.user!.accountId;
    if (status === '') {
      await pool.query('DELETE FROM waf_name_overrides WHERE account_id = $1 AND name = $2', [acc, name]);
    } else {
      await pool.query(
        `INSERT INTO waf_name_overrides (account_id, name, status) VALUES ($1, $2, $3)
         ON CONFLICT (account_id, name) DO UPDATE SET status = EXCLUDED.status, updated_at = now()`,
        [acc, name, status],
      );
    }
    await audit(pool, { accountId: acc, userId: req.user!.id, action: 'waf.intel.name', detail: { name, status: status || 'reset' }, ip: req.ip });
    return push(acc);
  });

  // ---- Rule approvals: new rules only log ("watch") until approved here.
  interface WatchEvent { at: number; ip: string; method: string; host: string; uri: string; action: string; detail: string }
  interface WatchRule { id: number; title: string; since: string; watching: boolean; hits: number; ips: number; hosts: number; examples: WatchEvent[] | null }
  app.get('/api/waf/approvals', viewer, async (req) => {
    const hours = Math.min(336, Math.max(1, Number((req.query as { hours?: string }).hours) || 48));
    const acc = await masterAccount(pool, req.user!.accountId);
    const { rows: servers } = await pool.query<{ id: string; hostname: string }>(
      "SELECT id, hostname FROM servers WHERE account_id = ANY($1::uuid[]) AND status = 'active' ORDER BY hostname",
      [await scopeAccounts(pool, acc)],
    );
    const { rows: dec } = await pool.query<{ rule_id: number; status: string; updated_at: Date }>('SELECT rule_id, status, updated_at FROM waf_rule_decisions WHERE account_id = $1', [acc]);
    const decided = new Map(dec.map((d) => [d.rule_id, d]));
    const rules = new Map<number, { id: number; title: string; since: string; servers: number; watching: number; hits: number; ips: number; sites: number; hit_servers: number; examples: (WatchEvent & { server: string })[] }>();
    const add = (r: Omit<WatchRule, 'examples' | 'watching' | 'hits' | 'ips' | 'hosts'>) => {
      let x = rules.get(r.id);
      if (!x) rules.set(r.id, (x = { id: r.id, title: r.title, since: r.since, servers: 0, watching: 0, hits: 0, ips: 0, sites: 0, hit_servers: 0, examples: [] }));
      return x;
    };
    // Patches under review are listed even before a server reports them.
    for (const p of PATCHES) if (p.id >= FIRST_REVIEWED_PATCH) add({ id: p.id, title: `Portal patch: ${p.title}`, since: 'portal' });
    let asked = 0;
    let answered = 0;
    const online = servers.filter((s) => hub.isOnline(String(s.id)));
    let next = 0;
    const worker = async () => {
      for (;;) {
        const srv = online[next++];
        if (!srv) return;
        asked++;
        try {
          const res = (await hub.command(String(srv.id), 'waf.watch_report', { hours }, 30_000)) as { rules: WatchRule[] | null };
          answered++;
          for (const r of res.rules ?? []) {
            const x = add(r);
            x.servers++;
            if (r.watching) x.watching++;
            x.hits += r.hits;
            x.ips += r.ips;
            x.sites += r.hosts;
            if (r.hits) x.hit_servers++;
            for (const e of r.examples ?? []) if (x.examples.length < 40) x.examples.push({ ...e, server: srv.hostname });
          }
        } catch {
          /* older agent or offline: not counted */
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(10, online.length) }, worker));
    const out = [...rules.values()]
      .map((r) => ({ ...r, decision: decided.get(r.id)?.status ?? null, decided_at: decided.get(r.id)?.updated_at ?? null }))
      .sort((a, b) => a.id - b.id);
    return { hours, servers: servers.length, asked, answered, rules: out };
  });

  const Decision = z.object({ rule_id: z.number().int().min(7700000).max(7709999), status: z.enum(['enforce', 'watch']) });
  app.post('/api/waf/approvals', admin, async (req, reply) => {
    const b = Decision.safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: 'invalid decision' });
    const acc = await masterAccount(pool, req.user!.accountId);
    await pool.query(
      `INSERT INTO waf_rule_decisions (account_id, rule_id, status, decided_by) VALUES ($1, $2, $3, $4)
       ON CONFLICT (account_id, rule_id) DO UPDATE SET status = EXCLUDED.status, decided_by = EXCLUDED.decided_by, updated_at = now()`,
      [acc, b.data.rule_id, b.data.status, req.user!.id],
    );
    await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, action: 'waf.rule_decision', detail: b.data, ip: req.ip });
    return push(acc);
  });

  // ---- agents: report names found and fetch the intelligence.
  const Report = z.object({
    etag: z.string().max(80),
    reports: z
      .array(
        z.object({
          name: z.string().max(80),
          tail: z.string().max(200).default(''),
          signature: z.string().max(120).default(''),
          clean: z.boolean().optional(),
        }),
      )
      .max(1000)
      .default([]),
  });
  app.post('/api/agent/waf/intel', { bodyLimit: 512 * 1024 }, async (req, reply) => {
    const r = await signedPayload(pool, req.body, Report, reply);
    if (!r) return;
    // Names are learned from every customer's servers, under the platform account.
    r.accountId = await masterAccount(pool, r.accountId);
    const before = r.data.reports.length ? (await intelFor(pool, r.accountId)).etag : '';
    for (const x of r.data.reports) {
      const name = x.name.toLowerCase();
      if (!/^[a-z0-9][a-z0-9._-]{0,78}\.(?:php[0-9]?|phtml|phar|pht)$/.test(name)) continue;
      await pool.query(
        `INSERT INTO waf_name_reports (account_id, server_id, name, clean, tail, signature) VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (account_id, server_id, name, clean) DO UPDATE
           SET reports = waf_name_reports.reports + 1, last_seen = now(), tail = EXCLUDED.tail, signature = EXCLUDED.signature`,
        [r.accountId, r.serverId, name, Boolean(x.clean), x.tail.replace(/[^\x20-\x7e]/g, ''), x.signature.replace(/[^\x20-\x7e]/g, '')],
      );
    }
    const intel = await intelFor(pool, r.accountId);
    // A name reached the threshold: the other servers get it now.
    if (before && before !== intel.etag) void push(r.accountId).catch(() => undefined);
    if (intel.etag === r.data.etag) return { unchanged: true };
    return { intel };
  });
}
