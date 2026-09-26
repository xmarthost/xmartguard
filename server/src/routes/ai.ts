import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import { audit, requireRole } from '../auth.js';
import { sha256 } from '../security.js';
import { verifyAgent } from '../agent-sign.js';
import { TRAIN_MIN_PER_CLASS, type AIGateway } from '../ai/gateway.js';
import { PRESETS, complete, listModels, preset } from '../ai/providers.js';

/**
 * AI scanner settings (one set of AI API keys for all servers of the
 * account) and the gateway agents call.
 */

/** Old (0.5) agents sign `xg-ai-v1:<server>:<ts>:<sha256(system+"\n"+prompt)>`. */
export function aiPayload(serverId: string, ts: string, system: string, prompt: string): string {
  return `xg-ai-v1:${serverId}:${ts}:${sha256(system + '\n' + prompt)}`;
}

/** 0.6+ agents sign `xg-ai-v2:<server>:<ts>:<sha256(payload)>`. */
export function aiPayloadV2(serverId: string, ts: string, payload: string): string {
  return `xg-ai-v2:${serverId}:${ts}:${sha256(payload)}`;
}

const MASK = '********';
const mask = (k: string) => (k ? MASK + k.slice(-4) : '');

const ProviderBody = z.object({
  kind: z.string().refine((k) => Boolean(preset(k)), 'unknown provider'),
  name: z.string().max(80).optional(),
  base_url: z.string().url().max(300).optional(),
  api_key: z.string().max(400).optional(),
  model: z.string().min(1).max(200),
  priority: z.number().int().min(1).max(1000).optional(),
  enabled: z.boolean().optional(),
});

const Envelope = z.object({
  server_id: z.string().uuid(),
  ts: z.string().regex(/^\d{1,12}$/),
  signature: z.string().max(200),
  payload: z.string().max(4_000_000),
});

const JudgeBody = z.object({
  scope: z.string().max(20).optional(),
  files: z
    .array(
      z.object({
        id: z.string().max(20),
        sha256: z.string().regex(/^[0-9a-fA-F]{64}$/),
        size: z.number().int().min(0),
        name: z.string().max(300),
        match: z.string().max(200).optional(),
        excerpt: z.string().max(200_000),
        lines: z.number().int().min(0),
        truncated: z.boolean(),
        base: z.string().max(80).optional(),
        z: z.number().optional(),
        features: z.array(z.number().int()).max(40_000).optional(),
      }),
    )
    .min(1)
    .max(20),
});

const SyncBody = z.object({
  cursor: z.number().int().min(0),
  base: z.string().max(80),
  model_version: z.number().int().min(0),
});

const LegacyBody = z.object({
  server_id: z.string().uuid(),
  ts: z.string().regex(/^\d{1,12}$/),
  signature: z.string().max(200),
  system: z.string().max(8_000),
  prompt: z.string().max(300_000),
});

export function aiRoutes(app: FastifyInstance, pool: Pool, gw: AIGateway): void {
  async function agentOf(serverId: string, ts: string, message: string, signature: string, reply: FastifyReply) {
    return (await verifyAgent(pool, serverId, ts, message, signature, reply))?.accountId ?? null;
  }

  // ---------------------------------------------------------------- settings

  app.get('/api/ai/presets', { preHandler: requireRole('viewer') }, async () => ({ presets: PRESETS }));

  app.get('/api/ai/providers', { preHandler: requireRole('viewer') }, async (req) => {
    const { rows } = await pool.query(
      `SELECT id, kind, name, base_url, api_key, model, priority, enabled, cooldown_until, last_error, last_error_at, last_ok_at,
         requests, failures, files, tokens_in, tokens_out, CASE WHEN day = current_date THEN requests_today ELSE 0 END AS requests_today, created_at
       FROM ai_providers WHERE account_id = $1 ORDER BY priority, created_at`,
      [req.user!.accountId],
    );
    return { providers: rows.map((r) => ({ ...r, api_key: mask(r.api_key) })) };
  });

  app.post('/api/ai/providers', { preHandler: requireRole('admin') }, async (req, reply) => {
    const b = ProviderBody.safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: b.error.issues[0]?.message ?? 'invalid provider' });
    const pre = preset(b.data.kind)!;
    const baseUrl = (b.data.base_url ?? pre.baseUrl).replace(/\/+$/, '');
    if (!/^https?:\/\//.test(baseUrl) || baseUrl.includes('ACCOUNT_ID')) return reply.code(400).send({ error: 'set the API address' });
    const { rows } = await pool.query(
      `INSERT INTO ai_providers (account_id, kind, name, base_url, api_key, model, priority, enabled)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [req.user!.accountId, b.data.kind, b.data.name ?? pre.label, baseUrl, b.data.api_key?.trim() ?? '', b.data.model.trim(), b.data.priority ?? 100, b.data.enabled ?? true],
    );
    await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, action: 'ai.provider_add', detail: { kind: b.data.kind, model: b.data.model }, ip: req.ip });
    return { id: rows[0].id };
  });

  app.patch('/api/ai/providers/:id', { preHandler: requireRole('admin') }, async (req, reply) => {
    const id = (req.params as { id: string }).id;
    if (!z.string().uuid().safeParse(id).success) return reply.code(404).send({ error: 'not found' });
    const b = ProviderBody.partial().safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: b.error.issues[0]?.message ?? 'invalid provider' });
    const sets: string[] = [];
    const args: unknown[] = [id, req.user!.accountId];
    const put = (col: string, v: unknown) => {
      args.push(v);
      sets.push(`${col} = $${args.length}`);
    };
    if (b.data.name !== undefined) put('name', b.data.name);
    if (b.data.base_url !== undefined) put('base_url', b.data.base_url.replace(/\/+$/, ''));
    if (b.data.api_key !== undefined && !b.data.api_key.startsWith(MASK)) put('api_key', b.data.api_key.trim());
    if (b.data.model !== undefined) put('model', b.data.model.trim());
    if (b.data.priority !== undefined) put('priority', b.data.priority);
    if (b.data.enabled !== undefined) put('enabled', b.data.enabled);
    // Any change gives a resting key another chance.
    sets.push('cooldown_until = NULL');
    const { rowCount } = await pool.query(`UPDATE ai_providers SET ${sets.join(', ')} WHERE id = $1 AND account_id = $2`, args);
    if (!rowCount) return reply.code(404).send({ error: 'not found' });
    return { ok: true };
  });

  app.delete('/api/ai/providers/:id', { preHandler: requireRole('admin') }, async (req, reply) => {
    const id = (req.params as { id: string }).id;
    if (!z.string().uuid().safeParse(id).success) return reply.code(404).send({ error: 'not found' });
    const { rowCount } = await pool.query('DELETE FROM ai_providers WHERE id = $1 AND account_id = $2', [id, req.user!.accountId]);
    if (!rowCount) return reply.code(404).send({ error: 'not found' });
    await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, action: 'ai.provider_delete', detail: { id }, ip: req.ip });
    return { ok: true };
  });

  /** Fetches the models a key can use (for the model picker). */
  app.post('/api/ai/models', { preHandler: requireRole('admin') }, async (req, reply) => {
    const b = z
      .object({ kind: z.string(), base_url: z.string().max(300).optional(), api_key: z.string().max(400).optional(), provider_id: z.string().uuid().optional() })
      .safeParse(req.body);
    if (!b.success || !preset(b.data.kind)) return reply.code(400).send({ error: 'invalid request' });
    let key = b.data.api_key ?? '';
    let baseUrl = b.data.base_url || preset(b.data.kind)!.baseUrl;
    if (b.data.provider_id && (!key || key.startsWith(MASK))) {
      const { rows } = await pool.query('SELECT api_key, base_url FROM ai_providers WHERE id = $1 AND account_id = $2', [b.data.provider_id, req.user!.accountId]);
      if (!rows[0]) return reply.code(404).send({ error: 'not found' });
      key = rows[0].api_key;
      baseUrl = b.data.base_url || rows[0].base_url;
    }
    try {
      return { models: await listModels({ kind: b.data.kind, base_url: baseUrl, api_key: key, model: '' }) };
    } catch (err) {
      return reply.code(502).send({ error: 'could not fetch models: ' + (err as Error).message });
    }
  });

  /** Sends a tiny test file through one key. */
  app.post('/api/ai/providers/:id/test', { preHandler: requireRole('admin') }, async (req, reply) => {
    const id = (req.params as { id: string }).id;
    if (!z.string().uuid().safeParse(id).success) return reply.code(404).send({ error: 'not found' });
    const { rows } = await pool.query('SELECT id, kind, name, base_url, api_key, model FROM ai_providers WHERE id = $1 AND account_id = $2', [id, req.user!.accountId]);
    if (!rows[0]) return reply.code(404).send({ error: 'not found' });
    const started = Date.now();
    try {
      const r = await complete(rows[0], 'Reply with JSON only: {"ok":true,"verdict":"clean|malicious"}', 'Is this PHP line malicious? 1|echo "hello";', 60, 60_000);
      await pool.query("UPDATE ai_providers SET cooldown_until = NULL, last_error = '', last_ok_at = now() WHERE id = $1", [id]);
      return { ok: true, ms: Date.now() - started, answer: r.text.slice(0, 200), tokens_in: r.tokensIn, tokens_out: r.tokensOut };
    } catch (err) {
      await pool.query('UPDATE ai_providers SET last_error = $2, last_error_at = now() WHERE id = $1', [id, (err as Error).message.slice(0, 500)]);
      return reply.code(502).send({ error: (err as Error).message });
    }
  });

  app.get('/api/ai/status', { preHandler: requireRole('viewer') }, async (req) => {
    const acc = req.user!.accountId;
    const [p, kb, models] = await Promise.all([
      pool.query(
        `SELECT count(*)::int AS total, count(*) FILTER (WHERE enabled)::int AS enabled,
           count(*) FILTER (WHERE enabled AND (cooldown_until IS NULL OR cooldown_until <= now()))::int AS ready,
           coalesce(sum(CASE WHEN day = current_date THEN requests_today ELSE 0 END), 0)::int AS requests_today,
           coalesce(sum(files), 0)::bigint AS files, coalesce(sum(tokens_in + tokens_out), 0)::bigint AS tokens
         FROM ai_providers WHERE account_id = $1`,
        [acc],
      ),
      pool.query(
        `SELECT count(*)::int AS total, count(*) FILTER (WHERE verdict = 'malicious')::int AS malicious,
           count(*) FILTER (WHERE verdict = 'suspicious')::int AS suspicious, count(*) FILTER (WHERE verdict = 'clean')::int AS clean,
           coalesce(sum(hits - 1), 0)::bigint AS reused
         FROM ai_kb`,
      ),
      pool.query('SELECT base_version, version, samples, accuracy, trained_at, jsonb_array_length(entries) AS weights FROM ai_models ORDER BY trained_at DESC LIMIT 3'),
    ]);
    // Engine signatures the AI overruled most (false positives to fix in the rules).
    const overruled = await pool.query(
      `SELECT match, count(*)::int AS files FROM ai_kb WHERE verdict = 'clean' AND match <> '' GROUP BY match ORDER BY files DESC LIMIT 10`,
    );
    const samples = await pool.query(
      'SELECT count(*)::int AS n, count(*) FILTER (WHERE label = 1)::int AS malicious, count(*) FILTER (WHERE label = 0)::int AS clean FROM ai_samples',
    );
    return {
      providers: { ...p.rows[0], files: Number(p.rows[0].files), tokens: Number(p.rows[0].tokens) },
      kb: { ...kb.rows[0], reused: Number(kb.rows[0].reused) },
      samples: samples.rows[0].n,
      samples_malicious: samples.rows[0].malicious,
      samples_clean: samples.rows[0].clean,
      train_min_per_class: TRAIN_MIN_PER_CLASS,
      overruled: overruled.rows,
      models: models.rows,
    };
  });

  // ---------------------------------------------------------------- knowledge base

  app.get('/api/ai/kb', { preHandler: requireRole('viewer') }, async (req) => {
    const q = z
      .object({ verdict: z.string().optional(), q: z.string().max(200).optional(), limit: z.coerce.number().int().min(1).max(200).optional(), offset: z.coerce.number().int().min(0).optional() })
      .parse(req.query);
    const where: string[] = ['1=1'];
    const args: unknown[] = [];
    if (q.verdict) {
      args.push(q.verdict);
      where.push(`k.verdict = $${args.length}`);
    }
    if (q.q) {
      args.push('%' + q.q + '%');
      where.push(`(k.name ILIKE $${args.length} OR k.reason ILIKE $${args.length} OR k.sha256 ILIKE $${args.length} OR k.match ILIKE $${args.length})`);
    }
    const cond = where.join(' AND ');
    const total = await pool.query(`SELECT count(*)::int AS n FROM ai_kb k WHERE ${cond}`, args);
    const { rows } = await pool.query(
      `SELECT k.sha256, k.size, k.verdict, k.confidence, k.reason, k.injected, k.cut, k.model, k.name, k.match, k.hits, k.overridden,
         k.created_at, k.updated_at, s.hostname AS server
       FROM ai_kb k LEFT JOIN servers s ON s.id = k.server_id AND s.account_id = $${args.length + 1}
       WHERE ${cond} ORDER BY k.updated_at DESC LIMIT ${q.limit ?? 50} OFFSET ${q.offset ?? 0}`,
      [...args, req.user!.accountId],
    );
    return { entries: rows.map((r) => ({ ...r, size: Number(r.size) })), total: total.rows[0].n };
  });

  /** An admin corrects the AI (false positive / missed malware); every server gets the fix. */
  app.put('/api/ai/kb/:sha', { preHandler: requireRole('admin') }, async (req, reply) => {
    const sha = (req.params as { sha: string }).sha.toLowerCase();
    const b = z.object({ verdict: z.enum(['malicious', 'clean']), reason: z.string().max(300).optional() }).safeParse(req.body);
    if (!/^[0-9a-f]{64}$/.test(sha) || !b.success) return reply.code(400).send({ error: 'invalid request' });
    const { rowCount } = await pool.query(
      `UPDATE ai_kb SET verdict = $2, confidence = 100, overridden = true, injected = CASE WHEN $2 = 'clean' THEN false ELSE injected END,
         reason = coalesce($3, reason), model = 'admin', updated_at = now(), seq = nextval(pg_get_serial_sequence('ai_kb', 'seq'))
       WHERE sha256 = $1`,
      [sha, b.data.verdict, b.data.reason ? `Marked ${b.data.verdict} by an administrator: ${b.data.reason}` : `Marked ${b.data.verdict} by an administrator.`],
    );
    if (!rowCount) return reply.code(404).send({ error: 'not found' });
    const { rows } = await pool.query('SELECT DISTINCT base_version FROM ai_samples WHERE sha256 = $1', [sha]);
    for (const r of rows) gw.markDirty(r.base_version);
    await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, action: 'ai.kb_override', detail: { sha256: sha, verdict: b.data.verdict }, ip: req.ip });
    return { ok: true };
  });

  app.post('/api/ai/train', { preHandler: requireRole('admin') }, async () => {
    const { rows } = await pool.query('SELECT DISTINCT base_version FROM ai_samples');
    const out = [];
    for (const r of rows) out.push({ base: r.base_version, result: await gw.train(r.base_version) });
    return { trained: out };
  });

  // ---------------------------------------------------------------- agents

  app.post('/api/agent/ai/judge', { bodyLimit: 8 * 1024 * 1024 }, async (req, reply) => {
    const env = Envelope.safeParse(req.body);
    if (!env.success) return reply.code(400).send({ error: 'invalid request' });
    const { server_id, ts, signature, payload } = env.data;
    const account = await agentOf(server_id, ts, aiPayloadV2(server_id, ts, payload), signature, reply);
    if (!account) return;
    let body;
    try {
      body = JudgeBody.parse(JSON.parse(payload));
    } catch {
      return reply.code(400).send({ error: 'invalid payload' });
    }
    return { results: await gw.judge(account, server_id, body.files) };
  });

  app.post('/api/agent/ai/sync', async (req, reply) => {
    const env = Envelope.safeParse(req.body);
    if (!env.success) return reply.code(400).send({ error: 'invalid request' });
    const { server_id, ts, signature, payload } = env.data;
    if (!(await agentOf(server_id, ts, aiPayloadV2(server_id, ts, payload), signature, reply))) return;
    let body;
    try {
      body = SyncBody.parse(JSON.parse(payload));
    } catch {
      return reply.code(400).send({ error: 'invalid payload' });
    }
    return gw.sync(body.base, body.cursor, body.model_version);
  });

  /** 0.5 agents: one file, their own instructions. Answered by the same keys. */
  app.post('/api/agent/ai', { bodyLimit: 400_000 }, async (req, reply) => {
    const b = LegacyBody.safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: 'invalid request' });
    const { server_id, ts, signature, system, prompt } = b.data;
    const account = await agentOf(server_id, ts, aiPayload(server_id, ts, system, prompt), signature, reply);
    if (!account) return;
    try {
      const r = await gw.ask(account, system + '\nReply with JSON only: {"verdict":"malicious|suspicious|clean","confidence":0-100,"reason":"..."}', prompt, 400);
      const text = r.text.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');
      const ans = JSON.parse(text.slice(text.indexOf('{'), text.lastIndexOf('}') + 1));
      if (!['malicious', 'suspicious', 'clean'].includes(ans.verdict)) throw new Error('unexpected answer');
      return {
        verdict: ans.verdict,
        confidence: Math.max(0, Math.min(100, Math.round(Number(ans.confidence) || 0))),
        reason: String(ans.reason ?? '').slice(0, 600),
        model: r.model,
      };
    } catch (err) {
      const e = err as Error & { noKeys?: boolean };
      return reply.code(e.noKeys ? 503 : 502).send({ error: e.message.slice(0, 300) });
    }
  });
}
