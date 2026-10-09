import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { AgentHub } from '../agents/hub.js';
import { audit, requirePlatform } from '../auth.js';
import { signedPayload } from '../agent-sign.js';
import { AUTO_REVIEW_FILES, FP_MIN_CONFIDENCE, overridable, overridesBundle, pushOverrides } from '../ai/learning.js';

const Filter = z.object({
  q: z.string().trim().max(200).default(''),
  days: z.coerce.number().int().min(0).max(3650).default(0), // 0 = all time
  signature: z.string().max(200).optional(),
});

function where(f: z.infer<typeof Filter>, args: unknown[]): string {
  const w = ['1=1'];
  if (f.signature) {
    args.push(f.signature);
    w.push(`f.signature = $${args.length}`);
  }
  if (f.days) {
    args.push(f.days);
    w.push(`f.last_at > now() - ($${args.length}::int * interval '1 day')`);
  }
  if (f.q) {
    args.push('%' + f.q + '%');
    const n = `$${args.length}`;
    w.push(`(f.signature ILIKE ${n} OR f.path ILIKE ${n} OR f.name ILIKE ${n} OR f.reason ILIKE ${n} OR f.sha256 ILIKE ${n})`);
  }
  return w.join(' AND ');
}

const SIG_SQL = (cond: string) => `
  SELECT f.signature, count(DISTINCT f.sha256)::int AS files, count(DISTINCT f.server_id)::int AS servers,
         sum(f.count)::int AS events, round(avg(f.confidence))::int AS confidence, max(f.last_at) AS last_at, min(f.first_at) AS first_at,
         o.action, o.auto, o.note, o.updated_at AS decided_at,
         (SELECT count(*)::int FROM ai_kb k WHERE k.match = f.signature AND k.verdict = 'malicious') AS malicious
    FROM ai_fp f LEFT JOIN sig_overrides o ON o.signature = f.signature
   WHERE ${cond}
   GROUP BY f.signature, o.action, o.auto, o.note, o.updated_at`;

function csvCell(v: unknown): string {
  const s = v === null || v === undefined ? '' : v instanceof Date ? v.toISOString() : String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/**
 * AI Learning (master): the scanner's false positives the AI restored,
 * grouped by signature, the decisions that stop them on every server, and
 * a report to export.
 */
export function aiLearningRoutes(app: FastifyInstance, pool: Pool, hub: AgentHub): void {
  app.get('/api/ai/learning', { preHandler: requirePlatform('viewer') }, async (req, reply) => {
    const f = Filter.safeParse(req.query);
    if (!f.success) return reply.code(400).send({ error: 'invalid request' });
    const args: unknown[] = [];
    const cond = where(f.data, args);
    const { rows } = await pool.query(`${SIG_SQL(cond)} ORDER BY count(DISTINCT f.sha256) DESC, max(f.last_at) DESC LIMIT 500`, args);
    const t = (
      await pool.query(
        `SELECT count(DISTINCT f.sha256)::int AS files, count(DISTINCT f.server_id)::int AS servers, coalesce(sum(f.count), 0)::int AS events,
                count(DISTINCT f.signature)::int AS signatures
           FROM ai_fp f WHERE ${cond}`,
        args,
      )
    ).rows[0];
    const d = (await pool.query("SELECT action, count(*)::int AS n FROM sig_overrides GROUP BY action")).rows;
    const decided = Object.fromEntries(d.map((r) => [r.action, r.n]));
    const decisions = (await pool.query('SELECT signature, action, auto, note, created_by, updated_at FROM sig_overrides ORDER BY updated_at DESC')).rows;
    return {
      totals: { ...t, review: decided.review ?? 0, off: decided.off ?? 0, keep: decided.keep ?? 0 },
      signatures: rows.map((r) => ({ ...r, can_override: overridable(r.signature) })),
      decisions,
      rules: { min_confidence: FP_MIN_CONFIDENCE, auto_review_files: AUTO_REVIEW_FILES },
    };
  });

  app.get('/api/ai/learning/files', { preHandler: requirePlatform('viewer') }, async (req, reply) => {
    const p = Filter.extend({
      limit: z.coerce.number().int().min(1).max(200).default(50),
      offset: z.coerce.number().int().min(0).default(0),
    }).safeParse(req.query);
    if (!p.success) return reply.code(400).send({ error: 'invalid request' });
    const args: unknown[] = [];
    const cond = where(p.data, args);
    const total = (await pool.query(`SELECT count(*)::int AS n FROM ai_fp f WHERE ${cond}`, args)).rows[0].n;
    const { rows } = await pool.query(
      `SELECT f.id, f.sha256, f.signature, f.path, f.name, f.size, f.line, f.snippet, f.reason, f.confidence, f.model, f.source,
              f.count, f.first_at, f.last_at, s.hostname AS server, s.id AS server_id
         FROM ai_fp f LEFT JOIN servers s ON s.id = f.server_id
        WHERE ${cond} ORDER BY f.last_at DESC LIMIT ${p.data.limit} OFFSET ${p.data.offset}`,
      args,
    );
    return { total, files: rows.map((r) => ({ ...r, size: Number(r.size), id: Number(r.id) })) };
  });

  // A decision for a signature on every server: review (the AI checks its
  // matches first), off, keep (never relaxed automatically), or none.
  app.put('/api/ai/learning/signature', { preHandler: requirePlatform('admin') }, async (req, reply) => {
    const b = z
      .object({ signature: z.string().trim().min(1).max(200), action: z.enum(['review', 'off', 'keep', 'none']), note: z.string().max(300).default('') })
      .safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: 'invalid request' });
    const { signature, action, note } = b.data;
    if (action !== 'none' && action !== 'keep' && !overridable(signature)) return reply.code(400).send({ error: 'this detection cannot be relaxed' });
    if (action === 'none') await pool.query('DELETE FROM sig_overrides WHERE signature = $1', [signature]);
    else
      await pool.query(
        `INSERT INTO sig_overrides (signature, action, note, auto, created_by) VALUES ($1,$2,$3,false,$4)
         ON CONFLICT (signature) DO UPDATE SET action = excluded.action, note = excluded.note, auto = false, created_by = excluded.created_by, updated_at = now()`,
        [signature, action, note, req.user!.email],
      );
    const pushed = await pushOverrides(pool, hub);
    await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, action: 'ai.signature_decision', detail: { signature, action, note }, ip: req.ip });
    return { ok: true, pushed };
  });

  app.delete('/api/ai/learning', { preHandler: requirePlatform('admin') }, async (req, reply) => {
    const f = Filter.safeParse(req.query);
    if (!f.success) return reply.code(400).send({ error: 'invalid request' });
    const args: unknown[] = [];
    const { rowCount } = await pool.query(`DELETE FROM ai_fp f WHERE ${where(f.data, args)}`, args);
    await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, action: 'ai.learning_cleared', detail: { ...f.data, deleted: rowCount }, ip: req.ip });
    return { deleted: rowCount };
  });

  /**
   * The report to share with the developers: per signature, why the scanner
   * flagged files (signature, matched line and code), why the AI restored
   * them, and how often. Servers are numbered and home folders shortened, so
   * it carries no host or account names.
   */
  app.get('/api/ai/learning/export', { preHandler: requirePlatform('viewer') }, async (req, reply) => {
    const p = Filter.extend({ format: z.enum(['json', 'csv']).default('json'), examples: z.coerce.number().int().min(1).max(200).default(25) }).safeParse(req.query);
    if (!p.success) return reply.code(400).send({ error: 'invalid request' });
    const args: unknown[] = [];
    const cond = where(p.data, args);
    const sigs = (await pool.query(`${SIG_SQL(cond)} ORDER BY count(DISTINCT f.sha256) DESC LIMIT 1000`, args)).rows;
    const { rows: files } = await pool.query(
      `SELECT * FROM (
         SELECT f.*, row_number() OVER (PARTITION BY f.signature ORDER BY f.count DESC, f.last_at DESC) AS rn
           FROM ai_fp f WHERE ${cond}) x
        WHERE rn <= ${p.data.examples} ORDER BY signature, rn`,
      args,
    );
    const label = new Map<string, string>();
    const server = (id: string | null) => {
      if (!id) return '';
      if (!label.has(id)) label.set(id, `server-${label.size + 1}`);
      return label.get(id)!;
    };
    const stamp = new Date().toISOString().slice(0, 10);
    if (p.data.format === 'csv') {
      const head = ['signature', 'decision', 'path', 'name', 'size', 'sha256', 'line', 'matched_code', 'ai_reason', 'ai_confidence', 'ai_model', 'source', 'server', 'times_seen', 'first_seen', 'last_seen'];
      const dec = new Map(sigs.map((s) => [s.signature, s.action ?? '']));
      const lines = [head.join(',')];
      for (const f of files) {
        lines.push(
          [f.signature, dec.get(f.signature), f.path, f.name, Number(f.size), f.sha256, f.line, f.snippet, f.reason, f.confidence, f.model, f.source, server(f.server_id), f.count, f.first_at, f.last_at]
            .map(csvCell)
            .join(','),
        );
      }
      reply.header('content-type', 'text/csv; charset=utf-8');
      reply.header('content-disposition', `attachment; filename="xpguard-false-positives-${stamp}.csv"`);
      return lines.join('\n') + '\n';
    }
    const bySig = new Map<string, unknown[]>();
    for (const f of files) {
      const list = bySig.get(f.signature) ?? [];
      list.push({
        path: f.path,
        name: f.name,
        size: Number(f.size),
        sha256: f.sha256,
        line: f.line || null,
        matched_code: f.snippet || null,
        ai_reason: f.reason,
        ai_confidence: f.confidence,
        ai_model: f.model,
        source: f.source,
        server: server(f.server_id),
        times_seen: f.count,
        first_seen: f.first_at,
        last_seen: f.last_at,
      });
      bySig.set(f.signature, list);
    }
    const report = {
      report: 'xPGuard scanner false positives (files the AI restored)',
      generated_at: new Date().toISOString(),
      filter: { days: p.data.days || 'all', q: p.data.q || null, signature: p.data.signature ?? null },
      how_to_read:
        'Each signature lists files it flagged that the AI then found clean (confidence >= ' +
        FP_MIN_CONFIDENCE +
        '). matched_code is the code around the line the signature matched (empty for heuristic and hash signatures). ' +
        'malicious_verdicts counts files with this signature the AI found malicious; above 0 the signature also catches real malware and needs narrowing, not removal.',
      signatures: sigs.map((s) => ({
        signature: s.signature,
        decision: s.action ?? 'none',
        decided_automatically: !!s.auto,
        clean_files: s.files,
        servers: s.servers,
        times_flagged: s.events,
        malicious_verdicts: s.malicious,
        avg_ai_confidence: s.confidence,
        first_seen: s.first_at,
        last_seen: s.last_at,
        examples: bySig.get(s.signature) ?? [],
      })),
    };
    reply.header('content-type', 'application/json; charset=utf-8');
    reply.header('content-disposition', `attachment; filename="xpguard-false-positives-${stamp}.json"`);
    return JSON.stringify(report, null, 2);
  });

  // Agents fetch the signature decisions (servers that were offline).
  app.post('/api/agent/scanner/overrides', { bodyLimit: 16 * 1024 }, async (req, reply) => {
    const r = await signedPayload(pool, req.body, z.object({ etag: z.string().max(80) }), reply);
    if (!r) return;
    const b = await overridesBundle(pool);
    if (r.data.etag === b.etag) return { etag: b.etag, unchanged: true };
    return b;
  });
}
