import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';
import { requireRole } from '../auth.js';
import { sha256, verifyEd25519 } from '../security.js';

/**
 * The portal's AI gateway: agents send the code of suspicious files, signed
 * with their identity key, and the portal asks a free, self-hosted Ollama
 * model (OLLAMA_URL/OLLAMA_MODEL) for a verdict. Ollama never has to be
 * reachable from the internet; only the portal talks to it.
 */

export function aiPayload(serverId: string, ts: string, system: string, prompt: string): string {
  return `xg-ai-v1:${serverId}:${ts}:${sha256(system + '\n' + prompt)}`;
}

const Body = z.object({
  server_id: z.string().uuid(),
  ts: z.string().regex(/^\d{1,12}$/),
  signature: z.string().max(200),
  system: z.string().max(8_000),
  prompt: z.string().max(300_000),
});

const schema = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: ['malicious', 'suspicious', 'clean'] },
    confidence: { type: 'integer' },
    reason: { type: 'string' },
  },
  required: ['verdict', 'confidence', 'reason'],
};

/** Limits concurrent model calls; a CPU-only model handles one file at a time best. */
class Gate {
  private active = 0;
  private waiters: (() => void)[] = [];
  constructor(private max: number, private queue: number) {}
  async run<T>(fn: () => Promise<T>): Promise<T> {
    if (this.active >= this.max) {
      if (this.waiters.length >= this.queue) throw new Error('busy');
      await new Promise<void>((r) => this.waiters.push(r));
    }
    this.active++;
    try {
      return await fn();
    } finally {
      this.active--;
      this.waiters.shift()?.();
    }
  }
}

export function aiRoutes(app: FastifyInstance, pool: Pool, cfg: Config): void {
  const gate = new Gate(cfg.aiConcurrency, 50);
  const enabled = () => Boolean(cfg.ollamaUrl && cfg.ollamaModel);

  async function ollama(path: string, body?: unknown, timeoutMs = 10_000): Promise<any> {
    const res = await fetch(cfg.ollamaUrl + path, {
      method: body ? 'POST' : 'GET',
      headers: body ? { 'content-type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`Ollama HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return res.json();
  }

  /** What the Settings page shows for the "XMart Guard AI server" provider. */
  app.get('/api/ai/status', { preHandler: requireRole('viewer') }, async () => {
    if (!enabled()) return { enabled: false, model: '', reachable: false, installed: false };
    try {
      const tags = await ollama('/api/tags');
      const names: string[] = (tags.models ?? []).map((m: { name: string }) => m.name);
      const installed = names.some((n) => n === cfg.ollamaModel || n === `${cfg.ollamaModel}:latest`);
      return { enabled: true, model: cfg.ollamaModel, reachable: true, installed };
    } catch {
      return { enabled: true, model: cfg.ollamaModel, reachable: false, installed: false };
    }
  });

  app.post('/api/agent/ai', { bodyLimit: 400_000 }, async (req, reply) => {
    const b = Body.safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: 'invalid request' });
    const { server_id, ts, signature, system, prompt } = b.data;
    if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return reply.code(401).send({ error: 'stale request' });
    const { rows } = await pool.query("SELECT public_key FROM servers WHERE id = $1 AND status = 'active'", [server_id]);
    if (!rows[0] || !verifyEd25519(rows[0].public_key, aiPayload(server_id, ts, system, prompt), signature)) {
      return reply.code(401).send({ error: 'bad signature' });
    }
    if (!enabled()) return reply.code(503).send({ error: 'no AI model is configured on the portal' });
    try {
      const out = await gate.run(() =>
        ollama(
          '/api/chat',
          {
            model: cfg.ollamaModel,
            stream: false,
            format: schema,
            options: { temperature: 0, num_ctx: 16384 },
            messages: [
              { role: 'system', content: system },
              { role: 'user', content: prompt },
            ],
          },
          cfg.aiTimeoutSeconds * 1000,
        ),
      );
      const ans = JSON.parse(out?.message?.content ?? '{}');
      if (!['malicious', 'suspicious', 'clean'].includes(ans.verdict)) throw new Error('unexpected answer');
      return {
        verdict: ans.verdict,
        confidence: Math.max(0, Math.min(100, Math.round(Number(ans.confidence) || 0))),
        reason: String(ans.reason ?? '').slice(0, 600),
        model: cfg.ollamaModel,
      };
    } catch (err) {
      const msg = (err as Error).message;
      if (msg === 'busy') return reply.code(429).send({ error: 'AI server busy; try again later' });
      req.log.warn({ err: msg }, 'AI request failed');
      return reply.code(502).send({ error: 'AI model failed: ' + msg.slice(0, 200) });
    }
  });
}
