import crypto from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';
import { signedPayload } from '../agent-sign.js';
import { audit, requirePlatform } from '../auth.js';
import type { VulnFeedService } from '../vulnfeed/service.js';

const hint = (k: string) => (k ? `${k.slice(0, 4)}…${k.slice(-4)}` : '');

/** Hex HMAC-SHA256 of the raw body (Wordfence's X-Wordfence-Signature). */
export function webhookSignature(secret: string, body: string): string {
  return crypto.createHmac('sha256', secret).update(body).digest('hex');
}

function sameSig(a: string, b: string): boolean {
  const x = Buffer.from(a.trim().toLowerCase().replace(/^sha256=/, ''));
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

/**
 * Fast plugin vulnerability alerts (Master » Plugin Vulnerabilities): the
 * operator's Wordfence API key and webhook, their tests, the agents' fetch.
 */
export function vulnFeedRoutes(app: FastifyInstance, pool: Pool, cfg: Config, feed: VulnFeedService): void {
  const admin = { preHandler: requirePlatform('admin') };
  const hookPath = '/api/hooks/wordfence';

  const Since = z.object({ since: z.number().int().min(-1) });
  app.post('/api/agent/cms/vulns', async (req, reply) => {
    const r = await signedPayload(pool, req.body, Since, reply);
    if (!r) return;
    return feed.since(r.data.since);
  });

  const state = async () => {
    const c = await feed.config();
    const { rows } = await pool.query('SELECT count(*)::int AS n, count(*) FILTER (WHERE seq > 0)::int AS sent FROM vuln_feed');
    return {
      key_set: c.api_key !== '',
      key_hint: hint(c.api_key),
      secret_set: c.webhook_secret !== '',
      webhook_url: cfg.publicUrl + hookPath,
      every_hours: cfg.vulnFeedHours,
      items: rows[0].n,
      sent: rows[0].sent,
      last_sync_at: c.last_sync_at,
      last_changed: c.last_changed,
      last_error: c.last_error,
      last_webhook_at: c.last_webhook_at,
      last_webhook_ok: c.last_webhook_ok,
    };
  };

  app.get('/api/vuln-feed', admin, async () => state());

  const Key = z.string().trim().regex(/^[A-Za-z0-9._~+/=-]{20,300}$/, 'that does not look like a Wordfence API key');
  const Secret = z.string().trim().min(32, 'use a secret of at least 32 characters').max(200);
  app.put('/api/vuln-feed', admin, async (req, reply) => {
    const b = z.object({ api_key: z.union([Key, z.literal('')]).optional(), webhook_secret: z.union([Secret, z.literal('')]).optional() }).safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: b.error.issues[0]?.message ?? 'invalid request' });
    if (b.data.api_key) {
      // A new key is saved only once Wordfence accepts it.
      const t = await feed.testKey(b.data.api_key);
      if (!t.ok) return reply.code(400).send({ error: t.error });
    }
    await pool.query(
      `INSERT INTO vuln_feed_config (id, api_key, webhook_secret) VALUES (1, coalesce($1, ''), coalesce($2, ''))
       ON CONFLICT (id) DO UPDATE SET api_key = coalesce($1, vuln_feed_config.api_key),
         webhook_secret = coalesce($2, vuln_feed_config.webhook_secret), updated_at = now()`,
      [b.data.api_key ?? null, b.data.webhook_secret ?? null],
    );
    await audit(pool, {
      accountId: req.user!.accountId,
      userId: req.user!.id,
      action: 'vulnfeed.config',
      detail: {
        key: b.data.api_key === undefined ? 'kept' : b.data.api_key ? 'set' : 'removed',
        secret: b.data.webhook_secret === undefined ? 'kept' : b.data.webhook_secret ? 'set' : 'removed',
      },
      ip: req.ip,
    });
    if (b.data.api_key) void feed.sync().catch(() => undefined); // first download in the background
    return state();
  });

  /** Tests a key (the one typed, else the saved one) without saving it. */
  app.post('/api/vuln-feed/test', admin, async (req, reply) => {
    const b = z.object({ api_key: z.union([Key, z.literal('')]).default('') }).safeParse(req.body ?? {});
    if (!b.success) return reply.code(400).send({ error: b.error.issues[0]?.message ?? 'invalid request' });
    const key = b.data.api_key || (await feed.config()).api_key;
    if (!key) return reply.code(400).send({ error: 'enter an API key first' });
    return feed.testKey(key);
  });

  /** Reads the feed now. */
  app.post('/api/vuln-feed/sync', admin, async (_req, reply) => {
    if (!(await feed.config()).api_key) return reply.code(400).send({ error: 'save an API key first' });
    try {
      const changed = await feed.sync();
      return { ok: true, changed };
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
  });

  /**
   * Tests the webhook end to end: a signed sample delivery (no
   * vulnerabilities) sent to the public webhook address, as Wordfence would.
   */
  app.post('/api/vuln-feed/webhook-test', admin, async () => {
    const { webhook_secret } = await feed.config();
    if (!webhook_secret) return { ok: false, error: 'save a webhook secret first' };
    const body = JSON.stringify({ vulnerabilities: { created: [], replaced: [], deleted: [] }, test: true });
    try {
      const r = await fetch(cfg.publicUrl + hookPath, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-wordfence-signature': webhookSignature(webhook_secret, body) },
        body,
        signal: AbortSignal.timeout(20_000),
      });
      if (r.ok) return { ok: true };
      return { ok: false, error: `the webhook address answered HTTP ${r.status}` };
    } catch (err) {
      return { ok: false, error: `the webhook address is not reachable: ${(err as Error).message}` };
    }
  });

  // Wordfence's deliveries: the raw body is needed for the signature.
  void app.register(async (sub) => {
    sub.addContentTypeParser('application/json', { parseAs: 'string', bodyLimit: 20 * 1024 * 1024 }, (_req, body, done) => done(null, body));
    sub.post(hookPath, async (req, reply) => {
      const raw = typeof req.body === 'string' ? req.body : '';
      const { webhook_secret } = await feed.config();
      if (!webhook_secret) return reply.code(503).send({ error: 'webhook not set up' });
      const sig = String(req.headers['x-wordfence-signature'] ?? req.headers['x-signature'] ?? '');
      const ok = sig !== '' && sameSig(sig, webhookSignature(webhook_secret, raw));
      await pool.query(
        `INSERT INTO vuln_feed_config (id, last_webhook_at, last_webhook_ok) VALUES (1, now(), $1)
         ON CONFLICT (id) DO UPDATE SET last_webhook_at = now(), last_webhook_ok = $1`,
        [ok],
      );
      if (!ok) return reply.code(401).send({ error: 'bad signature' });
      let body: unknown;
      try {
        body = JSON.parse(raw);
      } catch {
        return reply.code(400).send({ error: 'invalid JSON' });
      }
      const changed = await feed.applyWebhook(body);
      return { ok: true, changed };
    });
  });
}
