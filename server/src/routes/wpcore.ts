import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import { requireRole } from '../auth.js';
import { signedPayload } from '../agent-sign.js';
import type { WPCoreService } from '../wpcore/service.js';
import type { SignatureService } from '../signatures/service.js';

const Version = z.string().regex(/^\d+\.\d+(?:\.\d+)?(?:-(?:beta|RC)\d+)?$/i);

/**
 * Official WordPress core files and public malware signatures for agents
 * (signed requests), plus their status for the portal.
 */
export function wpcoreRoutes(app: FastifyInstance, pool: Pool, wp: WPCoreService, sigs: SignatureService): void {
  app.post('/api/agent/wp-core/set', async (req, reply) => {
    const r = await signedPayload(pool, req.body, z.object({ etag: z.string().max(80) }), reply);
    if (!r) return;
    const list = await wp.list();
    if (list.files === 0) return { etag: '', unchanged: true };
    if (r.data.etag === list.etag) return { etag: list.etag, unchanged: true };
    return { etag: list.etag, versions: list.versions, data: list.data.toString('base64') };
  });

  app.post('/api/agent/wp-core/checksums', async (req, reply) => {
    const r = await signedPayload(pool, req.body, z.object({ version: Version }), reply);
    if (!r) return;
    const sums = await wp.checksums(r.data.version);
    if (!sums) return reply.code(404).send({ error: `no official checksums for WordPress ${r.data.version}` });
    return { checksums: sums };
  });

  app.post('/api/agent/wp-core/file', async (req, reply) => {
    const r = await signedPayload(pool, req.body, z.object({ version: Version, path: z.string().min(1).max(300) }), reply);
    if (!r) return;
    try {
      const body = await wp.file(r.data.version, r.data.path);
      return { content: body.toString('base64') };
    } catch (err) {
      const e = err as Error & { status?: number };
      return reply.code(e.status ?? 502).send({ error: e.message });
    }
  });

  app.post('/api/agent/wp-plugin/checksums', async (req, reply) => {
    const r = await signedPayload(pool, req.body, z.object({ slug: z.string().max(100), version: z.string().max(40) }), reply);
    if (!r) return;
    try {
      const doc = await wp.pluginChecksums(r.data.slug, r.data.version);
      return doc ? { checksums: doc } : { missing: true };
    } catch (err) {
      return reply.code(502).send({ error: (err as Error).message });
    }
  });

  app.post('/api/agent/signatures', { bodyLimit: 64 * 1024 }, async (req, reply) => {
    const r = await signedPayload(pool, req.body, z.object({ etag: z.string().max(80) }), reply);
    if (!r) return;
    const b = await sigs.bundle();
    if (!b.etag || r.data.etag === b.etag) return { etag: b.etag, unchanged: true };
    return { etag: b.etag, ...b.bundle };
  });

  app.get('/api/wp-core/status', { preHandler: requireRole('viewer') }, async () => wp.status());
  app.post('/api/wp-core/sync', { preHandler: requireRole('admin') }, async (_req, reply) => {
    try {
      return { ...(await wp.sync()), status: await wp.status() };
    } catch (err) {
      return reply.code(502).send({ error: (err as Error).message });
    }
  });
  app.get('/api/signatures/status', { preHandler: requireRole('viewer') }, async () => sigs.status());
  app.post('/api/signatures/sync', { preHandler: requireRole('admin') }, async () => ({ results: await sigs.sync(), status: await sigs.status() }));
}
