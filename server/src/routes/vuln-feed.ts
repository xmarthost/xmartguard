import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import { signedPayload } from '../agent-sign.js';
import { requirePlatform } from '../auth.js';
import type { VulnFeedService } from '../vulnfeed/service.js';

/** Fast plugin vulnerability alerts: the agents' fetch, and the feed's status. */
export function vulnFeedRoutes(app: FastifyInstance, pool: Pool, feed: VulnFeedService): void {
  const Since = z.object({ since: z.number().int().min(-1) });
  app.post('/api/agent/cms/vulns', async (req, reply) => {
    const r = await signedPayload(pool, req.body, Since, reply);
    if (!r) return;
    return feed.since(r.data.since);
  });
  app.get('/api/vuln-feed/status', { preHandler: requirePlatform('viewer') }, async () => {
    const { rows } = await pool.query('SELECT count(*)::int AS n, coalesce(max(seq), 0)::bigint AS seq FROM vuln_feed');
    return { items: rows[0].n, seq: Number(rows[0].seq), synced_at: feed.syncedAt, error: feed.lastError };
  });
}
