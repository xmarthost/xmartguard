import type { FastifyReply } from 'fastify';
import { z } from 'zod';
import type { Pool } from './db.js';
import { sha256, verifyEd25519 } from './security.js';

/**
 * Signed agent requests over HTTPS (AI gateway, WordPress core files,
 * signature feeds): {server_id, ts, signature, payload}, where the agent signs
 * `xg-ai-v2:<server_id>:<ts>:<sha256(payload)>` with its identity key.
 */
export const Envelope = z.object({
  server_id: z.string().uuid(),
  ts: z.string().regex(/^\d{1,12}$/),
  signature: z.string().max(200),
  payload: z.string().max(4_000_000),
});

export function envelopeMessage(serverId: string, ts: string, payload: string): string {
  return `xg-ai-v2:${serverId}:${ts}:${sha256(payload)}`;
}

/** Verifies a request signature; replies 401 and returns null when it is not valid. */
export async function verifyAgent(pool: Pool, serverId: string, ts: string, message: string, signature: string, reply: FastifyReply) {
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) {
    reply.code(401).send({ error: 'stale request (check the server clock)' });
    return null;
  }
  const { rows } = await pool.query("SELECT account_id, public_key FROM servers WHERE id = $1 AND status = 'active'", [serverId]);
  if (!rows[0] || !verifyEd25519(rows[0].public_key, message, signature)) {
    reply.code(401).send({ error: 'bad signature' });
    return null;
  }
  return { accountId: rows[0].account_id as string, serverId };
}

/** Parses and verifies an envelope, then its payload with schema. */
export async function signedPayload<T>(pool: Pool, body: unknown, schema: z.ZodType<T>, reply: FastifyReply) {
  const env = Envelope.safeParse(body);
  if (!env.success) {
    reply.code(400).send({ error: 'invalid request' });
    return null;
  }
  const { server_id, ts, signature, payload } = env.data;
  const who = await verifyAgent(pool, server_id, ts, envelopeMessage(server_id, ts, payload), signature, reply);
  if (!who) return null;
  let data: T;
  try {
    data = schema.parse(JSON.parse(payload));
  } catch {
    reply.code(400).send({ error: 'invalid payload' });
    return null;
  }
  return { ...who, data };
}
