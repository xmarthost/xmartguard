import crypto from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import { withTx } from '../db.js';
import type { Config } from '../config.js';
import type { AgentHub, MetricsSample } from '../agents/hub.js';
import { audit } from '../auth.js';
import { parseEd25519PublicKey, sha256, verifyEd25519 } from '../security.js';

const uuid = z.string().uuid();

const EnrollBody = z.object({
  token: z.string().min(10).max(100),
  public_key: z.string().min(40).max(64),
  agent_version: z.string().max(50).default(''),
  inventory: z.record(z.string(), z.unknown()).default({}),
});

const UnenrollBody = z.object({
  server_id: uuid,
  ts: z.string().regex(/^\d{1,12}$/),
  signature: z.string().max(200),
});

export function authPayload(nonce: string, serverId: string): string {
  return `xg-auth-v1:${nonce}:${serverId}`;
}

export function unenrollPayload(serverId: string, ts: string): string {
  return `xg-unenroll-v1:${serverId}:${ts}`;
}

function s(v: unknown): string {
  return typeof v === 'string' ? v.slice(0, 255) : '';
}

export function agentRoutes(app: FastifyInstance, pool: Pool, cfg: Config, hub: AgentHub): void {
  app.post(
    '/api/agent/enroll',
    { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const parsed = EnrollBody.safeParse(req.body);
      if (!parsed.success) return reply.code(400).send({ error: 'invalid enrollment request' });
      const body = parsed.data;
      if (!parseEd25519PublicKey(body.public_key)) return reply.code(400).send({ error: 'invalid public key' });
      if (JSON.stringify(body.inventory).length > 64 * 1024) return reply.code(400).send({ error: 'inventory too large' });

      const inv = body.inventory;
      const result = await withTx(pool, async (c) => {
        const { rows } = await c.query(
          `SELECT id, account_id FROM enrollment_tokens
            WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
            FOR UPDATE`,
          [sha256(body.token.trim())],
        );
        const tok = rows[0];
        if (!tok) return null;
        const dup = await c.query('SELECT 1 FROM servers WHERE public_key = $1', [body.public_key]);
        if (dup.rowCount) return 'duplicate' as const;
        const ins = await c.query(
          `INSERT INTO servers (account_id, hostname, public_key, agent_version, inventory, primary_ip,
                                os_name, control_panel, web_server, last_seen_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now()) RETURNING id`,
          [
            tok.account_id, s(inv.hostname), body.public_key, body.agent_version, JSON.stringify(inv),
            s(inv.primary_ip), [s(inv.os_name), s(inv.os_version)].filter(Boolean).join(' '),
            s(inv.control_panel), s(inv.web_server),
          ],
        );
        const serverId: string = ins.rows[0].id;
        await c.query('UPDATE enrollment_tokens SET used_at = now(), server_id = $2 WHERE id = $1', [tok.id, serverId]);
        return { serverId, accountId: tok.account_id as string };
      });
      if (result === null) return reply.code(403).send({ error: 'token is invalid, expired or already used' });
      if (result === 'duplicate') return reply.code(409).send({ error: 'this agent key is already enrolled' });
      await audit(pool, {
        accountId: result.accountId,
        serverId: result.serverId,
        action: 'server.enrolled',
        detail: { hostname: s(inv.hostname), ip: req.ip },
        ip: req.ip,
      });
      req.log.info({ serverId: result.serverId }, 'server enrolled');
      return { server_id: result.serverId };
    },
  );

  app.post(
    '/api/agent/unenroll',
    { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const parsed = UnenrollBody.safeParse(req.body);
      if (!parsed.success) return reply.code(400).send({ error: 'invalid request' });
      const { server_id, ts, signature } = parsed.data;
      if (Math.abs(Date.now() / 1000 - Number(ts)) > 600) return reply.code(400).send({ error: 'stale request' });
      const { rows } = await pool.query("SELECT account_id, public_key FROM servers WHERE id = $1 AND status = 'active'", [server_id]);
      const srv = rows[0];
      if (!srv) return reply.code(404).send({ error: 'unknown server' });
      if (!verifyEd25519(srv.public_key, unenrollPayload(server_id, ts), signature)) {
        return reply.code(401).send({ error: 'bad signature' });
      }
      await pool.query("UPDATE servers SET status = 'revoked', revoked_at = now(), connected = false WHERE id = $1", [server_id]);
      hub.revoke(server_id);
      await audit(pool, { accountId: srv.account_id, serverId: server_id, action: 'server.unenrolled', ip: req.ip });
      return { ok: true };
    },
  );

  // Unknown/revoked servers get a plain HTTP 404 before the upgrade so the
  // agent can tell "removed" apart from a network error.
  app.get(
    '/api/agent/ws',
    {
      websocket: true,
      preValidation: async (req, reply) => {
        const id = (req.query as Record<string, string>).server_id;
        if (!uuid.safeParse(id).success) return reply.code(404).send({ error: 'unknown server' });
        const { rowCount } = await pool.query("SELECT 1 FROM servers WHERE id = $1 AND status = 'active'", [id]);
        if (!rowCount) return reply.code(404).send({ error: 'unknown server' });
      },
    },
    (socket, req) => {
      const serverId = (req.query as Record<string, string>).server_id;
      const nonce = crypto.randomBytes(32).toString('base64');
      const log = req.log.child({ serverId });
      let conn: Awaited<ReturnType<AgentHub['attach']>> | null = null;
      let authed = false;
      // Messages that arrive while auth is being verified are processed in order.
      let chain: Promise<void> = Promise.resolve();

      const authTimer = setTimeout(() => {
        if (!authed) socket.close(4002, 'auth timeout');
      }, 15_000);

      socket.send(JSON.stringify({ type: 'challenge', nonce }));

      socket.on('message', (raw) => {
        chain = chain.then(async () => {
          let msg: Record<string, unknown>;
          try {
            msg = JSON.parse(raw.toString());
          } catch {
            socket.close(4003, 'invalid json');
            return;
          }
          if (!authed) {
            if (msg.type !== 'auth' || msg.server_id !== serverId || typeof msg.signature !== 'string') {
              socket.close(4003, 'expected auth');
              return;
            }
            const { rows } = await pool.query("SELECT public_key FROM servers WHERE id = $1 AND status = 'active'", [serverId]);
            if (!rows[0] || !verifyEd25519(rows[0].public_key, authPayload(nonce, serverId), msg.signature)) {
              socket.send(JSON.stringify({ type: 'error', error: rows[0] ? 'authentication failed' : 'revoked' }));
              socket.close(4004, 'auth failed');
              return;
            }
            authed = true;
            clearTimeout(authTimer);
            conn = await hub.attach(serverId, socket, s(msg.version));
            socket.send(JSON.stringify({ type: 'welcome', config: { metrics_interval: cfg.metricsIntervalSeconds } }));
            log.info('agent connected');
            return;
          }
          if (!conn) return;
          switch (msg.type) {
            case 'inventory':
              if (msg.data && typeof msg.data === 'object') await hub.handleInventory(conn, msg.data as Record<string, unknown>);
              break;
            case 'metrics':
              await hub.handleMetrics(conn, msg.data as MetricsSample);
              break;
            case 'result':
              hub.handleResult(conn, msg as { id?: string; ok?: boolean; data?: unknown; error?: string });
              break;
          }
        }).catch((err) => log.error({ err }, 'agent message handling failed'));
      });

      socket.on('close', () => {
        clearTimeout(authTimer);
        chain = chain.then(async () => {
          if (conn) {
            await hub.detach(conn);
            log.info('agent disconnected');
          }
        }).catch((err) => log.error({ err }, 'detach failed'));
      });
    },
  );
}
