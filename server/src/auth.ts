import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { Pool } from './db.js';
import { randomToken, sha256 } from './security.js';
import type { Config } from './config.js';

export type Role = 'owner' | 'admin' | 'operator' | 'viewer';

export interface SessionUser {
  id: string;
  accountId: string;
  email: string;
  name: string;
  role: Role;
}

declare module 'fastify' {
  interface FastifyRequest {
    user: SessionUser | null;
  }
}

export const SESSION_COOKIE = 'xg_session';

const RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2, owner: 3 };

export function hasRole(user: SessionUser, min: Role): boolean {
  return RANK[user.role] >= RANK[min];
}

export async function createSession(pool: Pool, cfg: Config, userId: string, req: FastifyRequest): Promise<string> {
  const token = randomToken();
  await pool.query(
    `INSERT INTO sessions (id, user_id, expires_at, ip, user_agent)
     VALUES ($1, $2, now() + make_interval(hours => $3), $4, $5)`,
    [sha256(token), userId, cfg.sessionTtlHours, req.ip, String(req.headers['user-agent'] || '').slice(0, 300)],
  );
  return token;
}

export async function destroySession(pool: Pool, token: string | undefined): Promise<void> {
  if (token) await pool.query('DELETE FROM sessions WHERE id = $1', [sha256(token)]);
}

/** Resolves request.user from the session cookie on every request. */
export function registerAuth(app: FastifyInstance, pool: Pool): void {
  app.decorateRequest('user', null);
  app.addHook('onRequest', async (req) => {
    const token = req.cookies[SESSION_COOKIE];
    if (!token) return;
    const { rows } = await pool.query(
      `SELECT u.id, u.account_id, u.email, u.name, u.role
         FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.id = $1 AND s.expires_at > now()`,
      [sha256(token)],
    );
    if (rows[0]) {
      const r = rows[0];
      req.user = { id: r.id, accountId: r.account_id, email: r.email, name: r.name, role: r.role };
    }
  });
  // CSRF defence: state-changing browser requests must be JSON (not form-postable
  // cross-site) and, when an Origin header is present, same-origin.
  app.addHook('preHandler', async (req, reply) => {
    if (!req.user || ['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return;
    const ct = String(req.headers['content-type'] || '');
    if (req.body !== undefined && !ct.startsWith('application/json')) {
      return reply.code(415).send({ error: 'content-type must be application/json' });
    }
    const origin = req.headers.origin;
    if (origin && req.headers.host && new URL(origin).host !== req.headers.host) {
      return reply.code(403).send({ error: 'cross-origin request rejected' });
    }
  });
}

export function requireRole(min: Role) {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    if (!req.user) return reply.code(401).send({ error: 'authentication required' });
    if (!hasRole(req.user, min)) return reply.code(403).send({ error: 'insufficient permissions' });
  };
}

export async function audit(
  pool: Pool,
  e: { accountId?: string; userId?: string; serverId?: string; action: string; detail?: unknown; ip?: string },
): Promise<void> {
  await pool.query(
    'INSERT INTO audit_events (account_id, user_id, server_id, action, detail, ip) VALUES ($1,$2,$3,$4,$5,$6)',
    [e.accountId ?? null, e.userId ?? null, e.serverId ?? null, e.action, JSON.stringify(e.detail ?? {}), e.ip ?? null],
  );
}
