import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import { audit, requireRole } from '../auth.js';
import { hashPassword } from '../security.js';

const CreateUser = z.object({
  email: z.string().email().max(200),
  name: z.string().max(100).default(''),
  password: z.string().min(10).max(200),
  role: z.enum(['admin', 'operator', 'viewer']),
});

export function userRoutes(app: FastifyInstance, pool: Pool): void {
  const owner = { preHandler: requireRole('owner') };

  app.get('/api/users', owner, async (req) => {
    const { rows } = await pool.query(
      'SELECT id, email, name, role, created_at, last_login_at FROM users WHERE account_id = $1 ORDER BY created_at',
      [req.user!.accountId],
    );
    return { users: rows };
  });

  app.post('/api/users', owner, async (req, reply) => {
    const body = CreateUser.safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: 'valid email, role and a 10+ character password are required' });
    const { email, name, password, role } = body.data;
    try {
      const { rows } = await pool.query(
        `INSERT INTO users (account_id, email, name, password_hash, role) VALUES ($1,$2,$3,$4,$5)
         RETURNING id, email, name, role, created_at`,
        [req.user!.accountId, email, name, await hashPassword(password), role],
      );
      await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, action: 'user.created', detail: { email, role }, ip: req.ip });
      return { user: rows[0] };
    } catch (err: any) {
      if (err?.code === '23505') return reply.code(409).send({ error: 'a user with this email already exists' });
      throw err;
    }
  });

  app.delete('/api/users/:id', owner, async (req, reply) => {
    const id = (req.params as { id: string }).id;
    if (!z.string().uuid().safeParse(id).success) return reply.code(404).send({ error: 'user not found' });
    if (id === req.user!.id) return reply.code(400).send({ error: 'you cannot delete yourself' });
    const { rowCount } = await pool.query(
      "DELETE FROM users WHERE id = $1 AND account_id = $2 AND role <> 'owner'",
      [id, req.user!.accountId],
    );
    if (!rowCount) return reply.code(404).send({ error: 'user not found' });
    await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, action: 'user.deleted', detail: { id }, ip: req.ip });
    return { ok: true };
  });
}

/** Creates an account + owner user. Used by the CLI and first-run bootstrap. */
export async function createOwner(pool: Pool, email: string, password: string, accountName = 'Default'): Promise<string> {
  const { rows } = await pool.query('INSERT INTO accounts (name) VALUES ($1) RETURNING id', [accountName]);
  const accountId = rows[0].id;
  const u = await pool.query(
    "INSERT INTO users (account_id, email, name, password_hash, role) VALUES ($1,$2,'Owner',$3,'owner') RETURNING id",
    [accountId, email, await hashPassword(password)],
  );
  return u.rows[0].id;
}
