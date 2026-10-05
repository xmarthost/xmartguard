import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';
import { SESSION_COOKIE, audit, createSession, destroySession, requireRole } from '../auth.js';
import { hashPassword, verifyPassword } from '../security.js';
import { isPlatform } from '../tenancy.js';

const LoginBody = z.object({ email: z.string().email().max(200), password: z.string().min(1).max(200) });
const ProfileBody = z.object({
  name: z.string().trim().max(100),
  email: z.string().trim().email().max(200),
  current_password: z.string().max(200).optional(),
});
const PasswordBody = z.object({ current_password: z.string().min(1).max(200), new_password: z.string().min(10).max(200) });

// A real hash so unknown-email logins take as long as wrong-password ones.
const DUMMY_HASH = hashPassword('xpguard-timing-dummy');

export function authRoutes(app: FastifyInstance, pool: Pool, cfg: Config): void {
  const cookieOpts = {
    path: '/',
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: cfg.cookieSecure,
    maxAge: cfg.sessionTtlHours * 3600,
  };

  app.post('/api/auth/login', { config: { rateLimit: { max: 10, timeWindow: '5 minutes' } } }, async (req, reply) => {
    const parsed = LoginBody.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'email and password are required' });
    const { email, password } = parsed.data;
    const { rows } = await pool.query('SELECT id, account_id, password_hash FROM users WHERE lower(email) = lower($1)', [email]);
    const u = rows[0];
    const ok = await verifyPassword(password, u ? u.password_hash : await DUMMY_HASH);
    if (!u || !ok) {
      await audit(pool, { accountId: u?.account_id, userId: u?.id, action: 'auth.login_failed', detail: { email }, ip: req.ip });
      return reply.code(401).send({ error: 'invalid email or password' });
    }
    const token = await createSession(pool, cfg, u.id, req);
    await pool.query('UPDATE users SET last_login_at = now() WHERE id = $1', [u.id]);
    await audit(pool, { accountId: u.account_id, userId: u.id, action: 'auth.login', ip: req.ip });
    reply.setCookie(SESSION_COOKIE, token, cookieOpts);
    return { ok: true };
  });

  // Where the browser goes next: a customer signs out of the website's
  // client area too (else the website opens the panel again at once); the
  // platform's own staff stay on the operator sign-in and lose the client
  // marker (set when they tried the client area in this browser).
  app.post('/api/auth/logout', async (req, reply) => {
    const user = req.user;
    await destroySession(pool, req.cookies[SESSION_COOKIE]);
    reply.clearCookie(SESSION_COOKIE, { path: '/' });
    let redirect = '/login?out=1';
    if (user && (await isPlatform(pool, user.accountId))) {
      reply.clearCookie('xg_client', { path: '/' });
      redirect = '/login?admin&out=1';
    } else if (user && cfg.billingSiteUrl) {
      redirect = `${cfg.billingSiteUrl}/logout?from=panel`;
    }
    return { ok: true, redirect };
  });

  app.get('/api/auth/me', async (req, reply) => {
    if (!req.user) return reply.code(401).send({ error: 'not logged in' });
    return { user: req.user };
  });

  // The signed-in user's own name and email. A new email (the login) needs
  // the current password.
  app.put('/api/auth/profile', { preHandler: requireRole('viewer') }, async (req, reply) => {
    const parsed = ProfileBody.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues[0]?.path[0] === 'email' ? 'enter a valid email address' : 'invalid profile' });
    const user = req.user!;
    const { name, email, current_password } = parsed.data;
    const changingEmail = email.toLowerCase() !== user.email.toLowerCase();
    if (changingEmail) {
      const { rows } = await pool.query('SELECT password_hash FROM users WHERE id = $1', [user.id]);
      if (!current_password || !(await verifyPassword(current_password, rows[0].password_hash))) {
        return reply.code(403).send({ error: 'enter your current password to change the email' });
      }
      const taken = await pool.query('SELECT 1 FROM users WHERE lower(email) = lower($1) AND id <> $2', [email, user.id]);
      if (taken.rowCount) return reply.code(409).send({ error: 'another user already has this email' });
    }
    await pool.query('UPDATE users SET name = $2, email = $3 WHERE id = $1', [user.id, name, email]);
    await audit(pool, {
      accountId: user.accountId,
      userId: user.id,
      action: changingEmail ? 'auth.email_changed' : 'auth.profile_changed',
      detail: changingEmail ? { from: user.email, to: email } : {},
      ip: req.ip,
    });
    return { user: { ...user, name, email } };
  });

  app.post('/api/auth/password', { preHandler: requireRole('viewer') }, async (req, reply) => {
    const parsed = PasswordBody.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'new password must be at least 10 characters' });
    const user = req.user!;
    const { rows } = await pool.query('SELECT password_hash FROM users WHERE id = $1', [user.id]);
    if (!(await verifyPassword(parsed.data.current_password, rows[0].password_hash))) {
      return reply.code(403).send({ error: 'current password is incorrect' });
    }
    await pool.query('UPDATE users SET password_hash = $2 WHERE id = $1', [user.id, await hashPassword(parsed.data.new_password)]);
    // Invalidate all other sessions.
    await pool.query('DELETE FROM sessions WHERE user_id = $1', [user.id]);
    const token = await createSession(pool, cfg, user.id, req);
    reply.setCookie(SESSION_COOKIE, token, cookieOpts);
    await audit(pool, { accountId: user.accountId, userId: user.id, action: 'auth.password_changed', ip: req.ip });
    return { ok: true };
  });
}
