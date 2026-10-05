import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import crypto from 'node:crypto';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';
import { SESSION_COOKIE, audit, createSession, requireRole } from '../auth.js';
import { hashPassword, randomToken, sha256 } from '../security.js';
import { isPlatform } from '../tenancy.js';

/**
 * Licences sold on the website (xpguard.org): how many servers a customer
 * account may connect, until when. The website calls the signed billing API
 * below after a payment; the portal enforces the limit when install tokens
 * are made and servers enrol. Accounts without a licence (the platform
 * account, self-hosted portals) have no limit.
 */

export interface License {
  trial: boolean;
  plan: string;
  plan_name: string;
  max_servers: number;
  period_end: string | null;
  status: 'active' | 'expired' | 'suspended' | 'cancelled';
}

export async function loadLicense(pool: Pool, accountId: string): Promise<License | null> {
  const { rows } = await pool.query(
    'SELECT plan, plan_name, max_servers, period_end, status, trial FROM account_licenses WHERE account_id = $1',
    [accountId],
  );
  if (!rows[0]) return null;
  const r = rows[0];
  return { trial: Boolean(r.trial), plan: r.plan, plan_name: r.plan_name, max_servers: Number(r.max_servers), period_end: r.period_end ? new Date(r.period_end).toISOString() : null, status: r.status };
}

/** Servers connected plus install tokens not used yet. */
export async function serversInUse(pool: Pool, accountId: string, withTokens = true): Promise<number> {
  const { rows } = await pool.query(
    `SELECT (SELECT count(*) FROM servers WHERE account_id = $1 AND status = 'active')::int AS servers,
            (SELECT count(*) FROM enrollment_tokens WHERE account_id = $1 AND used_at IS NULL AND expires_at > now())::int AS tokens`,
    [accountId],
  );
  return rows[0].servers + (withTokens ? rows[0].tokens : 0);
}

/**
 * Why another server cannot be added to this account ('' when it can).
 * `withTokens`: count unused install tokens too (when making one).
 */
export async function serverLimitError(pool: Pool, accountId: string, withTokens: boolean): Promise<string> {
  const lic = await loadLicense(pool, accountId);
  if (!lic) return '';
  const expired = lic.status !== 'active' || (lic.period_end !== null && new Date(lic.period_end).getTime() < Date.now());
  if (expired) return 'Your xPGuard subscription is not active. Renew it to add servers; the servers you have stay protected.';
  const used = await serversInUse(pool, accountId, withTokens);
  if (used >= lic.max_servers) {
    return `Your plan allows ${lic.max_servers} server${lic.max_servers === 1 ? '' : 's'} and all are in use. Buy another server licence to add one.`;
  }
  return '';
}

/** Public addresses of a server (private, loopback and link-local left out). */
export function publicIPs(...lists: unknown[]): string[] {
  const out = new Set<string>();
  const priv = /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|0\.|::1$|fe80:|f[cd][0-9a-f]{2}:)/i;
  for (const l of lists) {
    for (const v of Array.isArray(l) ? l : [l]) {
      const ip = String(v ?? '').trim().replace(/^::ffff:/, '').replace(/\/\d+$/, '').toLowerCase();
      if (ip && /^[0-9a-f.:]+$/.test(ip) && !priv.test(ip)) out.add(ip);
    }
  }
  return [...out];
}

/**
 * A free trial is once per server: an address already recorded for another
 * account's trial cannot start one again ('' when it can). The addresses are
 * recorded for this account as the server joins.
 */
export async function trialHostError(c: { query: Pool['query'] }, accountId: string, trialUntil: string | null, ips: string[], serverId: string | null, hostname: string): Promise<string> {
  if (!ips.length) return '';
  // Used by another account, or by an earlier trial of this one: refused.
  // Reinstalling during the same trial (same end date) is allowed.
  const { rows } = await c.query(
    `SELECT ip FROM trial_hosts WHERE ip = ANY($1::text[])
       AND (account_id IS DISTINCT FROM $2 OR trial_until IS DISTINCT FROM $3::timestamptz) LIMIT 1`,
    [ips, accountId, trialUntil],
  );
  if (rows[0]) return `This server (${rows[0].ip}) already used its xPGuard free trial (one month per server). Buy a licence to protect it.`;
  if (serverId) {
    for (const ip of ips) {
      await c.query('INSERT INTO trial_hosts (ip, account_id, server_id, hostname, trial_until) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (ip) DO NOTHING', [ip, accountId, serverId, hostname.slice(0, 200), trialUntil]);
    }
  }
  return '';
}

const Provision = z.object({
  email: z.string().trim().toLowerCase().email().max(200),
  name: z.string().trim().max(100).default(''),
  plan: z.string().trim().min(1).max(40),
  plan_name: z.string().trim().max(100).default(''),
  max_servers: z.number().int().min(0).max(100000),
  period_end: z.string().datetime({ offset: true }).nullable(),
  status: z.enum(['active', 'expired', 'suspended', 'cancelled']).default('active'),
  customer_ref: z.string().trim().max(100).default(''),
  trial: z.boolean().default(false),
});
const ByEmail = z.object({ email: z.string().trim().toLowerCase().email().max(200) });

export function billingRoutes(app: FastifyInstance, pool: Pool, cfg: Config): void {
  const cookieOpts = { path: '/', httpOnly: true, sameSite: 'lax' as const, secure: cfg.cookieSecure, maxAge: cfg.sessionTtlHours * 3600 };

  /**
   * The website's signed requests: body {"payload": "<json>"}, headers
   * X-XG-Timestamp (unix seconds) and X-XG-Signature = hex HMAC-SHA256 of
   * "<timestamp>.<path>.<payload>" with BILLING_SECRET (path: /api/billing/…).
   * Each signature is used once (the website puts a random nonce in payloads).
   */
  async function signed<T>(req: FastifyRequest, reply: FastifyReply, schema: z.ZodType<T>): Promise<T | null> {
    if (!cfg.billingSecret) {
      reply.code(404).send({ error: 'billing is not enabled on this portal' });
      return null;
    }
    const ts = String(req.headers['x-xg-timestamp'] ?? '');
    const sig = String(req.headers['x-xg-signature'] ?? '');
    const payload = (req.body as { payload?: unknown } | undefined)?.payload;
    if (!/^\d{9,11}$/.test(ts) || !/^[0-9a-f]{64}$/.test(sig) || typeof payload !== 'string') {
      reply.code(401).send({ error: 'unsigned request' });
      return null;
    }
    if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) {
      reply.code(401).send({ error: 'request expired: check the clocks of the website and the portal' });
      return null;
    }
    const path = (req.url ?? '').split('?')[0];
    const want = crypto.createHmac('sha256', cfg.billingSecret).update(`${ts}.${path}.${payload}`).digest();
    const got = Buffer.from(sig, 'hex');
    if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) {
      reply.code(401).send({ error: 'bad signature' });
      return null;
    }
    const { rowCount } = await pool.query('INSERT INTO billing_nonces (sig) VALUES ($1) ON CONFLICT DO NOTHING', [sig]);
    if (!rowCount) {
      reply.code(409).send({ error: 'request replayed' });
      return null;
    }
    await pool.query("DELETE FROM billing_nonces WHERE at < now() - interval '1 day'");
    let data: unknown;
    try {
      data = JSON.parse(payload);
    } catch {
      reply.code(400).send({ error: 'invalid payload' });
      return null;
    }
    const p = schema.safeParse(data);
    if (!p.success) {
      reply.code(400).send({ error: p.error.issues[0]?.message ?? 'invalid payload' });
      return null;
    }
    return p.data;
  }

  async function userByEmail(email: string) {
    const { rows } = await pool.query(
      'SELECT u.id, u.account_id, u.password_hash, a.platform FROM users u JOIN accounts a ON a.id = u.account_id WHERE lower(u.email) = lower($1)',
      [email],
    );
    return rows[0] as { id: string; account_id: string; password_hash: string; platform: boolean } | undefined;
  }

  async function userLink(userId: string, purpose: 'set_password' | 'login', minutes: number): Promise<string> {
    const token = randomToken();
    await pool.query(
      `INSERT INTO user_tokens (token_hash, user_id, purpose, expires_at) VALUES ($1, $2, $3, now() + make_interval(mins => $4))`,
      [sha256(token), userId, purpose, minutes],
    );
    return purpose === 'login' ? `${cfg.publicUrl}/sso?token=${token}` : `${cfg.publicUrl}/set-password?token=${token}`;
  }

  // A paid (or free trial) licence: makes the customer's account and owner
  // user the first time, then keeps the licence up to date.
  app.post('/api/billing/provision', { bodyLimit: 16 * 1024 }, async (req, reply) => {
    const b = await signed(req, reply, Provision);
    if (!b) return;
    let user = await userByEmail(b.email);
    if (user?.platform) return reply.code(409).send({ error: 'this email belongs to the portal operator' });
    let created = false;
    if (!user) {
      const acc = await pool.query('INSERT INTO accounts (name) VALUES ($1) RETURNING id', [b.name || b.email]);
      // No usable password until the customer sets one from the link.
      const u = await pool.query(
        "INSERT INTO users (account_id, email, name, password_hash, role) VALUES ($1, $2, $3, $4, 'owner') RETURNING id",
        [acc.rows[0].id, b.email, b.name, '!' + (await hashPassword(randomToken()))],
      );
      user = { id: u.rows[0].id, account_id: acc.rows[0].id, password_hash: '!', platform: false };
      created = true;
    }
    await pool.query(
      `INSERT INTO account_licenses (account_id, plan, plan_name, max_servers, period_end, status, customer_ref, trial)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (account_id) DO UPDATE SET plan = EXCLUDED.plan, plan_name = EXCLUDED.plan_name, max_servers = EXCLUDED.max_servers,
         period_end = EXCLUDED.period_end, status = EXCLUDED.status, customer_ref = EXCLUDED.customer_ref, trial = EXCLUDED.trial, updated_at = now()`,
      [user.account_id, b.plan, b.plan_name, b.max_servers, b.period_end, b.status, b.customer_ref, b.trial],
    );
    await audit(pool, { accountId: user.account_id, action: 'billing.license', detail: { plan: b.plan, max_servers: b.max_servers, period_end: b.period_end, status: b.status, created }, ip: req.ip });
    const needsPassword = user.password_hash.startsWith('!');
    return {
      account_id: user.account_id,
      created,
      set_password_url: needsPassword ? await userLink(user.id, 'set_password', 7 * 24 * 60) : null,
      portal_url: cfg.publicUrl,
    };
  });

  // Servers in use, for the website's customer area.
  app.post('/api/billing/usage', async (req, reply) => {
    const b = await signed(req, reply, ByEmail);
    if (!b) return;
    const user = await userByEmail(b.email);
    if (!user) return reply.code(404).send({ error: 'no portal account for this email' });
    const { rows } = await pool.query(
      "SELECT hostname, (connected) AS online, last_seen_at FROM servers WHERE account_id = $1 AND status = 'active' ORDER BY hostname",
      [user.account_id],
    );
    return { license: await loadLicense(pool, user.account_id), servers_used: rows.length, servers: rows, needs_password: user.password_hash.startsWith('!') };
  });

  // One-time links from the website: sign in to the panel, or set a password.
  app.post('/api/billing/login-link', async (req, reply) => {
    const b = await signed(req, reply, ByEmail);
    if (!b) return;
    const user = await userByEmail(b.email);
    if (!user || user.platform) return reply.code(404).send({ error: 'no customer account for this email' });
    return { url: await userLink(user.id, 'login', 5), set_password_url: user.password_hash.startsWith('!') ? await userLink(user.id, 'set_password', 7 * 24 * 60) : null };
  });
  app.post('/api/billing/password-link', async (req, reply) => {
    const b = await signed(req, reply, ByEmail);
    if (!b) return;
    const user = await userByEmail(b.email);
    if (!user || user.platform) return reply.code(404).send({ error: 'no customer account for this email' });
    return { url: await userLink(user.id, 'set_password', 24 * 60) };
  });

  async function consume(token: string, purpose: 'set_password' | 'login'): Promise<{ user_id: string; account_id: string; email: string } | null> {
    if (!/^[A-Za-z0-9_-]{20,100}$/.test(token)) return null;
    const { rows } = await pool.query(
      `UPDATE user_tokens t SET used_at = now() FROM users u
        WHERE t.token_hash = $1 AND t.purpose = $2 AND t.used_at IS NULL AND t.expires_at > now() AND u.id = t.user_id
        RETURNING t.user_id, u.account_id, u.email`,
      [sha256(token), purpose],
    );
    return rows[0] ?? null;
  }

  // Where customers sign in: the website's client area (empty without one).
  const clientLogin = () => (cfg.billingSiteUrl ? `${cfg.billingSiteUrl}/login?next=${encodeURIComponent('/account/panel')}` : '');
  app.get('/api/auth/options', async () => ({ client_login_url: clientLogin(), client_area_url: cfg.billingSiteUrl ? `${cfg.billingSiteUrl}/account` : '' }));

  // Sign-in from the website's client area ("App Portal" button): no
  // password, and the session lasts CLIENT_SESSION_DAYS (30). A marker
  // cookie sends this browser back to the client area when it is signed out.
  app.get('/sso', async (req, reply) => {
    const u = await consume(String((req.query as Record<string, string>).token ?? ''), 'login');
    if (!u) return reply.redirect(clientLogin() || '/login?sso=expired');
    const hours = cfg.clientSessionDays * 24;
    reply.setCookie(SESSION_COOKIE, await createSession(pool, cfg, u.user_id, req, hours), { ...cookieOpts, maxAge: hours * 3600 });
    reply.setCookie('xg_client', '1', { path: '/', sameSite: 'lax', secure: cfg.cookieSecure, maxAge: 400 * 24 * 3600 });
    await audit(pool, { accountId: u.account_id, userId: u.user_id, action: 'auth.sso', ip: req.ip });
    return reply.redirect('/');
  });

  // New customers choose their password (the page is part of the web UI).
  app.get('/api/auth/set-password', async (req, reply) => {
    const token = String((req.query as Record<string, string>).token ?? '');
    const { rows } = await pool.query(
      `SELECT u.email FROM user_tokens t JOIN users u ON u.id = t.user_id
        WHERE t.token_hash = $1 AND t.purpose = 'set_password' AND t.used_at IS NULL AND t.expires_at > now()`,
      [/^[A-Za-z0-9_-]{20,100}$/.test(token) ? sha256(token) : ''],
    );
    if (!rows[0]) return reply.code(404).send({ error: 'This link has expired or was already used. Ask for a new one on the website.' });
    return { email: rows[0].email };
  });
  app.post('/api/auth/set-password', { config: { rateLimit: { max: 10, timeWindow: '5 minutes' } } }, async (req, reply) => {
    const b = z.object({ token: z.string(), password: z.string().min(10).max(200) }).safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: 'Choose a password of at least 10 characters.' });
    const u = await consume(b.data.token, 'set_password');
    if (!u) return reply.code(404).send({ error: 'This link has expired or was already used. Ask for a new one on the website.' });
    await pool.query('UPDATE users SET password_hash = $2 WHERE id = $1', [u.user_id, await hashPassword(b.data.password)]);
    await pool.query('DELETE FROM sessions WHERE user_id = $1', [u.user_id]);
    reply.setCookie(SESSION_COOKIE, await createSession(pool, cfg, u.user_id, req), cookieOpts);
    await audit(pool, { accountId: u.account_id, userId: u.user_id, action: 'auth.password_set', ip: req.ip });
    return { ok: true };
  });

  // The signed-in account's plan, for the Subscription page and limits.
  app.get('/api/license', { preHandler: requireRole('viewer') }, async (req) => {
    const acc = req.user!.accountId;
    const lic = await loadLicense(pool, acc);
    const site = cfg.billingSiteUrl;
    return {
      license: lic,
      unlimited: !lic,
      platform: await isPlatform(pool, acc),
      servers_used: await serversInUse(pool, acc, false),
      tokens_pending: (await serversInUse(pool, acc, true)) - (await serversInUse(pool, acc, false)),
      buy_url: site ? `${site}/account/add-servers` : '',
      renew_url: site ? `${site}/account` : '',
      site_url: site,
    };
  });
}
