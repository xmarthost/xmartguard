import type { FastifyInstance, FastifyRequest } from 'fastify';
import { isIP } from 'node:net';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';
import type { AgentHub } from '../agents/hub.js';
import { audit, requireRole } from '../auth.js';
import { signedPayload } from '../agent-sign.js';
import { CAPTCHA_DESIGNS, type CaptchaDesign, renderInfo, renderPage } from '../captcha/page.js';
import { altchaChallenge, altchaScript, altchaVerify } from '../captcha/altcha.js';

/**
 * CAPTCHA page for suspicious visitors of the websites' login pages
 * (captcha.xpguard.org, served by this portal).
 *
 * The WAF on a server redirects a suspicious address (IPDB, recent bans,
 * repeated WAF blocks) that asks for a protected login URL to
 * /v?s=<server>&ip=<address>&h=<host>&u=<page>. The visitor solves
 * Cloudflare Turnstile or ALTCHA (proof of work, run by this portal; also
 * the fallback when Turnstile cannot load); the portal checks it and tells
 * that server's agent
 * (captcha.pass), which lets the address through its WAF and confirms the
 * website is one of its own before the visitor is sent back.
 */

export const CaptchaConfig = z.object({
  enabled: z.boolean(),
  site_key: z.string().trim().max(200),
  secret_key: z.string().trim().max(200),
  minutes: z.number().int().min(10).max(7 * 24 * 60),
  // auto: Turnstile, and ALTCHA when Turnstile cannot load for a visitor
  // (or when no Turnstile keys are set); turnstile or altcha: only that one.
  provider: z.enum(['auto', 'turnstile', 'altcha']).default('auto'),
  // strict_ip: the check must be solved from the address the website saw.
  // Off: another address may solve it (mobile networks and ISPs often use
  // different addresses for different sites), a few per hour.
  strict_ip: z.boolean().default(false),
  // The page's look and the seconds shown before the visitor goes back.
  design: z.enum(CAPTCHA_DESIGNS).default('classic'),
  countdown: z.number().int().min(0).max(15).default(5),
});
export type CaptchaConfig = z.infer<typeof CaptchaConfig>;

const DEFAULT: CaptchaConfig = { enabled: false, site_key: '', secret_key: '', minutes: 720, provider: 'auto', strict_ip: false, design: 'classic', countdown: 5 };

/** The check the page shows ('' = not usable: Turnstile chosen without keys). */
export function effectiveProvider(c: CaptchaConfig): 'turnstile' | 'altcha' | 'auto' | '' {
  const keys = c.site_key !== '' && c.secret_key !== '';
  switch (c.provider) {
    case 'turnstile':
      return keys ? 'turnstile' : '';
    case 'altcha':
      return 'altcha';
    default:
      return keys ? 'auto' : 'altcha';
  }
}

/**
 * Addresses a visitor solved checks for other than its own, per hour: a
 * visitor on a network with changing addresses needs one or two; solving
 * checks for many addresses is someone passing bots through.
 */
const MAX_OTHER_ADDRESSES = 3;
const otherAddresses = new Map<string, Map<string, number>>();

export function allowOtherAddress(visitor: string, target: string, now = Date.now()): boolean {
  const hour = now - 3600_000;
  let m = otherAddresses.get(visitor);
  if (!m) {
    if (otherAddresses.size > 50_000) otherAddresses.clear();
    m = new Map();
    otherAddresses.set(visitor, m);
  }
  for (const [ip, at] of m) if (at < hour) m.delete(ip);
  if (!m.has(target) && m.size >= MAX_OTHER_ADDRESSES) return false;
  m.set(target, now);
  return true;
}

/** Turnstile's verification endpoint (tests replace it). */
export const turnstile = {
  url: 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
  async verify(secret: string, token: string, ip: string): Promise<boolean> {
    try {
      const res = await fetch(this.url, {
        method: 'POST',
        body: new URLSearchParams({ secret, response: token, remoteip: ip }),
        signal: AbortSignal.timeout(10_000),
      });
      const j = (await res.json()) as { success?: boolean };
      return j.success === true;
    } catch {
      return false;
    }
  },
};

async function load(pool: Pool, accountId: string) {
  const { rows } = await pool.query('SELECT config, version, updated_at FROM captcha_config WHERE account_id = $1', [accountId]);
  if (!rows[0]) return { config: DEFAULT, version: 0, updated_at: null as string | null };
  const p = CaptchaConfig.safeParse(rows[0].config);
  return { config: p.success ? p.data : DEFAULT, version: Number(rows[0].version), updated_at: rows[0].updated_at as string };
}

const reHost = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.?(?::\d{1,5})?$/i;
const reUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The visitor's address: Cloudflare's header when the portal is behind a proxy. */
function visitorIP(req: FastifyRequest, trustProxy: boolean): string {
  const cf = req.headers['cf-connecting-ip'];
  if (trustProxy && typeof cf === 'string' && isIP(cf.trim())) return cf.trim();
  return req.ip;
}

/** Same address, written either way (IPv4-mapped IPv6 included). */
function sameIP(a: string, b: string): boolean {
  const n = (x: string) => x.toLowerCase().replace(/^::ffff:/, '');
  return n(a) === n(b);
}

/**
 * The request parameters. The WAF writes the page ("u") last and unescaped:
 * everything after "&u=" is the page, "&" and "?" included.
 */
export function parseParams(rawUrl: string) {
  const q = rawUrl.indexOf('?');
  const query = q >= 0 ? rawUrl.slice(q + 1) : '';
  const at = query.indexOf('&u=');
  const head = new URLSearchParams(at >= 0 ? query.slice(0, at) : query);
  let u = at >= 0 ? query.slice(at + 3) : (head.get('u') ?? '/');
  if (!u.startsWith('/') && /^%2f/i.test(u)) u = decodeURIComponent(u);
  const d = head.get('d') ?? '';
  return {
    s: head.get('s') ?? '',
    ip: head.get('ip') ?? '',
    h: (head.get('h') ?? '').toLowerCase(),
    u,
    preview: head.get('preview') === '1',
    // Previews may show another design than the saved one.
    design: (CAPTCHA_DESIGNS as readonly string[]).includes(d) ? (d as CaptchaDesign) : undefined,
  };
}

function validParams(p: { s: string; ip: string; h: string; u: string }): string | null {
  if (!reUUID.test(p.s)) return 'This check link is not valid.';
  if (!isIP(p.ip)) return 'This check link is not valid.';
  if (!reHost.test(p.h)) return 'This check link is not valid.';
  if (!p.u.startsWith('/') || p.u.startsWith('//') || p.u.length > 2000 || /[\s<>"\\]/.test(p.u)) return 'This check link is not valid.';
  return null;
}

export function captchaRoutes(app: FastifyInstance, pool: Pool, cfg: Config, hub: AgentHub): void {
  const viewer = { preHandler: requireRole('viewer') };
  const admin = { preHandler: requireRole('admin') };
  const pageUrl = `${cfg.captchaUrl}/v`;
  turnstile.url = cfg.turnstileVerifyUrl;
  const captchaHost = (() => {
    try {
      return new URL(cfg.captchaUrl).host.toLowerCase();
    } catch {
      return '';
    }
  })();

  async function servers(accountId: string) {
    const { rows } = await pool.query("SELECT id, hostname FROM servers WHERE account_id = $1 AND status = 'active' ORDER BY hostname", [accountId]);
    return rows.map((r) => ({ id: String(r.id), hostname: String(r.hostname), online: hub.isOnline(String(r.id)) }));
  }

  async function record(accountId: string, serverId: string, ip: string, host: string, result: string) {
    await pool
      .query('INSERT INTO captcha_events (account_id, server_id, ip, host, result) VALUES ($1, $2, $3, $4, $5)', [accountId, serverId, ip, host.slice(0, 255), result])
      .catch(() => undefined);
    // Keep 30 days.
    if (Math.random() < 0.02) await pool.query("DELETE FROM captcha_events WHERE at < now() - interval '30 days'").catch(() => undefined);
  }

  const html = (reply: import('fastify').FastifyReply, body: string, code = 200) =>
    reply
      .code(code)
      .type('text/html; charset=utf-8')
      .header('Cache-Control', 'no-store')
      .header(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; worker-src 'self' blob:; connect-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
      )
      .send(body);

  // The CAPTCHA host's front page (the rest of the portal stays on its own host).
  app.addHook('onRequest', async (req, reply) => {
    if (!captchaHost || captchaHost === new URL(cfg.publicUrl).host.toLowerCase()) return;
    if ((req.headers.host ?? '').toLowerCase() !== captchaHost) return;
    const path = req.url.split('?')[0];
    if (path === '/v' || path === '/v/verify' || path === '/v/altcha.js' || path === '/v/altcha/challenge' || /^\/(?:xpguard-shield|xpguard-wordmark|favicon-32)\.png$/.test(path)) return;
    return html(reply, renderInfo());
  });

  app.get('/v', { config: { rateLimit: { max: 60, timeWindow: '10 minutes' } } }, async (req, reply) => {
    const p = parseParams(req.raw.url ?? '');
    const ip = visitorIP(req, cfg.trustProxy);
    // Preview from Overview » CAPTCHA Page: only the check itself is tried.
    if (p.preview) Object.assign(p, { ip, h: 'example.com', u: '/wp-login.php' });
    const bad = validParams(p);
    if (bad) return html(reply, renderPage({ host: '', visitorIp: ip, params: null, siteKey: '', error: bad }), 400);
    const { rows } = await pool.query("SELECT account_id FROM servers WHERE id = $1 AND status = 'active'", [p.s]);
    if (!rows[0]) return html(reply, renderPage({ host: p.h, visitorIp: ip, params: null, siteKey: '', error: 'This check link is not valid.' }), 404);
    const { config } = await load(pool, rows[0].account_id);
    const provider = effectiveProvider(config);
    if (!config.enabled || !provider) {
      return html(reply, renderPage({ host: p.h, visitorIp: ip, params: null, siteKey: '', error: 'The check is not available right now. Please try again later.' }), 503);
    }
    const params = p.preview ? { s: p.s, ip: p.ip, h: p.h, u: p.u, preview: true } : { s: p.s, ip: p.ip, h: p.h, u: p.u };
    const design = (p.preview && p.design) || config.design;
    return html(reply, renderPage({ host: p.h, visitorIp: ip, params, siteKey: provider === 'altcha' ? '' : config.site_key, provider, design, countdown: config.countdown }));
  });

  // ALTCHA: the widget (from this portal, not a CDN) and its checks.
  app.get('/v/altcha.js', async (_req, reply) =>
    reply.type('application/javascript; charset=utf-8').header('Cache-Control', 'public, max-age=86400').send(altchaScript),
  );
  app.get('/v/altcha/challenge', { config: { rateLimit: { max: 60, timeWindow: '10 minutes', keyGenerator: (req: FastifyRequest) => visitorIP(req, cfg.trustProxy) } } }, async (_req, reply) =>
    reply.header('Cache-Control', 'no-store').send(await altchaChallenge()),
  );

  const Verify = z.object({
    s: z.string(),
    ip: z.string(),
    h: z.string(),
    u: z.string(),
    token: z.string().min(1).max(4096).optional(),
    altcha: z.string().min(1).max(8192).optional(),
    preview: z.boolean().optional(),
  });
  app.post(
    '/v/verify',
    { bodyLimit: 16 * 1024, config: { rateLimit: { max: 20, timeWindow: '10 minutes', keyGenerator: (req: FastifyRequest) => visitorIP(req, cfg.trustProxy) } } },
    async (req, reply) => {
      const b = Verify.safeParse(req.body);
      if (!b.success) return reply.code(400).send({ error: 'Invalid request.' });
      const p = { s: b.data.s, ip: b.data.ip, h: b.data.h.toLowerCase(), u: b.data.u };
      if (validParams(p)) return reply.code(400).send({ error: 'This check link is not valid.' });
      const { rows } = await pool.query("SELECT account_id FROM servers WHERE id = $1 AND status = 'active'", [p.s]);
      if (!rows[0]) return reply.code(404).send({ error: 'This check link is not valid.' });
      const accountId = String(rows[0].account_id);
      const { config } = await load(pool, accountId);
      const provider = effectiveProvider(config);
      if (!config.enabled || !provider) return reply.code(503).send({ error: 'The check is not available right now.' });
      const ip = visitorIP(req, cfg.trustProxy);
      // Turnstile's token, or ALTCHA's solution where ALTCHA is allowed.
      const solved = async () => {
        if (b.data.altcha) return provider !== 'turnstile' && (await altchaVerify(b.data.altcha));
        if (b.data.token) return provider !== 'altcha' && (await turnstile.verify(config.secret_key, b.data.token, ip));
        return false;
      };
      // A preview only tests the check: no server is asked, nothing is recorded.
      if (b.data.preview) {
        if (!(await solved())) return reply.code(403).send({ error: 'The check failed. Please try again.' });
        return { ok: true, preview: true };
      }
      // The link is for the address the website saw. Mobile networks and
      // ISPs often reach different sites from different addresses, so
      // another address may solve it (a few per hour), unless the strict
      // setting is on. A dual-stack visitor can reach this page over the
      // other family: always allowed.
      if (isIP(ip) === isIP(p.ip) && !sameIP(ip, p.ip) && (config.strict_ip || !allowOtherAddress(ip, p.ip))) {
        await record(accountId, p.s, ip, p.h, 'rejected');
        return reply.code(403).send({
          error: config.strict_ip
            ? 'This check was opened for another address. Please go back to the website and try again.'
            : 'Too many checks from this address. Please try again in an hour.',
        });
      }
      if (!(await solved())) {
        await record(accountId, p.s, p.ip, p.h, 'failed');
        return reply.code(403).send({ error: 'The check failed. Please try again.' });
      }
      if (!hub.isOnline(p.s)) {
        await record(accountId, p.s, p.ip, p.h, 'offline');
        return reply.code(503).send({ error: "The website's server cannot be reached right now. Please try again in a minute." });
      }
      try {
        await hub.command(p.s, 'captcha.pass', { ip: p.ip, host: p.h }, 90_000);
      } catch (e) {
        await record(accountId, p.s, p.ip, p.h, 'rejected');
        req.log.warn({ err: (e as Error).message, server: p.s, host: p.h }, 'captcha pass refused');
        return reply.code(403).send({ error: 'This website could not confirm the check. Please try again later.' });
      }
      await record(accountId, p.s, p.ip, p.h, 'passed');
      return { ok: true, redirect: `https://${p.h.replace(/\.$/, '')}${p.u}` };
    },
  );

  // ---- Overview » CAPTCHA page
  app.get('/api/captcha', viewer, async (req) => {
    const acc = req.user!.accountId;
    const cur = await load(pool, acc);
    const { rows } = await pool.query(
      `SELECT result, count(*)::int AS n FROM captcha_events WHERE account_id = $1 AND at > now() - interval '24 hours' GROUP BY result`,
      [acc],
    );
    const last24h: Record<string, number> = { passed: 0, failed: 0, rejected: 0, offline: 0 };
    for (const r of rows) last24h[r.result] = r.n;
    return {
      config: {
        enabled: cur.config.enabled,
        site_key: cur.config.site_key,
        secret_set: cur.config.secret_key !== '',
        minutes: cur.config.minutes,
        provider: cur.config.provider,
        strict_ip: cur.config.strict_ip,
        design: cur.config.design,
        countdown: cur.config.countdown,
      },
      version: cur.version,
      updated_at: cur.updated_at,
      url: pageUrl,
      last24h,
      servers: await servers(acc),
    };
  });

  const Save = z.object({
    enabled: z.boolean(),
    site_key: z.string().trim().max(200),
    // Empty keeps the saved secret.
    secret_key: z.string().trim().max(200),
    minutes: z.number().int().min(10).max(7 * 24 * 60),
    provider: z.enum(['auto', 'turnstile', 'altcha']).default('auto'),
    strict_ip: z.boolean().default(false),
    design: z.enum(CAPTCHA_DESIGNS).default('classic'),
    countdown: z.number().int().min(0).max(15).default(5),
  });
  app.put('/api/captcha', admin, async (req, reply) => {
    const b = Save.safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: b.error.issues[0]?.message ?? 'invalid configuration' });
    const acc = req.user!.accountId;
    const cur = await load(pool, acc);
    const c: CaptchaConfig = { ...b.data, secret_key: b.data.secret_key || cur.config.secret_key };
    if (c.enabled && c.provider === 'turnstile' && (!c.site_key || !c.secret_key)) {
      return reply.code(400).send({ error: 'Add the Cloudflare Turnstile site key and secret key, or choose ALTCHA, before turning the CAPTCHA page on.' });
    }
    if (c.site_key && !/^[0-9A-Za-z_-]{10,100}$/.test(c.site_key)) return reply.code(400).send({ error: 'The site key does not look like a Turnstile site key.' });
    const { rows } = await pool.query(
      `INSERT INTO captcha_config (account_id, config, version) VALUES ($1, $2, 1)
       ON CONFLICT (account_id) DO UPDATE SET config = EXCLUDED.config, version = captcha_config.version + 1, updated_at = now()
       RETURNING version`,
      [acc, JSON.stringify(c)],
    );
    const version = Number(rows[0].version);
    await audit(pool, { accountId: acc, userId: req.user!.id, action: 'captcha.saved', detail: { version, enabled: c.enabled, minutes: c.minutes, provider: c.provider, strict_ip: c.strict_ip, design: c.design, countdown: c.countdown }, ip: req.ip });
    let pushed = 0;
    let offline = 0;
    for (const s of await servers(acc)) {
      if (!s.online) {
        offline++;
        continue;
      }
      pushed++;
      void hub.command(s.id, 'captcha.central', { version, enabled: c.enabled, url: pageUrl, minutes: c.minutes }, 120_000).catch(() => undefined);
    }
    return { version, pushed, offline };
  });

  // Clear the list of checks (e.g. after trying the page out).
  // The recorded checks, newest first, a page at a time.
  const Events = z.object({
    limit: z.coerce.number().int().refine((n) => [25, 50, 100, 200].includes(n)).default(50),
    offset: z.coerce.number().int().min(0).default(0),
    result: z.enum(['', 'passed', 'failed', 'rejected', 'offline']).default(''),
    q: z.string().trim().max(100).default(''),
  });
  app.get('/api/captcha/events', viewer, async (req, reply) => {
    const f = Events.safeParse(req.query);
    if (!f.success) return reply.code(400).send({ error: 'invalid filter' });
    const acc = req.user!.accountId;
    const where = ['e.account_id = $1'];
    const args: unknown[] = [acc];
    if (f.data.result) {
      args.push(f.data.result);
      where.push(`e.result = $${args.length}`);
    }
    if (f.data.q) {
      args.push(`%${f.data.q.replace(/[\\%_]/g, (c) => '\\' + c)}%`);
      where.push(`(e.ip ILIKE $${args.length} OR e.host ILIKE $${args.length})`);
    }
    const w = where.join(' AND ');
    const total = await pool.query(`SELECT count(*)::int AS n FROM captcha_events e WHERE ${w}`, args);
    const rows = await pool.query(
      `SELECT e.id::text, e.at, e.ip, e.host, e.result, s.hostname AS server FROM captcha_events e JOIN servers s ON s.id = e.server_id
       WHERE ${w} ORDER BY e.at DESC, e.id DESC LIMIT ${f.data.limit} OFFSET ${f.data.offset}`,
      args,
    );
    return { events: rows.rows, total: total.rows[0].n };
  });

  // Delete the chosen checks, or all of them when no ids are given.
  const Del = z.object({ ids: z.array(z.string().regex(/^\d{1,19}$/)).max(1000).optional() });
  app.delete('/api/captcha/events', admin, async (req, reply) => {
    const b = Del.safeParse(req.body ?? {});
    if (!b.success) return reply.code(400).send({ error: 'invalid request' });
    const acc = req.user!.accountId;
    const r = b.data.ids
      ? await pool.query('DELETE FROM captcha_events WHERE account_id = $1 AND id = ANY($2::bigint[])', [acc, b.data.ids])
      : await pool.query('DELETE FROM captcha_events WHERE account_id = $1', [acc]);
    await audit(pool, { accountId: acc, userId: req.user!.id, action: 'captcha.events_deleted', detail: { count: r.rowCount, all: !b.data.ids }, ip: req.ip });
    return { deleted: r.rowCount };
  });

  // Agents fetch the setting when it changed (servers that were offline).
  app.post('/api/agent/captcha/config', { bodyLimit: 16 * 1024 }, async (req, reply) => {
    const r = await signedPayload(pool, req.body, z.object({ version: z.number().int().min(0) }), reply);
    if (!r) return;
    const cur = await load(pool, r.accountId);
    if (cur.version === 0 || cur.version === r.data.version) return { unchanged: true };
    return { config: { version: cur.version, enabled: cur.config.enabled, url: pageUrl, minutes: cur.config.minutes } };
  });
}
