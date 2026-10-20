import { isCloudflare, plainIP } from '../proxy.js';
import { createHash } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { isIP } from 'node:net';
import { z } from 'zod';
import type { Pool } from '../db.js';
import { masterAccount, scopeAccounts } from '../tenancy.js';
import type { Config } from '../config.js';
import type { AgentHub } from '../agents/hub.js';
import { audit, requirePlatform, requireRole } from '../auth.js';
import { signedPayload } from '../agent-sign.js';
import { CAPTCHA_DESIGNS, type CaptchaDesign, renderInfo, renderPage } from '../captcha/page.js';
import { altchaChallenge, altchaScript, altchaVerify } from '../captcha/altcha.js';
import { checkAbuseIPDB, loadAbuseIPDB } from '../ipdb/abuseipdb.js';

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
  // Servers whose websites show the check on their own address (the
  // server's CAPTCHA port, this page in a full-window frame, a pass cookie:
  // no web server reload). The others send visitors to this domain.
  site_servers: z.array(z.string().uuid()).max(5000).default([]),
});
export type CaptchaConfig = z.infer<typeof CaptchaConfig>;

const DEFAULT: CaptchaConfig = { enabled: false, site_key: '', secret_key: '', minutes: 720, provider: 'auto', strict_ip: false, design: 'classic', countdown: 5, site_servers: [] };

/** Where a server's websites show the check: 'site' on their own address, '' here. */
export function modeFor(c: CaptchaConfig, serverId: string): 'site' | '' {
  return c.site_servers.includes(serverId) ? 'site' : '';
}

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

/**
 * ALTCHA is proof of work: a script solves it as well as a browser does.
 * Where Turnstile is the check (auto), ALTCHA is only the fallback for a
 * visitor whose browser cannot run Turnstile, so it lets in only the
 * visitor's own address, a few times a day, for at most an hour.
 */
/** How long a solved check waits for the website's server to reconnect. */
export const offlineWait = { ms: 20_000 };

export const ALTCHA_FALLBACK_MINUTES = 60;
const ALTCHA_PER_DAY = { auto: 3, altcha: 10 };
const altchaPasses = new Map<string, number[]>();

export function altchaAllowed(keys: string[], mode: 'auto' | 'altcha', now = Date.now()): boolean {
  const day = now - 86_400_000;
  if (altchaPasses.size > 100_000) altchaPasses.clear();
  return keys.every((k) => (altchaPasses.get(k) ?? []).filter((t) => t > day).length < ALTCHA_PER_DAY[mode]);
}

/**
 * The visitor's own network for the ALTCHA fallback: the same /24 (IPv4)
 * or /48 (IPv6), where carrier-grade NAT hands out neighbouring
 * addresses, or both in Cloudflare's WARP / iCloud Private Relay egress
 * (104.28.0.0/15), where one person's traffic moves between addresses.
 */
export function sameNetwork(a: string, b: string): boolean {
  const n = (x: string) => x.toLowerCase().replace(/^::ffff:/, '');
  a = n(a);
  b = n(b);
  if (isIP(a) === 4 && isIP(b) === 4) {
    const pa = a.split('.').map(Number);
    const pb = b.split('.').map(Number);
    if (pa[0] === pb[0] && pa[1] === pb[1] && pa[2] === pb[2]) return true;
    const relay = (p: number[]) => p[0] === 104 && (p[1] === 28 || p[1] === 29);
    return relay(pa) && relay(pb);
  }
  if (isIP(a) === 6 && isIP(b) === 6) {
    // The first three groups, with "::" expanded.
    const head = (x: string) => {
      const [l, r = ''] = x.split('::');
      const left = l ? l.split(':') : [];
      const right = r ? r.split(':') : [];
      const full = x.includes('::') ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
      return full
        .slice(0, 3)
        .map((g) => parseInt(g || '0', 16))
        .join(':');
    };
    return head(a) === head(b);
  }
  return false;
}

/**
 * Hosting and cloud addresses (AbuseIPDB's usage type, or a high abuse
 * score) may not use the ALTCHA fallback: a script there solves proof of
 * work as easily as a browser, and people do not browse from data
 * centres. Without an AbuseIPDB key, or when its checks run out, the
 * fallback stays open (the other limits still apply).
 */
const HOSTING_CHECKS_PER_DAY = 200;
const hostingSeen = new Map<string, { hosting: boolean; at: number }>();
let hostingDay = '';
let hostingChecks = 0;
export const hostingCheck = {
  async lookup(key: string, ip: string): Promise<boolean | undefined> {
    const r = await checkAbuseIPDB(key, ip);
    if (r.error || r.score === undefined) return undefined;
    return /data center|hosting|transit/i.test(r.usageType ?? '') || r.score >= 50;
  },
};

async function hostingAddress(pool: Pool, ip: string): Promise<boolean> {
  const hit = hostingSeen.get(ip);
  if (hit && Date.now() - hit.at < 7 * 86_400_000) return hit.hosting;
  const today = new Date().toISOString().slice(0, 10);
  if (today !== hostingDay) {
    hostingDay = today;
    hostingChecks = 0;
  }
  if (hostingChecks >= HOSTING_CHECKS_PER_DAY) return false;
  const c = await loadAbuseIPDB(pool).catch(() => null);
  if (!c?.api_key) return false;
  hostingChecks++;
  const hosting = await hostingCheck.lookup(c.api_key, ip).catch(() => undefined);
  if (hosting === undefined) return false;
  if (hostingSeen.size > 50_000) hostingSeen.clear();
  hostingSeen.set(ip, { hosting, at: Date.now() });
  return hosting;
}

export function noteAltchaPass(keys: string[], now = Date.now()): void {
  const day = now - 86_400_000;
  for (const k of keys) altchaPasses.set(k, [...(altchaPasses.get(k) ?? []).filter((t) => t > day), now]);
}

/** Turnstile's verification endpoint (tests replace it). */
export const turnstile = {
  url: 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
  // hosts: where the check may have been solved (this page); a token
  // solved on another site with the same key is refused.
  async verify(secret: string, token: string, ip: string, hosts: string[] = []): Promise<boolean> {
    try {
      const res = await fetch(this.url, {
        method: 'POST',
        body: new URLSearchParams({ secret, response: token, remoteip: ip }),
        signal: AbortSignal.timeout(10_000),
      });
      const j = (await res.json()) as { success?: boolean; hostname?: string };
      if (j.success !== true) return false;
      return hosts.length === 0 || !j.hostname || hosts.includes(j.hostname.toLowerCase());
    } catch {
      return false;
    }
  },
};

async function load(pool: Pool, accountId: string) {
  accountId = await masterAccount(pool, accountId);
  const { rows } = await pool.query('SELECT config, version, updated_at FROM captcha_config WHERE account_id = $1', [accountId]);
  if (!rows[0]) return { config: DEFAULT, version: 0, updated_at: null as string | null };
  const p = CaptchaConfig.safeParse(rows[0].config);
  return { config: p.success ? p.data : DEFAULT, version: Number(rows[0].version), updated_at: rows[0].updated_at as string };
}

const reHost = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.?(?::\d{1,5})?$/i;
const reUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The visitor's address. req.ip already walks back through the known proxies
 * (proxy.ts); when the chain ends at Cloudflare itself (a front proxy that
 * does not add its peer), Cloudflare's own header names the visitor. A
 * header sent by anyone else is ignored.
 */
function visitorIP(req: FastifyRequest, trustProxy: boolean): string {
  const ip = plainIP(req.ip);
  const cf = req.headers['cf-connecting-ip'];
  if (trustProxy && isCloudflare(ip) && typeof cf === 'string' && isIP(cf.trim())) return cf.trim();
  return ip;
}

/**
 * The address the page shows: IPv4 first. A phone often reaches this page
 * over IPv6 while the website saw its IPv4 address (or the other way round);
 * the IPv4 one is the one people know and the one the check is for.
 */
export function shownIP(visitor: string, linked: string): string {
  const v = visitor.replace(/^::ffff:/i, '');
  if (isIP(v) === 4) return v;
  const l = linked.replace(/^::ffff:/i, '');
  if (isIP(l) === 4) return l;
  return v || l;
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
  // A visitor (or crawler) on site.com//wp-admin/ gets a link with
  // u=//wp-admin/. The way back is always https://<h><u>, so the extra
  // slashes can not lead to another site: keep one instead of refusing.
  u = u.replace(/^\/{2,}/, '/');
  const d = head.get('d') ?? '';
  return {
    s: head.get('s') ?? '',
    ip: head.get('ip') ?? '',
    h: (head.get('h') ?? '').toLowerCase(),
    u,
    preview: head.get('preview') === '1',
    // Shown in a frame on the website's own address: n is that page's
    // ticket number (the server trades the portal's word for a cookie).
    n: /^[a-f0-9]{32}$/.test(head.get('n') ?? '') ? (head.get('n') as string) : '',
    frame: head.get('frame') === '1',
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
  // Checks being verified, by solution (see /v/verify).
  const verifying = new Map<string, Promise<{ code: number; body: unknown }>>();
  const res = (code: number, body: unknown) => ({ code, body });
  const viewer = { preHandler: requirePlatform('viewer') };
  const admin = { preHandler: requirePlatform('admin') };
  const pageUrl = `${cfg.captchaUrl}/v`;
  // A new CAPTCHA domain (setup --captcha-domain): a new version, so every
  // server picks up the new address instead of sending visitors to the old one.
  void pool
    .query(
      `UPDATE captcha_config SET version = version + 1, config = jsonb_set(config, '{url_seen}', to_jsonb($1::text)), updated_at = now()
        WHERE coalesce(config->>'url_seen', '') <> $1`,
      [pageUrl],
    )
    .catch(() => undefined);
  turnstile.url = cfg.turnstileVerifyUrl;
  const captchaHost = (() => {
    try {
      return new URL(cfg.captchaUrl).host.toLowerCase();
    } catch {
      return '';
    }
  })();
  // Where Turnstile tokens may come from: the CAPTCHA host (and the
  // portal's own host, for previews when both are one).
  const portalHost = (() => {
    try {
      return new URL(cfg.publicUrl).hostname.toLowerCase();
    } catch {
      return '';
    }
  })();
  const tokenHosts = [captchaHost, portalHost].filter(Boolean).map((x) => x.replace(/:\d+$/, ''));

  async function servers(accountId: string) {
    const { rows } = await pool.query("SELECT id, hostname FROM servers WHERE account_id = ANY($1::uuid[]) AND status = 'active' ORDER BY hostname", [await scopeAccounts(pool, accountId)]);
    return rows.map((r) => ({ id: String(r.id), hostname: String(r.hostname), online: hub.isOnline(String(r.id)) }));
  }

  // Answers of servers to "is this website yours?" (captcha.host), cached.
  const confirmed = new Map<string, { site: 'yes' | 'no'; at: number }>();
  async function siteConfirmed(serverId: string, ip: string, host: string): Promise<'yes' | 'no' | 'unknown'> {
    const key = `${serverId}|${ip}|${host}`;
    const hit = confirmed.get(key);
    if (hit && Date.now() - hit.at < 10 * 60_000) return hit.site;
    if (!hub.isOnline(serverId)) return 'unknown';
    try {
      const r = (await hub.command(serverId, 'captcha.host', { ip, host }, 8_000)) as { hosted?: unknown };
      // Agents before this check do not know the command (unknown below).
      if (typeof r?.hosted !== 'boolean') return 'unknown';
      if (confirmed.size > 20_000) confirmed.clear();
      const site = r.hosted ? 'yes' : 'no';
      confirmed.set(key, { site, at: Date.now() });
      return site;
    } catch {
      return 'unknown';
    }
  }

  // method: the check solved (turnstile / altcha); solver: the address the
  // page was solved from when it is not the website's visitor itself.
  async function record(accountId: string, serverId: string, ip: string, host: string, result: string, method = '', solver = '') {
    await pool
      .query('INSERT INTO captcha_events (account_id, server_id, ip, host, result, method, solver_ip) VALUES ($1, $2, $3, $4, $5, $6, $7)', [
        accountId,
        serverId,
        ip,
        host.slice(0, 255),
        result,
        method,
        sameIP(solver, ip) ? '' : solver,
      ])
      .catch(() => undefined);
    // Keep 30 days.
    if (Math.random() < 0.02) await pool.query("DELETE FROM captcha_events WHERE at < now() - interval '30 days'").catch(() => undefined);
  }

  // frameHost: the website that may show the page in a frame (its own
  // address, any port); otherwise no one may.
  const html = (reply: import('fastify').FastifyReply, body: string, code = 200, frameHost = '') =>
    reply
      .code(code)
      .type('text/html; charset=utf-8')
      .header('Cache-Control', 'no-store')
      // Never in search results: the page only makes sense for one visitor.
      .header('X-Robots-Tag', 'noindex, nofollow, noarchive')
      .header(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; worker-src 'self' blob:; connect-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors " +
          (frameHost ? `https://${frameHost}:* https://${frameHost} http://${frameHost}:* http://${frameHost}` : "'none'"),
      )
      .send(body);

  // The CAPTCHA host's front page (the rest of the portal stays on its own host).
  app.addHook('onRequest', async (req, reply) => {
    if (!captchaHost || captchaHost === new URL(cfg.publicUrl).host.toLowerCase()) return;
    if ((req.headers.host ?? '').toLowerCase() !== captchaHost) return;
    const path = req.url.split('?')[0];
    // Crawlers may look (and see noindex); nothing here is for search results.
    if (path === '/robots.txt') {
      return reply.type('text/plain; charset=utf-8').header('X-Robots-Tag', 'noindex').send('User-agent: *\nAllow: /\n');
    }
    if (path === '/v' || path === '/v/verify' || path === '/v/altcha.js' || path === '/v/altcha/challenge' || /^\/(?:xpguard-shield|xpguard-wordmark|favicon-32)\.png$/.test(path)) return;
    return html(reply, renderInfo());
  });

  // Counted per visitor, not per connecting address: behind Cloudflare and
  // a front proxy for the CAPTCHA domain, every visitor reaches the portal
  // from the same few addresses and would share one limit (429s).
  app.get('/v', { config: { rateLimit: { max: 60, timeWindow: '10 minutes', keyGenerator: (req: FastifyRequest) => visitorIP(req, cfg.trustProxy) } } }, async (req, reply) => {
    const p = parseParams(req.raw.url ?? '');
    const ip = visitorIP(req, cfg.trustProxy);
    // Preview from Overview » CAPTCHA Page: only the check itself is tried.
    if (p.preview) Object.assign(p, { ip, h: 'example.com', u: '/wp-login.php' });
    const bad = validParams(p);
    if (bad) return html(reply, renderPage({ host: '', visitorIp: shownIP(ip, ''), params: null, siteKey: '', error: bad }), 400);
    const { rows } = await pool.query("SELECT account_id FROM servers WHERE id = $1 AND status = 'active'", [p.s]);
    if (!rows[0]) return html(reply, renderPage({ host: '', visitorIp: shownIP(ip, ''), params: null, siteKey: '', error: 'This check link is not valid.' }), 404);
    const { config } = await load(pool, rows[0].account_id);
    const provider = effectiveProvider(config);
    if (!config.enabled || !provider) {
      return html(reply, renderPage({ host: '', visitorIp: shownIP(ip, ''), params: null, siteKey: '', error: 'The check is not available right now. Please try again later.' }), 503);
    }
    const frame = !p.preview && p.frame && p.n !== '';
    const params = p.preview ? { s: p.s, ip: p.ip, h: p.h, u: p.u, preview: true } : frame ? { s: p.s, ip: p.ip, h: p.h, u: p.u, n: p.n } : { s: p.s, ip: p.ip, h: p.h, u: p.u };
    const design = (p.preview && p.design) || config.design;
    // The page names the website only when its server confirms the site is
    // one of its own: a made-up link can not make this domain show another
    // name (say, a bank's), and a site that is not on the server is refused.
    const site = p.preview ? 'yes' : await siteConfirmed(p.s, p.ip, p.h);
    if (site === 'no') {
      return html(reply, renderPage({ host: '', visitorIp: shownIP(ip, ''), params: null, siteKey: '', error: 'This check link is not valid.' }), 404);
    }
    // In a frame only on a website its server confirmed (the frame is on
    // the website's own address).
    if (frame && site === 'yes') (req as FastifyRequest & { xgFrame?: boolean }).xgFrame = true;
    return html(
      reply,
      renderPage({ host: site === 'yes' ? p.h : '', visitorIp: shownIP(ip, p.ip), params, siteKey: provider === 'altcha' ? '' : config.site_key, provider, design, countdown: config.countdown, frame: frame && site === 'yes' }),
      200,
      frame && site === 'yes' ? p.h.replace(/\.$/, '') : '',
    );
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
    // Opened in a frame on the website's own address (see /v).
    n: z.string().regex(/^[a-f0-9]{32}$/).optional(),
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
      // The same solution sent again while the first request still waits for
      // the website's server (a proxy in front of the CAPTCHA domain retrying
      // it, or a double submit) gets the first request's answer: a check is
      // accepted once, so the repeat used to answer "The check failed" while
      // the first was still letting the visitor in.
      const answer = b.data.altcha ?? b.data.token;
      const ip0 = visitorIP(req, cfg.trustProxy);
      const key = answer ? createHash('sha256').update(`${p.s}|${p.ip}|${p.h}|${p.u}|${ip0}|${answer}`).digest('hex') : '';
      const earlier = key ? verifying.get(key) : undefined;
      if (earlier) {
        const r = await earlier;
        return reply.code(r.code).send(r.body);
      }
      const run = async (): Promise<{ code: number; body: unknown }> => {
        const ip = visitorIP(req, cfg.trustProxy);
        const method = b.data.altcha ? 'altcha' : 'turnstile';
        // Turnstile's token, or ALTCHA's solution where ALTCHA is allowed.
        const solved = async () => {
          if (b.data.altcha) return provider !== 'turnstile' && (await altchaVerify(b.data.altcha));
          if (b.data.token) return provider !== 'altcha' && (await turnstile.verify(config.secret_key, b.data.token, ip, tokenHosts));
          return false;
        };
        // A preview only tests the check: no server is asked, nothing is recorded.
        if (b.data.preview) {
          if (!(await solved())) return res(403, { error: 'The check failed. Please try again.' });
          return res(200, { ok: true, preview: true });
        }
        // The link is for the address the website saw. Mobile networks and
        // ISPs often reach different sites from different addresses, so
        // another address may solve it (a few per hour), unless the strict
        // setting is on. A dual-stack visitor can reach this page over the
        // other family (also with the strict setting), but that counts as
        // another address too: one IPv6 visitor must not pass any number of
        // IPv4 addresses.
        const other = !sameIP(ip, p.ip);
        const sameFamily = isIP(ip) === isIP(p.ip);
        if (other && ((config.strict_ip && sameFamily) || !allowOtherAddress(ip, p.ip))) {
          await record(accountId, p.s, p.ip, p.h, 'rejected', method, ip);
          return res(403, {
            error:
              config.strict_ip && sameFamily
                ? 'This check was opened for another address. Please go back to the website and try again.'
                : 'Too many checks from this address. Please try again in an hour.',
          });
        }
        // ALTCHA where Turnstile is the check: only the visitor's own network
        // (or its other family), not from a hosting network, a few times a
        // day, for a shorter time.
        const altchaKeys = [`s:${ip}`, `t:${p.ip}`];
        if (method === 'altcha' && provider !== 'turnstile') {
          if ((provider === 'auto' && other && sameFamily && !sameNetwork(ip, p.ip)) || !altchaAllowed(altchaKeys, provider === 'auto' ? 'auto' : 'altcha')) {
            await record(accountId, p.s, p.ip, p.h, 'rejected', method, ip);
            return res(403, { error: 'Too many checks from this address. Please try again later.' });
          }
          if (provider === 'auto' && (await hostingAddress(pool, ip))) {
            await record(accountId, p.s, p.ip, p.h, 'rejected', method, ip);
            return res(403, { error: 'This check cannot be completed from a hosting or cloud network. Please open the website from your own connection.' });
          }
        }
        if (!(await solved())) {
          await record(accountId, p.s, p.ip, p.h, 'failed', method, ip);
          return res(403, { error: 'The check failed. Please try again.' });
        }
        // An agent reconnecting (update, WAF reload, network blip) is back
        // within seconds: wait for it rather than throw the solved check away.
        for (const end = Date.now() + offlineWait.ms; !hub.isOnline(p.s) && Date.now() < end; ) {
          await new Promise((r) => setTimeout(r, 500));
        }
        if (!hub.isOnline(p.s)) {
          await record(accountId, p.s, p.ip, p.h, 'offline', method, ip);
          return res(503, { error: "The website's server cannot be reached right now. Please try again in a minute." });
        }
        try {
          // Also the address the visitor solved it from: on mobile networks
          // (CGNAT) the next request to the site may come from that one.
          const short = method === 'altcha' && provider === 'auto' ? { minutes: Math.min(config.minutes, ALTCHA_FALLBACK_MINUTES) } : {};
          if (b.data.n) {
            // On the website's own address the server gives a ticket the
            // page there trades for a pass cookie: no reload, no wait.
            await hub.command(p.s, 'captcha.ticket', { ip: p.ip, host: p.h, nonce: b.data.n }, 15_000);
          } else {
            await hub.command(p.s, 'captcha.pass', { ip: p.ip, host: p.h, also: sameIP(ip, p.ip) ? '' : ip, ...short }, 90_000);
          }
        } catch (e) {
          await record(accountId, p.s, p.ip, p.h, 'rejected', method, ip);
          req.log.warn({ err: (e as Error).message, server: p.s, host: p.h }, 'captcha pass refused');
          return res(403, { error: 'This website could not confirm the check. Please try again later.' });
        }
        if (method === 'altcha') noteAltchaPass(altchaKeys);
        await record(accountId, p.s, p.ip, p.h, 'passed', method, ip);
        return res(200, { ok: true, redirect: `https://${p.h.replace(/\.$/, '')}${p.u}`, ...(b.data.n ? { frame: true } : {}) });
      };
      const pending = run();
      if (key) verifying.set(key, pending);
      const r = await pending;
      // Only while it runs: a proxy retries a request that has not been
      // answered yet; afterwards the check is used up as before.
      if (key) verifying.delete(key);
      return reply.code(r.code).send(r.body);
    },
  );

  // ---- Overview » CAPTCHA page
  app.get('/api/captcha', viewer, async (req) => {
    const acc = req.user!.accountId;
    const cur = await load(pool, acc);
    const { rows } = await pool.query(
      `SELECT result, count(*)::int AS n FROM captcha_events WHERE account_id = ANY($1::uuid[]) AND at > now() - interval '24 hours' GROUP BY result`,
      [await scopeAccounts(pool, acc)],
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
        site_servers: cur.config.site_servers,
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
    site_servers: z.array(z.string().uuid()).max(5000).default([]),
  });
  app.put('/api/captcha', admin, async (req, reply) => {
    const b = Save.safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: b.error.issues[0]?.message ?? 'invalid configuration' });
    const acc = req.user!.accountId;
    const cur = await load(pool, acc);
    const c: CaptchaConfig = { ...b.data, secret_key: b.data.secret_key || cur.config.secret_key };
    // Only servers this account reaches.
    const reach = new Set((await servers(acc)).map((s) => s.id));
    c.site_servers = [...new Set(c.site_servers)].filter((id) => reach.has(id));
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
    await audit(pool, { accountId: acc, userId: req.user!.id, action: 'captcha.saved', detail: { version, enabled: c.enabled, minutes: c.minutes, provider: c.provider, strict_ip: c.strict_ip, design: c.design, countdown: c.countdown, site_servers: c.site_servers.length }, ip: req.ip });
    let pushed = 0;
    let offline = 0;
    for (const s of await servers(acc)) {
      if (!s.online) {
        offline++;
        continue;
      }
      pushed++;
      void hub.command(s.id, 'captcha.central', { version, enabled: c.enabled, url: pageUrl, minutes: c.minutes, mode: modeFor(c, s.id) }, 120_000).catch(() => undefined);
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
    // The master account sees the checks of its customers' servers too.
    const where = ['e.account_id = ANY($1::uuid[])'];
    const args: unknown[] = [await scopeAccounts(pool, acc)];
    if (f.data.result) {
      args.push(f.data.result);
      where.push(`e.result = $${args.length}`);
    }
    if (f.data.q) {
      args.push(`%${f.data.q.replace(/[\\%_]/g, (c) => '\\' + c)}%`);
      where.push(`(e.ip ILIKE $${args.length} OR e.host ILIKE $${args.length} OR e.solver_ip ILIKE $${args.length})`);
    }
    const w = where.join(' AND ');
    const total = await pool.query(`SELECT count(*)::int AS n FROM captcha_events e WHERE ${w}`, args);
    const rows = await pool.query(
      `SELECT e.id::text, e.at, e.ip, e.host, e.result, e.method, e.solver_ip, s.hostname AS server FROM captcha_events e JOIN servers s ON s.id = e.server_id
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
      ? await pool.query('DELETE FROM captcha_events WHERE account_id = ANY($1::uuid[]) AND id = ANY($2::bigint[])', [await scopeAccounts(pool, acc), b.data.ids])
      : await pool.query('DELETE FROM captcha_events WHERE account_id = ANY($1::uuid[])', [await scopeAccounts(pool, acc)]);
    await audit(pool, { accountId: acc, userId: req.user!.id, action: 'captcha.events_deleted', detail: { count: r.rowCount, all: !b.data.ids }, ip: req.ip });
    return { deleted: r.rowCount };
  });

  // Agents fetch the setting when it changed (servers that were offline).
  app.post('/api/agent/captcha/config', { bodyLimit: 16 * 1024 }, async (req, reply) => {
    const r = await signedPayload(pool, req.body, z.object({ version: z.number().int().min(0) }), reply);
    if (!r) return;
    const cur = await load(pool, r.accountId);
    if (cur.version === 0 || cur.version === r.data.version) return { unchanged: true };
    return { config: { version: cur.version, enabled: cur.config.enabled, url: pageUrl, minutes: cur.config.minutes, mode: modeFor(cur.config, r.serverId) } };
  });
}
