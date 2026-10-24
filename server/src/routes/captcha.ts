import { isCloudflare, plainIP } from '../proxy.js';
import { createHash } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { BlockList, isIP } from 'node:net';
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
  // Visitors on the IPDB get this check on websites instead of a dropped
  // connection (each server's ipdb.captcha): 'on' / 'off' for the whole
  // fleet, '' each server keeps its own setting.
  ipdb_captcha: z.enum(['', 'on', 'off']).default(''),
});
export type CaptchaConfig = z.infer<typeof CaptchaConfig>;

const DEFAULT: CaptchaConfig = { enabled: false, site_key: '', secret_key: '', minutes: 720, provider: 'auto', strict_ip: false, design: 'classic', countdown: 5, site_servers: [], ipdb_captcha: '' };

/** The setting a server applies (captcha.central, also when it asks). */
export function centralParams(version: number, c: CaptchaConfig, url: string, serverId: string) {
  return { version, enabled: c.enabled, url, minutes: c.minutes, mode: modeFor(c, serverId), ...(c.ipdb_captcha ? { ipdb_captcha: c.ipdb_captcha === 'on' } : {}) };
}

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

export function allowOtherAddress(visitor: string, target: string, now = Date.now(), host = ''): boolean {
  // A shared egress network (iCloud Private Relay, WARP, Meta's agent
  // browsers) is many people: the same person's two addresses there are
  // not "another address", and strangers solving there must not use up
  // one person's allowance (oxannebradley.org, 2026-10-23).
  // Only those networks: a solver passing its /24 neighbours (one hosting
  // network full of bots) still counts.
  const ev = egressNetwork(visitor);
  if (ev !== '' && ev === egressNetwork(target)) return true;
  // Solving from a shared egress address for an address outside it (iCloud
  // Private Relay or WARP for the check, another network for the website):
  // the allowance is per website there, so strangers on the same relay
  // address do not use it up (roxannebradley.org, 2026-10-24: 104.29.x
  // solving for 87.81.x, refused).
  const key = ev !== '' && host !== '' ? `${visitor}|${host}` : visitor;
  const hour = now - 3600_000;
  let m = otherAddresses.get(key);
  if (!m) {
    if (otherAddresses.size > 50_000) otherAddresses.clear();
    m = new Map();
    otherAddresses.set(key, m);
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
 * Networks where one person's traffic moves between addresses of both
 * families: Cloudflare WARP and iCloud Private Relay (a site over IPv4,
 * the check over IPv6), and Meta's cloud (the Muse agent's browser and
 * Meta AI fetch pages from 57.141.0.0/16 and solve from 2a03:2880::/29).
 */
const SHARED_EGRESS: Record<string, string[]> = {
  // 87.81.0.0/16: the website side of iCloud Private Relay visitors who
  // solve the check from Apple's 2606:54c1::/32 (14 websites, 2026-10-24).
  relay: ['104.28.0.0/15', '87.81.0.0/16', '2606:54c1::/32', '2a09:bac0::/29'],
  meta: ['57.141.0.0/16', '2a03:2880::/29'],
};
const sharedEgress = Object.entries(SHARED_EGRESS).map(([name, cidrs]) => {
  const b = new BlockList();
  for (const c of cidrs) {
    const [net, bits] = c.split('/');
    b.addSubnet(net, Number(bits), isIP(net) === 6 ? 'ipv6' : 'ipv4');
  }
  return { name, b };
});

/**
 * The daily ALTCHA allowance is kept per solving and per checked address;
 * on a shared egress network per website as well: thousands of people
 * share each address there, and strangers used up a customer's allowance.
 */
export function altchaKeysFor(solver: string, target: string, host: string): string[] {
  const per = (a: string) => (egressNetwork(a) ? `${a}|${host}` : a);
  return [`s:${per(solver)}`, `t:${per(target)}`];
}

/** The shared egress network an address is in ('' = none). */
export function egressNetwork(a: string): string {
  const x = plainIP(a);
  const v = isIP(x);
  if (!v) return '';
  return sharedEgress.find((e) => e.b.check(x, v === 6 ? 'ipv6' : 'ipv4'))?.name ?? '';
}

/**
 * The visitor's own network for the ALTCHA fallback: the same /24 (IPv4)
 * or /48 (IPv6), where carrier-grade NAT hands out neighbouring
 * addresses, or both in one shared egress network (SHARED_EGRESS).
 */
export function sameNetwork(a: string, b: string): boolean {
  const n = (x: string) => x.toLowerCase().replace(/^::ffff:/, '');
  a = n(a);
  b = n(b);
  const ea = egressNetwork(a);
  if (ea !== '' && ea === egressNetwork(b)) return true;
  if (isIP(a) === 4 && isIP(b) === 4) {
    const pa = a.split('.').map(Number);
    const pb = b.split('.').map(Number);
    return pa[0] === pb[0] && pa[1] === pb[1] && pa[2] === pb[2];
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
    // k=fw: a visitor the server's firewall sent (IPDB, ban).
    k: head.get('k') === 'fw' ? 'fw' : '',
    // The server's CAPTCHA port (site mode): the page sends a browser that
    // reaches it on to the website's own address (see probePage).
    g: /^[0-9]{1,5}$/.test(head.get('g') ?? '') && Number(head.get('g')) > 0 && Number(head.get('g')) < 65536 ? Number(head.get('g')) : 0,
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

/**
 * Whether an ALTCHA answer came with a person's tick: a trusted click (or
 * Space on the box) at least 0.7 s after the page opened and within 30
 * minutes, and pointer movement, a touch or a key press on the page. A
 * page that solved itself (the old auto-start) or a script that posts an
 * answer has none of these.
 */
export function humanTick(raw: string | undefined): boolean {
  if (!raw) return false;
  try {
    const h = JSON.parse(raw) as { t?: unknown; m?: unknown; k?: unknown; tr?: unknown; tc?: unknown };
    const n = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
    return h.tr === true && n(h.t) >= 700 && n(h.t) <= 30 * 60_000 && (n(h.m) >= 2 || h.tc === true || n(h.k) >= 1);
  } catch {
    return false;
  }
}

/**
 * Site mode's first stop: loads a pixel from the server's CAPTCHA port on
 * the website's address and goes on to the check there when it arrives
 * within 3 seconds (pass cookie, no reload), or to the check on this page
 * otherwise. The address and port come from a link the website's server
 * confirmed (captcha.host).
 */
export function probePage(host: string, port: number, back: string, fallback: string): string {
  const js = (v: string) => JSON.stringify(v).replace(/</g, '\\u003c');
  const base = `https://${host}:${port}/.xpguard/`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>One moment…</title></head>
<body style="font-family:system-ui,sans-serif;color:#334155;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><p>One moment…</p>
<script>(function(){var done=false,gate=${js(base + 'gate?back=' + back)},fb=${js(fallback)};
function go(u){if(done)return;done=true;location.replace(u)}
var t=setTimeout(function(){go(fb)},3000),img=new Image();
img.onload=function(){clearTimeout(t);go(gate)};img.onerror=function(){clearTimeout(t);go(fb)};
img.src=${js(base + 'ping.gif?')}+Date.now();})();</script>
<noscript><meta http-equiv="refresh" content="0;url=${fallback.replace(/&/g, '&amp;').replace(/"/g, '&quot;')}"></noscript></body></html>`;
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
  // reason: why a check was refused or failed (shown in the reports).
  async function record(accountId: string, serverId: string, ip: string, host: string, result: string, method = '', solver = '', reason = '', source = '') {
    await pool
      .query('INSERT INTO captcha_events (account_id, server_id, ip, host, result, method, solver_ip, reason, source) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)', [
        accountId,
        serverId,
        ip,
        host.slice(0, 255),
        result,
        method,
        sameIP(solver, ip) ? '' : solver,
        reason.slice(0, 200),
        source,
      ])
      .catch(() => undefined);
    // Kept 30 days (pruned hourly, see index.ts).
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
    // Framed only on the CAPTCHA host when it has its own: a website must
    // never frame a page of the portal's own origin (audit A7 F4).
    const onPortal = !!captchaHost && captchaHost !== new URL(cfg.publicUrl).host.toLowerCase() && (req.headers.host ?? '').toLowerCase() !== captchaHost;
    const frame = !p.preview && p.frame && p.n !== '' && !onPortal;
    const kind = p.k ? { k: p.k } : {};
    const params = p.preview ? { s: p.s, ip: p.ip, h: p.h, u: p.u, preview: true } : frame ? { s: p.s, ip: p.ip, h: p.h, n: p.n, ...kind, u: p.u } : { s: p.s, ip: p.ip, h: p.h, ...kind, u: p.u };
    const design = (p.preview && p.design) || config.design;
    // The page names the website only when its server confirms the site is
    // one of its own: a made-up link can not make this domain show another
    // name (say, a bank's), and a site that is not on the server is refused.
    const site = p.preview ? 'yes' : await siteConfirmed(p.s, p.ip, p.h);
    if (site === 'no') {
      return html(reply, renderPage({ host: '', visitorIp: shownIP(ip, ''), params: null, siteKey: '', error: 'This check link is not valid.' }), 404);
    }
    // Site mode: on to the CAPTCHA port on the website's address when the
    // browser reaches it, otherwise the check here (the server lets the
    // address in like portal mode). A website behind Cloudflare and agents'
    // cloud browsers only reach 80 and 443 (roxannebradley.online, Meta's
    // Muse agent: "refused to connect" on :7743).
    if (p.g && !frame && !p.preview && site === 'yes') {
      return reply
        .code(200)
        .type('text/html; charset=utf-8')
        .header('Cache-Control', 'no-store')
        .header('X-Robots-Tag', 'noindex, nofollow, noarchive')
        .header('X-Frame-Options', 'DENY')
        .header(
          'Content-Security-Policy',
          `default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src https://${p.h.replace(/\.$/, '')}:${p.g}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
        )
        .send(probePage(p.h.replace(/\.$/, ''), p.g, p.u, `${pageUrl}?s=${p.s}&ip=${encodeURIComponent(p.ip)}&h=${p.h}&u=${p.u}`));
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
    // What the visitor did on the page before an ALTCHA answer (humanTick).
    hu: z.string().max(300).optional(),
    // Opened in a frame on the website's own address (see /v).
    n: z.string().regex(/^[a-f0-9]{32}$/).optional(),
    k: z.enum(['fw']).optional(),
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
      // A visitor the server's firewall sent (IPDB, ban): told apart in the reports.
      const source = b.data.k === 'fw' ? 'firewall' : '';
      const rec = (result: string, method: string, solver: string, reason = '') => record(accountId, p.s, p.ip, p.h, result, method, solver, reason, source);
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
        const strict = config.strict_ip && sameFamily;
        if (other && (strict || !allowOtherAddress(ip, p.ip, Date.now(), p.h))) {
          await rec('rejected', method, ip, strict ? 'solved from another address (strict setting)' : 'solver passed too many other addresses this hour');
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
        const altchaKeys = altchaKeysFor(ip, p.ip, p.h);
        if (method === 'altcha' && provider !== 'turnstile') {
          const elsewhere = provider === 'auto' && other && sameFamily && !sameNetwork(ip, p.ip);
          if (elsewhere || !altchaAllowed(altchaKeys, provider === 'auto' ? 'auto' : 'altcha')) {
            await rec('rejected', method, ip, elsewhere ? 'ALTCHA from another network' : 'ALTCHA daily limit');
            return res(403, { error: 'Too many checks from this address. Please try again later.' });
          }
          // Not on a privacy relay (iCloud Private Relay, WARP, Meta's agent
          // browsers): AbuseIPDB calls those data centres, but they are
          // people (Private Relay visitors were refused on 14 websites).
          if (provider === 'auto' && egressNetwork(ip) === '' && (await hostingAddress(pool, ip))) {
            await rec('rejected', method, ip, 'ALTCHA from a hosting network');
            return res(403, { error: 'This check cannot be completed from a hosting or cloud network. Please open the website from your own connection.' });
          }
        }
        // ALTCHA is proof of work a script solves as well as a browser: the
        // box must have been ticked by a person (a real click or key press,
        // not at once, with some pointer, touch or key activity).
        if (method === 'altcha' && !humanTick(b.data.hu)) {
          await rec('failed', method, ip, 'box not ticked by a person');
          return res(403, { error: 'Please tick the box yourself to confirm you are human.' });
        }
        // Solved from a data centre for another address: CAPTCHA farms solve
        // for bots on proxy addresses (glasgowfitness.com: one proxy address
        // passed every few minutes from DigitalOcean and hosting addresses).
        if (other && egressNetwork(ip) === '' && (await hostingAddress(pool, ip))) {
          await rec('rejected', method, ip, 'solved from a hosting network for another address');
          return res(403, { error: 'This check cannot be completed from a hosting or cloud network. Please open the website from your own connection.' });
        }
        if (!(await solved())) {
          await rec('failed', method, ip, 'wrong answer');
          return res(403, { error: 'The check failed. Please try again.' });
        }
        // An agent reconnecting (update, WAF reload, network blip) is back
        // within seconds: wait for it rather than throw the solved check away.
        for (const end = Date.now() + offlineWait.ms; !hub.isOnline(p.s) && Date.now() < end; ) {
          await new Promise((r) => setTimeout(r, 500));
        }
        if (!hub.isOnline(p.s)) {
          await rec('offline', method, ip, 'website server offline');
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
          await rec('rejected', method, ip, 'server refused: ' + (e as Error).message);
          req.log.warn({ err: (e as Error).message, server: p.s, host: p.h }, 'captcha pass refused');
          return res(403, { error: 'This website could not confirm the check. Please try again later.' });
        }
        if (method === 'altcha') noteAltchaPass(altchaKeys);
        await rec('passed', method, ip);
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
        ipdb_captcha: cur.config.ipdb_captcha,
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
    ipdb_captcha: z.enum(['', 'on', 'off']).default(''),
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
      void hub.command(s.id, 'captcha.central', centralParams(version, c, pageUrl, s.id), 120_000).catch(() => undefined);
    }
    return { version, pushed, offline };
  });

  // Clear the list of checks (e.g. after trying the page out).
  // The recorded checks, newest first, a page at a time.
  const Events = z.object({
    limit: z.coerce.number().int().refine((n) => [25, 50, 100, 200].includes(n)).default(50),
    offset: z.coerce.number().int().min(0).default(0),
    result: z.enum(['', 'passed', 'failed', 'rejected', 'offline']).default(''),
    // firewall: visitors the servers' firewalls sent (IPDB, bans); login:
    // the login pages' suspects.
    source: z.enum(['', 'firewall', 'login']).default(''),
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
    if (f.data.source) where.push(f.data.source === 'firewall' ? "e.source = 'firewall'" : "e.source = ''");
    if (f.data.q) {
      args.push(`%${f.data.q.replace(/[\\%_]/g, (c) => '\\' + c)}%`);
      where.push(`(e.ip ILIKE $${args.length} OR e.host ILIKE $${args.length} OR e.solver_ip ILIKE $${args.length})`);
    }
    const w = where.join(' AND ');
    const total = await pool.query(`SELECT count(*)::int AS n FROM captcha_events e WHERE ${w}`, args);
    const rows = await pool.query(
      `SELECT e.id::text, e.at, e.ip, e.host, e.result, e.method, e.solver_ip, e.reason, e.source, s.hostname AS server FROM captcha_events e JOIN servers s ON s.id = e.server_id
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
    return { config: centralParams(cur.version, cur.config, pageUrl, r.serverId) };
  });
}
