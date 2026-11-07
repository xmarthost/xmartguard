import { BlockList, isIP } from 'node:net';
import { verifyEd25519 } from './security.js';
import type { Pool } from './db.js';
import { platformAccount } from './tenancy.js';

/**
 * Which proxies may tell the portal a visitor's address (X-Forwarded-For).
 * Trusting every hop let any client pick its own address with a forged
 * header, so per-address limits (login, CAPTCHA, unblock, enrolment) did
 * nothing. Trusted are: this host and private networks (the web server in
 * front of the portal container), Cloudflare's published networks, and the
 * master account's own servers (a server that proxies the CAPTCHA domain).
 */

// Cloudflare's published networks (same list as the agent's WAF).
const CLOUDFLARE = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
  '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];
const LOCAL = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10'];

function blockList(cidrs: string[]): BlockList {
  const b = new BlockList();
  for (const c of cidrs) {
    const [net, bits] = c.split('/');
    b.addSubnet(net, Number(bits), isIP(net) === 6 ? 'ipv6' : 'ipv4');
  }
  return b;
}

const local = blockList(LOCAL);
const cloudflare = blockList(CLOUDFLARE);
let own = new Set<string>();
// The master account's servers' keys (id -> public key): a visitor's address
// signed by the agent of the server that proxied it (agentVisitor).
let ownKeys = new Map<string, string>();
let extra = new Set<string>();

/** A plain address: no IPv4-mapped IPv6 prefix, lower case. */
export function plainIP(a: string): string {
  const s = a.trim().toLowerCase();
  return s.startsWith('::ffff:') && isIP(s.slice(7)) === 4 ? s.slice(7) : s;
}

function has(b: BlockList, a: string): boolean {
  const v = isIP(a);
  return v !== 0 && b.check(a, v === 6 ? 'ipv6' : 'ipv4');
}

export function isCloudflare(addr: string): boolean {
  return has(cloudflare, plainIP(addr));
}

/** trustProxy for Fastify: may this hop tell us who it forwarded for? */
export function trustedProxy(addr: string): boolean {
  const a = plainIP(addr);
  return has(local, a) || has(cloudflare, a) || own.has(a) || extra.has(a);
}

/** Extra proxies from the TRUST_PROXY_IPS setting (comma separated). */
export function setExtraProxies(list: string): void {
  extra = new Set(list.split(/[\s,]+/).map(plainIP).filter((x) => isIP(x)));
}

/** Loads the master account's server addresses (refreshed by the caller). */
export async function refreshOwnProxies(pool: Pool): Promise<void> {
  const acc = await platformAccount(pool);
  if (!acc) {
    own = new Set();
    return;
  }
  const { rows } = await pool.query<{ id: string; primary_ip: string; public_key: string }>(
    "SELECT id, primary_ip, public_key FROM servers WHERE account_id = $1 AND status = 'active'",
    [acc],
  );
  own = new Set(rows.map((r) => plainIP(r.primary_ip)).filter((x) => isIP(x)));
  ownKeys = new Map(rows.map((r) => [r.id, r.public_key]));
}

/** Is addr one of the master account's own servers? */
export function isOwnServer(addr: string): boolean {
  return own.has(plainIP(addr));
}

/** What the agent signs for a visitor it passes on to the portal. */
export function visitorPayload(serverId: string, ip: string, ts: string): string {
  return `xg-visitor-v1:${serverId}:${ip}:${ts}`;
}

/**
 * The visitor's address an agent passed on: a banned or IPDB-listed visitor
 * of the server hosting the portal reaches the portal through that server's
 * agent, and the web server in front of the portal names the agent, not
 * the visitor (every such visitor shared one address: one rate limit, and
 * passes refused as "solved from another address", 2026-11-08). Taken only
 * from one of the master account's servers, signed by its agent's key and
 * fresh: a website hosted on that server cannot name another address.
 */
export function agentVisitor(from: string, header: unknown, nowSec = Math.floor(Date.now() / 1000)): string {
  if (typeof header !== 'string' || !isOwnServer(from)) return '';
  const [ip, ts, serverId, sig] = header.trim().split(' ');
  if (!ip || !ts || !serverId || !sig || !isIP(ip) || !/^\d{1,12}$/.test(ts) || Math.abs(nowSec - Number(ts)) > 120) return '';
  const key = ownKeys.get(serverId);
  if (!key || !verifyEd25519(key, visitorPayload(serverId, ip, ts), sig)) return '';
  return plainIP(ip);
}

/** Tests: set the own servers directly. */
export function setOwnServersForTest(list: { id: string; ip: string; publicKey: string }[]): void {
  own = new Set(list.map((x) => plainIP(x.ip)));
  ownKeys = new Map(list.map((x) => [x.id, x.publicKey]));
}
