import net from 'node:net';

/**
 * Shared egress networks: one address carries thousands of people (iCloud
 * Private Relay, Meta's crawlers, in-app and agent browsers). A ban there
 * stays on the server that made it; the fleet's list leaves them out, or
 * one person's mistakes (or one stranger's attack) would send every Safari
 * visitor of every website to the CAPTCHA. Private Relay is Apple's own
 * published list (RELAY_URL): Cloudflare's WARP, a free VPN anyone runs,
 * shares Cloudflare's ranges and stays listable.
 */

/** Apple's iCloud Private Relay egress ranges (CSV: range,country,region,city,). */
export const RELAY_URL = 'https://mask-api.icloud.com/egress-ip-ranges.csv';
/** A download with fewer ranges is not taken (an error page, a cut file). */
export const RELAY_MIN_RANGES = 1000;
/** Meta's own networks (crawlers, link previews, in-app and agent browsers). */
export const META_RANGES = ['57.141.0.0/16', '2a03:2880::/29'];

type Range = [bigint, bigint];

function bounds(cidr: string): { fam: 4 | 6; lo: bigint; hi: bigint } | null {
  const [addr, len] = cidr.trim().split('/');
  const fam = net.isIP(addr);
  if (!fam) return null;
  const bits = fam === 4 ? 32 : 128;
  const n = len === undefined ? bits : Number(len);
  if (!Number.isInteger(n) || n < 0 || n > bits) return null;
  let v = 0n;
  if (fam === 4) {
    for (const p of addr.split('.')) v = (v << 8n) | BigInt(Number(p));
  } else {
    const [l, r = ''] = addr.toLowerCase().split('::');
    const left = l ? l.split(':') : [];
    const right = r ? r.split(':') : [];
    if (right.length && right[right.length - 1].includes('.')) return null; // no embedded IPv4 here
    const groups = addr.includes('::') ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
    for (const g of groups) v = (v << 16n) | BigInt(parseInt(g || '0', 16));
  }
  const host = (1n << BigInt(bits - n)) - 1n;
  return { fam: fam as 4 | 6, lo: v & ~host, hi: (v & ~host) | host };
}

/** Sorted, merged ranges per family, looked up by binary search. */
export class SharedEgress {
  private v4: Range[] = [];
  private v6: Range[] = [];
  relayRanges = 0;

  constructor(relay: string[] = []) {
    this.set(relay);
  }

  /** Replaces the Private Relay ranges (Meta's stay). */
  set(relay: string[]): void {
    const v4: Range[] = [];
    const v6: Range[] = [];
    const add = (c: string): boolean => {
      const b = bounds(c);
      if (b) (b.fam === 4 ? v4 : v6).push([b.lo, b.hi]);
      return b !== null;
    };
    META_RANGES.forEach(add);
    this.relayRanges = relay.filter(add).length;
    this.v4 = merge(v4);
    this.v6 = merge(v6);
  }

  /** True when the whole address or network lies in a shared egress network. */
  has(cidr: string): boolean {
    const b = bounds(cidr);
    if (!b) return false;
    const rs = b.fam === 4 ? this.v4 : this.v6;
    let lo = 0;
    let hi = rs.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (rs[mid][1] < b.lo) lo = mid + 1;
      else if (rs[mid][0] > b.lo) hi = mid - 1;
      else return b.hi <= rs[mid][1];
    }
    return false;
  }
}

function merge(rs: Range[]): Range[] {
  rs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const out: Range[] = [];
  for (const r of rs) {
    const last = out[out.length - 1];
    if (last && r[0] <= last[1] + 1n) {
      if (r[1] > last[1]) last[1] = r[1];
    } else out.push([r[0], r[1]]);
  }
  return out;
}

/** The ranges of Apple's CSV (first column), invalid lines skipped. */
export function parseRelayCSV(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split('\n')) {
    const c = line.split(',')[0]?.trim() ?? '';
    if (c && bounds(c)) out.push(c);
  }
  return out;
}
