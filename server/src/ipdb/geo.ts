import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import net from 'node:net';
import type { FastifyBaseLogger } from 'fastify';

/**
 * IP -> country lookups from a range CSV ("start,end,CC" per line; the
 * DB-IP Lite country format). Held in memory as sorted range arrays.
 */
export class GeoDB {
  private v4s = new Uint32Array(0);
  private v4e = new Uint32Array(0);
  private v4c: string[] = [];
  private v6s: bigint[] = [];
  private v6e: bigint[] = [];
  private v6c: string[] = [];
  loadedAt: Date | null = null;

  get size(): number {
    return this.v4c.length + this.v6c.length;
  }

  /** Parses the CSV text, replacing the current data. */
  load(text: string): number {
    const r4: [number, number, string][] = [];
    const r6: [bigint, bigint, string][] = [];
    for (const line of text.split('\n')) {
      const f = line.trim().split(',');
      if (f.length < 3) continue;
      const cc = f[2].replace(/"/g, '').trim().toUpperCase();
      const a = f[0].replace(/"/g, '');
      const b = f[1].replace(/"/g, '');
      if (cc.length !== 2) continue;
      if (net.isIPv4(a) && net.isIPv4(b)) r4.push([v4num(a), v4num(b), cc]);
      else if (net.isIPv6(a) && net.isIPv6(b)) r6.push([v6num(a), v6num(b), cc]);
    }
    r4.sort((x, y) => x[0] - y[0]);
    r6.sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
    this.v4s = Uint32Array.from(r4.map((r) => r[0]));
    this.v4e = Uint32Array.from(r4.map((r) => r[1]));
    this.v4c = r4.map((r) => r[2]);
    this.v6s = r6.map((r) => r[0]);
    this.v6e = r6.map((r) => r[1]);
    this.v6c = r6.map((r) => r[2]);
    this.loadedAt = new Date();
    return this.size;
  }

  /** Country code for an IP or CIDR (its network address), or ''. */
  lookup(addr: string): string {
    const ip = addr.split('/')[0];
    if (net.isIPv4(ip)) {
      const n = v4num(ip);
      const i = upper(this.v4s.length, (k) => this.v4s[k] > n) - 1;
      return i >= 0 && n <= this.v4e[i] ? this.v4c[i] : '';
    }
    if (net.isIPv6(ip)) {
      const n = v6num(ip);
      const i = upper(this.v6s.length, (k) => this.v6s[k] > n) - 1;
      return i >= 0 && n <= this.v6e[i] ? this.v6c[i] : '';
    }
    return '';
  }
}

/** First index for which pred is true (pred is monotonic). */
function upper(n: number, pred: (i: number) => boolean): number {
  let lo = 0;
  let hi = n;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (pred(mid)) hi = mid;
    else lo = mid + 1;
  }
  return lo;
}

export function v4num(ip: string): number {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

export function v6num(ip: string): bigint {
  let s = ip.toLowerCase();
  // Embedded IPv4 (::ffff:1.2.3.4).
  const m = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (m) {
    const n = v4num(m[2]);
    s = `${m[1]}${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const [head, tail] = s.split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail !== '' ? tail.split(':') : [];
  const groups = tail === undefined ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  let n = 0n;
  for (const g of groups) n = (n << 16n) + BigInt(parseInt(g || '0', 16));
  return n;
}

/**
 * Loads the country database from <dir>/geo-country.csv.gz and refreshes it
 * from `url` when missing or older than 30 days. Failures only disable
 * country names; the IPDB keeps working.
 */
export async function initGeo(geo: GeoDB, dir: string, url: string, log: FastifyBaseLogger): Promise<void> {
  const file = path.join(dir, 'geo-country.csv.gz');
  const loadFile = () => {
    try {
      const n = geo.load(zlib.gunzipSync(fs.readFileSync(file)).toString('utf8'));
      log.info({ ranges: n }, 'geoip database loaded');
    } catch (err) {
      log.warn({ err: (err as Error).message }, 'geoip database could not be loaded');
    }
  };
  let fresh = false;
  try {
    fresh = Date.now() - fs.statSync(file).mtimeMs < 30 * 86400_000;
    loadFile();
  } catch {
    /* not downloaded yet */
  }
  if (fresh || !url) return;
  const now = new Date();
  for (const back of [0, 1]) {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - back, 1));
    const u = url
      .replace('{YYYY}', String(d.getUTCFullYear()))
      .replace('{MM}', String(d.getUTCMonth() + 1).padStart(2, '0'));
    try {
      const res = await fetch(u, { signal: AbortSignal.timeout(120_000) });
      if (!res.ok) continue;
      const body = Buffer.from(await res.arrayBuffer());
      zlib.gunzipSync(body); // validate before replacing
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(file + '.tmp', body);
      fs.renameSync(file + '.tmp', file);
      loadFile();
      return;
    } catch (err) {
      log.warn({ url: u, err: (err as Error).message }, 'geoip download failed');
    }
  }
}
