import crypto from 'node:crypto';
import zlib from 'node:zlib';
import type { FastifyBaseLogger } from 'fastify';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';

export interface Bundle {
  /** [md5, size, name] of known malware files. */
  md5: [string, number, string][];
  /** [hex pattern, name]: byte patterns found in malware. */
  hex: [string, string][];
  /** YARA rule files: name -> self-contained source (includes resolved). */
  yara: { name: string; text: string }[];
}

/** Reads a (gzip-compressed) tar archive: path -> content. */
export function readTar(buf: Buffer): Map<string, Buffer> {
  const data = buf[0] === 0x1f && buf[1] === 0x8b ? zlib.gunzipSync(buf, { maxOutputLength: 512 << 20 }) : buf;
  const out = new Map<string, Buffer>();
  let p = 0;
  let longName = '';
  while (p + 512 <= data.length) {
    const h = data.subarray(p, p + 512);
    if (h.every((b) => b === 0)) break;
    const field = (a: number, b: number) => h.toString('latin1', a, b).replace(/\0.*$/s, '');
    let name = field(0, 100);
    const prefix = field(345, 500);
    if (prefix) name = prefix + '/' + name;
    const size = parseInt(field(124, 136).trim() || '0', 8);
    const type = String.fromCharCode(h[156] || 48);
    const body = data.subarray(p + 512, p + 512 + size);
    if (type === 'L') longName = body.toString('utf8').replace(/\0.*$/s, '');
    else {
      if (longName) (name = longName), (longName = '');
      if (type === '0' || type === '\0') out.set(name, Buffer.from(body));
    }
    p += 512 + Math.ceil(size / 512) * 512;
  }
  return out;
}

/** Parses LMD's md5v2.dat / md5.dat ("md5:size:{MD5}name" or "md5:name"). */
export function parseLMDMD5(text: string): Bundle['md5'] {
  const out: Bundle['md5'] = [];
  for (const line of text.split('\n')) {
    const parts = line.trim().split(':');
    if (parts.length < 2 || !/^[0-9a-f]{32}$/i.test(parts[0])) continue;
    const size = parts.length >= 3 ? Number(parts[1]) : 0;
    const name = (parts.length >= 3 ? parts.slice(2).join(':') : parts[1]).replace(/^\{MD5\}/, '');
    if (!Number.isFinite(size) || size < 0) continue;
    out.push([parts[0].toLowerCase(), size, name.slice(0, 120)]);
  }
  return out;
}

/** Parses LMD's hex.dat ("hexpattern:{HEX}name"); keeps plain, distinctive patterns. */
export function parseLMDHex(text: string): Bundle['hex'] {
  const out: Bundle['hex'] = [];
  for (const line of text.split('\n')) {
    const i = line.indexOf(':');
    if (i < 0) continue;
    const hex = line.slice(0, i).trim().toLowerCase();
    const name = line.slice(i + 1).trim().replace(/^\{HEX\}/, '');
    // At least 16 bytes, so short common strings cannot match legitimate code.
    if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 || hex.length < 32) continue;
    out.push([hex, name.slice(0, 120)]);
  }
  return out;
}

/** Inlines `include` files (relative to the URL) and hoists `import` lines. */
export async function flattenYara(url: string, get: (u: string) => Promise<string>): Promise<string> {
  const imports: string[] = [];
  const seen = new Set<string>();
  const flat = async (u: string, depth: number): Promise<string> => {
    if (seen.has(u) || depth > 5 || seen.size > 60) return '';
    seen.add(u);
    const out: string[] = [];
    for (const line of (await get(u)).split('\n')) {
      const inc = /^\s*include\s+"([^"]+)"/.exec(line);
      if (inc) {
        out.push(await flat(new URL(inc[1], u).toString(), depth + 1));
        continue;
      }
      const imp = /^\s*import\s+"([^"]+)"/.exec(line);
      if (imp) {
        if (!imports.includes(imp[1])) imports.push(imp[1]);
        continue;
      }
      out.push(line);
    }
    return out.join('\n');
  };
  const body = await flat(url, 0);
  return imports.map((i) => `import "${i}"`).join('\n') + '\n' + body;
}

/**
 * Public malware signature feeds, downloaded daily and sent to agents:
 * Linux Malware Detect (MD5 + hex) and YARA rule files.
 */
export class SignatureService {
  private timer: NodeJS.Timeout | null = null;
  private merged: { etag: string; bundle: Bundle } | null = null;

  constructor(
    private pool: Pool,
    private cfg: Config,
    private log: FastifyBaseLogger,
  ) {}

  start(): void {
    if (!this.cfg.sigSync || this.cfg.sigFeeds.length === 0) return;
    const tick = () => void this.sync().catch((err) => this.log.warn({ err: (err as Error).message }, 'signature sync failed'));
    setTimeout(tick, 45_000).unref();
    this.timer = setInterval(tick, 24 * 3600_000);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
  }

  private async get(url: string): Promise<Buffer> {
    const res = await fetch(url, { headers: { 'user-agent': 'XMartGuard' }, signal: AbortSignal.timeout(120_000) });
    if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  }

  async fetchFeed(kind: string, url: string): Promise<Bundle> {
    const b: Bundle = { md5: [], hex: [], yara: [] };
    if (kind === 'lmd') {
      const files = readTar(await this.get(url));
      for (const [name, body] of files) {
        const base = name.split('/').pop() ?? '';
        if (base === 'md5v2.dat' || base === 'md5.dat') b.md5.push(...parseLMDMD5(body.toString('latin1')));
        else if (base === 'hex.dat') b.hex.push(...parseLMDHex(body.toString('latin1')));
        else if (base === 'rfxn.yara' || base === 'custom.yara') b.yara.push({ name: 'lmd-' + base.replace(/\W+/g, '-'), text: body.toString('utf8') });
      }
      if (b.md5.length + b.hex.length === 0) throw new Error('no LMD signatures found in the archive');
    } else if (kind === 'yara') {
      const text = await flattenYara(url, async (u) => (await this.get(u)).toString('utf8'));
      if (!/\brule\s+\w+/.test(text)) throw new Error('no YARA rules in the file');
      const name = (new URL(url).pathname.split('/').pop() ?? 'rules').replace(/\.(yara?|txt)$/i, '').replace(/\W+/g, '-');
      b.yara.push({ name, text });
    } else {
      throw new Error(`unknown feed kind ${kind}`);
    }
    return b;
  }

  async sync(): Promise<{ url: string; ok: boolean; error?: string }[]> {
    const results: { url: string; ok: boolean; error?: string }[] = [];
    for (const f of this.cfg.sigFeeds) {
      const i = f.indexOf(':');
      const kind = f.slice(0, i);
      const url = f.slice(i + 1);
      try {
        const bundle = await this.fetchFeed(kind, url);
        const etag = crypto.createHash('sha256').update(JSON.stringify(bundle)).digest('hex').slice(0, 32);
        const counts = { md5: bundle.md5.length, hex: bundle.hex.length, yara: bundle.yara.length };
        await this.pool.query(
          `INSERT INTO sig_feeds (url, kind, etag, bundle, counts, error, fetched_at) VALUES ($1,$2,$3,$4,$5,'',now())
           ON CONFLICT (url) DO UPDATE SET kind = excluded.kind, etag = excluded.etag, bundle = excluded.bundle,
             counts = excluded.counts, error = '', fetched_at = now()`,
          [url, kind, etag, JSON.stringify(bundle), JSON.stringify(counts)],
        );
        results.push({ url, ok: true });
      } catch (err) {
        // Keep the last good copy; record the error.
        await this.pool.query(
          `INSERT INTO sig_feeds (url, kind, error) VALUES ($1,$2,$3) ON CONFLICT (url) DO UPDATE SET error = excluded.error`,
          [url, kind, (err as Error).message.slice(0, 300)],
        );
        results.push({ url, ok: false, error: (err as Error).message });
      }
    }
    this.merged = null;
    return results;
  }

  /** All feeds merged, as sent to agents. */
  async bundle(): Promise<{ etag: string; bundle: Bundle }> {
    if (this.merged) return this.merged;
    const urls = this.cfg.sigFeeds.map((f) => f.slice(f.indexOf(':') + 1));
    const { rows } = await this.pool.query('SELECT url, bundle FROM sig_feeds WHERE url = ANY($1) ORDER BY url', [urls]);
    const b: Bundle = { md5: [], hex: [], yara: [] };
    for (const r of rows) {
      b.md5.push(...(r.bundle.md5 ?? []));
      b.hex.push(...(r.bundle.hex ?? []));
      b.yara.push(...(r.bundle.yara ?? []));
    }
    const etag = b.md5.length + b.hex.length + b.yara.length ? crypto.createHash('sha256').update(JSON.stringify(b)).digest('hex').slice(0, 32) : '';
    this.merged = { etag, bundle: b };
    return this.merged;
  }

  async status() {
    const { rows } = await this.pool.query('SELECT url, kind, counts, error, fetched_at FROM sig_feeds ORDER BY url');
    const byUrl = new Map(rows.map((r) => [r.url, r]));
    return {
      feeds: this.cfg.sigFeeds.map((f) => {
        const url = f.slice(f.indexOf(':') + 1);
        const r = byUrl.get(url);
        return { url, kind: f.slice(0, f.indexOf(':')), counts: r?.counts ?? {}, error: r?.error ?? '', fetched_at: r?.fetched_at ?? null };
      }),
      etag: (await this.bundle()).etag,
    };
  }
}
