import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import type { FastifyBaseLogger } from 'fastify';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';
import { readZip } from './zip.js';

/** File types the agents' scanner inspects (the known-good list covers these). */
const SCANNED = /\.(php|phtml|inc|js|html|htm|txt|ico|jpg|png|gif)$/i;

export interface WPStatus {
  versions: number;
  stable: number;
  prerelease: number;
  latest: string;
  newest_prerelease: string;
  files: number;
  etag: string;
  synced_at: string | null;
  error: string;
}

/** Numeric sort key for "7.1.2", "6.9-beta1", "6.9-RC2". */
export function versionKey(v: string): number[] {
  const m = /^(\d+)\.(\d+)(?:\.(\d+))?(?:-(beta|RC)(\d+))?$/i.exec(v);
  if (!m) return [0];
  const stage = m[4] ? (m[4].toLowerCase() === 'beta' ? 0 : 1) : 2;
  return [Number(m[1]), Number(m[2]), Number(m[3] ?? 0), stage, Number(m[5] ?? 0)];
}

export function compareVersions(a: string, b: string): number {
  const x = versionKey(a);
  const y = versionKey(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

const isPre = (v: string) => /-(beta|rc)\d+$/i.test(v);

/**
 * Official WordPress core files for the whole fleet: the MD5 of every file of
 * every release (and beta / release candidate) since WP_CORE_MIN_VERSION, so
 * agents never flag official core files, plus a verified cache of the files
 * themselves, from which agents restore infected core files.
 */
export class WPCoreService {
  private timer: NodeJS.Timeout | null = null;
  private running = false;
  private blob: { etag: string; data: Buffer; versions: number; files: number } | null = null;
  private lastError = '';
  private syncedAt: Date | null = null;

  constructor(
    private pool: Pool,
    private cfg: Config,
    private log: FastifyBaseLogger,
  ) {}

  start(): void {
    if (!this.cfg.wpCoreSync) return;
    const tick = () => void this.sync().catch((err) => this.log.warn({ err: (err as Error).message }, 'WordPress core sync failed'));
    setTimeout(tick, 30_000).unref();
    this.timer = setInterval(tick, 12 * 3600_000);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
  }

  private async fetch(url: string, timeoutMs = 60_000): Promise<Response> {
    const res = await fetch(url, { headers: { 'user-agent': 'XMartGuard' }, signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
    return res;
  }

  /** All versions to know: every release since the minimum, plus betas and RCs. */
  async listVersions(): Promise<string[]> {
    const out = new Set<string>();
    const stable = (await (await this.fetch(`${this.cfg.wpApi}/core/stable-check/1.0/`)).json()) as Record<string, string>;
    for (const v of Object.keys(stable)) out.add(v);
    try {
      const html = await (await this.fetch(`${this.cfg.wpSite}/download/releases/`)).text();
      for (const m of html.matchAll(/wordpress-(\d+\.\d+(?:\.\d+)?(?:-(?:beta|RC)\d+)?)\.zip/gi)) out.add(m[1]);
    } catch (err) {
      this.log.warn({ err: (err as Error).message }, 'WordPress releases page unavailable; betas skipped');
    }
    return [...out].filter((v) => versionKey(v).length > 1 && compareVersions(v, this.cfg.wpCoreMinVersion) >= 0).sort(compareVersions);
  }

  /** Official checksums of one version: the checksums API, else the release zip. */
  async fetchChecksums(version: string): Promise<{ sums: Record<string, string>; source: string }> {
    try {
      const r = (await (await this.fetch(`${this.cfg.wpApi}/core/checksums/1.0/?version=${encodeURIComponent(version)}&locale=en_US`)).json()) as {
        checksums?: Record<string, string> | false;
      };
      if (r.checksums && Object.keys(r.checksums).length > 100) return { sums: r.checksums, source: 'api' };
    } catch {
      // Betas and RCs are usually not in the API: use the zip below.
    }
    const zip = Buffer.from(await (await this.fetch(`${this.cfg.wpSite}/wordpress-${version}.zip`, 300_000)).arrayBuffer());
    const sums: Record<string, string> = {};
    for (const e of readZip(zip)) {
      if (e.name.endsWith('/')) continue;
      const rel = e.name.replace(/^wordpress\//, '');
      sums[rel] = crypto.createHash('md5').update(e.data()).digest('hex');
    }
    if (Object.keys(sums).length < 100) throw new Error(`WordPress ${version}: the release zip looks incomplete`);
    return { sums, source: 'zip' };
  }

  async sync(): Promise<{ added: string[] }> {
    if (this.running) return { added: [] };
    this.running = true;
    const added: string[] = [];
    try {
      const versions = await this.listVersions();
      const { rows } = await this.pool.query<{ version: string }>('SELECT version FROM wp_core_versions');
      const have = new Set(rows.map((r) => r.version));
      for (const v of versions) {
        if (have.has(v)) continue;
        try {
          const { sums, source } = await this.fetchChecksums(v);
          await this.store(v, sums, source);
          added.push(v);
        } catch (err) {
          this.log.warn({ version: v, err: (err as Error).message }, 'WordPress checksums unavailable');
        }
      }
      this.lastError = '';
      this.syncedAt = new Date();
      if (added.length || !this.blob) await this.rebuild();
      if (added.length) this.log.info({ added }, 'WordPress core versions added');
      return { added };
    } catch (err) {
      this.lastError = (err as Error).message;
      throw err;
    } finally {
      this.running = false;
    }
  }

  private async store(version: string, sums: Record<string, string>, source: string) {
    await this.pool.query(
      `INSERT INTO wp_core_versions (version, channel, files, checksums, source) VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (version) DO UPDATE SET files = excluded.files, checksums = excluded.checksums, source = excluded.source, fetched_at = now()`,
      [version, isPre(version) ? 'prerelease' : 'stable', Object.keys(sums).length, JSON.stringify(sums), source],
    );
    this.blob = null;
  }

  /** The distributed list: sorted unique MD5 digests, gzip-compressed. */
  async rebuild(): Promise<NonNullable<WPCoreService['blob']>> {
    const { rows } = await this.pool.query<{ checksums: Record<string, string> }>('SELECT checksums FROM wp_core_versions');
    const set = new Set<string>();
    for (const r of rows) for (const [rel, md5] of Object.entries(r.checksums)) if (SCANNED.test(rel) && /^[0-9a-f]{32}$/i.test(md5)) set.add(md5.toLowerCase());
    const sorted = [...set].sort();
    const raw = Buffer.concat(sorted.map((h) => Buffer.from(h, 'hex')));
    const data = zlib.gzipSync(raw, { level: 9 });
    this.blob = { etag: crypto.createHash('sha256').update(raw).digest('hex').slice(0, 32), data, versions: rows.length, files: sorted.length };
    return this.blob;
  }

  async list() {
    return this.blob ?? (await this.rebuild());
  }

  /** Checksums for one version (fetched and stored on first use). */
  async checksums(version: string): Promise<Record<string, string> | null> {
    if (versionKey(version).length < 2) return null;
    const { rows } = await this.pool.query('SELECT checksums FROM wp_core_versions WHERE version = $1', [version]);
    if (rows[0]) return rows[0].checksums;
    try {
      const { sums, source } = await this.fetchChecksums(version);
      await this.store(version, sums, source);
      return sums;
    } catch {
      return null;
    }
  }

  /** The official content of a core file, verified against its MD5 and cached. */
  async file(version: string, rel: string): Promise<Buffer> {
    const sums = await this.checksums(version);
    const want = sums?.[rel];
    if (!want) throw Object.assign(new Error('not a core file of this version'), { status: 404 });
    if (rel.includes('..') || rel.startsWith('/')) throw Object.assign(new Error('invalid path'), { status: 400 });
    const cache = path.join(this.cfg.dataDir, 'wpcore', version, rel);
    const md5 = (b: Buffer) => crypto.createHash('md5').update(b).digest('hex');
    try {
      const b = fs.readFileSync(cache);
      if (md5(b) === want) return b;
    } catch {
      // not cached yet
    }
    let last: Error | null = null;
    for (const url of [`${this.cfg.wpSvn}/${version}/${rel}`, `${this.cfg.wpMirror}/${version}/${rel}`]) {
      try {
        const b = Buffer.from(await (await this.fetch(url)).arrayBuffer());
        if (md5(b) !== want) throw new Error(`${url}: checksum mismatch`);
        fs.mkdirSync(path.dirname(cache), { recursive: true });
        fs.writeFileSync(cache, b);
        return b;
      } catch (err) {
        last = err as Error;
      }
    }
    throw Object.assign(last ?? new Error('file unavailable'), { status: 502 });
  }

  /**
   * Official checksums of a WordPress.org plugin version (cached on disk;
   * premium plugins have none: null, remembered for a day).
   */
  async pluginChecksums(slug: string, version: string): Promise<unknown | null> {
    if (!/^[a-z0-9][a-z0-9._-]{0,99}$/.test(slug) || !/^[0-9][0-9A-Za-z.\-+]{0,40}$/.test(version) || version.includes('..')) return null;
    const file = path.join(this.cfg.dataDir, 'wpplugins', slug, version + '.json');
    try {
      const st = fs.statSync(file);
      const body = fs.readFileSync(file, 'utf8');
      if (body === 'missing') {
        if (Date.now() - st.mtimeMs < 24 * 3600_000) return null;
      } else {
        return JSON.parse(body);
      }
    } catch {
      // not cached
    }
    const res = await fetch(`${this.cfg.wpDownloads}/plugin-checksums/${slug}/${version}.json`, {
      headers: { 'user-agent': 'XMartGuard' },
      signal: AbortSignal.timeout(30_000),
    });
    fs.mkdirSync(path.dirname(file), { recursive: true });
    if (res.status === 404) {
      fs.writeFileSync(file, 'missing');
      return null;
    }
    if (!res.ok) throw new Error(`plugin checksums: HTTP ${res.status}`);
    const doc = (await res.json()) as { files?: Record<string, unknown> };
    if (!doc.files || typeof doc.files !== 'object') throw new Error('plugin checksums: unexpected format');
    fs.writeFileSync(file, JSON.stringify(doc));
    return doc;
  }

  async status(): Promise<WPStatus> {
    const { rows } = await this.pool.query<{ version: string; channel: string }>('SELECT version, channel FROM wp_core_versions');
    const stable = rows.filter((r) => r.channel === 'stable').map((r) => r.version).sort(compareVersions);
    const pre = rows.filter((r) => r.channel !== 'stable').map((r) => r.version).sort(compareVersions);
    const blob = await this.list();
    return {
      versions: rows.length,
      stable: stable.length,
      prerelease: pre.length,
      latest: stable.at(-1) ?? '',
      newest_prerelease: pre.at(-1) ?? '',
      files: blob.files,
      etag: blob.etag,
      synced_at: this.syncedAt?.toISOString() ?? null,
      error: this.lastError,
    };
  }
}
