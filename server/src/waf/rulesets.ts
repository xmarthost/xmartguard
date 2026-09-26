import crypto from 'node:crypto';
import { z } from 'zod';
import type { FastifyBaseLogger } from 'fastify';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';
import { readTar } from '../signatures/service.js';

/**
 * WAF Rule Sets: the account's ModSecurity configuration that every server
 * applies (see docs/WAF-RULESETS.md).
 */

export const PRESET_VENDORS = [
  {
    id: 'malware_expert',
    name: 'Malware.Expert ModSecurity rules',
    price: 'Paid (per server or unlimited)',
    url_hint: 'Vendor configuration URL from your Malware.Expert subscription page',
    default_url: '',
    site: 'https://malware.expert/modsecurity-rules/',
    note: 'Commercial rules for WordPress/Joomla/PHP exploits and web shells, updated often. The URL contains your license.',
  },
  {
    id: 'comodo',
    name: 'Comodo WAF (CWAF) free rules',
    price: 'Free (registration)',
    url_hint: 'Apache URL; LiteSpeed servers switch to the LiteSpeed variant automatically',
    default_url: 'https://waf.comodo.com/doc/meta_comodo_apache.yaml',
    site: 'https://waf.comodo.com/',
    note: 'Free rule set, but waf.comodo.com has been unreliable; servers report an error when it cannot be downloaded.',
  },
  {
    id: 'custom',
    name: 'Other cPanel vendor',
    price: 'Depends on the vendor',
    url_hint: 'Any cPanel ModSecurity vendor configuration (YAML) URL',
    default_url: '',
    site: '',
    note: 'For vendors that publish a cPanel vendor YAML (for example a rule set your provider licenses to you).',
  },
] as const;

const Vendor = z.object({
  id: z.string().regex(/^[a-z0-9_-]{2,40}$/),
  name: z.string().trim().min(1).max(80),
  url: z
    .string()
    .trim()
    .max(500)
    .regex(/^https:\/\/[^\s"'<>]+\.ya?ml(?:\?[^\s"'<>]*)?$/i, 'vendor URL must be an https:// link to a .yaml file'),
  enabled: z.boolean(),
});

export const RuleSetsConfig = z.object({
  xmartguard: z.object({ enabled: z.boolean() }),
  crs: z.object({
    enabled: z.boolean(),
    version: z.string().regex(/^(latest|\d+\.\d+\.\d+)$/),
    paranoia: z.number().int().min(1).max(4),
    inbound_threshold: z.number().int().min(3).max(1000),
    outbound_threshold: z.number().int().min(2).max(1000),
  }),
  vendors: z.array(Vendor).max(10),
  custom: z.object({ enabled: z.boolean(), rules: z.string().max(200_000) }),
});
export type RuleSetsConfig = z.infer<typeof RuleSetsConfig>;

export const DEFAULT_CONFIG: RuleSetsConfig = {
  xmartguard: { enabled: true },
  crs: { enabled: false, version: 'latest', paranoia: 1, inbound_threshold: 5, outbound_threshold: 4 },
  vendors: [],
  custom: { enabled: false, rules: '' },
};

const ALLOWED = new Set([
  'secrule', 'secaction', 'secmarker', 'secruleremovebyid', 'secruleremovebytag', 'secruleremovebymsg',
  'secruleupdatetargetbyid', 'secruleupdatetargetbytag', 'secruleupdatetargetbymsg', 'secruleupdateactionbyid',
]);
const FORBIDDEN = /(?:\bexec\s*:|@inspectfile\b|@\w+fromfile\b|\bsetenv\s*:)/i;

/** Same checks as the agent: only ModSecurity rule directives, no command execution. */
export function validateCustomRules(text: string): string | null {
  const logical: string[] = [];
  let cur = '';
  for (const l of text.replace(/\r/g, '').split('\n')) {
    if (l.endsWith('\\')) {
      cur += l.slice(0, -1) + ' ';
      continue;
    }
    logical.push(cur + l);
    cur = '';
  }
  if (cur) logical.push(cur);
  for (let i = 0; i < logical.length; i++) {
    const t = logical[i].trim();
    if (!t || t.startsWith('#')) continue;
    const word = t.split(/\s+/)[0];
    if (!ALLOWED.has(word.toLowerCase())) return `rule ${i + 1}: only SecRule, SecAction, SecMarker and SecRuleRemove…/SecRuleUpdate… directives are allowed (found "${word}")`;
    const bad = t.match(FORBIDDEN);
    if (bad) return `rule ${i + 1}: "${bad[0]}" is not allowed in custom rules`;
    const id = t.match(/\bid\s*:\s*'?(\d+)/);
    if (id && +id[1] >= 7700000 && +id[1] <= 7709999) return `rule ${i + 1}: ids 7700000-7709999 are reserved for XMart Guard`;
  }
  return null;
}

export async function loadConfig(pool: Pool, accountId: string): Promise<{ config: RuleSetsConfig; version: number; updated_at: string | null }> {
  const { rows } = await pool.query('SELECT config, version, updated_at FROM waf_rulesets WHERE account_id = $1', [accountId]);
  if (!rows[0]) return { config: DEFAULT_CONFIG, version: 0, updated_at: null };
  const parsed = RuleSetsConfig.safeParse({ ...DEFAULT_CONFIG, ...rows[0].config });
  return { config: parsed.success ? parsed.data : DEFAULT_CONFIG, version: Number(rows[0].version), updated_at: rows[0].updated_at };
}

const CRS_FILE = /^(crs-setup\.conf\.example|rules\/[A-Za-z0-9._-]+\.(?:conf|data))$/;

interface Release {
  tag_name: string;
  published_at?: string;
  tarball_url?: string;
  assets?: { name: string; browser_download_url: string }[];
}

/** Downloads OWASP CRS releases from the official repository for the agents. */
export class CRSService {
  private timer: NodeJS.Timeout | null = null;
  lastError = '';
  lastCheck: Date | null = null;

  constructor(
    private pool: Pool,
    private cfg: Config,
    private log: FastifyBaseLogger,
  ) {}

  start(): void {
    if (!this.cfg.crsSync) return;
    const tick = () => void this.sync().catch((err) => this.log.warn({ err: (err as Error).message }, 'OWASP CRS sync failed'));
    setTimeout(tick, 60_000).unref();
    this.timer = setInterval(tick, 12 * 3600_000);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
  }

  private async get(url: string, json = false): Promise<any> {
    const res = await fetch(url, {
      headers: { 'user-agent': 'XMartGuard', accept: json ? 'application/vnd.github+json' : '*/*' },
      signal: AbortSignal.timeout(120_000),
    });
    if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
    return json ? res.json() : Buffer.from(await res.arrayBuffer());
  }

  /** Fetches the latest release and every pinned version not yet stored. */
  async sync(): Promise<{ versions: string[] }> {
    this.lastCheck = new Date();
    const want: string[] = ['latest'];
    const { rows } = await this.pool.query(`SELECT DISTINCT config->'crs'->>'version' AS v FROM waf_rulesets WHERE (config->'crs'->>'enabled')::boolean`);
    for (const r of rows) if (r.v && r.v !== 'latest') want.push(r.v);
    const got: string[] = [];
    try {
      for (const w of want) got.push(await this.fetchRelease(w));
      this.lastError = '';
    } catch (err) {
      this.lastError = (err as Error).message;
      throw err;
    }
    // Keep the three newest releases plus pinned ones.
    await this.pool.query(
      `DELETE FROM waf_crs WHERE version NOT IN (SELECT version FROM waf_crs ORDER BY published DESC NULLS LAST, fetched_at DESC LIMIT 3)
         AND version <> ALL($1::text[])`,
      [want.filter((w) => w !== 'latest')],
    );
    return { versions: got };
  }

  async fetchRelease(which: string): Promise<string> {
    const base = `${this.cfg.crsApi}/repos/${this.cfg.crsRepo}/releases`;
    const rel: Release = await this.get(which === 'latest' ? `${base}/latest` : `${base}/tags/v${which}`, true);
    const version = rel.tag_name.replace(/^v/, '');
    if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`unexpected CRS release tag ${rel.tag_name}`);
    const have = await this.pool.query('SELECT 1 FROM waf_crs WHERE version = $1', [version]);
    if (have.rowCount) return version;

    const assets = rel.assets ?? [];
    const minimal = assets.find((a) => /^coreruleset-[\d.]+-minimal\.tar\.gz$/.test(a.name));
    const url = minimal?.browser_download_url ?? rel.tarball_url;
    if (!url) throw new Error(`CRS ${version}: no download`);
    const buf: Buffer = await this.get(url);
    const sumAsset = minimal && assets.find((a) => a.name === minimal.name + '.sha256');
    if (sumAsset) {
      const want = (await this.get(sumAsset.browser_download_url)).toString('utf8').trim().split(/\s+/)[0].toLowerCase();
      const got = crypto.createHash('sha256').update(buf).digest('hex');
      if (want !== got) throw new Error(`CRS ${version}: checksum mismatch`);
    }
    const files: Record<string, string> = {};
    let size = 0;
    for (const [name, body] of readTar(buf)) {
      const rel = name.split('/').slice(1).join('/'); // drop the top folder
      if (!CRS_FILE.test(rel)) continue;
      files[rel] = body.toString('utf8');
      size += body.length;
    }
    if (!files['crs-setup.conf.example'] || !Object.keys(files).some((f) => f.endsWith('.conf') && f.startsWith('rules/'))) {
      throw new Error(`CRS ${version}: the archive has no rule files`);
    }
    await this.pool.query(
      `INSERT INTO waf_crs (version, files, size, source, published) VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (version) DO NOTHING`,
      [version, JSON.stringify(files), size, url, rel.published_at ?? null],
    );
    this.log.info({ version, files: Object.keys(files).length }, 'OWASP CRS release stored');
    return version;
  }

  /** The stored release a configuration uses ("latest" = newest stored). */
  async resolve(which: string): Promise<string | null> {
    const { rows } =
      which === 'latest'
        ? await this.pool.query('SELECT version FROM waf_crs ORDER BY published DESC NULLS LAST, fetched_at DESC LIMIT 1')
        : await this.pool.query('SELECT version FROM waf_crs WHERE version = $1', [which]);
    return rows[0]?.version ?? null;
  }

  async files(version: string): Promise<Record<string, string> | null> {
    const { rows } = await this.pool.query('SELECT files FROM waf_crs WHERE version = $1', [version]);
    return rows[0]?.files ?? null;
  }

  async status() {
    const { rows } = await this.pool.query(
      `SELECT version, size, published, fetched_at, (SELECT count(*)::int FROM jsonb_object_keys(files)) AS files FROM waf_crs ORDER BY published DESC NULLS LAST, fetched_at DESC`,
    );
    return { releases: rows, last_check: this.lastCheck, error: this.lastError, repo: this.cfg.crsRepo };
  }
}
