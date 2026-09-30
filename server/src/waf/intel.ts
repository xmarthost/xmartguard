import { createHash } from 'node:crypto';
import type { Pool } from '../db.js';

/**
 * WAF fleet intelligence. Agents report the file names of web shells their
 * scanners found; a name found on enough servers (and never restored as a
 * false positive) is blocked by the WAF of every server. The portal also
 * sends virtual patches for plugin vulnerabilities as data: agents write
 * the ModSecurity rules themselves and drop anything that does not validate.
 */

export interface PatchMatch {
  name: string;
  op: 'present' | 'equals' | 'contains' | 'rx';
  value?: string;
}

export interface PortalPatch {
  id: number;
  title: string;
  cve?: string;
  plugin: string;
  path?: string;
  uri?: string;
  method?: 'GET' | 'POST';
  args?: PatchMatch[];
  header?: PatchMatch;
  logged_out?: boolean;
}

/** Virtual patches (ids 7703000-7703999). Agents from 0.14.0 apply them. */
export const PATCHES: PortalPatch[] = [
  { id: 7703001, title: 'WP Automatic SQL injection', cve: 'CVE-2024-27956', plugin: 'WP Automatic', path: '/wp-content/plugins/wp-automatic/inc/csv\\.php$', logged_out: true },
  {
    id: 7703002,
    title: 'Bricks Builder remote code execution',
    cve: 'CVE-2024-25600',
    plugin: 'Bricks Builder',
    uri: '(?:/wp-json/+bricks/v1/render_element|rest_route=/?bricks/v1/render_element)',
    logged_out: true,
  },
  { id: 7703003, title: 'Kaswara Modern VC Addons file upload', cve: 'CVE-2021-24284', plugin: 'Kaswara Modern WPBakery Addons', args: [{ name: 'action', op: 'equals', value: 'uploadFontIcon' }], logged_out: true },
  { id: 7703004, title: 'WooCommerce Payments authentication bypass', cve: 'CVE-2023-28121', plugin: 'WooCommerce Payments', header: { name: 'X-WCPAY-PLATFORM-CHECKOUT-USER', op: 'present' } },
  { id: 7703005, title: 'Social Warfare remote code execution', cve: 'CVE-2019-9978', plugin: 'Social Warfare', args: [{ name: 'swp_debug', op: 'equals', value: 'load_options' }] },
  {
    id: 7703006,
    title: 'WPCargo remote code execution',
    cve: 'CVE-2021-25003',
    plugin: 'WPCargo Track & Trace',
    path: '/wp-content/plugins/wpcargo/includes/barcode\\.php$',
    args: [{ name: 'text', op: 'contains', value: '<?' }],
  },
];

/** File names legitimate software uses everywhere: never blocked by name (same list as the agent). */
const GENERIC = new Set(
  `index admin config configuration settings setting functions function header footer sidebar
  style styles init load loader ajax api upload uploader uploads login logout signin signup user users main home db database
  connect connection cache class common core global globals helper helpers install installer update updater upgrade cron search
  page pages post posts test tests info about contact mail mailer form forms cart checkout product products category image images
  media file files download downloads template templates theme themes plugin plugins widget widgets options option default base
  app application bootstrap autoload router route routes controller model view server client session auth register account
  profile dashboard error errors 404 license readme uninstall activate deactivate xmlrpc wp-config wp-load wp-settings wp-login
  wp-cron wp-blog-header wp-mail wp-signup wp-activate wp-trackback wp-comments-post wp-links-opml functions.inc config.inc
  constants define defines version lang language languages locale redirect proxy feed rss sitemap robots export import backup
  restore payment ipn notify callback webhook webhooks order orders invoice report reports stats status health ping sync
  process handler handlers action actions include includes lib library vendor module modules block blocks data item items
  color colors sapp-wp-signon`
    .split(/\s+/)
    .filter(Boolean)
    .map((n) => `${n}.php`),
);

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,78}\.(?:php[0-9]?|phtml|phar|pht)$/;

/** Whether a file name may be blocked on every server. */
export function nameOK(name: string): boolean {
  const n = name.toLowerCase();
  if (!NAME_RE.test(n) || GENERIC.has(n)) return false;
  const stem = n.slice(0, n.lastIndexOf('.'));
  return stem.length >= 3 && !GENERIC.has(`${stem}.php`);
}

export interface IntelConfig {
  enabled: boolean;
  /** Servers that must have found a name before it is blocked automatically. */
  min_servers: number;
  disabled_patches: number[];
}

export const DEFAULT_INTEL: IntelConfig = { enabled: true, min_servers: 2, disabled_patches: [] };

export async function loadIntelConfig(pool: Pool, accountId: string): Promise<IntelConfig> {
  const { rows } = await pool.query('SELECT config FROM waf_intel_config WHERE account_id = $1', [accountId]);
  return { ...DEFAULT_INTEL, ...((rows[0]?.config as Partial<IntelConfig>) ?? {}) };
}

export type NameStatus = 'active' | 'pending' | 'ignored' | 'not_allowed' | 'false_positive';

export interface LearnedName {
  name: string;
  servers: number;
  reports: number;
  clean_servers: number;
  tails: string[];
  signatures: string[];
  first_seen: string;
  last_seen: string;
  override: 'approved' | 'ignored' | 'added' | null;
  status: NameStatus;
  reason: string;
}

/** Every reported or added name with its state. */
export async function learnedNames(pool: Pool, accountId: string, cfg: IntelConfig): Promise<LearnedName[]> {
  const { rows } = await pool.query(
    `WITH r AS (
       SELECT name,
              count(DISTINCT server_id) FILTER (WHERE NOT clean) AS servers,
              count(DISTINCT server_id) FILTER (WHERE clean) AS clean_servers,
              coalesce(sum(reports) FILTER (WHERE NOT clean), 0) AS reports,
              (array_agg(DISTINCT tail) FILTER (WHERE NOT clean AND tail <> ''))[1:5] AS tails,
              (array_agg(DISTINCT signature) FILTER (WHERE signature <> ''))[1:5] AS signatures,
              min(first_seen) AS first_seen, max(last_seen) AS last_seen
         FROM waf_name_reports WHERE account_id = $1 GROUP BY name)
     SELECT coalesce(r.name, o.name) AS name, coalesce(r.servers, 0) AS servers, coalesce(r.clean_servers, 0) AS clean_servers,
            coalesce(r.reports, 0) AS reports, coalesce(r.tails, '{}') AS tails, coalesce(r.signatures, '{}') AS signatures,
            coalesce(r.first_seen, o.updated_at) AS first_seen, coalesce(r.last_seen, o.updated_at) AS last_seen, o.status AS override
       FROM r FULL JOIN (SELECT name, status, updated_at FROM waf_name_overrides WHERE account_id = $1) o ON o.name = r.name
      ORDER BY last_seen DESC`,
    [accountId],
  );
  return rows.map((r) => {
    const n: LearnedName = {
      name: String(r.name),
      servers: Number(r.servers),
      reports: Number(r.reports),
      clean_servers: Number(r.clean_servers),
      tails: (r.tails as string[]) ?? [],
      signatures: (r.signatures as string[]) ?? [],
      first_seen: new Date(r.first_seen).toISOString(),
      last_seen: new Date(r.last_seen).toISOString(),
      override: (r.override as LearnedName['override']) ?? null,
      status: 'pending',
      reason: '',
    };
    if (!nameOK(n.name)) [n.status, n.reason] = ['not_allowed', 'Too common a name: legitimate software uses it, so it is never blocked by name.'];
    else if (n.override === 'ignored') [n.status, n.reason] = ['ignored', 'Ignored by an administrator.'];
    else if (n.override === 'approved' || n.override === 'added') [n.status, n.reason] = ['active', n.override === 'added' ? 'Added by an administrator.' : 'Approved by an administrator.'];
    else if (n.clean_servers > 0) [n.status, n.reason] = ['false_positive', 'A file with this name was restored as clean on a server: approve it to block the name anyway.'];
    else if (n.servers >= cfg.min_servers) [n.status, n.reason] = ['active', `Found on ${n.servers} server(s).`];
    else [n.status, n.reason] = ['pending', `Found on ${n.servers} of the ${cfg.min_servers} servers needed: approve it to block it now.`];
    return n;
  });
}

export interface Intel {
  etag: string;
  names: string[];
  patches: Omit<PortalPatch, 'plugin'>[];
}

/** What the agents of an account apply. */
export async function intelFor(pool: Pool, accountId: string): Promise<Intel> {
  const cfg = await loadIntelConfig(pool, accountId);
  const names = cfg.enabled ? (await learnedNames(pool, accountId, cfg)).filter((n) => n.status === 'active').map((n) => n.name).sort().slice(0, 3000) : [];
  const patches = cfg.enabled ? PATCHES.filter((p) => !cfg.disabled_patches.includes(p.id)).map(({ plugin: _p, ...p }) => p) : [];
  const etag = createHash('sha256').update(JSON.stringify({ names, patches })).digest('hex').slice(0, 32);
  return { etag, names, patches };
}
