import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

export interface Config {
  databaseUrl: string;
  host: string;
  port: number;
  /** Public base URL of the portal, used in install commands (no trailing slash). */
  publicUrl: string;
  cookieSecure: boolean;
  trustProxy: boolean;
  /** Directory holding built agent binaries and their .sha256 files. */
  downloadsDir: string;
  /** Directory holding install.sh / uninstall.sh templates. */
  installerDir: string;
  /** Directory holding the built web UI (index.html). Empty disables static serving. */
  webDir: string;
  sessionTtlHours: number;
  enrollTokenTtlHours: number;
  metricsIntervalSeconds: number;
  metricsRetentionDays: number;
  autoUpdateAgents: boolean;
  /** IPDB: list an IP reported by this many different servers... */
  ipdbMinReporters: number;
  /** ...or reported this many times in the window (single-server fleets). */
  ipdbMinReports: number;
  ipdbWindowDays: number;
  /** Community entries expire this long after the last report. */
  ipdbTtlDays: number;
  ipdbMaxEntries: number;
  /** Public blocklist feeds merged into the IPDB (empty disables). */
  ipdbFeeds: string[];
  /** Background IPDB sync with agents (disabled in tests). */
  ipdbSync: boolean;
  /** Writable directory for the GeoIP database. */
  dataDir: string;
  /** Country database (DB-IP Lite, CC BY 4.0); {YYYY}/{MM} are substituted. Empty disables. */
  geoUrl: string;
  adminEmail?: string;
  adminPassword?: string;
  logLevel: string;
  /** AI scanner gateway: seconds per AI API call before trying the next key. */
  aiTimeoutSeconds: number;
  /** Files judged in one AI API request (fewer requests, one copy of the instructions). */
  aiBatchFiles: number;
  /** How long a request waits for more files to share its batch. */
  aiBatchWaitMs: number;
  /** Background retraining of the fleet model (disabled in tests). */
  aiTraining: boolean;
  /** Official WordPress core files: background sync (disabled in tests) and sources. */
  wpCoreSync: boolean;
  wpCoreMinVersion: string;
  wpApi: string;
  wpSite: string;
  wpSvn: string;
  wpMirror: string;
  /** downloads.wordpress.org: official plugin checksums. */
  wpDownloads: string;
  /** Malware signature feeds merged and sent to agents (empty disables). */
  sigFeeds: string[];
  sigSync: boolean;
}

/**
 * Public malware signature feeds (see docs/SIGNATURES.md): Linux Malware
 * Detect's signature pack (MD5 + hex patterns, GPLv2) and the web shell YARA
 * rules of Florian Roth's signature-base (Detection Rule License 1.1).
 * Downloaded by the portal at run
 * time, validated, and sent to agents.
 */
const DEFAULT_SIG_FEEDS = [
  'lmd:https://cdn.rfxn.com/downloads/maldet-sigpack.tgz',
  'yara:https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_webshells.yar',
  'yara:https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-webshells.yar',
].join(',');

function bool(v: string | undefined, def: boolean): boolean {
  if (v === undefined || v === '') return def;
  return ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());
}

function int(v: string | undefined, def: number): number {
  const n = v ? Number.parseInt(v, 10) : NaN;
  return Number.isFinite(n) ? n : def;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const publicUrl = (env.PUBLIC_URL || 'http://localhost:8080').replace(/\/+$/, '');
  const repoRoot = path.resolve(here, '..', '..');
  return {
    databaseUrl: env.DATABASE_URL || 'postgres://xg:xg@localhost:5432/xmartguard',
    host: env.HOST || '0.0.0.0',
    port: int(env.PORT, 8080),
    publicUrl,
    cookieSecure: bool(env.COOKIE_SECURE, publicUrl.startsWith('https://')),
    trustProxy: bool(env.TRUST_PROXY, false),
    downloadsDir: path.resolve(env.DOWNLOADS_DIR || path.join(repoRoot, 'dist', 'downloads')),
    installerDir: path.resolve(env.INSTALLER_DIR || path.join(repoRoot, 'installer')),
    // Empty string disables static UI serving.
    webDir: env.WEB_DIR === '' ? '' : path.resolve(env.WEB_DIR ?? path.join(repoRoot, 'web', 'dist')),
    sessionTtlHours: int(env.SESSION_TTL_HOURS, 24 * 7),
    enrollTokenTtlHours: int(env.ENROLL_TOKEN_TTL_HOURS, 24),
    metricsIntervalSeconds: int(env.METRICS_INTERVAL_SECONDS, 60),
    metricsRetentionDays: int(env.METRICS_RETENTION_DAYS, 35),
    autoUpdateAgents: bool(env.AUTO_UPDATE_AGENTS, true),
    ipdbMinReporters: int(env.IPDB_MIN_REPORTERS, 2),
    ipdbMinReports: int(env.IPDB_MIN_REPORTS, 3),
    ipdbWindowDays: int(env.IPDB_WINDOW_DAYS, 7),
    ipdbTtlDays: int(env.IPDB_TTL_DAYS, 30),
    ipdbMaxEntries: int(env.IPDB_MAX_ENTRIES, 200_000),
    ipdbFeeds: (env.IPDB_FEEDS ?? 'https://www.spamhaus.org/drop/drop_v4.json,https://www.spamhaus.org/drop/drop_v6.json')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    ipdbSync: bool(env.IPDB_SYNC, true),
    dataDir: path.resolve(env.DATA_DIR || path.join(repoRoot, 'data')),
    geoUrl: env.GEO_URL ?? 'https://download.db-ip.com/free/dbip-country-lite-{YYYY}-{MM}.csv.gz',
    adminEmail: env.ADMIN_EMAIL || undefined,
    adminPassword: env.ADMIN_PASSWORD || undefined,
    logLevel: env.LOG_LEVEL || 'info',
    aiTimeoutSeconds: int(env.AI_TIMEOUT_SECONDS, 90),
    aiBatchFiles: int(env.AI_BATCH_FILES, 6),
    aiBatchWaitMs: int(env.AI_BATCH_WAIT_MS, 2500),
    aiTraining: bool(env.AI_TRAINING, true),
    wpCoreSync: bool(env.WP_CORE_SYNC, true),
    wpCoreMinVersion: env.WP_CORE_MIN_VERSION || '5.8',
    wpApi: (env.WP_API || 'https://api.wordpress.org').replace(/\/+$/, ''),
    wpSite: (env.WP_SITE || 'https://wordpress.org').replace(/\/+$/, ''),
    wpSvn: (env.WP_SVN || 'https://core.svn.wordpress.org/tags').replace(/\/+$/, ''),
    wpDownloads: (env.WP_DOWNLOADS || 'https://downloads.wordpress.org').replace(/\/+$/, ''),
    wpMirror: (env.WP_MIRROR || 'https://raw.githubusercontent.com/WordPress/WordPress').replace(/\/+$/, ''),
    sigFeeds: (env.SIG_FEEDS ?? DEFAULT_SIG_FEEDS)
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    sigSync: bool(env.SIG_SYNC, true),
  };
}
