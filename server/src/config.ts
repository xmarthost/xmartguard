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
  adminEmail?: string;
  adminPassword?: string;
  logLevel: string;
}

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
    adminEmail: env.ADMIN_EMAIL || undefined,
    adminPassword: env.ADMIN_PASSWORD || undefined,
    logLevel: env.LOG_LEVEL || 'info',
  };
}
