import type { Pool } from '../db.js';

/**
 * AbuseIPDB (abuseipdb.com): the portal operator's API key adds AbuseIPDB's
 * blacklist (the most reported addresses worldwide) to the shared IPDB, so
 * every server of every account drops them. The key stays on the portal;
 * agents only receive the merged list.
 */

/** API base (tests point it at a mock). */
export let ABUSEIPDB_API = process.env.ABUSEIPDB_API || 'https://api.abuseipdb.com/api/v2';
export function setAbuseIPDBApi(url: string): void {
  ABUSEIPDB_API = url;
}

/** Feed names on the IPDB entries it adds: the blacklist, and addresses our servers reported that a check confirmed. */
export const ABUSEIPDB_NOTE = 'abuseipdb';
export const ABUSEIPDB_CHECK_NOTE = 'abuseipdb-check';
/** Days an address a check confirmed stays listed (a new report and check renews it). */
export const ABUSEIPDB_CHECK_DAYS = 7;
/** Share of the daily checks the portal uses (the rest is left for the Test button and spare). */
export const ABUSEIPDB_CHECK_SHARE = 0.8;

/**
 * Time between blacklist downloads, from the plan's daily downloads
 * (X-RateLimit-Limit of the blacklist endpoint): the free plan's 5 give
 * every 6 hours, larger plans down to every hour. One download a day is
 * kept spare for "Download now".
 */
export function downloadEveryMs(dailyDownloads: number): number {
  const n = Math.max(2, dailyDownloads || 5) - 1;
  return Math.max(3600_000, Math.ceil((24 * 3600_000) / n));
}

export interface AbuseIPDBConfig {
  api_key: string;
  enabled: boolean;
  confidence: number; // confidenceMinimum (below 100 needs a paid plan)
  max_ips: number; // limit (free plan: 10,000)
  last_fetch_at: Date | null;
  last_count: number;
  last_error: string;
  /** Daily blacklist downloads and checks of the plan (from AbuseIPDB's answers). */
  blacklist_limit: number;
  check_limit: number;
  /** Check new attackers our servers report; list those scoring at least check_min. */
  check_enabled: boolean;
  check_min: number;
  checks_day: string;
  checks_today: number;
}

const COLUMNS = 'api_key, enabled, confidence, max_ips, last_fetch_at, last_count, last_error, blacklist_limit, check_limit, check_enabled, check_min, checks_today';

export async function loadAbuseIPDB(pool: Pool): Promise<AbuseIPDBConfig> {
  const { rows } = await pool.query(`SELECT ${COLUMNS}, checks_day::text AS checks_day FROM ipdb_abuseipdb WHERE id = 1`);
  return (
    rows[0] ?? {
      api_key: '',
      enabled: true,
      confidence: 100,
      max_ips: 10000,
      last_fetch_at: null,
      last_count: 0,
      last_error: '',
      blacklist_limit: 5,
      check_limit: 1000,
      check_enabled: true,
      check_min: 75,
      checks_day: '',
      checks_today: 0,
    }
  );
}

export function keyHint(key: string): string {
  return key ? `${key.slice(0, 4)}…${key.slice(-4)}` : '';
}

async function call(path: string, key: string, accept: string): Promise<Response> {
  return fetch(`${ABUSEIPDB_API}${path}`, { headers: { Key: key, Accept: accept }, signal: AbortSignal.timeout(60_000) });
}

/** The API's own error text ({"errors":[{"detail": ...}]}), else the HTTP status. */
async function apiError(res: Response): Promise<string> {
  const text = (await res.text().catch(() => '')).slice(0, 2000);
  try {
    const d = JSON.parse(text)?.errors?.[0]?.detail;
    if (d) return `${String(d).slice(0, 300)} (HTTP ${res.status})`;
  } catch {
    /* not JSON */
  }
  return res.status === 401 ? 'the API key was refused (HTTP 401)' : res.status === 429 ? 'daily limit reached (HTTP 429)' : `HTTP ${res.status}`;
}

export interface TestResult {
  ok: boolean;
  error?: string;
  /** Daily checks left / allowed (X-RateLimit-* of the check endpoint). */
  remaining?: number;
  limit?: number;
}

/** Proves the key works with one lookup of a public address (uses 1 of the daily checks, no blacklist download). */
export async function testAbuseIPDB(key: string): Promise<TestResult> {
  try {
    const res = await call('/check?ipAddress=1.1.1.1&maxAgeInDays=1', key, 'application/json');
    if (!res.ok) return { ok: false, error: await apiError(res) };
    const body = (await res.json().catch(() => null)) as { data?: { ipAddress?: string } } | null;
    if (!body?.data?.ipAddress) return { ok: false, error: 'unexpected answer from AbuseIPDB' };
    return { ok: true, remaining: header(res, 'x-ratelimit-remaining'), limit: header(res, 'x-ratelimit-limit') };
  } catch (err) {
    return { ok: false, error: `AbuseIPDB cannot be reached: ${(err as Error).message}` };
  }
}

function header(res: Response, name: string): number | undefined {
  const v = res.headers.get(name);
  return v !== null && v !== '' && Number.isFinite(Number(v)) ? Number(v) : undefined;
}

/** Downloads the blacklist (one address per line); limit is the plan's daily downloads. */
export async function fetchAbuseIPDB(key: string, confidence: number, maxIPs: number): Promise<{ ips: string[]; error?: string; limit?: number }> {
  try {
    const res = await call(`/blacklist?confidenceMinimum=${confidence}&limit=${maxIPs}`, key, 'text/plain');
    const limit = header(res, 'x-ratelimit-limit');
    if (!res.ok) return { ips: [], error: await apiError(res), limit };
    const ips = (await res.text())
      .slice(0, 50 << 20)
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    return { ips, limit };
  } catch (err) {
    return { ips: [], error: `AbuseIPDB cannot be reached: ${(err as Error).message}` };
  }
}

export interface CheckResult {
  score?: number;
  whitelisted?: boolean;
  country?: string;
  /** The plan's daily checks and how many are left (rate-limit headers). */
  limit?: number;
  remaining?: number;
  error?: string;
  /** The daily limit is reached: stop checking until tomorrow. */
  exhausted?: boolean;
}

/** Looks one address up (reports of the last 30 days). */
export async function checkAbuseIPDB(key: string, ip: string): Promise<CheckResult> {
  try {
    const res = await call(`/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=30`, key, 'application/json');
    const limit = header(res, 'x-ratelimit-limit');
    const remaining = header(res, 'x-ratelimit-remaining');
    if (!res.ok) return { error: await apiError(res), limit, remaining, exhausted: res.status === 429 || res.status === 401 };
    const body = (await res.json().catch(() => null)) as { data?: { abuseConfidenceScore?: number; isWhitelisted?: boolean; countryCode?: string } } | null;
    const d = body?.data;
    if (!d || typeof d.abuseConfidenceScore !== 'number') return { error: 'unexpected answer from AbuseIPDB', limit, remaining };
    return { score: d.abuseConfidenceScore, whitelisted: !!d.isWhitelisted, country: d.countryCode ?? '', limit, remaining };
  } catch (err) {
    return { error: `AbuseIPDB cannot be reached: ${(err as Error).message}` };
  }
}
