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

/** Feed name on the IPDB entries it adds. */
export const ABUSEIPDB_NOTE = 'abuseipdb';
/** Hours between downloads: the free plan allows 5 blacklist downloads a day. */
export const ABUSEIPDB_EVERY_HOURS = 6;

export interface AbuseIPDBConfig {
  api_key: string;
  enabled: boolean;
  confidence: number; // confidenceMinimum (below 100 needs a paid plan)
  max_ips: number; // limit (free plan: 10,000)
  last_fetch_at: Date | null;
  last_count: number;
  last_error: string;
}

export async function loadAbuseIPDB(pool: Pool): Promise<AbuseIPDBConfig> {
  const { rows } = await pool.query('SELECT api_key, enabled, confidence, max_ips, last_fetch_at, last_count, last_error FROM ipdb_abuseipdb WHERE id = 1');
  return rows[0] ?? { api_key: '', enabled: true, confidence: 100, max_ips: 10000, last_fetch_at: null, last_count: 0, last_error: '' };
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
    const num = (h: string) => (res.headers.get(h) !== null && Number.isFinite(Number(res.headers.get(h))) ? Number(res.headers.get(h)) : undefined);
    return { ok: true, remaining: num('x-ratelimit-remaining'), limit: num('x-ratelimit-limit') };
  } catch (err) {
    return { ok: false, error: `AbuseIPDB cannot be reached: ${(err as Error).message}` };
  }
}

/** Downloads the blacklist (one address per line). */
export async function fetchAbuseIPDB(key: string, confidence: number, maxIPs: number): Promise<{ ips: string[]; error?: string }> {
  try {
    const res = await call(`/blacklist?confidenceMinimum=${confidence}&limit=${maxIPs}`, key, 'text/plain');
    if (!res.ok) return { ips: [], error: await apiError(res) };
    const ips = (await res.text())
      .slice(0, 50 << 20)
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    return { ips };
  } catch (err) {
    return { ips: [], error: `AbuseIPDB cannot be reached: ${(err as Error).message}` };
  }
}
