import type { Pool } from './db.js';

/**
 * Accounts: the platform account runs the portal; customer accounts (made
 * by the website's billing) see only their own servers and use the
 * platform's master settings (AI, CAPTCHA page, keys, WAF rule sets,
 * trusted services, appearance), which only the platform can change.
 */
let cached: { id: string | null; at: number } | null = null;

export async function platformAccount(pool: Pool): Promise<string | null> {
  if (cached && Date.now() - cached.at < 30_000) return cached.id;
  const { rows } = await pool.query('SELECT id FROM accounts WHERE platform ORDER BY created_at LIMIT 1');
  cached = { id: rows[0] ? String(rows[0].id) : null, at: Date.now() };
  return cached.id;
}

/** Forget the cached platform account (tests, first owner created). */
export function resetTenancyCache(): void {
  cached = null;
}

/** The account whose master settings apply to an account's servers. */
export async function masterAccount(pool: Pool, accountId: string): Promise<string> {
  return (await platformAccount(pool)) ?? accountId;
}

export async function isPlatform(pool: Pool, accountId: string): Promise<boolean> {
  const p = await platformAccount(pool);
  return p === null || p === accountId;
}

/**
 * The accounts whose servers a master setting reaches: every account for
 * the platform, only its own for a customer.
 */
export async function scopeAccounts(pool: Pool, accountId: string): Promise<string[]> {
  if (!(await isPlatform(pool, accountId))) return [accountId];
  const { rows } = await pool.query('SELECT id FROM accounts');
  return rows.map((r) => String(r.id));
}
