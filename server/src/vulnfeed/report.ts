import type { Pool } from '../db.js';

/**
 * The report of the vulnerabilities sent to the servers (owner, 2026-11-13):
 * what was sent when, which servers received it, and what each server did on
 * each website. Used by Master » Plugin Vulnerabilities » Sent to servers and
 * by the connector's vuln_sent tool.
 */

const acted = `count(*) FILTER (WHERE r.action = 'updated')::int AS updated,
      count(*) FILTER (WHERE r.action IN ('shielded', 'shielded_deactivated'))::int AS shielded,
      count(*) FILTER (WHERE r.action IN ('deactivated', 'shielded_deactivated'))::int AS deactivated,
      count(*) FILTER (WHERE r.action IN ('failed', 'manual'))::int AS not_fixed,
      count(*) FILTER (WHERE r.action = 'gone')::int AS gone,
      count(DISTINCT (r.server_id, r.site_path))::int AS sites`;

export const RESULT_FILTERS = ['updated', 'shielded', 'deactivated', 'not_fixed', 'gone'] as const;
export type ResultFilter = (typeof RESULT_FILTERS)[number];

const byAction: Record<ResultFilter, string> = {
  updated: "r.action = 'updated'",
  shielded: "r.action IN ('shielded', 'shielded_deactivated')",
  deactivated: "r.action IN ('deactivated', 'shielded_deactivated')",
  not_fixed: "r.action IN ('failed', 'manual')",
  gone: "r.action = 'gone'",
};

export async function listDispatches(pool: Pool, limit: number, offset: number) {
  const { rows } = await pool.query(
    `SELECT d.id, d.created_at, d.source, d.note, d.count,
       (SELECT count(*)::int FROM vuln_receipts x WHERE x.dispatch_id = d.id) AS servers,
       s.updated, s.shielded, s.deactivated, s.not_fixed, s.gone, s.sites
     FROM vuln_dispatch d
     LEFT JOIN LATERAL (SELECT ${acted} FROM vuln_results r WHERE r.dispatch_id = d.id) s ON true
     ORDER BY d.id DESC LIMIT $1 OFFSET $2`,
    [limit, offset],
  );
  const { rows: t } = await pool.query('SELECT count(*)::int AS n FROM vuln_dispatch');
  return { dispatches: rows, total: t[0].n as number };
}

export async function dispatchDetail(pool: Pool, id: number, advisoryLimit = 2000) {
  const { rows: d } = await pool.query('SELECT id, created_at, source, note, count, seq_from, seq_to FROM vuln_dispatch WHERE id = $1', [id]);
  if (!d[0]) return null;
  const { rows: servers } = await pool.query(
    `SELECT sv.id AS server_id, sv.hostname, x.received_at, coalesce(x.advisories, 0) AS advisories,
       coalesce(s.updated, 0) AS updated, coalesce(s.shielded, 0) AS shielded, coalesce(s.deactivated, 0) AS deactivated,
       coalesce(s.not_fixed, 0) AS not_fixed, coalesce(s.gone, 0) AS gone, coalesce(s.sites, 0) AS sites
     FROM servers sv
     LEFT JOIN vuln_receipts x ON x.server_id = sv.id AND x.dispatch_id = $1
     LEFT JOIN LATERAL (SELECT ${acted} FROM vuln_results r WHERE r.dispatch_id = $1 AND r.server_id = sv.id) s ON true
     WHERE sv.status = 'active' ORDER BY sv.hostname`,
    [id],
  );
  const { rows: advisories } = await pool.query(
    `SELECT f.id, f.kind, f.slug, f.title, f.cvss, f.published,
       count(r.id)::int AS sites, count(r.id) FILTER (WHERE r.action = 'updated')::int AS updated,
       count(r.id) FILTER (WHERE r.action IN ('failed', 'manual'))::int AS not_fixed
     FROM vuln_feed f LEFT JOIN vuln_results r ON r.advisory_id = f.id AND r.dispatch_id = $1
     WHERE f.seq BETWEEN $2 AND $3
     GROUP BY f.id ORDER BY count(r.id) DESC, f.cvss DESC LIMIT $4`,
    [id, d[0].seq_from, d[0].seq_to, advisoryLimit],
  );
  return { dispatch: d[0], servers, advisories };
}

export interface ResultQuery {
  server?: string;
  action?: ResultFilter;
  q?: string;
  limit: number;
  offset: number;
}

export async function dispatchResults(pool: Pool, id: number, f: ResultQuery) {
  const where = ['r.dispatch_id = $1'];
  const args: unknown[] = [id];
  if (f.server) {
    args.push(f.server);
    where.push(`r.server_id = $${args.length}`);
  }
  if (f.action) where.push(byAction[f.action]);
  if (f.q) {
    args.push(f.q.toLowerCase());
    const n = `$${args.length}`;
    where.push(`(strpos(lower(r.domain), ${n}) > 0 OR strpos(lower(r.site_path), ${n}) > 0 OR strpos(lower(r.slug), ${n}) > 0 OR strpos(lower(r.account), ${n}) > 0)`);
  }
  const w = where.join(' AND ');
  const { rows: t } = await pool.query(`SELECT count(*)::int AS n FROM vuln_results r WHERE ${w}`, args);
  args.push(f.limit, f.offset);
  const { rows } = await pool.query(
    `SELECT r.at, sv.hostname, r.server_id, r.domain, r.site_path, r.account, r.kind, r.slug, r.title, r.cvss, r.version, r.action, r.to_version, r.detail
     FROM vuln_results r JOIN servers sv ON sv.id = r.server_id
     WHERE ${w} ORDER BY r.at DESC, r.id DESC LIMIT $${args.length - 1} OFFSET $${args.length}`,
    args,
  );
  return { results: rows, total: t[0].n as number };
}

/** Why sites were not updated, most common first (the connector's summary). */
export async function failureReasons(pool: Pool, id: number, server?: string) {
  const args: unknown[] = [id];
  let w = "r.dispatch_id = $1 AND r.action IN ('failed', 'manual', 'shielded', 'shielded_deactivated', 'deactivated')";
  if (server) {
    args.push(server);
    w += ` AND r.server_id = $${args.length}`;
  }
  const { rows } = await pool.query(
    `SELECT r.action, left(r.detail, 160) AS reason, count(*)::int AS n FROM vuln_results r WHERE ${w}
     GROUP BY 1, 2 ORDER BY n DESC LIMIT 40`,
    args,
  );
  return rows;
}
