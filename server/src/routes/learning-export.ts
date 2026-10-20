import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import { CommandError, type AgentHub } from '../agents/hub.js';
import { audit, requirePlatform } from '../auth.js';

/**
 * xPGuard Learning (master): exports for reviewing how the rules behave on
 * every server. Each file holds, per server, its settings, every WAF rule
 * (or detection signature) with its count in the window, and a few
 * examples of each from different sites and files, so a busy server or a
 * noisy rule cannot fill the file. Servers share the size limit equally.
 */

export const MAX_EXPORT_BYTES = 25 * 1024 * 1024;

const Query = z.object({
  kind: z.enum(['waf', 'detections']),
  hours: z.coerce.number().int().min(1).max(336).default(12),
});

const WAF_COLUMNS = ['row_type', 'server', 'server_version', 'control_panel', 'waf_enabled', 'waf_level', 'auto_exclusions', 'window_hours',
  'rule_id', 'rule_msg', 'rule_action', 'rule_total', 'rule_ips', 'rule_hosts', 'time', 'method', 'host', 'uri', 'ip', 'user', 'category',
  'action', 'matched', 'note'];

const DET_COLUMNS = ['row_type', 'server', 'server_version', 'control_panel', 'virus_action', 'suspicious_action', 'binary_action',
  'ai_provider', 'window_hours', 'signature', 'category', 'status', 'sig_total', 'sig_files', 'first_seen', 'last_seen', 'path', 'owner',
  'size', 'sha256', 'source', 'repeats', 'clean_note', 'ai_verdict', 'ai_confidence', 'ai_model', 'ai_reason', 'match_line', 'matched_code',
  'note'];

/**
 * One CSV cell. Text that a spreadsheet would run as a formula (starting
 * with = + - @, tab or CR) gets a leading ' (OWASP CSV injection rule): file
 * names, matched code and request URIs come from attackers, and the master
 * opens these files in a spreadsheet. Numbers and dates stay as they are.
 */
export function csvCell(v: unknown): string {
  if (v === undefined || v === null) return '';
  let s = v instanceof Date ? v.toISOString() : String(v);
  if (typeof v === 'string' && /^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
const cell = csvCell;

function line(cols: string[], r: Record<string, unknown>): string {
  return cols.map((c) => cell(r[c])).join(',') + '\n';
}

const iso = (t?: number) => (t ? new Date(t * 1000).toISOString() : '');

interface ServerRow {
  id: string;
  hostname: string;
  agent_version: string | null;
  control_panel: string | null;
}

interface Sample {
  server: Record<string, unknown>;
  waf_groups?: { rule_id: number; msg: string; action: string; count: number; ips: number; hosts: number }[];
  waf_events?: { at: number; ip: string; method: string; host: string; uri: string; rule_id: number; msg: string; category: string; action: string; user: string; detail: string }[];
  sig_groups?: { signature: string; category: string; status: string; count: number; files: number }[];
  detections?: Record<string, any>[];
}

/** Rows for one server, its settings row and group rows first, examples while the budget lasts. */
export function serverRows(kind: 'waf' | 'detections', srv: ServerRow, hours: number, s: Sample | null, note: string, budget: number): string {
  const cols = kind === 'waf' ? WAF_COLUMNS : DET_COLUMNS;
  const info = s?.server ?? {};
  const base: Record<string, unknown> = {
    server: srv.hostname,
    server_version: info.version ?? srv.agent_version ?? '',
    control_panel: srv.control_panel ?? '',
    window_hours: hours,
    waf_enabled: info.waf_enabled,
    waf_level: info.waf_level,
    auto_exclusions: info.waf_auto_exclusions,
    virus_action: info.virus_action,
    suspicious_action: info.suspicious_action,
    binary_action: info.binary_action,
    ai_provider: info.ai_provider,
  };
  let out = line(cols, { ...base, row_type: 'server', note });
  if (!s) return out;
  let bytes = Buffer.byteLength(out);
  if (kind === 'waf') {
    const groups = new Map((s.waf_groups ?? []).map((g) => [g.rule_id, g]));
    for (const g of s.waf_groups ?? []) {
      const row = line(cols, { ...base, row_type: 'group', rule_id: g.rule_id, rule_msg: g.msg, rule_action: g.action, rule_total: g.count, rule_ips: g.ips, rule_hosts: g.hosts });
      out += row;
      bytes += Buffer.byteLength(row);
    }
    for (const e of s.waf_events ?? []) {
      const g = groups.get(e.rule_id);
      const row = line(cols, {
        ...base, row_type: 'example', rule_id: e.rule_id, rule_msg: e.msg, rule_action: g?.action, rule_total: g?.count, time: iso(e.at),
        method: e.method, host: e.host, uri: e.uri, ip: e.ip, user: e.user, category: e.category, action: e.action, matched: e.detail,
      });
      const n = Buffer.byteLength(row);
      if (bytes + n > budget) break;
      out += row;
      bytes += n;
    }
  } else {
    const totals = new Map<string, { count: number; files: number }>();
    for (const g of s.sig_groups ?? []) {
      const t = totals.get(g.signature) ?? { count: 0, files: 0 };
      totals.set(g.signature, { count: t.count + g.count, files: t.files + g.files });
      const row = line(cols, { ...base, row_type: 'group', signature: g.signature, category: g.category, status: g.status, sig_total: g.count, sig_files: g.files });
      out += row;
      bytes += Buffer.byteLength(row);
    }
    for (const d of s.detections ?? []) {
      const t = totals.get(d.signature);
      const row = line(cols, {
        ...base, row_type: 'example', signature: d.signature, category: d.category, status: d.status, sig_total: t?.count, sig_files: t?.files,
        first_seen: iso(d.created_at), last_seen: iso(d.updated_at), path: d.path, owner: d.owner, size: d.size, sha256: d.sha256,
        source: d.source, repeats: d.repeats, clean_note: d.note, ai_verdict: d.ai_verdict, ai_confidence: d.ai_confidence,
        ai_model: d.ai_model, ai_reason: d.ai_reason, match_line: d.match_line, matched_code: d.matched,
      });
      const n = Buffer.byteLength(row);
      if (bytes + n > budget) break;
      out += row;
      bytes += n;
    }
  }
  return out;
}

export function learningExportRoutes(app: FastifyInstance, pool: Pool, hub: AgentHub): void {
  app.get('/api/learning/export', { preHandler: requirePlatform('admin') }, async (req, reply) => {
    const p = Query.safeParse(req.query);
    if (!p.success) return reply.code(400).send({ error: 'invalid request' });
    const { kind, hours } = p.data;
    const { rows: servers } = await pool.query<ServerRow & { connected: boolean }>(
      `SELECT id, hostname, agent_version, control_panel, connected FROM servers WHERE status = 'active' ORDER BY hostname`,
    );
    const cols = kind === 'waf' ? WAF_COLUMNS : DET_COLUMNS;
    const header = cols.join(',') + '\n';
    const budget = Math.floor((MAX_EXPORT_BYTES - header.length) / Math.max(1, servers.length));
    // About 450 bytes a WAF example and 900 a detection: ask each server for what fits its share.
    const maxRows = Math.max(20, Math.min(20_000, Math.floor(budget / (kind === 'waf' ? 450 : 900))));
    const parts: string[] = new Array(servers.length).fill('');
    let next = 0;
    const worker = async () => {
      for (;;) {
        const i = next++;
        if (i >= servers.length) return;
        const srv = servers[i];
        if (!srv.connected) {
          parts[i] = serverRows(kind, srv, hours, null, 'offline: not included', budget);
          continue;
        }
        try {
          const s = (await hub.command(srv.id, 'learning.sample', { kind, hours, per_group: 30, max_rows: maxRows }, 90_000)) as Sample;
          parts[i] = serverRows(kind, srv, hours, s, '', budget);
        } catch (err) {
          const msg = err instanceof CommandError && err.message.startsWith('unsupported action') ? 'agent too old: update it to include this server' : `error: ${(err as Error).message}`.slice(0, 200);
          parts[i] = serverRows(kind, srv, hours, null, msg, budget);
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(10, servers.length) }, worker));
    await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, action: 'learning.export', detail: { kind, hours, servers: servers.length }, ip: req.ip });
    const name = `xpguard-learning-${kind}-${hours}h-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-')}.csv`;
    reply.header('content-type', 'text/csv; charset=utf-8').header('content-disposition', `attachment; filename="${name}"`);
    return header + parts.join('');
  });
}
