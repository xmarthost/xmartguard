import crypto from 'node:crypto';
import type { WebSocket } from 'ws';
import type { FastifyBaseLogger } from 'fastify';
import type { Pool } from '../db.js';

interface Pending {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
}

export interface AgentConn {
  serverId: string;
  socket: WebSocket;
  version: string;
  connectedAt: Date;
  pending: Map<string, Pending>;
  lastMetrics?: MetricsSample;
  lastMetricsPersistedAt: number;
}

export interface MetricsSample {
  ts: number;
  cpu_percent: number;
  load1: number;
  load5: number;
  load15: number;
  mem_total: number;
  mem_used: number;
  swap_total: number;
  swap_used: number;
  disk_total: number;
  disk_used: number;
  connections: number;
  uptime_seconds: number;
  top_processes: unknown[];
}

export class CommandError extends Error {}

/** Tracks live agent connections and routes commands/results. */
export class AgentHub {
  private conns = new Map<string, AgentConn>();

  constructor(
    private pool: Pool,
    private log: FastifyBaseLogger,
  ) {}

  isOnline(serverId: string): boolean {
    return this.conns.has(serverId);
  }

  get(serverId: string): AgentConn | undefined {
    return this.conns.get(serverId);
  }

  connections(): AgentConn[] {
    return [...this.conns.values()];
  }

  onlineCount(): number {
    return this.conns.size;
  }

  async attach(serverId: string, socket: WebSocket, version: string): Promise<AgentConn> {
    const prev = this.conns.get(serverId);
    if (prev) prev.socket.close(4000, 'replaced by a newer connection');
    const conn: AgentConn = {
      serverId,
      socket,
      version,
      connectedAt: new Date(),
      pending: new Map(),
      lastMetricsPersistedAt: 0,
    };
    this.conns.set(serverId, conn);
    await this.pool.query(
      'UPDATE servers SET connected = true, last_seen_at = now(), agent_version = $2 WHERE id = $1',
      [serverId, version],
    );
    return conn;
  }

  async detach(conn: AgentConn): Promise<void> {
    for (const p of conn.pending.values()) {
      clearTimeout(p.timer);
      p.reject(new CommandError('agent disconnected'));
    }
    conn.pending.clear();
    if (this.conns.get(conn.serverId) === conn) {
      this.conns.delete(conn.serverId);
      await this.pool.query('UPDATE servers SET connected = false, last_seen_at = now() WHERE id = $1', [conn.serverId]);
    }
  }

  /** Disconnects an agent and tells it it has been revoked. */
  revoke(serverId: string): void {
    const c = this.conns.get(serverId);
    if (!c) return;
    c.socket.send(JSON.stringify({ type: 'error', error: 'revoked' }));
    c.socket.close(4001, 'revoked');
  }

  /** Sends a command and resolves with the agent's result data. */
  command(serverId: string, action: string, params: unknown = {}, timeoutMs = 30_000): Promise<unknown> {
    const conn = this.conns.get(serverId);
    if (!conn) return Promise.reject(new CommandError('server is offline'));
    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        conn.pending.delete(id);
        reject(new CommandError('command timed out'));
      }, timeoutMs);
      conn.pending.set(id, { resolve, reject, timer });
      conn.socket.send(JSON.stringify({ type: 'command', id, action, params }));
    });
  }

  handleResult(conn: AgentConn, msg: { id?: string; ok?: boolean; data?: unknown; error?: string }): void {
    if (!msg.id) return;
    const p = conn.pending.get(msg.id);
    if (!p) return;
    clearTimeout(p.timer);
    conn.pending.delete(msg.id);
    if (msg.ok) p.resolve(msg.data);
    else p.reject(new CommandError(msg.error || 'command failed'));
  }

  async handleInventory(conn: AgentConn, inv: Record<string, unknown>): Promise<void> {
    await this.pool.query(
      `UPDATE servers SET inventory = $2, hostname = $3, primary_ip = $4, os_name = $5,
              control_panel = $6, web_server = $7, last_seen_at = now()
        WHERE id = $1`,
      [
        conn.serverId,
        JSON.stringify(inv),
        str(inv.hostname),
        str(inv.primary_ip),
        [str(inv.os_name), str(inv.os_version)].filter(Boolean).join(' '),
        str(inv.control_panel),
        str(inv.web_server),
      ],
    );
  }

  /**
   * Stores the latest sample in memory/servers.last_metrics and persists at most
   * one row per ~55s to server_metrics (live mode sends every 5s).
   */
  async handleMetrics(conn: AgentConn, m: MetricsSample, persistEveryMs = 55_000): Promise<void> {
    if (typeof m?.ts !== 'number') return;
    conn.lastMetrics = m;
    const now = Date.now();
    const persist = now - conn.lastMetricsPersistedAt >= persistEveryMs;
    await this.pool.query('UPDATE servers SET last_metrics = $2, last_seen_at = now() WHERE id = $1', [
      conn.serverId,
      JSON.stringify(m),
    ]);
    if (!persist) return;
    conn.lastMetricsPersistedAt = now;
    await this.pool.query(
      `INSERT INTO server_metrics (server_id, ts, cpu, load1, load5, load15, mem_used, mem_total,
                                   swap_used, swap_total, disk_used, disk_total, connections)
       VALUES ($1, to_timestamp($2), $3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
       ON CONFLICT DO NOTHING`,
      [
        conn.serverId, m.ts, num(m.cpu_percent), num(m.load1), num(m.load5), num(m.load15),
        num(m.mem_used), num(m.mem_total), num(m.swap_used), num(m.swap_total),
        num(m.disk_used), num(m.disk_total), num(m.connections),
      ],
    );
  }

  closeAll(): void {
    for (const c of this.conns.values()) c.socket.close(1001, 'portal shutting down');
  }

  logger(): FastifyBaseLogger {
    return this.log;
  }
}

function str(v: unknown): string {
  return typeof v === 'string' ? v.slice(0, 255) : '';
}

function num(v: unknown): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : 0;
}
