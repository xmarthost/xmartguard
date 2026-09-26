import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';

let h: Harness;
let c: Client;
let readUrl = '';
let writeUrl = '';
let readId = '';

beforeAll(async () => {
  h = await startHarness();
  c = new Client(h.url);
  await c.login();
  const { rows: acc } = await h.pool.query('SELECT id FROM accounts LIMIT 1');
  await h.pool.query(
    `INSERT INTO servers (account_id, hostname, public_key, agent_version, last_metrics)
     VALUES ($1, 'web1.example.com', 'k1', '0.7.4', '{"security":{"scanner":{"quarantined":3,"open_findings":2},"blacklisted_ips":1}}')`,
    [acc[0].id],
  );
});
afterAll(async () => h.close());

async function rpc(url: string, method: string, params?: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  return { status: res.status, body: res.status === 202 ? null : await res.json() };
}

const text = (r: any) => JSON.parse(r.body.result.content[0].text);

describe('mcp tokens', () => {
  it('only admins manage tokens and the secret is shown once', async () => {
    expect((await new Client(h.url).req('GET', '/api/mcp/tokens')).status).toBe(401);
    expect((await c.req('POST', '/api/mcp/tokens', { label: 'x', scope: 'root' })).status).toBe(400);
    const r = await c.req('POST', '/api/mcp/tokens', { label: 'Claude read', scope: 'read' });
    expect(r.status).toBe(200);
    expect(r.body.token).toMatch(/^xgm_/);
    expect(r.body.url).toBe(`${h.url}/mcp/${r.body.token}`);
    readUrl = r.body.url;
    readId = r.body.id;
    const w = await c.req('POST', '/api/mcp/tokens', { label: 'Claude write', scope: 'write' });
    writeUrl = w.body.url;
    const list = await c.req('GET', '/api/mcp/tokens');
    expect(list.body.tokens).toHaveLength(2);
    expect(JSON.stringify(list.body)).not.toContain(r.body.token);
    const { rows } = await h.pool.query('SELECT token_hash FROM mcp_tokens');
    expect(rows.every((x) => x.token_hash.length === 64)).toBe(true);
  });
});

describe('mcp endpoint', () => {
  it('rejects missing or wrong tokens', async () => {
    expect((await rpc(`${h.url}/mcp`, 'ping')).status).toBe(401);
    expect((await rpc(`${h.url}/mcp/xgm_wrong`, 'ping')).status).toBe(401);
  });

  it('initializes and accepts a bearer header', async () => {
    const r = await rpc(readUrl, 'initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '1' } });
    expect(r.body.result.protocolVersion).toBe('2025-03-26');
    expect(r.body.result.serverInfo.name).toBe('xmartguard');
    expect(r.body.result.capabilities.tools).toBeTruthy();
    const token = readUrl.split('/').pop()!;
    expect((await rpc(`${h.url}/mcp`, 'ping', undefined, { authorization: `Bearer ${token}` })).body.result).toEqual({});
    expect((await rpc(readUrl, 'notifications/initialized')).status).toBe(202);
    expect((await rpc(readUrl, 'nope')).body.error.code).toBe(-32601);
  });

  it('lists only read tools for a read token', async () => {
    const r = (await rpc(readUrl, 'tools/list')).body.result.tools.map((t: any) => t.name);
    expect(r).toContain('list_servers');
    expect(r).toContain('get_finding_content');
    expect(r).not.toContain('finding_action');
    const w = (await rpc(writeUrl, 'tools/list')).body.result.tools.map((t: any) => t.name);
    expect(w).toContain('finding_action');
    expect(w).toContain('update_settings');
  });

  it('returns fleet data', async () => {
    const s = text(await rpc(readUrl, 'tools/call', { name: 'list_servers', arguments: {} }));
    expect(s.servers[0].hostname).toBe('web1.example.com');
    expect(s.servers[0].online).toBe(false);
    const o = text(await rpc(readUrl, 'tools/call', { name: 'fleet_overview', arguments: {} }));
    expect(o.totals).toMatchObject({ servers: 1, quarantined: 3, open_findings: 2, servers_with_alerts: 1 });
  });

  it('reports agent errors as tool errors', async () => {
    const r = await rpc(readUrl, 'tools/call', { name: 'list_findings', arguments: { server: 'web1.example.com' } });
    expect(r.body.result.isError).toBe(true);
    expect(r.body.result.content[0].text).toContain('offline');
    const nf = await rpc(readUrl, 'tools/call', { name: 'server_dashboard', arguments: { server: 'other.example.com' } });
    expect(nf.body.result.content[0].text).toContain('server not found');
  });

  it('keeps read tokens read-only', async () => {
    const r = await rpc(readUrl, 'tools/call', { name: 'start_scan', arguments: { server: 'web1.example.com', kind: 'quick' } });
    expect(r.body.error.message).toContain('read & write');
    const g = await rpc(readUrl, 'tools/call', { name: 'agent_command', arguments: { server: 'web1.example.com', action: 'finding.action', params: { ids: [1], action: 'delete' } } });
    expect(g.body.result.isError).toBe(true);
    expect(g.body.result.content[0].text).toContain('read-only');
    const u = await rpc(readUrl, 'tools/call', { name: 'agent_command', arguments: { server: 'web1.example.com', action: 'agent.update' } });
    expect(u.body.result.content[0].text).toContain('unknown agent action');
  });

  it('write tokens correct the knowledge base and are audited', async () => {
    const sha = 'a'.repeat(64);
    await h.pool.query(`INSERT INTO ai_kb (sha256, verdict, confidence, reason) VALUES ($1, 'malicious', 80, 'x')`, [sha]);
    const r = await rpc(writeUrl, 'tools/call', { name: 'mark_file', arguments: { sha256: sha, verdict: 'clean', reason: 'plugin file' } });
    expect(r.body.result.isError).toBe(false);
    const { rows } = await h.pool.query('SELECT verdict, overridden FROM ai_kb WHERE sha256 = $1', [sha]);
    expect(rows[0]).toEqual({ verdict: 'clean', overridden: true });
    const a = await h.pool.query("SELECT 1 FROM audit_events WHERE action = 'mcp.ai.kb_override'");
    expect(a.rowCount).toBe(1);
  });

  it('stops working once revoked', async () => {
    expect((await c.req('DELETE', `/api/mcp/tokens/${readId}`)).status).toBe(200);
    expect((await rpc(readUrl, 'ping')).status).toBe(401);
    const { rows } = await h.pool.query('SELECT calls FROM mcp_tokens WHERE id = $1', [readId]);
    expect(Number(rows[0].calls)).toBeGreaterThan(5);
  });
});
