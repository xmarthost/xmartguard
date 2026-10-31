import { createHash } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { contentPart, toText } from '../src/routes/mcp.js';
import { Client, OWNER, startHarness, type Harness } from './helpers.js';
import { createOwner } from '../src/routes/users.js';

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
    expect(r.body.result.serverInfo.name).toBe('xpguard');
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

  it("keeps the fleet knowledge base from customers; the master's tokens reach customers' servers", async () => {
    await createOwner(h.pool, 'mcp-cust@example.com', 'customer-long-password', 'MCP Customer');
    const cust = new Client(h.url);
    await cust.login('mcp-cust@example.com', 'customer-long-password');
    const { rows: acc } = await h.pool.query("SELECT account_id FROM users WHERE email = 'mcp-cust@example.com'");
    await h.pool.query("INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, 'cust.example.com', 'k-cust')", [acc[0].account_id]);
    const t = await cust.req('POST', '/api/mcp/tokens', { label: 'mine', scope: 'write' });
    const names = (await rpc(t.body.url, 'tools/list')).body.result.tools.map((x: any) => x.name);
    expect(names).not.toContain('ai_knowledge');
    expect(names).not.toContain('mark_file');
    const kb = await rpc(t.body.url, 'tools/call', { name: 'ai_knowledge', arguments: { q: '%' } });
    expect(kb.body.error).toBeTruthy();
    expect(JSON.stringify(kb.body)).not.toContain('a'.repeat(64));
    const o = text(await rpc(t.body.url, 'tools/call', { name: 'fleet_overview', arguments: {} }));
    expect(o.ai_knowledge_base).toBeUndefined();
    expect(o.totals.servers).toBe(1);
    // The customer sees only their server; the master reaches it too.
    expect(text(await rpc(t.body.url, 'tools/call', { name: 'list_servers', arguments: {} })).servers.map((s: any) => s.hostname)).toEqual(['cust.example.com']);
    expect(text(await rpc(readUrl, 'tools/call', { name: 'list_servers', arguments: {} })).servers.map((s: any) => s.hostname)).toContain('cust.example.com');
    const d = await rpc(readUrl, 'tools/call', { name: 'server_dashboard', arguments: { server: 'cust.example.com' } });
    expect(d.body.result.content[0].text).toContain('offline');
    const other = await rpc(t.body.url, 'tools/call', { name: 'server_dashboard', arguments: { server: 'web1.example.com' } });
    expect(other.body.result.content[0].text).toContain('server not found');
  });

  it('stops working once revoked', async () => {
    expect((await c.req('DELETE', `/api/mcp/tokens/${readId}`)).status).toBe(200);
    expect((await rpc(readUrl, 'ping')).status).toBe(401);
    const { rows } = await h.pool.query('SELECT calls FROM mcp_tokens WHERE id = $1', [readId]);
    expect(Number(rows[0].calls)).toBeGreaterThan(5);
  });
});

// Claude Code in the cloud (and other MCP clients) sign in with OAuth: they
// find the portal from the 401 on /mcp, register, get the owner's approval
// and keep a token that a refresh never cuts off.
describe('mcp oauth sign-in', () => {
  const redirect = 'https://claude.ai/api/mcp/auth_callback';
  const verifier = 'v'.repeat(20) + '-0123456789abcdefghijklmnopqrstuvwxyz';
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  let clientId = '';

  const form = (body: Record<string, string>) =>
    fetch(`${h.url}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body).toString() });

  async function approve(scope = 'read write', state = 'st8') {
    const q = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: redirect, code_challenge: challenge, code_challenge_method: 'S256', state, scope, resource: `${h.url}/mcp` });
    const page = await c.req('GET', `/oauth/authorize?${q}`);
    expect(page.status).toBe(200);
    const d = await c.req('POST', '/oauth/authorize/decision', { client_id: clientId, redirect_uri: redirect, code_challenge: challenge, state, scope: scope === 'read' ? 'read' : 'write', approve: true });
    expect(d.status).toBe(200);
    const u = new URL(d.body.redirect);
    expect(u.origin + u.pathname).toBe(redirect);
    expect(u.searchParams.get('state')).toBe(state);
    return u.searchParams.get('code')!;
  }

  it('points clients from /mcp to the discovery documents', async () => {
    const r = await fetch(`${h.url}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    expect(r.status).toBe(401);
    expect(r.headers.get('www-authenticate')).toContain(`resource_metadata="${h.url}/.well-known/oauth-protected-resource"`);
    for (const p of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
      const m = await (await fetch(h.url + p)).json();
      expect(m).toMatchObject({ resource: `${h.url}/mcp`, authorization_servers: [h.url] });
    }
    const a = await (await fetch(`${h.url}/.well-known/oauth-authorization-server`)).json();
    expect(a).toMatchObject({ issuer: h.url, token_endpoint: `${h.url}/oauth/token`, registration_endpoint: `${h.url}/oauth/register`, code_challenge_methods_supported: ['S256'] });
  });

  it('registers public clients with safe redirect addresses only', async () => {
    const bad = await fetch(`${h.url}/oauth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: ['http://evil.example.net/cb'] }) });
    expect(bad.status).toBe(400);
    const r = await fetch(`${h.url}/oauth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_name: 'Claude', redirect_uris: [redirect, 'http://localhost:33418/callback'] }) });
    expect(r.status).toBe(201);
    const b = await r.json();
    expect(b.client_id).toMatch(/^xgc_/);
    expect(b.token_endpoint_auth_method).toBe('none');
    clientId = b.client_id;
  });

  it('sends a signed-out browser to the login and back', async () => {
    const q = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: redirect, code_challenge: challenge, code_challenge_method: 'S256', state: 'x' });
    const r = await fetch(`${h.url}/oauth/authorize?${q}`, { redirect: 'manual' });
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe(`/login?admin&next=${encodeURIComponent(`/oauth/authorize?${q}`)}`);
    // A redirect address the client did not register gets no redirect at all.
    const other = new URLSearchParams({ ...Object.fromEntries(q), redirect_uri: 'https://evil.example.net/cb' });
    expect((await fetch(`${h.url}/oauth/authorize?${other}`, { redirect: 'manual' })).status).toBe(400);
    // No PKCE: refused back to the client.
    const plain = new URLSearchParams({ ...Object.fromEntries(q), code_challenge_method: 'plain' });
    const p = await fetch(`${h.url}/oauth/authorize?${plain}`, { redirect: 'manual' });
    expect(new URL(p.headers.get('location')!).searchParams.get('error')).toBe('invalid_request');
  });

  it('issues a read & write token that works on /mcp, once per code', async () => {
    const code = await approve();
    expect((await form({ grant_type: 'authorization_code', code, redirect_uri: redirect, client_id: clientId, code_verifier: 'wrong'.repeat(10) })).status).toBe(400);
    // The failed try used the code up: a stolen code is worth one guess.
    expect((await form({ grant_type: 'authorization_code', code, redirect_uri: redirect, client_id: clientId, code_verifier: verifier })).status).toBe(400);

    const code2 = await approve();
    const t = await form({ grant_type: 'authorization_code', code: code2, redirect_uri: redirect, client_id: clientId, code_verifier: verifier });
    expect(t.status).toBe(200);
    const tok = await t.json();
    expect(tok).toMatchObject({ token_type: 'Bearer', scope: 'write' });
    expect(tok.access_token).toMatch(/^xgm_/);
    expect(tok.refresh_token).toMatch(/^xgr_/);
    expect(tok.expires_in).toBe(24 * 3600);
    const tools = (await rpc(`${h.url}/mcp`, 'tools/list', undefined, { authorization: `Bearer ${tok.access_token}` })).body.result.tools.map((x: any) => x.name);
    expect(tools).toContain('finding_action');
    expect(tools).toContain('update_settings');

    // Refresh: a new token, the same refresh token, and the old token keeps
    // working for a while (another session may still use it).
    const r = await (await form({ grant_type: 'refresh_token', refresh_token: tok.refresh_token, client_id: clientId })).json();
    expect(r.access_token).not.toBe(tok.access_token);
    expect(r.refresh_token).toBe(tok.refresh_token);
    for (const a of [tok.access_token, r.access_token]) {
      expect((await rpc(`${h.url}/mcp`, 'ping', undefined, { authorization: `Bearer ${a}` })).body.result).toEqual({});
    }
    const again = await (await form({ grant_type: 'refresh_token', refresh_token: tok.refresh_token, client_id: clientId })).json();
    expect(again.access_token).toMatch(/^xgm_/);

    // The portal lists one connection; revoking it ends every token and the refresh.
    const list = (await c.req('GET', '/api/mcp/tokens')).body.tokens.filter((x: any) => x.oauth);
    expect(list).toHaveLength(1);
    expect(list[0].label).toBe('Claude (sign-in)');
    expect((await c.req('DELETE', `/api/mcp/tokens/${list[0].id}`)).status).toBe(200);
    for (const a of [tok.access_token, r.access_token, again.access_token]) {
      expect((await rpc(`${h.url}/mcp`, 'ping', undefined, { authorization: `Bearer ${a}` })).status).toBe(401);
    }
    const dead = await form({ grant_type: 'refresh_token', refresh_token: tok.refresh_token, client_id: clientId });
    expect((await dead.json()).error).toBe('invalid_grant');
  });

  it('gives a read-only token when only read is asked for', async () => {
    const code = await approve('read');
    const tok = await (await form({ grant_type: 'authorization_code', code, redirect_uri: redirect, client_id: clientId, code_verifier: verifier })).json();
    expect(tok.scope).toBe('read');
    const tools = (await rpc(`${h.url}/mcp`, 'tools/list', undefined, { authorization: `Bearer ${tok.access_token}` })).body.result.tools.map((x: any) => x.name);
    expect(tools).not.toContain('finding_action');
  });

  it('ends access tokens after a day, and every token of a user who changes the password', async () => {
    const ping = async (a: string) => (await rpc(`${h.url}/mcp`, 'ping', undefined, { authorization: `Bearer ${a}` })).status;
    const tok = await (await form({ grant_type: 'authorization_code', code: await approve(), redirect_uri: redirect, client_id: clientId, code_verifier: verifier })).json();
    expect(await ping(tok.access_token)).toBe(200);
    await h.pool.query("UPDATE mcp_tokens SET expires_at = now() - interval '1 minute' WHERE token_hash = $1", [createHash('sha256').update(tok.access_token).digest('hex')]);
    expect(await ping(tok.access_token)).toBe(401);
    const fresh = await (await form({ grant_type: 'refresh_token', refresh_token: tok.refresh_token, client_id: clientId })).json();
    expect(await ping(fresh.access_token)).toBe(200);
    // A token made on the AI Connector page and the OAuth connection both end
    // when the user changes the password (an intruder's tokens with it).
    const page = (await c.req('POST', '/api/mcp/tokens', { label: 'page token', scope: 'write' })).body.token;
    expect(await ping(page)).toBe(200);
    expect((await c.req('POST', '/api/auth/password', { current_password: OWNER.password, new_password: 'a-new-long-password' })).status).toBe(200);
    expect(await ping(page)).toBe(401);
    expect(await ping(fresh.access_token)).toBe(401);
    expect((await (await form({ grant_type: 'refresh_token', refresh_token: tok.refresh_token, client_id: clientId })).json()).error).toBe('invalid_grant');
    expect((await c.req('POST', '/api/auth/password', { current_password: 'a-new-long-password', new_password: OWNER.password })).status).toBe(200);
  });
});

describe('mcp discovery with the web app served', () => {
  it('answers machine paths with JSON, never the SPA page', async () => {
    const fs = await import('node:fs');
    const os = await import('node:os');
    const path = await import('node:path');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'xgweb-'));
    fs.writeFileSync(path.join(dir, 'index.html'), '<html>spa</html>');
    await h.close();
    h = await startHarness({ webDir: dir });
    expect((await (await fetch(h.url + '/.well-known/oauth-protected-resource')).json()).resource).toBe(`${h.url}/mcp`);
    for (const p of ['/.well-known/oauth-protected-resource/mcp/xgm_x', '/.well-known/security.txt', '/oauth/nothing']) {
      const r = await fetch(h.url + p);
      expect(r.status).toBe(404);
    }
    expect(await (await fetch(h.url + '/servers')).text()).toContain('spa');
  });
});

describe('tool result text', () => {
  it('shortens a long event list to valid JSON with the next page', () => {
    const events = Array.from({ length: 2000 }, (_, i) => ({ id: 5000 - i, uri: '/wp-admin/admin-ajax.php?x=' + 'a'.repeat(40), method: '', detail: null }));
    const out = toText({ events, total: 9000 });
    expect(out.length).toBeLessThanOrEqual(60_000);
    const parsed = JSON.parse(out);
    expect(parsed.total).toBe(9000);
    expect(parsed.events.length).toBe(parsed.truncated.shown);
    expect(parsed.truncated.of).toBe(2000);
    expect(parsed.truncated.next_before_id).toBe(parsed.events[parsed.events.length - 1].id);
    expect(parsed.events[0]).not.toHaveProperty('method'); // empty fields dropped
    expect(parsed.events[0]).not.toHaveProperty('detail');
  });
  it('leaves short results whole', () => {
    expect(JSON.parse(toText({ events: [{ id: 1, ip: '1.2.3.4' }], total: 1 }))).toEqual({ events: [{ id: 1, ip: '1.2.3.4' }], total: 1 });
  });  // A finding's file of 95-330 KB (business600: a Joomla component's
  // model, Akeeba's restore.php) is read in parts, to its end.
  it('pages a long file content', () => {
    const content = 'a'.repeat(40_000) + 'b'.repeat(40_000) + 'c'.repeat(15_000);
    const r = { finding: { id: 7 }, content, truncated: false };
    let off = 0;
    let read = '';
    for (let i = 0; i < 5; i++) {
      const p = contentPart(r, off);
      expect(p.content.length).toBeLessThanOrEqual(40_000);
      expect(p.content_length).toBe(95_000);
      expect(p.content_offset).toBe(off);
      expect(p.finding.id).toBe(7);
      read += p.content;
      if (p.content_next === undefined) {
        expect(p.truncated).toBe(false);
        break;
      }
      expect(p.truncated).toBe(true);
      off = p.content_next;
    }
    expect(read).toBe(content);
    expect(contentPart(r, 999_999).content).toBe('');
    expect(contentPart(r, -5).content_offset).toBe(0);
    expect(contentPart({ content: '', binary: true }, 0).content).toBe('');
  });
});
