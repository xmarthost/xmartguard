import crypto from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';
import { envelopeMessage } from '../src/agent-sign.js';
import { nameOK } from '../src/waf/intel.js';

let h: Harness;
let admin: Client;
const servers: { id: string; key: crypto.KeyPairKeyObjectResult }[] = [];
const pushed: { id: string; params: { names: string[]; patches: unknown[]; etag: string } }[] = [];

beforeAll(async () => {
  h = await startHarness({});
  const { rows: acc } = await h.pool.query('SELECT id FROM accounts LIMIT 1');
  for (const host of ['web-a', 'web-b', 'web-c']) {
    const key = crypto.generateKeyPairSync('ed25519');
    const pub = key.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
    const { rows } = await h.pool.query('INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, $2, $3) RETURNING id', [acc[0].id, host, pub]);
    servers.push({ id: rows[0].id, key });
  }
  admin = new Client(h.url);
  await admin.login();
  h.hub.isOnline = () => true;
  h.hub.command = async (id: string, action: string, params: unknown) => {
    if (action === 'waf.intel') pushed.push({ id, params: params as (typeof pushed)[0]['params'] });
    return { ok: true };
  };
});

afterAll(async () => {
  await h.close();
});

async function agent(i: number, payload: unknown) {
  const s = servers[i];
  const raw = JSON.stringify(payload);
  const ts = String(Math.floor(Date.now() / 1000));
  const signature = crypto.sign(null, Buffer.from(envelopeMessage(s.id, ts, raw)), s.key.privateKey).toString('base64');
  const r = await fetch(h.url + '/api/agent/waf/intel', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ server_id: s.id, ts, signature, payload: raw }) });
  return { status: r.status, body: await r.json() };
}

describe('WAF fleet intelligence', () => {
  it('never blocks common file names', () => {
    for (const n of ['wp-2019.php', 'alfa-rex.php7', 'gzdecodes.php']) expect(nameOK(n)).toBe(true);
    for (const n of ['index.php', 'Config.php', 'about.php', 'ab.php', 'x.js', '../a.php']) expect(nameOK(n)).toBe(false);
  });

  it('sends the virtual patches, then names found on two servers', async () => {
    const first = await agent(0, { etag: '', reports: [{ name: 'gzdecodes.php', tail: 'wp-content/plugins/x/gzdecodes.php', signature: 'php.webshell' }, { name: 'index.php' }] });
    expect(first.status).toBe(200);
    expect(first.body.intel.names).toEqual([]);
    expect(first.body.intel.patches.length).toBeGreaterThanOrEqual(6);
    expect(first.body.intel.patches[0]).not.toHaveProperty('plugin');
    const etag = first.body.intel.etag;
    expect((await agent(0, { etag, reports: [] })).body).toEqual({ unchanged: true });
    // A second server finds it: every server gets the name now.
    pushed.length = 0;
    const second = await agent(1, { etag, reports: [{ name: 'GZDECODES.php', tail: 'gzdecodes.php', signature: 'php.webshell' }] });
    expect(second.body.intel.names).toEqual(['gzdecodes.php']);
    await new Promise((r) => setTimeout(r, 200));
    expect(pushed.map((p) => p.id).sort()).toEqual(servers.map((s) => s.id).sort());
    const g = await admin.req('GET', '/api/waf/intel');
    const n = g.body.names.find((x: { name: string }) => x.name === 'gzdecodes.php');
    expect(n).toMatchObject({ servers: 2, status: 'active' });
    expect(g.body.names.find((x: { name: string }) => x.name === 'index.php').status).toBe('not_allowed');
  });

  it('stops blocking a name restored as clean, unless approved', async () => {
    await agent(2, { etag: '', reports: [{ name: 'gzdecodes.php', clean: true }] });
    let g = await admin.req('GET', '/api/waf/intel');
    expect(g.body.names.find((x: { name: string }) => x.name === 'gzdecodes.php').status).toBe('false_positive');
    expect((await agent(0, { etag: '', reports: [] })).body.intel.names).toEqual([]);
    expect((await admin.req('POST', '/api/waf/intel/names', { name: 'gzdecodes.php', status: 'approved' })).status).toBe(200);
    expect((await agent(0, { etag: '', reports: [] })).body.intel.names).toEqual(['gzdecodes.php']);
    await admin.req('POST', '/api/waf/intel/names', { name: 'gzdecodes.php', status: 'ignored' });
    g = await admin.req('GET', '/api/waf/intel');
    expect(g.body.names.find((x: { name: string }) => x.name === 'gzdecodes.php').status).toBe('ignored');
  });

  it('adds names by hand, refuses common ones, switches patches off', async () => {
    expect((await admin.req('POST', '/api/waf/intel/names', { name: 'config.php', status: 'added' })).status).toBe(400);
    expect((await admin.req('POST', '/api/waf/intel/names', { name: 'wp-l0gin.php', status: 'added' })).status).toBe(200);
    const put = await admin.req('PUT', '/api/waf/intel/config', { enabled: true, min_servers: 1, disabled_patches: [7703001] });
    expect(put.status).toBe(200);
    const i = (await agent(0, { etag: '', reports: [] })).body.intel;
    expect(i.names).toEqual(['wp-l0gin.php']);
    expect(i.patches.map((p: { id: number }) => p.id)).not.toContain(7703001);
    const viewer = await admin.req('GET', '/api/waf/intel');
    expect(viewer.body.patches.find((p: { id: number }) => p.id === 7703001).enabled).toBe(false);
    // Off: nothing is sent.
    await admin.req('PUT', '/api/waf/intel/config', { enabled: false, min_servers: 1, disabled_patches: [] });
    const off = (await agent(0, { etag: '', reports: [] })).body.intel;
    expect(off.names).toEqual([]);
    expect(off.patches).toEqual([]);
    expect((await admin.req('PUT', '/api/waf/intel/config', { enabled: true, min_servers: 0, disabled_patches: [] })).status).toBe(400);
  });

  it('refuses unsigned reports', async () => {
    const r = await fetch(h.url + '/api/agent/waf/intel', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ server_id: servers[0].id, ts: '1', signature: 'x', payload: '{}' }) });
    expect(r.status).toBeGreaterThanOrEqual(400);
  });
});
