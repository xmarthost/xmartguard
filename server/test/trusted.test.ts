import crypto from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';
import { envelopeMessage } from '../src/agent-sign.js';

let h: Harness;
let admin: Client;
let serverId = '';
const keys = crypto.generateKeyPairSync('ed25519');
const pub = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');

beforeAll(async () => {
  h = await startHarness({});
  const { rows: acc } = await h.pool.query('SELECT id FROM accounts LIMIT 1');
  const { rows } = await h.pool.query("INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, 'web-trusted', $2) RETURNING id", [acc[0].id, pub]);
  serverId = rows[0].id;
  admin = new Client(h.url);
  await admin.login();
});

afterAll(async () => {
  await h.close();
});

async function agent(path: string, payload: unknown) {
  const raw = JSON.stringify(payload);
  const ts = String(Math.floor(Date.now() / 1000));
  const signature = crypto.sign(null, Buffer.from(envelopeMessage(serverId, ts, raw)), keys.privateKey).toString('base64');
  const r = await fetch(h.url + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ server_id: serverId, ts, signature, payload: raw }) });
  return { status: r.status, body: await r.json() };
}

describe('trusted services for all servers', () => {
  it('leaves servers alone until saved, then gives every server the same list', async () => {
    const g = await admin.req('GET', '/api/trusted');
    expect(g.body.version).toBe(0);
    expect(g.body.config.enabled).toBe(true);
    expect(g.body.servers.map((s: { hostname: string }) => s.hostname)).toContain('web-trusted');
    expect((await agent('/api/agent/trusted/config', { version: 0 })).body.unchanged).toBe(true);

    const bad = await admin.req('PUT', '/api/trusted', { enabled: true, disabled: [], custom: ['10.0.0.0/4'] });
    expect(bad.status).toBe(400);
    const bad2 = await admin.req('PUT', '/api/trusted', { enabled: true, disabled: [], custom: ['not-an-ip'] });
    expect(bad2.status).toBe(400);

    const put = await admin.req('PUT', '/api/trusted', { enabled: true, disabled: ['openai-gptbot', 'openai-gptbot'], custom: ['203.0.113.7', '2001:db8::/48', ''] });
    expect(put.status).toBe(200);
    expect(put.body.version).toBe(1);
    expect(put.body.config).toEqual({ enabled: true, disabled: ['openai-gptbot'], custom: ['203.0.113.7', '2001:db8::/48'] });
    expect(put.body.offline).toBeGreaterThanOrEqual(1);

    const a = await agent('/api/agent/trusted/config', { version: 0 });
    expect(a.body.config).toEqual({ version: 1, enabled: true, disabled: ['openai-gptbot'], custom: ['203.0.113.7', '2001:db8::/48'] });
    expect((await agent('/api/agent/trusted/config', { version: 1 })).body.unchanged).toBe(true);
  });

  it('only admins save', async () => {
    const r = await fetch(h.url + '/api/trusted', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: '{}' });
    expect(r.status).toBe(401);
  });
});
