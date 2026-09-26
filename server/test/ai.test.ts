import crypto from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';
import { aiPayload } from '../src/routes/ai.js';

let h: Harness;
let ollama: http.Server;
let lastChat: any = null;
let serverId = '';
const keys = crypto.generateKeyPairSync('ed25519');
const pub = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');

beforeAll(async () => {
  ollama = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      res.setHeader('content-type', 'application/json');
      if (req.url === '/api/tags') return res.end(JSON.stringify({ models: [{ name: 'qwen2.5-coder:7b' }] }));
      lastChat = JSON.parse(body);
      res.end(JSON.stringify({ message: { role: 'assistant', content: '{"verdict":"malicious","confidence":93,"reason":"runs request data"}' } }));
    });
  });
  await new Promise<void>((r) => ollama.listen(0, '127.0.0.1', r));
  const port = (ollama.address() as AddressInfo).port;
  h = await startHarness({ ollamaUrl: `http://127.0.0.1:${port}`, ollamaModel: 'qwen2.5-coder:7b' });
  const { rows: acc } = await h.pool.query('SELECT id FROM accounts LIMIT 1');
  const { rows } = await h.pool.query("INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, 'web1', $2) RETURNING id", [acc[0].id, pub]);
  serverId = rows[0].id;
});

afterAll(async () => {
  await h.close();
  ollama.close();
});

function signed(ts = String(Math.floor(Date.now() / 1000)), system = 'sys', prompt = '<file>x</file>') {
  const signature = crypto.sign(null, Buffer.from(aiPayload(serverId, ts, system, prompt)), keys.privateKey).toString('base64');
  return { server_id: serverId, ts, signature, system, prompt };
}

async function post(body: unknown) {
  const r = await fetch(h.url + '/api/agent/ai', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}

describe('AI gateway', () => {
  it('reports the model to portal users', async () => {
    const c = new Client(h.url);
    await c.login();
    const r = await c.req('GET', '/api/ai/status');
    expect(r.body).toEqual({ enabled: true, model: 'qwen2.5-coder:7b', reachable: true, installed: true });
    expect((await new Client(h.url).req('GET', '/api/ai/status')).status).toBe(401);
  });

  it('answers signed requests from enrolled agents', async () => {
    const r = await post(signed());
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ verdict: 'malicious', confidence: 93, reason: 'runs request data', model: 'qwen2.5-coder:7b' });
    expect(lastChat.model).toBe('qwen2.5-coder:7b');
    expect(lastChat.format.properties.verdict.enum).toContain('clean');
    expect(lastChat.messages[1].content).toBe('<file>x</file>');
  });

  it('rejects forged, altered and stale requests', async () => {
    const good = signed();
    expect((await post({ ...good, prompt: 'changed' })).status).toBe(401);
    expect((await post({ ...good, signature: Buffer.alloc(64).toString('base64') })).status).toBe(401);
    expect((await post(signed(String(Math.floor(Date.now() / 1000) - 3600)))).status).toBe(401);
    expect((await post({ ...good, server_id: crypto.randomUUID() })).status).toBe(401);
  });
});
