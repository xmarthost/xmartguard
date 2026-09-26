import crypto from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';
import { aiPayload, aiPayloadV2 } from '../src/routes/ai.js';
import { parseAnswer } from '../src/ai/prompt.js';
import { cooldownFor } from '../src/ai/providers.js';

let h: Harness;
let api: http.Server;
let apiUrl = '';
let admin: Client;
let serverId = '';
const calls: { key: string; body: any; path: string }[] = [];
const keys = crypto.generateKeyPairSync('ed25519');
const pub = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');

/** Fake OpenAI-compatible API: key "k-empty" is out of quota, "k-good" answers. */
function answerFor(user: string): string {
  const ids = [...user.matchAll(/<file id=(\d+)/g)].map((m) => m[1]);
  return JSON.stringify({
    results: ids.map((id) => {
      const block = user.split(`<file id=${id} `)[1].split('</file>')[0];
      return block.includes('eval(')
        ? { id, verdict: 'malicious', confidence: 97, reason: 'eval of POST data prepended to plugin', injected: true, cut: [{ from: 1, to: 1 }] }
        : { id, verdict: 'clean', confidence: 92, reason: 'ordinary template code', injected: false, cut: [] };
    }),
  });
}

beforeAll(async () => {
  api = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      const key = (req.headers.authorization ?? '').replace('Bearer ', '');
      res.setHeader('content-type', 'application/json');
      if (req.url === '/v1/models') {
        return res.end(JSON.stringify({ data: [{ id: 'big-model' }, { id: 'small-model:free', pricing: { prompt: '0', completion: '0' } }, { id: 'text-embedding-3' }] }));
      }
      const body = JSON.parse(raw || '{}');
      calls.push({ key, body, path: req.url ?? '' });
      if (key === 'k-empty') {
        res.statusCode = 429;
        return res.end(JSON.stringify({ error: { message: 'Quota exceeded for requests per day (RPD)' } }));
      }
      const user = body.messages?.[1]?.content ?? '';
      const content = user.includes('echo "hello"') ? '{"ok":true,"verdict":"clean"}' : user.includes('<file') ? answerFor(user) : '{"verdict":"malicious","confidence":90,"reason":"legacy"}';
      res.end(JSON.stringify({ choices: [{ message: { content }, finish_reason: 'stop' }], usage: { prompt_tokens: 100, completion_tokens: 20 } }));
    });
  });
  await new Promise<void>((r) => api.listen(0, '127.0.0.1', r));
  apiUrl = `http://127.0.0.1:${(api.address() as AddressInfo).port}/v1`;
  h = await startHarness({ aiBatchWaitMs: 300, aiTraining: false });
  const { rows: acc } = await h.pool.query('SELECT id FROM accounts LIMIT 1');
  const { rows } = await h.pool.query("INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, 'web1', $2) RETURNING id", [acc[0].id, pub]);
  serverId = rows[0].id;
  admin = new Client(h.url);
  await admin.login();
});

afterAll(async () => {
  await h.close();
  api.close();
});

function envelope(payload: unknown, ts = String(Math.floor(Date.now() / 1000))) {
  const raw = JSON.stringify(payload);
  const signature = crypto.sign(null, Buffer.from(aiPayloadV2(serverId, ts, raw)), keys.privateKey).toString('base64');
  return { server_id: serverId, ts, signature, payload: raw };
}

async function agentPost(path: string, body: unknown) {
  const r = await fetch(h.url + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}

const sha = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
const file = (id: string, text: string, extra: Record<string, unknown> = {}) => ({
  id,
  sha256: sha(text),
  size: text.length,
  name: `f${id}.php`,
  excerpt: text,
  lines: text.split('\n').length,
  truncated: false,
  ...extra,
});

describe('AI settings', () => {
  it('stores keys per provider, masks them and lists models', async () => {
    const presets = await admin.req('GET', '/api/ai/presets');
    expect(presets.body.presets.map((p: any) => p.kind)).toEqual(expect.arrayContaining(['gemini', 'groq', 'openrouter']));

    const a = await admin.req('POST', '/api/ai/providers', { kind: 'custom', name: 'Gemini #1', base_url: apiUrl, api_key: 'k-empty', model: 'big-model', priority: 1 });
    expect(a.status).toBe(200);
    const b = await admin.req('POST', '/api/ai/providers', { kind: 'custom', name: 'Groq #1', base_url: apiUrl, api_key: 'k-good', model: 'big-model', priority: 2 });
    expect(b.status).toBe(200);
    const list = await admin.req('GET', '/api/ai/providers');
    expect(list.body.providers.map((p: any) => p.api_key)).toEqual(['********mpty', '********good']);

    // Saving the masked key back keeps the real one.
    await admin.req('PATCH', `/api/ai/providers/${b.body.id}`, { api_key: '********good', model: 'big-model' });
    const models = await admin.req('POST', '/api/ai/models', { kind: 'custom', base_url: apiUrl, provider_id: b.body.id });
    expect(models.status).toBe(200);
    expect(models.body.models.map((m: any) => m.id)).toEqual(['big-model', 'small-model:free']);

    const t = await admin.req('POST', `/api/ai/providers/${b.body.id}/test`);
    expect(t.status).toBe(200);
    expect(calls.at(-1)!.key).toBe('k-good');

    const viewer = new Client(h.url);
    expect((await viewer.req('POST', '/api/ai/providers', {})).status).toBe(401);
  });
});

describe('AI gateway', () => {
  it('batches files, fails over to the next key and rests the exhausted one', async () => {
    calls.length = 0;
    const bad = '1|<?php eval($_POST["x"]);\n2|function plugin_init() { add_action("init", "x"); }';
    const good = '1|<?php echo esc_html($title);';
    const r = await agentPost('/api/agent/ai/judge', envelope({ files: [file('a', bad, { base: 'v1', z: -2, features: [5, 9, 11] }), file('b', good, { base: 'v1', z: 1, features: [5, 7] })] }));
    expect(r.status).toBe(200);
    const [ra, rb] = r.body.results;
    expect(ra).toMatchObject({ id: 'a', verdict: 'malicious', injected: true, cut: [{ from: 1, to: 1 }], source: 'ai' });
    expect(rb).toMatchObject({ id: 'b', verdict: 'clean', source: 'ai' });
    // One request per key: both files went in the same request.
    expect(calls.map((c) => c.key)).toEqual(['k-empty', 'k-good']);
    expect(calls[1].body.messages[0].content).toContain('Reply with JSON only');
    expect(calls[1].body.response_format).toEqual({ type: 'json_object' });

    const list = await admin.req('GET', '/api/ai/providers');
    const [empty, ok] = list.body.providers;
    expect(new Date(empty.cooldown_until).getTime()).toBeGreaterThan(Date.now() + 30 * 60_000);
    expect(empty.last_error).toContain('429');
    expect(ok).toMatchObject({ requests: '1', files: '2' });
  });

  it('answers from the fleet knowledge base without calling any API', async () => {
    calls.length = 0;
    const bad = '1|<?php eval($_POST["x"]);\n2|function plugin_init() { add_action("init", "x"); }';
    const r = await agentPost('/api/agent/ai/judge', envelope({ files: [file('z', bad)] }));
    expect(r.body.results[0]).toMatchObject({ verdict: 'malicious', source: 'fleet', injected: true });
    expect(calls).toHaveLength(0);
    const st = await admin.req('GET', '/api/ai/status');
    expect(st.body.kb).toMatchObject({ total: 2, malicious: 1, clean: 1, reused: 1 });
    expect(st.body.providers).toMatchObject({ total: 2, ready: 1 });
  });

  it('shares verdicts and the trained model with every server', async () => {
    let s = await agentPost('/api/agent/ai/sync', envelope({ cursor: 0, base: 'v1', model_version: 0 }));
    expect(s.status).toBe(200);
    expect(s.body.kb).toHaveLength(2);
    expect(s.body.delta).toBeNull();
    const cursor = s.body.cursor;

    // Two verdicts are not enough to train on.
    let trained = await admin.req('POST', '/api/ai/train');
    expect(trained.body.trained[0].result.waiting).toContain('1 malicious and 1 clean');
    // With enough examples of both kinds the update is trained: feature 9
    // appears only in malicious files, 7 only in clean ones, 5 in both.
    for (let i = 0; i < 6; i++) {
      await h.pool.query('INSERT INTO ai_samples (sha256, base_version, z, features, label) VALUES ($1, $2, $3, $4, $5)', [sha('m' + i), 'v1', -1, [5, 9, 100 + i], 1]);
      await h.pool.query('INSERT INTO ai_samples (sha256, base_version, z, features, label) VALUES ($1, $2, $3, $4, $5)', [sha('c' + i), 'v1', 1, [5, 7, 200 + i], 0]);
    }
    trained = await admin.req('POST', '/api/ai/train');
    expect(trained.body.trained[0].result).toMatchObject({ samples: 14, accuracy: 1 });
    s = await agentPost('/api/agent/ai/sync', envelope({ cursor, base: 'v1', model_version: 0 }));
    expect(s.body.kb).toHaveLength(0);
    expect(s.body.delta.base_version).toBe('v1');
    const w = new Map<number, number>(s.body.delta.entries);
    expect(w.get(9)!).toBeGreaterThan(0.5);
    expect(w.get(7)!).toBeLessThan(-0.5);
    expect(Math.abs(w.get(5) ?? 0)).toBeLessThan(Math.abs(w.get(9)!));

    // An admin marks the malicious file clean: it is re-sent to agents.
    const kb = await admin.req('GET', '/api/ai/kb?verdict=malicious');
    expect(kb.body.entries[0]).toMatchObject({ name: 'fa.php', server: 'web1' });
    const fix = await admin.req('PUT', `/api/ai/kb/${kb.body.entries[0].sha256}`, { verdict: 'clean', reason: 'our own admin tool' });
    expect(fix.status).toBe(200);
    s = await agentPost('/api/agent/ai/sync', envelope({ cursor, base: 'v1', model_version: 0 }));
    expect(s.body.kb).toEqual([expect.objectContaining({ verdict: 'clean', confidence: 100 })]);
  });

  it('rejects forged, altered and stale requests', async () => {
    const good = envelope({ files: [file('a', 'x')] });
    expect((await agentPost('/api/agent/ai/judge', { ...good, payload: good.payload.replace('"x"', '"y"') })).status).toBe(401);
    expect((await agentPost('/api/agent/ai/judge', { ...good, signature: Buffer.alloc(64).toString('base64') })).status).toBe(401);
    expect((await agentPost('/api/agent/ai/judge', envelope({ files: [file('a', 'x')] }, String(Math.floor(Date.now() / 1000) - 3600)))).status).toBe(401);
    expect((await agentPost('/api/agent/ai/sync', { ...envelope({ cursor: 0, base: 'v1', model_version: 0 }), server_id: crypto.randomUUID() })).status).toBe(401);
  });

  it('still serves 0.5 agents', async () => {
    const ts = String(Math.floor(Date.now() / 1000));
    const system = 'sys';
    const prompt = 'legacy file';
    const signature = crypto.sign(null, Buffer.from(aiPayload(serverId, ts, system, prompt)), keys.privateKey).toString('base64');
    const r = await agentPost('/api/agent/ai', { server_id: serverId, ts, signature, system, prompt });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ verdict: 'malicious', confidence: 90, model: 'custom/big-model' });
  });
});

describe('AI answer parsing', () => {
  it('accepts fenced JSON and drops invalid cuts', () => {
    const m = parseAnswer('```json\n{"results":[{"id":"1","verdict":"malicious","confidence":150,"reason":"x","injected":true,"cut":[{"from":0},{"from":3,"to":2},{"from":4,"to":4,"text":"bad()"}]}]}\n```', ['1']);
    expect(m.get('1')).toEqual({ id: '1', verdict: 'malicious', confidence: 100, reason: 'x', injected: true, cut: [{ from: 4, to: 4, text: 'bad()' }] });
    expect(parseAnswer('{"verdict":"clean","confidence":80,"reason":"ok"}', ['7']).get('7')?.verdict).toBe('clean');
    expect(parseAnswer('not json', ['1']).size).toBe(0);
  });

  it('rests keys according to the error', () => {
    expect(cooldownFor(429, 'per day limit', null)).toBe(3_600_000);
    expect(cooldownFor(429, 'slow down', '30')).toBe(30_000);
    expect(cooldownFor(401, '', null)).toBeGreaterThan(3_600_000);
    expect(cooldownFor(400, '', null)).toBe(0);
  });
});
