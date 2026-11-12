import crypto from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';
import { webhookSignature } from '../src/routes/vuln-feed.js';
import { envelopeMessage } from '../src/agent-sign.js';
import { feedRecords, parseFeed, VulnFeedService } from '../src/vulnfeed/service.js';

let h: Harness;
let feed: VulnFeedService;
let server: { id: string; key: crypto.KeyPairKeyObjectResult };
const nudged: string[] = [];

const wf = (id: string, slug: string, to: string, updated: string) => ({
  [id]: {
    id, title: `Plugin ${slug} <= ${to} - Unauthenticated Arbitrary File Upload`, informational: false,
    software: [{ type: 'plugin', slug, affected_versions: { [`* - ${to}`]: { from_version: '*', from_inclusive: true, to_version: to, to_inclusive: true } }, patched_versions: ['9.9'] }],
    cvss: { score: 9.8 }, published: new Date().toISOString(), updated,
  },
});

beforeAll(async () => {
  h = await startHarness({});
  const { rows: acc } = await h.pool.query('SELECT id FROM accounts LIMIT 1');
  const key = crypto.generateKeyPairSync('ed25519');
  const pub = key.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
  const { rows } = await h.pool.query('INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, $2, $3) RETURNING id', [acc[0].id, 'web-a', pub]);
  server = { id: rows[0].id, key };
  h.hub.isOnline = () => true;
  h.hub.command = async (id: string, action: string) => {
    if (action === 'cms.vuln_sync') nudged.push(id);
    return { ok: true };
  };
  feed = h.vulnFeed;
});

afterAll(async () => {
  await h.close();
});

async function fetchSince(since: number) {
  const raw = JSON.stringify({ since });
  const ts = String(Math.floor(Date.now() / 1000));
  const signature = crypto.sign(null, Buffer.from(envelopeMessage(server.id, ts, raw)), server.key.privateKey).toString('base64');
  const r = await fetch(h.url + '/api/agent/cms/vulns', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ server_id: server.id, ts, signature, payload: raw }) });
  return { status: r.status, body: await r.json() };
}

describe('fast plugin vulnerability alerts', () => {
  it('reads the feed one record at a time, across chunk boundaries and tricky strings', async () => {
    const text = JSON.stringify({
      a: { id: 'a', title: 'brace } in "quotes" \\ and {', software: [] },
      b: { id: 'b', title: 'unicode é ✓', software: [{ type: 'plugin', slug: 'x', affected_versions: { '* - 1': { from_version: '*', to_version: '1' } } }] },
    });
    const bytes = new TextEncoder().encode(text);
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        for (let i = 0; i < bytes.length; i += 7) c.enqueue(bytes.slice(i, i + 7)); // splits characters too
        c.close();
      },
    });
    const out: { id: string; title: string }[] = [];
    for await (const r of feedRecords(stream)) out.push(r as { id: string; title: string });
    expect(out.map((r) => r.id)).toEqual(['a', 'b']);
    expect(out[0].title).toBe('brace } in "quotes" \\ and {');
    expect(out[1].title).toBe('unicode é ✓');
  });

  it('parses the feed into one item per component, skipping informational and bad slugs', () => {
    const items = parseFeed({ ...wf('a', 'contact-form-7', '6.2.3', '1'), b: { id: 'b', informational: true, software: [] }, c: { id: 'c', software: [{ type: 'plugin', slug: '../x', affected_versions: { x: {} } }] } });
    expect(items).toHaveLength(1);
    expect(items[0].item).toMatchObject({ kind: 'plugin', slug: 'contact-form-7', cvss: 9.8, patched: ['9.9'] });
    expect(items[0].item.ranges[0]).toEqual({ from: '*', from_inc: true, to: '6.2.3', to_inc: true });
  });

  it('keeps the first import as backlog, then sends only new and changed items and nudges the agents', async () => {
    // A webhook delivery before the first download (Wordfence's own test of
    // the webhook) does not turn the backlog into new items.
    expect(await feed.applyWebhook({ vulnerabilities: { created: Object.values(wf('pre', 'pre-plugin', '1.0', '1')) } })).toBe(1);
    nudged.length = 0;
    expect(await feed.sync({ ...wf('old', 'old-plugin', '1.0', '1'), ...wf('old2', 'old-plugin2', '1.0', '1') })).toBe(0);
    expect(nudged).toHaveLength(0);
    const start = await fetchSince(-1);
    expect(start.status).toBe(200);
    expect(start.body.items).toEqual([]);
    expect(await feed.sync({ ...wf('old', 'old-plugin', '1.0', '1'), ...wf('new', 'contact-form-7', '6.2.3', '1') })).toBe(1);
    expect(nudged).toEqual([server.id]);
    const next = await fetchSince(start.body.cursor);
    expect(next.body.items.map((i: { slug: string }) => i.slug)).toEqual(['contact-form-7']);
    // Unchanged: nothing new; a changed range is sent again.
    expect(await feed.sync({ ...wf('old', 'old-plugin', '1.0', '1'), ...wf('new', 'contact-form-7', '6.2.3', '1') })).toBe(0);
    expect((await fetchSince(next.body.cursor)).body.items).toEqual([]);
    expect(await feed.sync({ ...wf('old', 'old-plugin', '1.0', '1'), ...wf('new', 'contact-form-7', '6.2.4', '2') })).toBe(1);
    expect((await fetchSince(next.body.cursor)).body.items[0].ranges[0].to).toBe('6.2.4');
  });

  it('keeps the key and secret on the portal, shows only a hint, refuses bad keys before saving', async () => {
    const admin = new Client(h.url);
    await admin.login();
    let r = await admin.req('GET', '/api/vuln-feed');
    expect(r.body).toMatchObject({ key_set: false, secret_set: false });
    expect(r.body.webhook_url).toBe(h.url + '/api/hooks/wordfence');
    // One request per download; a 429 waits for Retry-After, and the
    // test button does not ask Wordfence again in the meantime.
    let hits = 0;
    let answer: { status: number; body: unknown } = { status: 429, body: {} };
    const wfServer = http.createServer((req, res) => {
      hits++;
      expect(req.headers.authorization).toBe('Bearer abcd' + 'k'.repeat(40) + 'wxyz');
      res.writeHead(answer.status, { 'content-type': 'application/json', 'retry-after': '600' });
      res.end(JSON.stringify(answer.body));
    });
    await new Promise<void>((r) => wfServer.listen(0, '127.0.0.1', () => r()));
    h.cfg.wordfenceFeedUrl = `http://127.0.0.1:${(wfServer.address() as AddressInfo).port}/feed`;
    r = await admin.req('PUT', '/api/vuln-feed', { api_key: 'abcd' + 'k'.repeat(40) + 'wxyz', webhook_secret: 's'.repeat(40) });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ key_set: true, key_hint: 'abcd…wxyz', secret_set: true });
    expect(JSON.stringify(r.body)).not.toContain('k'.repeat(40));
    await new Promise((res) => setTimeout(res, 300));
    expect(hits).toBe(1);
    expect((await admin.req('GET', '/api/vuln-feed')).body.last_error).toContain('too many feed downloads');
    r = await admin.req('POST', '/api/vuln-feed/test');
    expect(r.body.ok).toBe(false);
    expect(r.body.error).toContain('next try after');
    expect(hits).toBe(1);
    // A restarted portal keeps waiting (the limit is in the database).
    const restarted = new VulnFeedService(h.pool, h.cfg, h.hub, h.app.log);
    await expect(restarted.sync()).rejects.toThrow('next try after');
    expect(hits).toBe(1);
    await h.pool.query('UPDATE vuln_feed_config SET retry_at = NULL');
    // Later: the download works; a second test does not download again.
    feed.retryAt = 0;
    answer = { status: 200, body: wf('later', 'later-plugin', '1.0', '1') };
    expect((await admin.req('POST', '/api/vuln-feed/test')).body).toEqual({ ok: true });
    expect(hits).toBe(2);
    r = await admin.req('POST', '/api/vuln-feed/test');
    expect(r.body.ok).toBe(true);
    expect(r.body.note).toContain('downloaded with this key');
    expect(hits).toBe(2);
    wfServer.close();
    expect((await admin.req('PUT', '/api/vuln-feed', { webhook_secret: 'short' })).status).toBe(400);
    // The test button: a signed sample delivery through the public address.
    r = await admin.req('POST', '/api/vuln-feed/webhook-test');
    expect(r.body).toEqual({ ok: true });
    expect((await admin.req('GET', '/api/vuln-feed')).body.last_webhook_ok).toBe(true);
  });

  it('stores signed webhook deliveries at once, deletes removed ones and refuses bad signatures', async () => {
    const secret = 's'.repeat(40);
    const hook = (body: string, sig: string) =>
      fetch(h.url + '/api/hooks/wordfence', { method: 'POST', headers: { 'content-type': 'application/json', 'x-wordfence-signature': sig }, body });
    const created = Object.values(wf('aaaaaaaa-0000-0000-0000-000000000001', 'printcart-integration', '2.13.2', '1'));
    const body = JSON.stringify({ vulnerabilities: { created, replaced: [], deleted: [] } });
    expect((await hook(body, webhookSignature('wrong'.repeat(8), body))).status).toBe(401);
    nudged.length = 0;
    const r = await hook(body, webhookSignature(secret, body));
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ ok: true, changed: 1 });
    expect(nudged).toEqual([server.id]);
    const { rows } = await h.pool.query("SELECT slug, seq FROM vuln_feed WHERE id LIKE 'aaaaaaaa-0000-0000-0000-000000000001:%'");
    expect(rows[0].slug).toBe('printcart-integration');
    expect(Number(rows[0].seq)).toBeGreaterThan(0);
    const del = JSON.stringify({ vulnerabilities: { created: [], replaced: [], deleted: ['aaaaaaaa-0000-0000-0000-000000000001'] } });
    expect((await hook(del, webhookSignature(secret, del))).status).toBe(200);
    expect((await h.pool.query("SELECT 1 FROM vuln_feed WHERE id LIKE 'aaaaaaaa-0000-0000-0000-000000000001:%'")).rowCount).toBe(0);
  });

  it('stores a download with more than a thousand unseen records as backlog', async () => {
    const many: Record<string, unknown> = {};
    for (let i = 0; i < 1100; i++) Object.assign(many, wf(`bulk-${i}`, `bulk-plugin-${i}`, '1.0', '1'));
    nudged.length = 0;
    expect(await feed.sync(many)).toBe(0);
    expect(nudged).toHaveLength(0);
    expect((await h.pool.query("SELECT count(*)::int AS n FROM vuln_feed WHERE id LIKE 'bulk-%' AND seq = 0")).rows[0].n).toBe(1100);
  });

  it('refuses unsigned requests', async () => {
    const r = await fetch(h.url + '/api/agent/cms/vulns', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ since: 0 }) });
    expect(r.status).toBe(400);
  });
});
