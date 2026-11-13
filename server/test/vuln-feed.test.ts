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

  // Owner (2026-11-13): the first download is backlog, so the holes of the
  // weeks before it were never acted on. A resend from a date numbers the
  // advisories published since then again and nudges the agents.
  it('sends the advisories published since a date to the servers again', async () => {
    await h.pool.query(
      `INSERT INTO vuln_feed (id, kind, slug, title, cvss, ranges, patched, published, updated, seq) VALUES
       ('rp-new', 'plugin', 'rp-new', 't', 9.8, '[]', '[]', now() - interval '3 days', '1', 0),
       ('rp-old', 'plugin', 'rp-old', 't', 9.8, '[]', '[]', now() - interval '40 days', '1', 0)`,
    );
    const { rows } = await h.pool.query('SELECT coalesce(max(seq), 0)::bigint AS c FROM vuln_feed');
    const before = Number(rows[0].c);
    const admin = new Client(h.url);
    await admin.login();
    expect((await admin.req('POST', '/api/vuln-feed/replay', { since: 'yesterday' })).status).toBe(400);
    expect((await admin.req('POST', '/api/vuln-feed/replay', { since: '2000-01-01' })).status).toBe(400);
    const since = new Date(Date.now() - 10 * 86400_000).toISOString().slice(0, 10);
    nudged.length = 0;
    const r = await admin.req('POST', '/api/vuln-feed/replay', { since });
    expect(r.status).toBe(200);
    expect(r.body.sent).toBeGreaterThanOrEqual(1);
    expect(nudged).toEqual([server.id]);
    const slugs = (await fetchSince(before)).body.items.map((i: { slug: string }) => i.slug);
    expect(slugs).toContain('rp-new');
    expect(slugs).not.toContain('rp-old');
  });

  // Owner (2026-11-13): the Master panel shows which vulnerabilities were
  // sent on which day and what each server did on each website.
  it('records each send and what the servers report back, and lists it for the report', async () => {
    nudged.length = 0;
    const since = new Date(Date.now() - 10 * 86400_000).toISOString().slice(0, 10);
    const admin = new Client(h.url);
    await admin.login();
    expect((await admin.req('POST', '/api/vuln-feed/replay', { since })).status).toBe(200);
    const list = await admin.req('GET', '/api/vuln-feed/dispatches');
    expect(list.status).toBe(200);
    const d = list.body.dispatches[0];
    expect(d).toMatchObject({ source: 'resend', note: `published since ${since}` });
    expect(d.count).toBeGreaterThanOrEqual(1);
    const { rows } = await h.pool.query("SELECT seq FROM vuln_feed WHERE id = 'rp-new'");
    const seq = Number(rows[0].seq);
    // The server confirms it received the send and reports two sites.
    const post = async (payload: unknown) => {
      const raw = JSON.stringify(payload);
      const ts = String(Math.floor(Date.now() / 1000));
      const signature = crypto.sign(null, Buffer.from(envelopeMessage(server.id, ts, raw)), server.key.privateKey).toString('base64');
      return fetch(h.url + '/api/agent/cms/vulns/results', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ server_id: server.id, ts, signature, payload: raw }) });
    };
    const at = Math.floor(Date.now() / 1000);
    const res = (path: string, action: string, extra = {}) => ({ at, advisory: 'rp-new', cvss: 0, path, domain: path.split('/')[2] + '.test', user: path.split('/')[2], kind: 'plugin', slug: 'rp-new', version: '1.0', action, ...extra });
    const r = await post({ results: [res('/home/alice/public_html', 'updated', { to_version: '1.1' }), res('/home/bob/public_html', 'failed', { detail: 'update failed: disk full' })], receipt: { seqs: [seq], sites: 2 } });
    expect(r.status).toBe(200);
    // Reported again (the agent retries): no duplicates.
    expect((await post({ results: [res('/home/alice/public_html', 'updated', { to_version: '1.1' })] })).status).toBe(200);
    const again = (await admin.req('GET', '/api/vuln-feed/dispatches')).body.dispatches[0];
    expect(again).toMatchObject({ servers: 1, sites: 2, updated: 1, not_fixed: 1 });
    const detail = await admin.req('GET', `/api/vuln-feed/dispatches/${d.id}`);
    expect(detail.status).toBe(200);
    const srv = detail.body.servers.find((x: { server_id: string }) => x.server_id === server.id);
    expect(srv).toMatchObject({ hostname: 'web-a', updated: 1, not_fixed: 1, advisories: 1 });
    expect(srv.received_at).toBeTruthy();
    expect(detail.body.advisories.find((a: { id: string }) => a.id === 'rp-new')).toMatchObject({ sites: 2, updated: 1, not_fixed: 1 });
    const failed = await admin.req('GET', `/api/vuln-feed/dispatches/${d.id}/results?action=not_fixed`);
    expect(failed.body.total).toBe(1);
    // The title and score come from the feed when the server does not send them.
    expect(failed.body.results[0]).toMatchObject({ domain: 'bob.test', account: 'bob', hostname: 'web-a', detail: 'update failed: disk full', title: 't' });
    expect(failed.body.results[0].cvss).toBeCloseTo(9.8);
    expect((await admin.req('GET', `/api/vuln-feed/dispatches/${d.id}/results?q=ALICE`)).body.total).toBe(1);
    expect((await admin.req('GET', `/api/vuln-feed/dispatches/${d.id}/results?server=${server.id}`)).body.total).toBe(2);
    // Feed downloads and webhook deliveries are recorded as sends too.
    expect(await feed.applyWebhook({ vulnerabilities: { created: Object.values(wf('hook-1', 'hook-plugin', '1.0', '1')) } })).toBe(1);
    expect((await admin.req('GET', '/api/vuln-feed/dispatches')).body.dispatches[0]).toMatchObject({ source: 'webhook', count: 1 });
  });

  it('refuses unsigned requests', async () => {
    const r = await fetch(h.url + '/api/agent/cms/vulns', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ since: 0 }) });
    expect(r.status).toBe(400);
  });
});
