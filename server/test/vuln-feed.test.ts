import crypto from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';
import { webhookSignature } from '../src/routes/vuln-feed.js';
import { envelopeMessage } from '../src/agent-sign.js';
import { parseFeed, VulnFeedService } from '../src/vulnfeed/service.js';

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
  it('parses the feed into one item per component, skipping informational and bad slugs', () => {
    const items = parseFeed({ ...wf('a', 'contact-form-7', '6.2.3', '1'), b: { id: 'b', informational: true, software: [] }, c: { id: 'c', software: [{ type: 'plugin', slug: '../x', affected_versions: { x: {} } }] } });
    expect(items).toHaveLength(1);
    expect(items[0].item).toMatchObject({ kind: 'plugin', slug: 'contact-form-7', cvss: 9.8, patched: ['9.9'] });
    expect(items[0].item.ranges[0]).toEqual({ from: '*', from_inc: true, to: '6.2.3', to_inc: true });
  });

  it('keeps the first import as backlog, then sends only new and changed items and nudges the agents', async () => {
    expect(await feed.sync({ ...wf('old', 'old-plugin', '1.0', '1') })).toBe(0);
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
    // Wordfence refusing the key: not saved.
    feed.testKey = async () => ({ ok: false, error: 'Wordfence refused the key' });
    r = await admin.req('PUT', '/api/vuln-feed', { api_key: 'k'.repeat(40) });
    expect(r.status).toBe(400);
    feed.testKey = async () => ({ ok: true });
    r = await admin.req('PUT', '/api/vuln-feed', { api_key: 'abcd' + 'k'.repeat(40) + 'wxyz', webhook_secret: 's'.repeat(40) });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ key_set: true, key_hint: 'abcd…wxyz', secret_set: true });
    expect(JSON.stringify(r.body)).not.toContain('k'.repeat(40));
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

  it('refuses unsigned requests', async () => {
    const r = await fetch(h.url + '/api/agent/cms/vulns', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ since: 0 }) });
    expect(r.status).toBe(400);
  });
});
