import crypto from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startHarness, type Harness } from './helpers.js';
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
  feed = new VulnFeedService(h.pool, h.cfg, h.hub, h.app.log);
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

  it('refuses unsigned requests', async () => {
    const r = await fetch(h.url + '/api/agent/cms/vulns', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ since: 0 }) });
    expect(r.status).toBe(400);
  });
});
