import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';
import { createOwner } from '../src/routes/users.js';
import { setAbuseIPDBApi } from '../src/ipdb/abuseipdb.js';

// A stand-in for api.abuseipdb.com (never the real service in tests).
const GOOD = 'a'.repeat(80);
let downloads = 0;
let failNext = false;
const mock = http.createServer((req, res) => {
  const key = req.headers.key;
  if (key !== GOOD) {
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ errors: [{ detail: 'Authentication failed. Your API key is either missing, incorrect, or revoked.', status: 401 }] }));
    return;
  }
  if (req.url?.startsWith('/check')) {
    res.writeHead(200, { 'content-type': 'application/json', 'x-ratelimit-limit': '1000', 'x-ratelimit-remaining': '999' });
    res.end(JSON.stringify({ data: { ipAddress: '1.1.1.1', abuseConfidenceScore: 0 } }));
    return;
  }
  if (req.url?.startsWith('/blacklist')) {
    downloads++;
    if (failNext) {
      failNext = false;
      res.writeHead(429, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ errors: [{ detail: 'Daily rate limit of 5 requests exceeded for this endpoint.', status: 429 }] }));
      return;
    }
    expect(req.url).toContain('confidenceMinimum=100');
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('198.51.100.11\n198.51.100.12\n2001:db8::77\nnot-an-ip\n10.0.0.1\n');
    return;
  }
  res.writeHead(404).end();
});

let h: Harness;
let master: Client;
let cust: Client;

beforeAll(async () => {
  await new Promise<void>((r) => mock.listen(0, '127.0.0.1', r));
  setAbuseIPDBApi(`http://127.0.0.1:${(mock.address() as AddressInfo).port}`);
  h = await startHarness();
  master = new Client(h.url);
  await master.login();
  await createOwner(h.pool, 'cust@example.com', 'customer-password-123', 'Customer Co');
  cust = new Client(h.url);
  await cust.login('cust@example.com', 'customer-password-123');
});

afterAll(async () => {
  await h.close();
  mock.close();
});

const waitFor = async (fn: () => Promise<boolean>) => {
  for (let i = 0; i < 50; i++) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('timed out');
};

describe('AbuseIPDB (master)', () => {
  it('is for the portal operator only', async () => {
    expect((await cust.req('GET', '/api/ipdb/abuseipdb')).status).toBe(403);
    expect((await cust.req('PUT', '/api/ipdb/abuseipdb', { api_key: GOOD })).status).toBe(403);
    expect((await cust.req('POST', '/api/ipdb/abuseipdb/test', { api_key: GOOD })).status).toBe(403);
    const r = await master.req('GET', '/api/ipdb/abuseipdb');
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ key_set: false, listed: 0 });
  });

  it('tests a key without saving it', async () => {
    const bad = await master.req('POST', '/api/ipdb/abuseipdb/test', { api_key: 'b'.repeat(80) });
    expect(bad.body.ok).toBe(false);
    expect(bad.body.error).toContain('Authentication failed');
    const ok = await master.req('POST', '/api/ipdb/abuseipdb/test', { api_key: GOOD });
    expect(ok.body).toEqual({ ok: true, remaining: 999, limit: 1000 });
    expect((await master.req('GET', '/api/ipdb/abuseipdb')).body.key_set).toBe(false);
    expect((await master.req('POST', '/api/ipdb/abuseipdb/test', { api_key: 'short' })).status).toBe(400);
  });

  it('refuses a key AbuseIPDB does not accept', async () => {
    const r = await master.req('PUT', '/api/ipdb/abuseipdb', { api_key: 'b'.repeat(80) });
    expect(r.status).toBe(400);
    expect((await master.req('GET', '/api/ipdb/abuseipdb')).body.key_set).toBe(false);
  });

  it('saves the key, downloads the list into the shared IPDB and never shows the key', async () => {
    const r = await master.req('PUT', '/api/ipdb/abuseipdb', { api_key: GOOD });
    expect(r.status).toBe(200);
    expect(r.body.key_hint).toBe('aaaa…aaaa');
    expect(JSON.stringify(r.body)).not.toContain(GOOD);
    await waitFor(async () => (await master.req('GET', '/api/ipdb/abuseipdb')).body.listed === 3);
    const st = (await master.req('GET', '/api/ipdb/abuseipdb')).body;
    expect(st).toMatchObject({ key_set: true, enabled: true, last_count: 3, last_error: '' });
    await h.ipdb.rebuild();
    // The same list goes to every server, whatever its account.
    expect(h.ipdb.entries).toEqual(expect.arrayContaining(['198.51.100.11', '198.51.100.12', '2001:db8::77']));
    expect(h.ipdb.entries.join(' ')).not.toContain('10.0.0.1');
    const ent = await master.req('GET', '/api/ipdb/entries?source=feed&q=198.51.100.11');
    expect(ent.body.entries[0].reason).toContain('AbuseIPDB');
  });

  it('downloads at most every few hours, keeps the list when a download fails', async () => {
    const before = downloads;
    expect((await h.ipdb.refreshAbuseIPDB()).skipped).toBe(true);
    expect(downloads).toBe(before);
    failNext = true;
    const r = await master.req('POST', '/api/ipdb/abuseipdb/refresh');
    expect(r.body.error).toContain('Daily rate limit');
    expect(r.body.state.listed).toBe(3);
    expect(r.body.state.last_error).toContain('Daily rate limit');
  });

  it('switching it off or removing the key takes its addresses off every server', async () => {
    await master.req('PUT', '/api/ipdb/abuseipdb', { enabled: false });
    await waitFor(async () => (await master.req('GET', '/api/ipdb/abuseipdb')).body.listed === 0);
    await h.ipdb.rebuild();
    expect(h.ipdb.entries).not.toContain('198.51.100.11');
    await master.req('PUT', '/api/ipdb/abuseipdb', { enabled: true });
    await waitFor(async () => (await master.req('GET', '/api/ipdb/abuseipdb')).body.listed === 3);
    await master.req('PUT', '/api/ipdb/abuseipdb', { api_key: '' });
    await waitFor(async () => (await master.req('GET', '/api/ipdb/abuseipdb')).body.listed === 0);
    expect((await master.req('GET', '/api/ipdb/abuseipdb')).body.key_set).toBe(false);
  });
});
