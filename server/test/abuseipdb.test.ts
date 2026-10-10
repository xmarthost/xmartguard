import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';
import { createOwner } from '../src/routes/users.js';
import { downloadEveryMs, setAbuseIPDBApi } from '../src/ipdb/abuseipdb.js';

// A stand-in for api.abuseipdb.com (never the real service in tests).
const GOOD = 'a'.repeat(80);
let downloads = 0;
const checked: string[] = [];
let failNext = false;
const mock = http.createServer((req, res) => {
  const key = req.headers.key;
  if (key !== GOOD) {
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ errors: [{ detail: 'Authentication failed. Your API key is either missing, incorrect, or revoked.', status: 401 }] }));
    return;
  }
  if (req.url?.startsWith('/check')) {
    const ip = new URL(req.url, 'http://x').searchParams.get('ipAddress') ?? '';
    checked.push(ip);
    const score = ip === '203.0.113.70' ? 96 : ip === '203.0.113.72' ? 100 : 5;
    res.writeHead(200, { 'content-type': 'application/json', 'x-ratelimit-limit': '50000', 'x-ratelimit-remaining': '49999' });
    res.end(JSON.stringify({ data: { ipAddress: ip, abuseConfidenceScore: score, isWhitelisted: ip === '203.0.113.72', countryCode: 'NL' } }));
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
    res.writeHead(200, { 'content-type': 'text/plain', 'x-ratelimit-limit': '100' });
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
    expect(ok.body).toEqual({ ok: true, remaining: 49999, limit: 50000 });
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
    // The plan is read from AbuseIPDB's answers: 100 downloads and 50,000 checks a day.
    expect(st).toMatchObject({ key_set: true, enabled: true, last_count: 3, last_error: '', blacklist_limit: 100, check_limit: 50000, check_budget: 40000, every_minutes: 60 });
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

  it('checks new attackers our servers report and blocks the ones AbuseIPDB scores high', async () => {
    const { rows: acc } = await h.pool.query('SELECT id FROM accounts WHERE platform');
    const { rows: srv } = await h.pool.query(
      "INSERT INTO servers (account_id, hostname, public_key, primary_ip) VALUES ($1, 'web1.example.net', 'k1', '192.0.2.10') RETURNING id",
      [acc[0].id],
    );
    for (const ip of ['203.0.113.70', '203.0.113.71', '203.0.113.72', '198.51.100.11']) {
      await h.pool.query("INSERT INTO ipdb_reports (ip, server_id, account_id, source, reason) VALUES ($1, $2, $3, 'waf-probe', 'scanner')", [ip, srv[0].id, acc[0].id]);
    }
    checked.length = 0;
    const r = await h.ipdb.checkAbuseIPDBSuspects(96);
    // 198.51.100.11 is listed already; 71 scores low; 72 is whitelisted on AbuseIPDB.
    expect(checked.sort()).toEqual(['203.0.113.70', '203.0.113.71', '203.0.113.72']);
    expect(r).toMatchObject({ checked: 3, listed: 1 });
    await h.ipdb.rebuild();
    expect(h.ipdb.entries).toContain('203.0.113.70 NL');
    expect(h.ipdb.entries.join(' ')).not.toContain('203.0.113.71');
    expect(h.ipdb.entries.join(' ')).not.toContain('203.0.113.72');
    const st = (await master.req('GET', '/api/ipdb/abuseipdb')).body;
    expect(st).toMatchObject({ checks_today: 3, check_listed: 1 });
    // Not checked again for a few days.
    checked.length = 0;
    expect((await h.ipdb.checkAbuseIPDBSuspects(96)).checked).toBe(0);
    expect(checked).toEqual([]);
    // Turned off: nothing checked, and the checked entries leave the list.
    await master.req('PUT', '/api/ipdb/abuseipdb', { check_enabled: false });
    await waitFor(async () => (await master.req('GET', '/api/ipdb/abuseipdb')).body.check_listed === 0);
    await master.req('PUT', '/api/ipdb/abuseipdb', { check_enabled: true });
  });

  it('downloads as often as the plan allows', () => {
    expect(downloadEveryMs(5)).toBe(6 * 3600_000); // free
    expect(downloadEveryMs(100)).toBe(3600_000); // never more than hourly
    expect(downloadEveryMs(0)).toBe(6 * 3600_000);
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
