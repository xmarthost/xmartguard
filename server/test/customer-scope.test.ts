import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';
import { createOwner } from '../src/routes/users.js';

// Owner's rule: nothing of the master (its lists, keys or their hints, the
// AI knowledge base, WAF intel, trusted services, global settings) is
// readable by a customer account.
let h: Harness;
let master: Client;
let cust: Client;

beforeAll(async () => {
  h = await startHarness();
  master = new Client(h.url);
  await master.login();
  await createOwner(h.pool, 'scope-cust@example.com', 'customer-long-password', 'Scope Customer');
  cust = new Client(h.url);
  await cust.login('scope-cust@example.com', 'customer-long-password');
  await master.req('POST', '/api/ipdb/entries', { cidr: '198.51.100.77', note: 'operator note' });
  await master.req('POST', '/api/ipdb/whitelist', { cidr: '192.0.2.77', note: 'operator partner' });
  await h.pool.query("INSERT INTO ipdb_reports (ip, source, reason) VALUES ('198.51.100.77', 'waf', 'fleet report')");
});
afterAll(async () => h.close());

describe("the master's data and customers", () => {
  it('refuses every master read to a customer', async () => {
    for (const p of [
      '/api/ipdb/entries',
      '/api/ipdb/whitelist',
      '/api/ipdb/abuseipdb',
      '/api/ai/kb',
      '/api/ai/status',
      '/api/ai/providers',
      '/api/ai/learning',
      '/api/waf/intel',
      '/api/waf/approvals',
      '/api/waf/rulesets',
      '/api/trusted',
      '/api/captcha',
      '/api/mail-protection',
      '/api/domain-reputation',
    ]) {
      const r = await cust.req('GET', p);
      expect(r.status, p).toBe(403);
    }
    // The master reads them.
    expect((await master.req('GET', '/api/ipdb/entries')).status).toBe(200);
    expect((await master.req('GET', '/api/ipdb/whitelist')).status).toBe(200);
  });

  it("shows a customer whether an address is dropped, never the operator's notes or the fleet's reports", async () => {
    const c = await cust.req('GET', '/api/ipdb/check?ip=198.51.100.77');
    expect(c.status).toBe(200);
    expect(c.body.listed).toBe(true);
    expect(JSON.stringify(c.body)).not.toContain('operator note');
    expect(c.body.reports).toBeUndefined();
    const w = await cust.req('GET', '/api/ipdb/check?ip=192.0.2.77');
    expect(JSON.stringify(w.body)).not.toContain('operator partner');
    const s = await cust.req('GET', '/api/ipdb/summary');
    expect(s.body).toMatchObject({ reports_24h: 0, sources: { manual: 0 } });
    // The master keeps the detail.
    const m = await master.req('GET', '/api/ipdb/check?ip=198.51.100.77');
    expect(JSON.stringify(m.body)).toContain('operator note');
    expect(m.body.reports).toBe(1);
  });
});
