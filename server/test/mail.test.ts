import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';
import { syncMail } from '../src/routes/mail.js';
import type { AgentHub } from '../src/agents/hub.js';

let h: Harness;
let c: Client;
beforeAll(async () => {
  h = await startHarness();
  c = new Client(h.url);
});
afterAll(async () => h.close());

describe('mail protection', () => {
  it('keeps one Spamhaus DQS key for all servers and never shows it whole', async () => {
    expect((await c.req('PUT', '/api/mail-protection', { dqs_key: 'abcdefghijklmnopqrstuvwxyz' })).status).toBe(401);
    await c.login();
    expect((await c.req('PUT', '/api/mail-protection', { dqs_key: 'not a key' })).status).toBe(400);
    const r = await c.req('PUT', '/api/mail-protection', { dqs_key: 'abcdefghijklmnopqrstuvwxyz' });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ dqs_key_set: true, dqs_key_hint: 'abcd…xyz', pushed: 0 });
    const g = await c.req('GET', '/api/mail-protection');
    expect(g.body.dqs_key_set).toBe(true);
    expect(JSON.stringify(g.body)).not.toContain('abcdefghijklmnopqrstuvwxyz');
    // The audit log keeps only the hint too.
    const { rows } = await h.pool.query("SELECT detail FROM audit_events WHERE action = 'mail.dqs_key_set'");
    expect(JSON.stringify(rows)).not.toContain('abcdefghijklmnopqrstuvwxyz');
    // Removed.
    expect((await c.req('PUT', '/api/mail-protection', { dqs_key: '' })).body.dqs_key_set).toBe(false);
  });
});

describe('domain reputation', () => {
  it('keeps one Google Safe Browsing key for all servers, next to the DQS key', async () => {
    await c.login();
    await c.req('PUT', '/api/mail-protection', { dqs_key: 'abcdefghijklmnopqrstuvwxyz' });
    expect((await c.req('PUT', '/api/domain-reputation', { safe_browsing_key: 'bad key/' })).status).toBe(400);
    const r = await c.req('PUT', '/api/domain-reputation', { safe_browsing_key: 'AIzaSyA1234567890abcdefXYZ' });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ key_set: true, key_hint: 'AIza…XYZ' });
    const g = await c.req('GET', '/api/domain-reputation');
    expect(g.body.key_set).toBe(true);
    expect(JSON.stringify(g.body)).not.toContain('AIzaSyA1234567890abcdefXYZ');
    // Saving one key keeps the other.
    const { rows } = await h.pool.query('SELECT dqs_key, safe_browsing_key FROM account_mail');
    expect(rows[0]).toMatchObject({ dqs_key: 'abcdefghijklmnopqrstuvwxyz', safe_browsing_key: 'AIzaSyA1234567890abcdefXYZ' });
    await c.req('PUT', '/api/mail-protection', { dqs_key: '' });
    const after = await h.pool.query('SELECT dqs_key, safe_browsing_key FROM account_mail');
    expect(after.rows[0]).toMatchObject({ dqs_key: '', safe_browsing_key: 'AIzaSyA1234567890abcdefXYZ' });
  });
});

describe("the master's keys", () => {
  it("are sent to the platform's servers only, never to a customer's", async () => {
    await c.login();
    await c.req('PUT', '/api/mail-protection', { dqs_key: 'masterdqskey0123456789' });
    await c.req('PUT', '/api/domain-reputation', { safe_browsing_key: 'AIzaMasterSafeBrowsing' });
    const sent = new Map<string, unknown>();
    const hub = { command: async (id: string, _a: string, p: unknown) => void sent.set(id, p) } as unknown as AgentHub;
    const master = (await h.pool.query('SELECT id FROM accounts WHERE platform')).rows[0].id;
    const cust = (await h.pool.query("INSERT INTO accounts (name) VALUES ('Mail Customer') RETURNING id")).rows[0].id;
    const srv = async (acc: string, key: string) =>
      (await h.pool.query("INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, 'm', $2) RETURNING id", [acc, key])).rows[0].id as string;
    const own = await srv(master, 'k-mail-own');
    const theirs = await srv(cust, 'k-mail-cust');
    await syncMail(h.pool, hub, own);
    await syncMail(h.pool, hub, theirs);
    expect(sent.get(own)).toEqual({ dqs_key: 'masterdqskey0123456789', safe_browsing_key: 'AIzaMasterSafeBrowsing' });
    expect(sent.get(theirs)).toEqual({ dqs_key: '', safe_browsing_key: '' });
  });
});
