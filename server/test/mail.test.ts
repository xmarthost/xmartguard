import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';

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
