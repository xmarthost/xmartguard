import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';

let h: Harness;
let admin: Client;
const ids: string[] = [];

beforeAll(async () => {
  h = await startHarness({});
  const { rows: acc } = await h.pool.query('SELECT id FROM accounts LIMIT 1');
  for (const host of ['web-a', 'web-b']) {
    const { rows } = await h.pool.query("INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, $2, $3) RETURNING id", [acc[0].id, host, 'key-' + host]);
    ids.push(String(rows[0].id));
  }
  admin = new Client(h.url);
  await admin.login();
  h.hub.isOnline = () => true;
  h.hub.command = async (id: string, action: string, params: unknown) => {
    const p = params as { ip: string; host: string };
    if (action === 'waf.events') {
      if (id === ids[0] && (p.ip === '198.51.100.7' || p.host === 'shop.example'))
        return { events: [{ id: 1, at: 1, ip: '198.51.100.7', method: 'POST', host: 'shop.example', uri: '/wp-admin/post.php', rule_id: 941100, msg: 'XSS', category: 'waf', action: 'Access denied with code 403', user: 'shop' }], total: 1 };
      return { events: [], total: 0 };
    }
    if (action === 'fw.check') return { ip: p.ip, status: id === ids[1] ? 'temp-blocked' : 'none', found: id === ids[1] ? ['TEMP-BAN'] : [] };
    throw new Error('unexpected ' + action);
  };
});

afterAll(async () => {
  await h.close();
});

describe('block lookup and unblock requests', () => {
  it('finds an address in the WAF logs and firewalls of every server', async () => {
    const r = await admin.req('GET', '/api/blocks/lookup?ip=198.51.100.7');
    expect(r.status).toBe(200);
    expect(r.body.found.map((f: { server: string }) => f.server)).toEqual(['web-a', 'web-b']);
    expect(r.body.found[0].waf[0].rule_id).toBe(941100);
    expect(r.body.found[1].firewall.status).toBe('temp-blocked');
    const byHost = await admin.req('GET', '/api/blocks/lookup?host=Shop.Example');
    expect(byHost.body.found.length).toBe(1);
    expect((await admin.req('GET', '/api/blocks/lookup?ip=not-ip')).status).toBe(400);
    expect((await admin.req('GET', '/api/blocks/lookup')).status).toBe(400);
    expect((await new Client(h.url).req('GET', '/api/blocks/lookup?ip=198.51.100.7')).status).toBe(401);
  });

  it('takes unblock requests from visitors and lists them for the provider', async () => {
    const anon = new Client(h.url);
    expect((await anon.req('POST', '/api/unblock', { site: 'shop.example', email: 'a@b.example', message: 'cannot save a post' })).status).toBe(200);
    expect((await anon.req('POST', '/api/unblock', { site: 'nodot' })).status).toBe(400);
    expect((await anon.req('POST', '/api/unblock', { site: 'shop.example', website: 'spam' })).status).toBe(400);
    const l = await admin.req('GET', '/api/unblock-requests');
    expect(l.body.open).toBe(1);
    expect(l.body.requests[0]).toMatchObject({ site: 'shop.example', status: 'open' });
    expect((await admin.req('POST', `/api/unblock-requests/${l.body.requests[0].id}`, { status: 'done' })).status).toBe(200);
    expect((await admin.req('GET', '/api/unblock-requests')).body.open).toBe(0);
  });
});
