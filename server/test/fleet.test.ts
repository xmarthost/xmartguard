import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startHarness, type Harness } from './helpers.js';

describe('fleet whitelist', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await startHarness();
  });
  afterAll(async () => {
    await h?.close();
  });

  it("lists the public addresses of an account's active servers only", async () => {
    const { rows: acc } = await h.pool.query('SELECT id FROM accounts LIMIT 1');
    const { rows: other } = await h.pool.query("INSERT INTO accounts (name) VALUES ('other') RETURNING id");
    const add = (account: string, host: string, ip: string, ips: string[], status = 'active') =>
      h.pool.query(
        "INSERT INTO servers (account_id, hostname, public_key, primary_ip, inventory, status) VALUES ($1, $2, $3, $4, $5, $6)",
        [account, host, `key-${host}`, ip, JSON.stringify({ ips }), status],
      );
    await add(acc[0].id, 'business900.example', '198.51.100.9', ['198.51.100.9', '10.0.0.5', '2001:db8::9', 'fe80::1']);
    await add(acc[0].id, 'server100.example', '203.0.113.20', ['203.0.113.20', '127.0.0.1']);
    await add(acc[0].id, 'old.example', '203.0.113.99', [], 'revoked');
    await add(other[0].id, 'someone-else.example', '192.0.2.44', []);
    const list = await h.ipdb.fleet(acc[0].id);
    expect(list).toEqual([
      { ip: '198.51.100.9', host: 'business900.example' },
      { ip: '2001:db8::9', host: 'business900.example' },
      { ip: '203.0.113.20', host: 'server100.example' },
    ]);
  });
});
