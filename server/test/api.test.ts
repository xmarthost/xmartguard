import crypto from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';

let h: Harness;
let c: Client;

beforeAll(async () => {
  h = await startHarness();
  c = new Client(h.url);
});
afterAll(async () => h.close());

function agentKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64');
  return { pub, sign: (m: string) => crypto.sign(null, Buffer.from(m), privateKey).toString('base64') };
}

describe('auth', () => {
  it('rejects anonymous access', async () => {
    expect((await c.req('GET', '/api/servers')).status).toBe(401);
    expect((await c.req('GET', '/api/auth/me')).status).toBe(401);
  });

  it('rejects bad credentials', async () => {
    const r = await c.req('POST', '/api/auth/login', { email: 'owner@example.com', password: 'nope' });
    expect(r.status).toBe(401);
  });

  it('logs in and returns the user', async () => {
    await c.login();
    const me = await c.req('GET', '/api/auth/me');
    expect(me.status).toBe(200);
    expect(me.body.user.role).toBe('owner');
  });

  it('blocks form-encoded (CSRF-able) mutations', async () => {
    const r = await c.req('POST', '/api/enrollment-tokens', 'label=x', { 'content-type': 'text/plain' });
    expect(r.status).toBe(415);
  });

  it('blocks cross-origin mutations', async () => {
    const r = await c.req('POST', '/api/enrollment-tokens', {}, { origin: 'https://evil.example' });
    expect(r.status).toBe(403);
  });
});

describe('enrollment', () => {
  it('issues a token with an install command', async () => {
    const r = await c.req('POST', '/api/enrollment-tokens', { label: 'test' });
    expect(r.status).toBe(200);
    expect(r.body.token).toMatch(/^XG-/);
    expect(r.body.install_command).toBe(`curl -fsSL ${h.url}/install.sh | bash -s -- --token ${r.body.token}`);
  });

  it('enrolls once per token and rejects reuse', async () => {
    const { body } = await c.req('POST', '/api/enrollment-tokens', {});
    const k = agentKeys();
    const ok = await c.req('POST', '/api/agent/enroll', { token: body.token, public_key: k.pub, inventory: { hostname: 'web1' } });
    expect(ok.status).toBe(200);
    expect(ok.body.server_id).toMatch(/^[0-9a-f-]{36}$/);
    const again = await c.req('POST', '/api/agent/enroll', { token: body.token, public_key: agentKeys().pub });
    expect(again.status).toBe(403);
  });

  it('rejects unknown tokens and bad keys', async () => {
    expect((await c.req('POST', '/api/agent/enroll', { token: 'XG-AAAA-BBBB-CCCC', public_key: agentKeys().pub })).status).toBe(403);
    const { body } = await c.req('POST', '/api/enrollment-tokens', {});
    expect((await c.req('POST', '/api/agent/enroll', { token: body.token, public_key: 'x'.repeat(44) })).status).toBe(400);
  });

  it('rejects expired tokens', async () => {
    const { body } = await c.req('POST', '/api/enrollment-tokens', {});
    await h.pool.query("UPDATE enrollment_tokens SET expires_at = now() - interval '1 minute'");
    expect((await c.req('POST', '/api/agent/enroll', { token: body.token, public_key: agentKeys().pub })).status).toBe(403);
  });

  it('unenrolls only with a valid signature', async () => {
    const { body } = await c.req('POST', '/api/enrollment-tokens', {});
    const k = agentKeys();
    const { body: e } = await c.req('POST', '/api/agent/enroll', { token: body.token, public_key: k.pub });
    const ts = String(Math.floor(Date.now() / 1000));
    const bad = await c.req('POST', '/api/agent/unenroll', { server_id: e.server_id, ts, signature: agentKeys().sign('x') });
    expect(bad.status).toBe(401);
    const good = await c.req('POST', '/api/agent/unenroll', {
      server_id: e.server_id, ts, signature: k.sign(`xg-unenroll-v1:${e.server_id}:${ts}`),
    });
    expect(good.status).toBe(200);
    expect((await c.req('GET', `/api/servers/${e.server_id}`)).status).toBe(404);
  });
});

describe('tenant isolation and roles', () => {
  it('hides other accounts servers and enforces viewer role', async () => {
    const { body } = await c.req('POST', '/api/enrollment-tokens', {});
    const { body: e } = await c.req('POST', '/api/agent/enroll', { token: body.token, public_key: agentKeys().pub });

    // Second account.
    const other = new Client(h.url);
    const { createOwner } = await import('../src/routes/users.js');
    await createOwner(h.pool, 'other@example.com', 'another-long-password', 'Other');
    await other.login('other@example.com', 'another-long-password');
    expect((await other.req('GET', `/api/servers/${e.server_id}`)).status).toBe(404);
    expect((await other.req('GET', '/api/servers')).body.servers).toHaveLength(0);

    // Viewer in the first account.
    const add = await c.req('POST', '/api/users', { email: 'viewer@example.com', password: 'viewer-password-1', role: 'viewer' });
    expect(add.status).toBe(200);
    const viewer = new Client(h.url);
    await viewer.login('viewer@example.com', 'viewer-password-1');
    expect((await viewer.req('GET', `/api/servers/${e.server_id}`)).status).toBe(200);
    expect((await viewer.req('DELETE', `/api/servers/${e.server_id}`)).status).toBe(403);
    expect((await viewer.req('POST', '/api/enrollment-tokens', {})).status).toBe(403);
  });
});

describe('downloads', () => {
  it('serves install.sh with the portal URL baked in', async () => {
    const r = await c.req('GET', '/install.sh');
    expect(r.status).toBe(200);
    expect(r.body).toContain(`PORTAL_URL="${h.url}"`);
    expect(r.body).not.toContain('__XG_PORTAL_URL__');
    for (const name of ['uninstall.sh', 'selftest.sh']) {
      const u = await c.req('GET', `/${name}`);
      expect(u.status).toBe(200);
      expect(u.body).toMatch(/^#!\/usr\/bin\/env bash/);
    }
  });

  it('refuses arbitrary download paths', async () => {
    expect((await c.req('GET', '/downloads/..%2F..%2Fetc%2Fpasswd')).status).toBe(404);
    expect((await c.req('GET', '/downloads/other-file')).status).toBe(404);
  });
});
