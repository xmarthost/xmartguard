import { describe, expect, it } from 'vitest';
import Fastify from 'fastify';
import { isCloudflare, setExtraProxies, trustedProxy } from '../src/proxy.js';

// A visitor must not choose its own address with a forged X-Forwarded-For:
// only this host, private networks, Cloudflare and the own servers may name
// the visitor.
describe('proxy trust', () => {
  const app = Fastify({ trustProxy: (a: string) => trustedProxy(a) });
  app.get('/ip', async (req) => ({ ip: req.ip }));
  const ip = async (remoteAddress: string, xff?: string) =>
    (await app.inject({ url: '/ip', remoteAddress, headers: xff ? { 'x-forwarded-for': xff } : {} })).json().ip;

  it('takes the address the local web server added, not one the client made up', async () => {
    // Apache on this host appends the real peer to what the client sent.
    expect(await ip('127.0.0.1', '6.6.6.6, 203.0.113.9')).toBe('203.0.113.9');
    expect(await ip('172.18.0.1', '203.0.113.9')).toBe('203.0.113.9');
  });

  it('ignores X-Forwarded-For from anyone who is not a proxy', async () => {
    expect(await ip('198.51.100.7', '6.6.6.6')).toBe('198.51.100.7');
  });

  it('walks back through Cloudflare and configured front proxies', async () => {
    setExtraProxies('198.51.100.50');
    expect(await ip('127.0.0.1', '6.6.6.6, 203.0.113.9, 104.16.0.1, 198.51.100.50')).toBe('203.0.113.9');
    setExtraProxies('');
    expect(await ip('127.0.0.1', '203.0.113.9, 104.16.0.1, 198.51.100.50')).toBe('198.51.100.50');
  });

  it('knows Cloudflare addresses, also IPv4-mapped', () => {
    expect(isCloudflare('104.16.0.1')).toBe(true);
    expect(isCloudflare('::ffff:104.16.0.1')).toBe(true);
    expect(isCloudflare('2606:4700::1')).toBe(true);
    expect(isCloudflare('203.0.113.9')).toBe(false);
  });
});

// A banned visitor of the server hosting the portal reaches it through
// that server's agent; the web server in front of the portal names the
// agent. The visitor's address comes in a header the agent signs, taken
// only from the master account's servers (2026-11-08: every such visitor
// shared one address, so one rate limit and refused passes).
describe('visitor address from an agent', () => {
  it('takes a fresh header signed by an own server only', async () => {
    const crypto = await import('node:crypto');
    const { agentVisitor, setOwnServersForTest, visitorPayload } = await import('../src/proxy.js');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64');
    const sid = '15d69a72-653a-47b6-90f6-fde737bce061';
    setOwnServersForTest([{ id: sid, ip: '162.55.6.159', publicKey: pub }]);
    const now = 1_794_100_000;
    const sign = (ip: string, ts: number) => `${ip} ${ts} ${sid} ${crypto.sign(null, Buffer.from(visitorPayload(sid, ip, String(ts))), privateKey).toString('base64')}`;
    expect(agentVisitor('162.55.6.159', sign('37.203.35.18', now), now)).toBe('37.203.35.18');
    // From anywhere else (a visitor sending it itself): ignored.
    expect(agentVisitor('203.0.113.9', sign('37.203.35.18', now), now)).toBe('');
    // A website on that server forging it: no valid signature.
    expect(agentVisitor('162.55.6.159', `6.6.6.6 ${now} ${sid} ${Buffer.from('x').toString('base64')}`, now)).toBe('');
    // Another address with a signature made for the first one.
    const good = sign('37.203.35.18', now).split(' ');
    expect(agentVisitor('162.55.6.159', ['6.6.6.6', ...good.slice(1)].join(' '), now)).toBe('');
    // Old (replayed).
    expect(agentVisitor('162.55.6.159', sign('37.203.35.18', now - 600), now)).toBe('');
    expect(agentVisitor('162.55.6.159', undefined, now)).toBe('');
    setOwnServersForTest([]);
  });
});
