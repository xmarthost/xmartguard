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
