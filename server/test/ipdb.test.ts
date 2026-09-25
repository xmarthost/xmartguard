import { describe, expect, it } from 'vitest';
import { GeoDB, v6num } from '../src/ipdb/geo.js';
import { entryText, parseCidr, parseFeed, reportable } from '../src/ipdb/service.js';

describe('geoip', () => {
  const geo = new GeoDB();
  geo.load(['1.0.0.0,1.0.0.255,AU', '"8.8.8.0","8.8.8.255","US"', '2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,NL', 'bad,line'].join('\n'));
  it('looks up IPv4, IPv6 and CIDRs', () => {
    expect(geo.size).toBe(3);
    expect(geo.lookup('1.0.0.7')).toBe('AU');
    expect(geo.lookup('8.8.8.8')).toBe('US');
    expect(geo.lookup('8.8.9.1')).toBe('');
    expect(geo.lookup('0.1.1.1')).toBe('');
    expect(geo.lookup('8.8.8.0/24')).toBe('US');
    expect(geo.lookup('2001:db8::5')).toBe('NL');
    expect(geo.lookup('2001:db9::5')).toBe('');
  });
  it('parses IPv6 forms', () => {
    expect(v6num('::1')).toBe(1n);
    expect(v6num('::ffff:1.2.3.4')).toBe((0xffffn << 32n) + 0x01020304n);
  });
});

describe('ipdb helpers', () => {
  it('validates addresses and networks', () => {
    expect(parseCidr('203.0.113.5')).toBe('203.0.113.5');
    expect(parseCidr('203.0.113.5/32')).toBe('203.0.113.5');
    expect(parseCidr('198.51.100.0/24')).toBe('198.51.100.0/24');
    expect(parseCidr('1.0.0.0/4')).toBeNull();
    expect(parseCidr('1.2.3.4/33')).toBeNull();
    expect(parseCidr('nope')).toBeNull();
    expect(parseCidr('2001:DB8::/32')).toBe('2001:db8::/32');
    expect(entryText('1.2.3.4/32')).toBe('1.2.3.4');
  });
  it('never reports private or reserved addresses', () => {
    for (const ip of ['10.1.2.3', '192.168.1.1', '127.0.0.1', '172.20.0.1', '100.64.1.1', '169.254.1.1', '::1', 'fe80::1', 'fd00::1', 'x']) {
      expect(reportable(ip), ip).toBe(false);
    }
    expect(reportable('203.0.113.9')).toBe(true);
    expect(reportable('2a00:1450::1')).toBe(true);
  });
  it('parses NDJSON and plain feeds', () => {
    const ndjson = '{"cidr":"1.10.16.0/20","sblid":"SBL1"}\n{"type":"metadata","timestamp":1}\n{"cidr":"10.0.0.0/8"}\n';
    expect(parseFeed(ndjson)).toEqual(['1.10.16.0/20']);
    const plain = '; Spamhaus DROP\n1.19.0.0/16 ; SBL2\n# comment\n203.0.113.4\n\ngarbage\n';
    expect(parseFeed(plain)).toEqual(['1.19.0.0/16', '203.0.113.4']);
  });
});
