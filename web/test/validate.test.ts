import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isDomain, isIPorCIDR } from '../src/validate.ts';

// A8 F13: one validation for every page, with octet and prefix range checks.
test('IP and CIDR', () => {
  for (const v of ['203.0.113.7', '203.0.113.0/24', '0.0.0.0/0', '2001:db8::1', '2001:db8::/32', '::1', '2001:db8:0:0:0:0:0:1'])
    assert.equal(isIPorCIDR(v), null, v);
  for (const v of ['999.1.1.1/99', '1.2.3.4/33', '256.1.1.1', '1.2.3', '2001:db8::/129', '1::2::3', 'abcd', '1.2.3.4/', '1.2.3.4/8/8', 'example.com'])
    assert.notEqual(isIPorCIDR(v), null, v);
});

test('domains', () => {
  for (const v of ['example.com', '*.example.com', 'a-b.example.co.uk']) assert.equal(isDomain(v), true, v);
  for (const v of ['-a-.com', 'a-.com', 'example', '1.2.3.4', '*.1.2.3', 'exa mple.com', 'Example.com']) assert.equal(isDomain(v), false, v);
});
