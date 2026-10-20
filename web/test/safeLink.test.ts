import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serverPageLink } from '../src/safeLink.ts';

// A8 F4: links from an agent are pages of that server, never other sites.
test('server pages pass', () => {
  for (const l of ['settings', 'scanner-logs', 'scanner-logs?paused=1', 'domain-reputation', 'waf-logs']) assert.equal(serverPageLink(l), l);
});

test('other targets are dropped', () => {
  for (const l of ['https://phish.example/login', '//phish.example', '/admin', '../../ai', 'javascript:alert(1)', 'settings#x', ' settings', '', null, 42])
    assert.equal(serverPageLink(l), '');
});
