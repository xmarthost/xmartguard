import { test } from 'node:test';
import assert from 'node:assert/strict';
import { requestGate } from '../src/requestGate.ts';

// A8 F2: a page mounted for server A switches to server B while A's answer
// is still on the way. B must never show A's data.
test('an answer for the previous server is dropped after a switch', () => {
  const g = requestGate('A:settings.get:{}');
  const fromA = g.begin('A:settings.get:{}');
  assert.equal(g.use('B:settings.get:{}'), true);
  const fromB = g.begin('B:settings.get:{}');
  assert.equal(fromB(), true);
  assert.equal(fromA(), false);
});

test('an answer for the previous server is dropped even if it arrives first', () => {
  const g = requestGate('A');
  const fromA = g.begin('A');
  g.use('B');
  assert.equal(fromA(), false);
});

test('an older answer for the same key never overwrites a newer one', () => {
  const g = requestGate('A');
  const poll = g.begin('A');
  const reload = g.begin('A');
  assert.equal(reload(), true);
  assert.equal(poll(), false);
});

test('the same key is not a switch', () => {
  const g = requestGate('A');
  const r = g.begin('A');
  assert.equal(g.use('A'), false);
  assert.equal(r(), true);
});
