import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyListEdit, listDelta, mergeListPatch, patchHasLists } from '../src/listEdit.ts';

// A8 F3: Settings » WAF was loaded at 10:00; at 10:05 WAF Logs added a rule
// exclusion; at 10:10 the admin removes an unrelated one in Settings. The
// 10:05 exclusion must survive.
test('a list changed elsewhere since the page loaded keeps the other change', () => {
  const a = { rule: 941100, domain: 'a.example', note: 'one' };
  const b = { rule: 942100, domain: 'b.example', note: 'two' };
  const c = { domain: 'c.example', rule: 930120, path: '/x', note: 'added elsewhere' };
  const loaded = { waf: { rule_exclusions: [a, b], enabled: true } };
  const fresh = { waf: { rule_exclusions: [a, b, c], enabled: true } };
  const patch = { waf: { rule_exclusions: [a] } };
  assert.deepEqual(mergeListPatch(loaded, fresh, patch), { waf: { rule_exclusions: [a, c] } });
});

test('an IP added on the page is added to the current list, not the old one', () => {
  const loaded = { firewall: { ddns: ['one.example'] } };
  const fresh = { firewall: { ddns: ['one.example', 'two.example'] } };
  const patch = { firewall: { ddns: ['one.example', 'three.example'], enabled: true } };
  assert.deepEqual(mergeListPatch(loaded, fresh, patch), { firewall: { ddns: ['one.example', 'two.example', 'three.example'], enabled: true } });
});

test('an unchanged list is sent as the page built it (order kept)', () => {
  const loaded = { scanner: { whitelist_users: ['a', 'b'] } };
  const patch = { scanner: { whitelist_users: ['b', 'a'] } };
  assert.deepEqual(mergeListPatch(loaded, structuredClone(loaded), patch), patch);
});

test('removal is by value, not by position', () => {
  const x = { rule: 1, domain: 'x.example' };
  const y = { rule: 2, domain: 'y.example' };
  const z = { rule: 3, domain: 'z.example' };
  // The page showed [x, y] and removes y; the server has [z, x, y] now.
  assert.deepEqual(applyListEdit([z, x, y], { remove: [y] }), [z, x]);
});

test('objects match whatever their field order or empty fields', () => {
  assert.deepEqual(listDelta([{ rule: 1, domain: 'a', path: '' }], [{ domain: 'a', rule: 1 }]), { add: [], remove: [] });
});

test('adding an entry the server already has does not duplicate it', () => {
  assert.deepEqual(applyListEdit(['1.2.3.4'], { add: ['1.2.3.4'] }), ['1.2.3.4']);
});

test('only patches with lists need a fresh read', () => {
  assert.equal(patchHasLists({ waf: { enabled: true } }, { waf: { enabled: false } }), false);
  assert.equal(patchHasLists({ waf: { whitelist_ips: [] } }, { waf: { whitelist_ips: ['1.2.3.4'] } }), true);
});
