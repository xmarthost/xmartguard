import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fromZonedInput, toZonedInput } from '../src/zonedInput.ts';

// A8 F5: an admin reads "changed at 14:00" (PKT) and types 14:00 into the
// fleet rollback: that is 09:00 UTC, whatever zone the browser is in.
test('a typed time is read in the portal zone, not the browser zone', () => {
  assert.equal(fromZonedInput('2026-10-20T14:00', 'Asia/Karachi'), Date.UTC(2026, 9, 20, 9, 0) / 1000);
  assert.equal(fromZonedInput('2026-10-20T14:00', 'UTC'), Date.UTC(2026, 9, 20, 14, 0) / 1000);
});

test('the default "from" shows the portal zone time', () => {
  assert.equal(toZonedInput(Date.UTC(2026, 9, 20, 21, 30) / 1000, 'Asia/Karachi'), '2026-10-21T02:30');
});

test('round trip, also across a daylight-saving change', () => {
  for (const zone of ['Asia/Karachi', 'America/New_York', 'Europe/London']) {
    for (const t of [Date.UTC(2026, 2, 8, 12, 0) / 1000, Date.UTC(2026, 10, 1, 12, 0) / 1000, Date.UTC(2026, 6, 1, 0, 0) / 1000]) {
      assert.equal(fromZonedInput(toZonedInput(t, zone), zone), t, `${zone} ${t}`);
    }
  }
});

test('empty or invalid is 0', () => {
  assert.equal(fromZonedInput('', 'Asia/Karachi'), 0);
  assert.equal(fromZonedInput('yesterday', 'Asia/Karachi'), 0);
});
