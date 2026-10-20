/**
 * "datetime-local" inputs hold a wall-clock time with no zone, and
 * `new Date(value)` reads it in the browser's zone. The portal shows every
 * time in its own zone (PKT), so an admin who reads "14:00" in a log and
 * types 14:00 means 14:00 PKT. These read and write such values in a given
 * zone (timezone.ts passes the portal's).
 */

function fields(zone: string, ms: number) {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: zone,
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
    second: 'numeric',
    hourCycle: 'h23',
  }).formatToParts(new Date(ms));
  const get = (t: string) => Number(parts.find((p) => p.type === t)?.value ?? 0);
  return { year: get('year'), month: get('month'), day: get('day'), hour: get('hour'), minute: get('minute'), second: get('second') };
}

/** How far the zone's wall clock is ahead of UTC at a moment, in ms. */
function offset(zone: string, ms: number): number {
  const f = fields(zone, ms);
  return Date.UTC(f.year, f.month - 1, f.day, f.hour, f.minute, f.second) - Math.floor(ms / 1000) * 1000;
}

/** Unix seconds of a "YYYY-MM-DDTHH:mm" value read in zone; 0 if empty or invalid. */
export function fromZonedInput(v: string, zone: string): number {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(v);
  if (!m) return 0;
  const wall = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] ?? 0));
  // Twice: the offset at the guess can differ from the one at the answer
  // around a daylight-saving change.
  let t = wall - offset(zone, wall);
  t = wall - offset(zone, t);
  return Math.floor(t / 1000);
}

/** "YYYY-MM-DDTHH:mm" of unix seconds in zone. */
export function toZonedInput(unix: number, zone: string): string {
  const f = fields(zone, unix * 1000);
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  return `${p(f.year, 4)}-${p(f.month)}-${p(f.day)}T${p(f.hour)}:${p(f.minute)}`;
}
