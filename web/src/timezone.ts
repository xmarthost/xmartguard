/**
 * The portal shows every date and time in one time zone: Pakistan Standard
 * Time by default (VITE_TIME_ZONE at build time overrides it), whatever the
 * viewer's computer is set to.
 */
export const TIME_ZONE: string = import.meta.env.VITE_TIME_ZONE || 'Asia/Karachi';

/** Short label for headings and tooltips, e.g. "PKT". */
export const TIME_ZONE_LABEL = TIME_ZONE === 'Asia/Karachi' ? 'PKT' : TIME_ZONE;

type Opts = Intl.DateTimeFormatOptions | undefined;
const withZone = (o: Opts): Intl.DateTimeFormatOptions => (o && o.timeZone ? o : { ...o, timeZone: TIME_ZONE });

/**
 * Makes toLocaleString/DateString/TimeString and Intl.DateTimeFormat use the
 * portal's time zone unless a call names another. Called once at start-up.
 */
export function installTimeZone(): void {
  try {
    new Intl.DateTimeFormat('en', { timeZone: TIME_ZONE }).format(0);
  } catch {
    return; // unknown zone in this browser: keep the local time
  }
  const P = Date.prototype;
  const ls = P.toLocaleString;
  const ld = P.toLocaleDateString;
  const lt = P.toLocaleTimeString;
  P.toLocaleString = function (this: Date, l?: Intl.LocalesArgument, o?: Opts) {
    return ls.call(this, l, withZone(o));
  };
  P.toLocaleDateString = function (this: Date, l?: Intl.LocalesArgument, o?: Opts) {
    return ld.call(this, l, withZone(o));
  };
  P.toLocaleTimeString = function (this: Date, l?: Intl.LocalesArgument, o?: Opts) {
    return lt.call(this, l, withZone(o));
  };
  const DTF = Intl.DateTimeFormat;
  // Works with and without `new`, like the original.
  const Zoned = function (l?: Intl.LocalesArgument, o?: Opts) {
    return new DTF(l, withZone(o));
  } as unknown as { prototype: unknown; supportedLocalesOf: unknown };
  Zoned.prototype = DTF.prototype;
  Zoned.supportedLocalesOf = DTF.supportedLocalesOf;
  Intl.DateTimeFormat = Zoned as unknown as typeof Intl.DateTimeFormat;
}

/** Calendar fields of a moment in the portal's time zone (for hand-made labels). */
export function zoned(d: Date | number): { year: number; month: number; day: number; hour: number; minute: number; second: number } {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: TIME_ZONE,
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
    second: 'numeric',
    hourCycle: 'h23',
  }).formatToParts(typeof d === 'number' ? new Date(d) : d);
  const get = (t: string) => Number(parts.find((p) => p.type === t)?.value ?? 0);
  return { year: get('year'), month: get('month'), day: get('day'), hour: get('hour'), minute: get('minute'), second: get('second') };
}
