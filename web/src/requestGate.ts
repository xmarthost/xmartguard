/**
 * Tracks which answer a data hook may still show. Every load starts a
 * request for the hook's current key (server + action + params, or a path);
 * an answer is shown only if no newer request started and the key did not
 * change since. So switching servers on a mounted page never shows (or
 * later saves) the previous server's data, and a slow old answer never
 * overwrites a newer one.
 */
export function requestGate(key = '') {
  let cur = key;
  let seq = 0;
  return {
    /** Switches to key; true if it changed (the shown data must be dropped). */
    use(k: string) {
      if (k === cur) return false;
      cur = k;
      seq++;
      return true;
    },
    /** Starts a request for key; the returned check is true while its answer may be shown. */
    begin(k: string) {
      const my = ++seq;
      return () => my === seq && k === cur;
    },
  };
}
