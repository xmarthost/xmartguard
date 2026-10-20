/**
 * List settings (allow lists, disabled rules, rule exclusions…) are saved
 * whole. A page that shows a list read minutes ago must not send that old
 * list plus its own change: an entry added elsewhere since (another admin,
 * WAF Logs » Allow on this site) would be lost. These helpers turn the
 * page's change into a delta (what it added, what it removed) and apply it
 * to the list the server has now.
 */

/** Same entry: strings by value, objects by their fields (in any order). */
export function itemKey(v: unknown): string {
  return JSON.stringify(v, (_, x) =>
    x && typeof x === 'object' && !Array.isArray(x) ? Object.fromEntries(Object.entries(x).filter(([, y]) => y !== undefined && y !== '').sort(([a], [b]) => (a < b ? -1 : 1))) : x,
  );
}

export interface ListEdit<T> {
  add?: T[];
  remove?: T[];
}

/** What next added to and removed from old. */
export function listDelta<T>(old: T[], next: T[]): Required<ListEdit<T>> {
  const o = new Set(old.map(itemKey));
  const n = new Set(next.map(itemKey));
  return { add: next.filter((x) => !o.has(itemKey(x))), remove: old.filter((x) => !n.has(itemKey(x))) };
}

/** current with the removed entries taken out and the added ones appended (once). */
export function applyListEdit<T>(current: T[], edit: ListEdit<T>): T[] {
  const rm = new Set((edit.remove ?? []).map(itemKey));
  const out = current.filter((x) => !rm.has(itemKey(x)));
  const have = new Set(out.map(itemKey));
  for (const x of edit.add ?? []) {
    const k = itemKey(x);
    if (!have.has(k)) {
      have.add(k);
      out.push(x);
    }
  }
  return out;
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/** True if the patch writes a list that the page had loaded. */
export function patchHasLists(loaded: unknown, patch: unknown): boolean {
  if (!isObj(patch) || !isObj(loaded)) return false;
  return Object.entries(patch).some(([k, v]) => (Array.isArray(v) ? Array.isArray(loaded[k]) : patchHasLists(loaded[k], v)));
}

/**
 * Rewrites every list in a settings patch against the server's current
 * settings: a list the server still has as loaded is sent as the page
 * built it (keeps its order); a list that changed since is sent as the
 * current list plus the page's own additions and removals.
 */
export function mergeListPatch(loaded: unknown, fresh: unknown, patch: unknown): unknown {
  if (!isObj(patch)) return patch;
  const l = isObj(loaded) ? loaded : {};
  const f = isObj(fresh) ? fresh : {};
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(patch)) {
    if (Array.isArray(v) && Array.isArray(l[k]) && Array.isArray(f[k])) {
      const was = l[k] as unknown[];
      const now = f[k] as unknown[];
      out[k] = itemKey(was) === itemKey(now) ? v : applyListEdit(now, listDelta(was, v));
    } else out[k] = isObj(v) ? mergeListPatch(l[k], f[k], v) : v;
  }
  return out;
}
