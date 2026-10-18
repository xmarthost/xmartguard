import { useState } from 'react';
import { Trash2, UserCheck } from 'lucide-react';

/** The account lists of every section, one per column. */
export const EXCEPTION_COLUMNS = [
  { key: 'scan', section: 'scanner', field: 'whitelist_users', label: 'Not scanned', desc: 'The virus scanner skips its files' },
  { key: 'proc', section: 'processes', field: 'whitelist_users', label: 'Processes', desc: 'The process monitor never checks or kills its processes' },
  { key: 'cron', section: 'cron', field: 'whitelist_users', label: 'Cron jobs', desc: 'Its cron jobs are not checked' },
  { key: 'patch', section: 'cms', field: 'exclude_users', label: 'CMS patches', desc: 'Its websites are never updated, patched or have plugins switched off' },
  { key: 'suspend', section: 'auto_suspend', field: 'exclude_users', label: 'Never suspend', desc: 'Never suspended automatically' },
  { key: 'notify', section: 'notifications', field: 'exclude_users', label: 'No emails', desc: 'Gets no xPGuard emails' },
] as const;

type Lists = Record<string, Record<string, unknown> | undefined>;

/** Settings » Account exceptions: one table instead of six lists. */
export function AccountExceptions({ st, users, disabled, save }: {
  st: Lists;
  users: string[];
  disabled: boolean;
  save: (patch: Record<string, Record<string, string[]>>, msg?: string) => Promise<unknown>;
}) {
  const list = (c: (typeof EXCEPTION_COLUMNS)[number]) => ((st[c.section]?.[c.field] as string[] | undefined) ?? []);
  const [extra, setExtra] = useState<string[]>([]);
  const [add, setAdd] = useState('');
  const rows = [...new Set([...EXCEPTION_COLUMNS.flatMap((c) => list(c)), ...extra])].sort();
  const toggle = (c: (typeof EXCEPTION_COLUMNS)[number], user: string, on: boolean) => {
    const cur = list(c);
    const next = on ? [...cur, user] : cur.filter((u) => u !== user);
    void save({ [c.section]: { [c.field]: next } }, `${user}: ${c.label.toLowerCase()} ${on ? 'on' : 'off'}`);
  };
  const remove = (user: string) => {
    const patch: Record<string, Record<string, string[]>> = {};
    for (const c of EXCEPTION_COLUMNS) if (list(c).includes(user)) patch[c.section] = { ...(patch[c.section] ?? {}), [c.field]: list(c).filter((u) => u !== user) };
    setExtra(extra.filter((u) => u !== user));
    if (Object.keys(patch).length) void save(patch, `${user} has no exceptions`);
  };
  return (
    <div>
      <h2 className="flex items-center gap-2 text-lg font-semibold text-navy-900">
        <UserCheck className="h-5 w-5" /> Account exceptions
      </h2>
      <p className="mb-4 text-sm text-slate-500">
        Hosting accounts that xPGuard leaves alone, one row per account. Use it for your own tools and trusted developers, not for customer websites: their
        files then stay unprotected.
      </p>
      <div className="overflow-x-auto rounded-lg border border-slate-200">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-50 text-xs text-slate-500">
            <tr>
              <th className="px-3 py-2">Account</th>
              {EXCEPTION_COLUMNS.map((c) => (
                <th key={c.key} className="px-3 py-2 text-center" title={c.desc}>
                  {c.label}
                </th>
              ))}
              <th />
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {rows.length === 0 && (
              <tr>
                <td colSpan={EXCEPTION_COLUMNS.length + 2} className="px-3 py-5 text-center text-slate-500">
                  No exceptions: every account is protected.
                </td>
              </tr>
            )}
            {rows.map((u) => (
              <tr key={u}>
                <td className="px-3 py-2 font-medium text-navy-900">{u}</td>
                {EXCEPTION_COLUMNS.map((c) => (
                  <td key={c.key} className="px-3 py-2 text-center">
                    <input type="checkbox" className="h-4 w-4" disabled={disabled} checked={list(c).includes(u)} onChange={(e) => toggle(c, u, e.target.checked)} />
                  </td>
                ))}
                <td className="px-3 py-2 text-right">
                  <button className="text-slate-400 hover:text-red-600" disabled={disabled} title="Remove every exception of this account" onClick={() => remove(u)}>
                    <Trash2 className="h-4 w-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <select className="input w-60" value={add} disabled={disabled} onChange={(e) => setAdd(e.target.value)}>
          <option value="">Add an account…</option>
          {users.filter((u) => !rows.includes(u)).map((u) => (
            <option key={u} value={u}>
              {u}
            </option>
          ))}
        </select>
        <button className="btn-outline" disabled={disabled || !add} onClick={() => (setExtra([...extra, add]), setAdd(''))}>
          Add
        </button>
        <span className="text-xs text-slate-400">then tick what it is excepted from.</span>
      </div>
      <ul className="mt-4 grid gap-1 text-xs text-slate-500 sm:grid-cols-2">
        {EXCEPTION_COLUMNS.map((c) => (
          <li key={c.key}>
            <b className="text-slate-600">{c.label}:</b> {c.desc}.
          </li>
        ))}
      </ul>
    </div>
  );
}
