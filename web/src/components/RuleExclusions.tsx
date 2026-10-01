import { useState } from 'react';
import { Plus, Trash2 } from 'lucide-react';

export interface RuleExclusion {
  rule: number;
  domain?: string;
  path?: string;
  note?: string;
}

const reDomain = /^(?:\*\.)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;
const rePath = /^\/[A-Za-z0-9._~/-]*$/;

/** Checks one exclusion the way the agent does (it drops invalid ones). */
export function exclusionError(e: RuleExclusion): string | null {
  if (!Number.isInteger(e.rule) || e.rule <= 0 || e.rule > 99999999) return 'Enter a numeric rule id';
  if (e.domain && (!reDomain.test(e.domain) || /^(?:\*\.)?[\d.]+$/.test(e.domain))) return 'Enter a domain like example.com or *.example.com';
  if (e.path && !rePath.test(e.path)) return 'Enter a path starting with / (letters, digits, . _ ~ - / only)';
  return null;
}

/** The path part of a request URI, as an exclusion path. */
export function uriPath(uri: string): string {
  const p = (uri || '/').split('?')[0].split('#')[0];
  return rePath.test(p) ? p : '';
}

/** Per-website rule exclusions: one rule switched off for one website
 *  (and path) instead of everywhere. */
export function RuleExclusionsEditor({
  items,
  domains,
  disabled,
  vendor,
  onChange,
}: {
  items: RuleExclusion[];
  domains?: string[];
  disabled: boolean;
  vendor?: string;
  onChange: (v: RuleExclusion[]) => void;
}) {
  const [rule, setRule] = useState('');
  const [domain, setDomain] = useState('');
  const [path, setPath] = useState('');
  const [note, setNote] = useState('');
  const [err, setErr] = useState('');
  const add = () => {
    const e: RuleExclusion = {
      rule: Number(rule),
      domain: domain.trim().toLowerCase() || undefined,
      path: path.trim() || undefined,
      note: note.trim() || undefined,
    };
    const bad = exclusionError(e);
    if (bad) return setErr(bad);
    setErr('');
    onChange([...items, e]);
    setRule('');
    setPath('');
    setNote('');
  };
  return (
    <div className="border-b border-slate-100 py-4">
      <div className="font-medium text-navy-900">Rule exclusions per website</div>
      <p className="mb-3 text-sm text-slate-500">
        Switch one rule off only where it blocks something legitimate (a website, or a path of it), instead of for every website. Works for xPGuard's rules, the
        OWASP Core Rule Set
        {vendor ? ` and ${vendor}` : ' and vendor rules'}. WAF Logs has an "Allow on this site" button that fills this in from a blocked request. WordPress
        admin screens of logged-in users and writes to WordPress's own REST API are already exempt from the injection rules (rules 7700010–7700012).
      </p>
      {items.length > 0 && (
        <div className="mb-3 overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-slate-500 uppercase">
              <tr>
                <th className="py-1 pr-3">Rule</th>
                <th className="pr-3">Website</th>
                <th className="pr-3">Path</th>
                <th className="pr-3">Note</th>
                <th />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {items.map((e, i) => (
                <tr key={`${e.rule}-${e.domain}-${e.path}-${i}`}>
                  <td className="py-2 pr-3 font-mono text-xs">{e.rule}</td>
                  <td className="pr-3">{e.domain || <span className="text-slate-400">all websites</span>}</td>
                  <td className="pr-3 font-mono text-xs break-all">{e.path || <span className="font-sans text-slate-400">whole site</span>}</td>
                  <td className="pr-3 text-xs text-slate-500">{e.note}</td>
                  <td className="text-right">
                    <button
                      className="text-slate-400 hover:text-red-600"
                      title="Remove"
                      disabled={disabled}
                      onClick={() => onChange(items.filter((_, j) => j !== i))}
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-sm">
          <div className="label">Rule id</div>
          <input
            className="input w-28"
            inputMode="numeric"
            placeholder="941100"
            value={rule}
            disabled={disabled}
            onChange={(e) => setRule(e.target.value.replace(/\D/g, ''))}
          />
        </label>
        <label className="text-sm">
          <div className="label">Website</div>
          <input
            className="input w-56"
            list="xg-excl-domains"
            placeholder="all websites"
            value={domain}
            disabled={disabled}
            onChange={(e) => setDomain(e.target.value)}
          />
          <datalist id="xg-excl-domains">
            {(domains ?? []).map((d) => (
              <option key={d} value={d} />
            ))}
          </datalist>
        </label>
        <label className="text-sm">
          <div className="label">Path starts with</div>
          <input className="input w-56" placeholder="/wp-admin/admin.php" value={path} disabled={disabled} onChange={(e) => setPath(e.target.value)} />
        </label>
        <label className="text-sm">
          <div className="label">Note</div>
          <input className="input w-48" placeholder="why" value={note} disabled={disabled} onChange={(e) => setNote(e.target.value)} />
        </label>
        <button className="btn-primary" disabled={disabled || !rule} onClick={add}>
          <Plus className="h-4 w-4" /> Add
        </button>
      </div>
      {err && <p className="mt-2 text-sm text-red-600">{err}</p>}
    </div>
  );
}

export interface LearnedExclusion extends RuleExclusion {
  key: string;
  where?: string;
  sample?: string;
  msg?: string;
  ips: number;
  hits: number;
  learned: number;
  expires: number;
  state: 'active' | 'suggested' | 'rejected';
}

const MODES = [
  { v: 'auto', l: 'Switch off automatically (recommended)' },
  { v: 'suggest', l: 'Only suggest, I decide' },
  { v: 'off', l: 'Off' },
];

/** False positives the agent learned from the WAF log: a rule that several
 *  clean visitors of one website keep hitting on the same path. */
export function LearnedExclusions({
  mode,
  items,
  cpanelOff,
  disabled,
  onMode,
  onAction,
}: {
  mode: string;
  items: LearnedExclusion[];
  cpanelOff: string[];
  disabled: boolean;
  onMode: (m: string) => void;
  onAction: (key: string, action: 'accept' | 'reject' | 'forget') => void;
}) {
  const [all, setAll] = useState(false);
  const shown = all ? items : items.slice(0, 5);
  const day = (t: number) => (t ? new Date(t * 1000).toLocaleDateString() : '–');
  return (
    <div className="border-b border-slate-100 py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="max-w-3xl">
          <div className="font-medium text-navy-900">Automatic false-positive protection</div>
          <p className="text-sm text-slate-500">
            A rule that keeps blocking real visitors on one page of one website is switched off for that page only, for 30 days. Scans, probes and whole-website
            exclusions of attack rules are never learned.
          </p>
        </div>
        <select className="input w-72" value={mode} disabled={disabled} onChange={(e) => onMode(e.target.value)}>
          {MODES.map((m) => (
            <option key={m.v} value={m.v}>
              {m.l}
            </option>
          ))}
        </select>
      </div>
      {shown.length === 0 ? (
        <p className="mt-3 rounded-lg bg-slate-50 px-3 py-2 text-sm text-slate-500">Nothing learned on this server yet.</p>
      ) : (
        <div className="mt-3 overflow-x-auto">
          <table className="w-full min-w-[760px] text-sm">
            <thead className="text-left text-xs text-slate-500 uppercase">
              <tr>
                <th className="py-1 pr-3">Website &amp; path</th>
                <th className="pr-3">Rule</th>
                <th className="pr-3">Visitors</th>
                <th className="pr-3">Learned</th>
                <th className="pr-3">State</th>
                <th />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {shown.map((e) => (
                <tr key={e.key} className="align-top">
                  <td className="py-2 pr-3">
                    <div className="text-navy-900">{e.domain}</div>
                    <div className="font-mono text-xs break-all text-slate-500">{e.path || 'whole website'}</div>
                  </td>
                  <td className="pr-3">
                    <span className="font-mono text-xs">{e.rule}</span>
                    {e.where && <div className="font-mono text-xs text-slate-400">{e.where}</div>}
                    {e.msg && (
                      <div className="max-w-xs truncate text-xs text-slate-400" title={e.msg}>
                        {e.msg}
                      </div>
                    )}
                  </td>
                  <td className="pr-3 text-xs">
                    {e.ips} <span className="text-slate-400">({e.hits} blocks)</span>
                  </td>
                  <td className="pr-3 text-xs whitespace-nowrap">
                    {day(e.learned)}
                    {e.state === 'active' && <div className="text-slate-400">until {day(e.expires)}</div>}
                  </td>
                  <td className="pr-3 text-xs">
                    <span
                      className={`rounded-full px-2 py-0.5 ${e.state === 'active' ? 'bg-emerald-50 text-emerald-700' : e.state === 'suggested' ? 'bg-amber-50 text-amber-700' : 'bg-slate-100 text-slate-500'}`}
                    >
                      {e.state === 'active' ? 'allowed' : e.state}
                    </span>
                  </td>
                  <td className="text-right whitespace-nowrap">
                    {e.state === 'suggested' && (
                      <button className="btn-outline mr-2 px-2 py-1 text-xs" disabled={disabled} onClick={() => onAction(e.key, 'accept')}>
                        Allow
                      </button>
                    )}
                    {e.state !== 'rejected' ? (
                      <button
                        className="btn-outline px-2 py-1 text-xs"
                        disabled={disabled}
                        title="Keep the rule on here and never learn this again"
                        onClick={() => onAction(e.key, 'reject')}
                      >
                        Keep blocking
                      </button>
                    ) : (
                      <button
                        className="btn-outline px-2 py-1 text-xs"
                        disabled={disabled}
                        title="Forget the decision; it may be learned again"
                        onClick={() => onAction(e.key, 'forget')}
                      >
                        Forget
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {items.length > 5 && (
            <button className="mt-2 text-sm text-blue-700 hover:underline" onClick={() => setAll(!all)}>
              {all ? 'Show less' : `Show all ${items.length}`}
            </button>
          )}
        </div>
      )}
      {cpanelOff.length > 0 && (
        <div className="mt-4 rounded-lg bg-sky-50 px-3 py-2 text-sm text-sky-800">
          <b>ModSecurity switched off in cPanel</b> for {cpanelOff.length} website{cpanelOff.length > 1 ? 's' : ''} (by the account owner in cPanel »
          ModSecurity): no WAF rule runs there, xPGuard's included. {cpanelOff.slice(0, 12).join(', ')}
          {cpanelOff.length > 12 && ` and ${cpanelOff.length - 12} more`}
        </div>
      )}
    </div>
  );
}
