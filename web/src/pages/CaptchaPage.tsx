import { useEffect, useState } from 'react';
import { ExternalLink, Save, Search, ShieldQuestion, Trash2 } from 'lucide-react';
import { api } from '../api';
import { can, useAuth } from '../auth';
import { Breadcrumb, ErrorBox, PageLoader } from '../components/ui';
import { Card, Pager, SettingRow, Toggle, useAction } from '../components/controls';
import { useApi } from '../hooks';

interface Resp {
  config: { enabled: boolean; site_key: string; secret_set: boolean; minutes: number };
  version: number;
  updated_at: string | null;
  url: string;
  last24h: { passed: number; failed: number; rejected: number; offline: number };
  servers: { id: string; hostname: string; online: boolean }[];
}

const DURATIONS: [number, string][] = [
  [60, '1 hour'],
  [360, '6 hours'],
  [720, '12 hours'],
  [1440, '24 hours'],
  [4320, '3 days'],
  [10080, '7 days'],
];

const RESULT: Record<string, [string, string]> = {
  passed: ['Passed', 'bg-emerald-50 text-emerald-700'],
  failed: ['Failed check', 'bg-amber-50 text-amber-700'],
  rejected: ['Refused', 'bg-red-50 text-red-700'],
  offline: ['Server offline', 'bg-slate-100 text-slate-600'],
};

/** Overview » CAPTCHA Page: the xPGuard CAPTCHA page for suspicious visitors of login pages. */
export default function CaptchaPage() {
  const { user } = useAuth();
  const admin = can(user, 'admin');
  const res = useApi<Resp>('/api/captcha');
  const { run, busy } = useAction();
  const [enabled, setEnabled] = useState(false);
  const [siteKey, setSiteKey] = useState('');
  const [secret, setSecret] = useState('');
  const [minutes, setMinutes] = useState(720);

  useEffect(() => {
    if (!res.data) return;
    setEnabled(res.data.config.enabled);
    setSiteKey(res.data.config.site_key);
    setMinutes(res.data.config.minutes);
    setSecret('');
  }, [res.data]);

  if (res.error && !res.data) return <ErrorBox message={res.error} />;
  if (!res.data) return <PageLoader />;
  const d = res.data;
  const dirty = enabled !== d.config.enabled || siteKey !== d.config.site_key || minutes !== d.config.minutes || secret !== '';
  const online = d.servers.filter((s) => s.online).length;
  const preview = d.servers[0] ? `${d.url}?s=${d.servers[0].id}&preview=1` : '';
  const save = () =>
    run(
      () => api<{ version: number; pushed: number; offline: number }>('PUT', '/api/captcha', { enabled, site_key: siteKey.trim(), secret_key: secret.trim(), minutes }).then((r) => (res.reload(), r)),
      (r) => `Saved: applied on ${r.pushed} online server${r.pushed === 1 ? '' : 's'}${r.offline ? `; ${r.offline} offline will follow when they reconnect` : ''}`,
    );

  return (
    <div className="space-y-5">
      <Breadcrumb items={['Overview', 'CAPTCHA Page']} />
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="h-title flex items-center gap-2">
            <ShieldQuestion className="h-6 w-6 text-orange-500" /> CAPTCHA Page
          </h1>
          <p className="max-w-3xl text-sm text-slate-500">
            Suspicious visitors of the websites' login pages (addresses on the IPDB, banned in the last 7 days, or blocked by the WAF 3 times in 24 hours) are sent to
            xPGuard's own verification page. After a Cloudflare Turnstile check they go straight back to the login page, and the address is not asked again for the time
            below. Everyone else logs in as usual. While this page is on it also replaces each server's own CAPTCHA: the login-page CAPTCHA for every
            visitor (WAF settings) and the CAPTCHA for banned addresses (Firewall » CAPTCHA) send visitors here, and solving it lifts a temporary ban.
          </p>
        </div>
        {admin && (
          <button className="btn-primary" disabled={busy || !dirty} onClick={save}>
            <Save className="h-4 w-4" /> {dirty ? 'Save & apply to all servers' : 'Saved'}
          </button>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {(
          [
            ['Passed (24 h)', d.last24h.passed, 'text-emerald-600'],
            ['Failed check', d.last24h.failed, 'text-amber-600'],
            ['Refused', d.last24h.rejected, 'text-red-600'],
            ['Servers online', `${online} / ${d.servers.length}`, 'text-navy-900'],
          ] as [string, number | string, string][]
        ).map(([l, v, c]) => (
          <div key={l} className="card p-4">
            <div className="text-xs uppercase text-slate-500">{l}</div>
            <div className={`mt-1 text-2xl font-bold ${c}`}>{v}</div>
          </div>
        ))}
      </div>

      <Card title="Setup" desc="The page runs on this portal. Its address is used by the WAF of every server.">
        <SettingRow title="Send suspicious visitors of login pages to the CAPTCHA page" desc="On all servers, except where Malware.Expert's own login CAPTCHA is used, or where the login-page CAPTCHA already asks every visitor.">
          <Toggle on={enabled} disabled={!admin || busy} onChange={setEnabled} />
        </SettingRow>
        <div className="grid gap-4 py-4 md:grid-cols-2">
          <label className="block">
            <span className="text-sm font-medium text-navy-900">Turnstile site key</span>
            <input className="input mt-1 w-full font-mono" value={siteKey} disabled={!admin || busy} placeholder="0x4AAAAAAA…" onChange={(e) => setSiteKey(e.target.value)} />
          </label>
          <label className="block">
            <span className="text-sm font-medium text-navy-900">Turnstile secret key</span>
            <input
              className="input mt-1 w-full font-mono"
              type="password"
              value={secret}
              disabled={!admin || busy}
              placeholder={d.config.secret_set ? 'Saved; type a new one to replace it' : '0x4AAAAAAA…'}
              onChange={(e) => setSecret(e.target.value)}
            />
          </label>
        </div>
        <p className="text-xs text-slate-500">
          Cloudflare dashboard » Turnstile » Add widget: hostname{' '}
          <span className="font-mono">{(() => { try { return new URL(d.url).host; } catch { return d.url; } })()}</span>, widget mode "Managed". The secret key stays on the portal;
          it is never shown again or sent to the servers.
        </p>
        <SettingRow title="Do not ask a verified address again for" desc="How long a solved check lets the address into the login pages of that server.">
          <select className="input w-40" value={minutes} disabled={!admin || busy} onChange={(e) => setMinutes(Number(e.target.value))}>
            {DURATIONS.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </SettingRow>
        <div className="flex flex-wrap items-center justify-between gap-3 pt-3 text-sm">
          <span className="text-slate-500">
            Page address: <span className="font-mono text-navy-900">{d.url}</span>
          </span>
          {preview && (
            <a className="btn-outline" href={preview} target="_blank" rel="noreferrer">
              <ExternalLink className="h-4 w-4" /> Preview the page
            </a>
          )}
        </div>
      </Card>

      <RecentChecks admin={admin} />
    </div>
  );
}

interface Check {
  id: string;
  at: string;
  ip: string;
  host: string;
  result: string;
  server: string;
}

const PAGE_SIZES = [25, 50, 100, 200];

function savedPageSize(): number {
  try {
    const n = Number(localStorage.getItem('xg-captcha-page-size'));
    return PAGE_SIZES.includes(n) ? n : 50;
  } catch {
    return 50;
  }
}

/** The recorded checks: filter, search, page size, pages, delete chosen or all. */
function RecentChecks({ admin }: { admin: boolean }) {
  const [limit, setLimit] = useState(savedPageSize);
  const [offset, setOffset] = useState(0);
  const [result, setResult] = useState('');
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [sel, setSel] = useState<Set<string>>(new Set());
  const { run, busy } = useAction();
  const path = `/api/captcha/events?limit=${limit}&offset=${offset}&result=${result}&q=${encodeURIComponent(query)}`;
  const res = useApi<{ events: Check[]; total: number }>(path);
  useEffect(() => setSel(new Set()), [path]);
  // Search as you type, a moment after the last key.
  useEffect(() => {
    const t = setTimeout(() => {
      setOffset(0);
      setQuery(q.trim());
    }, 400);
    return () => clearTimeout(t);
  }, [q]);

  const rows = res.data?.events ?? [];
  const total = res.data?.total ?? 0;
  const allOn = rows.length > 0 && rows.every((r) => sel.has(r.id));
  const toggle = (id: string) => {
    const n = new Set(sel);
    if (n.has(id)) n.delete(id);
    else n.add(id);
    setSel(n);
  };
  const del = (ids?: string[]) =>
    run(
      () => api<{ deleted: number }>('DELETE', '/api/captcha/events', ids ? { ids } : {}).then((r) => (res.reload(), r)),
      (r) => `${r.deleted} check${r.deleted === 1 ? '' : 's'} deleted`,
    );

  return (
    <Card title="Recent checks" desc="Visitors sent to the page, newest first (kept 30 days).">
      <div className="flex flex-wrap items-center gap-2 pb-3">
        <div className="relative min-w-[180px] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input className="input w-full pl-9" placeholder="Search address or website" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <select className="input w-40" value={result} onChange={(e) => (setOffset(0), setResult(e.target.value))}>
          <option value="">All results</option>
          <option value="passed">Passed</option>
          <option value="failed">Failed check</option>
          <option value="rejected">Refused</option>
          <option value="offline">Server offline</option>
        </select>
        <select
          className="input w-32"
          value={limit}
          aria-label="Rows per page"
          onChange={(e) => {
            const n = Number(e.target.value);
            setLimit(n);
            setOffset(0);
            try {
              localStorage.setItem('xg-captcha-page-size', String(n));
            } catch {
              /* not kept */
            }
          }}
        >
          {PAGE_SIZES.map((n) => (
            <option key={n} value={n}>
              {n} per page
            </option>
          ))}
        </select>
        {admin && (
          <>
            <button className="btn-outline" disabled={busy || sel.size === 0} onClick={() => confirm(`Delete ${sel.size} selected check(s)?`) && del(Array.from(sel))}>
              <Trash2 className="h-4 w-4" /> Delete selected{sel.size ? ` (${sel.size})` : ''}
            </button>
            <button className="btn-outline text-red-600" disabled={busy || total === 0} onClick={() => confirm('Delete all recorded checks?') && del()}>
              <Trash2 className="h-4 w-4" /> Clear all
            </button>
          </>
        )}
      </div>
      {res.error && !res.data ? (
        <ErrorBox message={res.error} />
      ) : rows.length === 0 ? (
        <p className="py-4 text-sm text-slate-500">{res.data ? 'No checks.' : 'Loading…'}</p>
      ) : (
        <div className="max-h-[560px] overflow-auto rounded-lg border border-slate-100">
          <table className="w-full min-w-[620px] text-sm">
            <thead className="sticky top-0 bg-white">
              <tr className="border-b border-slate-200 text-left text-xs uppercase text-slate-500">
                {admin && (
                  <th className="w-8 py-2 pl-3">
                    <input type="checkbox" checked={allOn} onChange={() => setSel(allOn ? new Set() : new Set(rows.map((r) => r.id)))} aria-label="Select all on this page" />
                  </th>
                )}
                <th className="py-2 pr-3">Time</th>
                <th className="py-2 pr-3">Address</th>
                <th className="py-2 pr-3">Website</th>
                <th className="py-2 pr-3">Server</th>
                <th className="py-2 pr-3">Result</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((r) => {
                const [label, cls] = RESULT[r.result] ?? [r.result, 'bg-slate-100 text-slate-600'];
                return (
                  <tr key={r.id} className={sel.has(r.id) ? 'bg-slate-50' : ''}>
                    {admin && (
                      <td className="py-2 pl-3">
                        <input type="checkbox" checked={sel.has(r.id)} onChange={() => toggle(r.id)} aria-label="Select" />
                      </td>
                    )}
                    <td className="py-2 pr-3 whitespace-nowrap text-slate-500">{new Date(r.at).toLocaleString()}</td>
                    <td className="py-2 pr-3 font-mono">{r.ip}</td>
                    <td className="py-2 pr-3 break-all">{r.host}</td>
                    <td className="py-2 pr-3">{r.server}</td>
                    <td className="py-2 pr-3">
                      <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${cls}`}>{label}</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <Pager total={total} limit={limit} offset={offset} onChange={setOffset} />
    </Card>
  );
}
