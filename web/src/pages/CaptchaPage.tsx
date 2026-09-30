import { useEffect, useState } from 'react';
import { ExternalLink, Save, ShieldQuestion, Trash2 } from 'lucide-react';
import { api } from '../api';
import { can, useAuth } from '../auth';
import { Breadcrumb, ErrorBox, PageLoader } from '../components/ui';
import { Card, SettingRow, Toggle, useAction } from '../components/controls';
import { useApi } from '../hooks';

interface Resp {
  config: { enabled: boolean; site_key: string; secret_set: boolean; minutes: number };
  version: number;
  updated_at: string | null;
  url: string;
  last24h: { passed: number; failed: number; rejected: number; offline: number };
  recent: { at: string; ip: string; host: string; result: string; server: string }[];
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
            below. Everyone else logs in as usual.
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

      <Card
        title="Recent checks"
        desc="The last 50 visitors sent to the page (kept 30 days)."
        right={
          admin && d.recent.length > 0 ? (
            <button
              className="btn-outline"
              disabled={busy}
              onClick={() => confirm('Clear the list of checks?') && run(() => api('DELETE', '/api/captcha/events').then(res.reload), 'List cleared')}
            >
              <Trash2 className="h-4 w-4" /> Clear list
            </button>
          ) : undefined
        }
      >
        {d.recent.length === 0 ? (
          <p className="text-sm text-slate-500">No checks yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-left text-xs uppercase text-slate-500">
                  <th className="py-2 pr-3">Time</th>
                  <th className="py-2 pr-3">Address</th>
                  <th className="py-2 pr-3">Website</th>
                  <th className="py-2 pr-3">Server</th>
                  <th className="py-2">Result</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {d.recent.map((r, i) => {
                  const [label, cls] = RESULT[r.result] ?? [r.result, 'bg-slate-100 text-slate-600'];
                  return (
                    <tr key={i}>
                      <td className="py-2 pr-3 whitespace-nowrap text-slate-500">{new Date(r.at).toLocaleString()}</td>
                      <td className="py-2 pr-3 font-mono">{r.ip}</td>
                      <td className="py-2 pr-3 break-all">{r.host}</td>
                      <td className="py-2 pr-3">{r.server}</td>
                      <td className="py-2">
                        <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${cls}`}>{label}</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
