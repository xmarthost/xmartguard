import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { CheckCircle2, Copy, Search, ShieldOff, Unlock, XCircle } from 'lucide-react';
import { api } from '../api';
import { can, useAuth } from '../auth';
import { Breadcrumb, Empty, ErrorBox, SectionLoader } from '../components/ui';
import { Card, Tabs, agentCall, fmtTime, useAction } from '../components/controls';
import { useApi } from '../hooks';
import { ago } from '../format';
import { AllowDialog, type WafEvent } from './WAF';

interface Found {
  server_id: string;
  server: string;
  firewall: { status: string; found?: string[] | null; trusted?: string } | null;
  waf: WafEvent[];
  waf_total: number;
}

interface LookupResp {
  ip: string;
  host: string;
  hours: number;
  servers: number;
  online: number;
  failed: string[];
  found: Found[];
}

interface UnblockRequest {
  id: number;
  ip: string;
  site: string;
  email: string;
  message: string;
  status: 'open' | 'done' | 'rejected';
  created_at: string;
}

const isIP = (v: string) => /^[0-9.]+$/.test(v) || v.includes(':');

const FW_LABEL: Record<string, string> = {
  blocked: 'Blacklisted', 'temp-blocked': 'Temporarily banned', 'ipdb-blocked': 'Blocked by IPDB', 'country-blocked': 'Country blocked',
};

/** "Why is it blocked?": an address or website on every server at once,
 *  with the fixes next to each block. */
export default function BlockLookup() {
  const { user } = useAuth();
  const platform = user?.platform !== false;
  const [sp, setSp] = useSearchParams();
  const [tab, setTab] = useState<'lookup' | 'requests'>(sp.get('tab') === 'requests' && platform ? 'requests' : 'lookup');
  const [q, setQ] = useState(sp.get('q') ?? '');
  const [hours, setHours] = useState(72);
  const [res, setRes] = useState<LookupResp | null>(null);
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(false);

  const search = async (value = q, h = hours) => {
    const v = value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!v) return;
    setQ(v);
    setSp({ q: v }, { replace: true });
    setLoading(true);
    setErr('');
    try {
      setRes(await api<LookupResp>('GET', `/api/blocks/lookup?${isIP(v) ? 'ip' : 'host'}=${encodeURIComponent(v)}&hours=${h}`));
    } catch (e: any) {
      setErr(e.message);
      setRes(null);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    if (q) void search();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="space-y-5">
      <Breadcrumb items={['Why blocked?']} />
      <div className="max-w-3xl">
        <h1 className="h-title flex items-center gap-2">
          <ShieldOff className="h-6 w-6" /> Why is it blocked?
        </h1>
        <p className="text-sm text-slate-500">
          Enter a visitor's IP address or a website. Every server's WAF log and firewall is searched at once, with the fix next to each block.
        </p>
      </div>
      {platform && (
        <Tabs
          tabs={[
            { v: 'lookup', l: 'Look up' },
            { v: 'requests', l: 'Unblock requests' },
          ]}
          value={tab}
          onChange={setTab}
        />
      )}
      {tab === 'requests' ? (
        <Requests onLookup={(ip) => (setTab('lookup'), void search(ip))} />
      ) : (
        <>
          <form
            className="card flex flex-wrap items-center gap-2 p-4"
            onSubmit={(e) => {
              e.preventDefault();
              void search();
            }}
          >
            <input className="input min-w-0 flex-1 sm:max-w-md" placeholder="203.0.113.7 or example.com" value={q} onChange={(e) => setQ(e.target.value)} />
            <select className="input w-36" value={hours} onChange={(e) => (setHours(Number(e.target.value)), q && void search(q, Number(e.target.value)))}>
              {[24, 72, 168, 720].map((h) => (
                <option key={h} value={h}>
                  Last {h / 24} day{h > 24 ? 's' : ''}
                </option>
              ))}
            </select>
            <button className="btn-primary" disabled={loading || !q.trim()}>
              <Search className="h-4 w-4" /> Search all servers
            </button>
            {platform && (
              <span className="w-full text-xs text-slate-400 sm:ml-auto sm:w-auto">
                Visitors can ask to be unblocked at{' '}
                <a className="underline" href="/unblock" target="_blank" rel="noreferrer">
                  {location.host}/unblock
                </a>
              </span>
            )}
          </form>
          {err && <ErrorBox message={err} />}
          {loading && <SectionLoader />}
          {res && !loading && <Results res={res} onChanged={() => void search()} />}
        </>
      )}
    </div>
  );
}

function Results({ res, onChanged }: { res: LookupResp; onChanged: () => void }) {
  const canAct = can(useAuth().user, 'operator');
  const { run, busy } = useAction();
  const [allow, setAllow] = useState<{ server: string; ev: WafEvent } | null>(null);
  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-500">
        Searched {res.online} online of {res.servers} servers{res.failed.length > 0 && ` (no answer from ${res.failed.join(', ')})`}.
      </p>
      {res.found.length === 0 && (
        <div className="card p-6">
          <Empty text={`${res.ip || res.host} is not blocked on any server in this time window.`} />
        </div>
      )}
      {res.found.map((f) => {
        const fw = f.firewall;
        const listed = fw && FW_LABEL[fw.status];
        return (
          <Card
            key={f.server_id}
            title={f.server}
            right={
              <Link className="text-sm text-navy-700 underline" to={`/servers/${f.server_id}/waf-logs`}>
                WAF Logs
              </Link>
            }
          >
            {listed && (
              <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-800">
                <XCircle className="h-4 w-4" /> Firewall: {listed}
                {fw!.found?.length ? <span className="text-red-600">({fw!.found.join(', ')})</span> : null}
                {canAct && (
                  <span className="ml-auto flex gap-2">
                    <button
                      className="btn-outline px-3 py-1 text-xs"
                      disabled={busy}
                      onClick={() => run(() => agentCall(f.server_id, 'fw.unblock', { addr: res.ip }), `${res.ip} unblocked on ${f.server}`).then(onChanged)}
                    >
                      <Unlock className="h-3.5 w-3.5" /> Unblock
                    </button>
                    <button
                      className="btn-outline px-3 py-1 text-xs"
                      disabled={busy}
                      onClick={() => {
                        if (!confirm(`Whitelist ${res.ip} on ${f.server}? No rule will check it any more.`)) return;
                        void run(() => agentCall(f.server_id, 'fw.add', { kind: 'allow', addr: res.ip, comment: 'Why blocked? lookup' }), `${res.ip} whitelisted`).then(onChanged);
                      }}
                    >
                      Whitelist
                    </button>
                  </span>
                )}
              </div>
            )}
            {f.waf.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="text-xs text-slate-500">
                    <tr>
                      <th className="py-1.5 pr-3">Time</th>
                      <th className="py-1.5 pr-3">Request</th>
                      <th className="py-1.5 pr-3">Rule</th>
                      <th className="py-1.5 pr-3">Address</th>
                      <th className="py-1.5" />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {f.waf.map((e) => (
                      <tr key={e.id}>
                        <td className="py-1.5 pr-3 whitespace-nowrap text-xs">{fmtTime(e.at)}</td>
                        <td className="max-w-sm py-1.5 pr-3">
                          <div className="truncate font-mono text-xs" title={`${e.method} ${e.host}${e.uri}`}>
                            {e.method} {e.host}
                            {e.uri}
                          </div>
                        </td>
                        <td className="py-1.5 pr-3 text-xs">
                          <span className="font-mono">#{e.rule_id}</span> {e.msg}
                          {!e.action.startsWith('Access denied') && <span className="ml-1 rounded bg-amber-50 px-1 text-amber-700">logged only</span>}
                        </td>
                        <td className="py-1.5 pr-3 font-mono text-xs">{e.ip}</td>
                        <td className="py-1.5 text-right">
                          {canAct && e.action.startsWith('Access denied') && (
                            <button className="text-xs whitespace-nowrap text-emerald-700 hover:underline" onClick={() => setAllow({ server: f.server_id, ev: e })}>
                              <CheckCircle2 className="mr-1 inline h-3.5 w-3.5" />
                              Allow on this site
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {f.waf_total > f.waf.length && <p className="mt-2 text-xs text-slate-400">{f.waf_total.toLocaleString()} blocks in all; the newest are shown.</p>}
              </div>
            )}
          </Card>
        );
      })}
      {allow && <AllowDialog serverId={allow.server} ev={allow.ev} onClose={() => (setAllow(null), onChanged())} />}
    </div>
  );
}

function Requests({ onLookup }: { onLookup: (ip: string) => void }) {
  const [all, setAll] = useState(false);
  const res = useApi<{ requests: UnblockRequest[]; open: number }>(`/api/unblock-requests${all ? '?status=all' : ''}`, 60_000);
  const { run, busy } = useAction();
  const canAct = can(useAuth().user, 'operator');
  const set = (id: number, status: string) => run(() => api('POST', `/api/unblock-requests/${id}`, { status }), status === 'done' ? 'Marked as done' : 'Updated').then(() => res.reload());
  return (
    <Card
      title="Unblock requests"
      desc="Visitors who could not open a website send these from the portal's public page. Look the address up, fix the block, then mark the request done."
      right={
        <label className="flex items-center gap-2 text-sm text-slate-500">
          <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} /> Show handled
        </label>
      }
    >
      {res.error && <ErrorBox message={res.error} />}
      {!res.data ? (
        <SectionLoader />
      ) : res.data.requests.length === 0 ? (
        <Empty text="No open requests." />
      ) : (
        <div className="divide-y divide-slate-100">
          {res.data.requests.map((r) => (
            <div key={r.id} className="flex flex-wrap items-start gap-3 py-3 text-sm">
              <div className="min-w-0 flex-1">
                <div className="font-medium text-navy-900">
                  {r.site} <span className="font-mono font-normal text-slate-500">from {r.ip}</span>
                  <button className="ml-1 text-slate-400 hover:text-navy-700" title="Copy address" onClick={() => navigator.clipboard?.writeText(r.ip)}>
                    <Copy className="inline h-3.5 w-3.5" />
                  </button>
                </div>
                {r.message && <p className="mt-0.5 text-slate-600">{r.message}</p>}
                <p className="text-xs text-slate-400">
                  {ago(r.created_at)}
                  {r.email && ` · ${r.email}`} · {r.status}
                </p>
              </div>
              <button className="btn-outline px-3 py-1 text-xs" onClick={() => onLookup(r.ip)}>
                <Search className="h-3.5 w-3.5" /> Look up
              </button>
              {canAct && r.status === 'open' && (
                <>
                  <button className="btn-primary px-3 py-1 text-xs" disabled={busy} onClick={() => set(r.id, 'done')}>
                    Done
                  </button>
                  <button className="btn-outline px-3 py-1 text-xs" disabled={busy} onClick={() => set(r.id, 'rejected')}>
                    Reject
                  </button>
                </>
              )}
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
