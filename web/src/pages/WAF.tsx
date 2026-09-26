import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { Ban, Download, EyeOff, Search, ShieldAlert } from 'lucide-react';
import { can, useAuth } from '../auth';
import { Breadcrumb, Empty, ErrorBox, PageLoader } from '../components/ui';
import { Pager, agentCall, fmtTime, useAction, useAgent } from '../components/controls';
import { useServerName } from './Scanner';

interface WafEvent {
  id: number;
  at: number;
  ip: string;
  method: string;
  host: string;
  uri: string;
  rule_id: number;
  msg: string;
  category: string;
  action: string;
  user: string;
}

interface WafStatus {
  status: { available: boolean; enabled: boolean; web_server: string; error: string; warning: string; rules: number };
  stats: { blocked_24h: number; bots_24h: number; logins_24h: number; total: number };
}

function toCSV(rows: WafEvent[]): string {
  const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const head = ['time', 'ip', 'host', 'uri', 'rule_id', 'reason', 'action'];
  return [head.join(','), ...rows.map((r) => [new Date(r.at * 1000).toISOString(), r.ip, r.host, r.uri, r.rule_id, r.msg, r.action].map(esc).join(','))].join('\n');
}

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/csv' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

/** Shared table for WAF Logs and Bot Attacks. */
function WafEventsPage({ title, categories, emptyText }: { title: string; categories: { v: string; l: string }[]; emptyText: string }) {
  const { id } = useParams();
  const host = useServerName(id);
  const { user } = useAuth();
  const operator = can(user, 'operator');
  const admin = can(user, 'admin');
  const [cat, setCat] = useState(categories[0].v);
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const [limit, setLimit] = useState(25);
  const status = useAgent<WafStatus>(id, 'waf.status');
  const ev = useAgent<{ events: WafEvent[]; total: number }>(id, 'waf.events', { category: cat, q: query, limit, offset }, 10_000);
  const { run, busy } = useAction();

  const blockIP = (ip: string) =>
    run(() => agentCall(id!, 'fw.add', { kind: 'deny', addr: ip, comment: `WAF: blocked from ${title}` }), `${ip} blocked`);
  const disableRule = async (ruleId: number) => {
    if (!confirm(`Disable ModSecurity rule ${ruleId} on this server?`)) return;
    const cur = await agentCall<{ settings: { waf: { disabled_rules: number[] } } }>(id!, 'settings.get');
    const ids = Array.from(new Set([...(cur.settings.waf?.disabled_rules ?? []), ruleId]));
    await run(() => agentCall(id!, 'settings.set', { waf: { disabled_rules: ids } }), `Rule ${ruleId} disabled`);
  };

  if (status.loading && !status.data) return <PageLoader />;
  const st = status.data?.status;

  return (
    <div className="space-y-5">
      <Breadcrumb items={[host, title]} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="h-title">{title}</h1>
        <div className="flex flex-wrap items-center gap-2">
          {categories.length > 1 && (
            <select className="input w-44" value={cat} onChange={(e) => (setOffset(0), setCat(e.target.value))}>
              {categories.map((c) => (
                <option key={c.v} value={c.v}>
                  {c.l}
                </option>
              ))}
            </select>
          )}
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              setOffset(0);
              setQuery(q.trim());
            }}
          >
            <input className="input w-60" placeholder="Type to filter (IP, domain, URL, rule)" value={q} onChange={(e) => setQ(e.target.value)} />
            <button className="btn-outline">
              <Search className="h-4 w-4" />
            </button>
          </form>
          <button className="btn-outline" title="Download CSV" disabled={!ev.data?.events.length} onClick={() => download(`${title.toLowerCase().replace(/ /g, '-')}.csv`, toCSV(ev.data!.events))}>
            <Download className="h-4 w-4" />
          </button>
        </div>
      </div>

      {st && !st.available && (
        <div className="flex items-start gap-3 rounded-lg bg-amber-50 p-4 text-sm text-amber-800">
          <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0" />
          <div>
            <b>ModSecurity is not available on this server</b> ({st.web_server}). On cPanel install it in WHM » EasyApache 4 (package{' '}
            <code>ea-apache24-mod_security2</code>); XMart Guard loads its rules automatically afterwards.
          </div>
        </div>
      )}
      {st?.error && <ErrorBox message={st.error} />}
      {st?.warning && <div className="rounded-lg bg-amber-50 p-3 text-sm text-amber-800">{st.warning}</div>}
      {st && st.available && !st.enabled && (
        <div className="rounded-lg bg-amber-50 p-3 text-sm text-amber-800">The WAF is disabled in Settings » WAF &amp; Bruteforce.</div>
      )}
      {status.data && (
        <div className="grid gap-3 sm:grid-cols-3">
          <Stat v={status.data.stats.blocked_24h} l="Web attacks blocked (24 h)" />
          <Stat v={status.data.stats.bots_24h} l="Bot requests blocked (24 h)" />
          <Stat v={status.data.stats.logins_24h} l="Failed CMS logins (24 h)" />
        </div>
      )}

      <div className="card overflow-x-auto p-0">
        {ev.error && !ev.data ? (
          <div className="p-4">
            <ErrorBox message={ev.error} />
          </div>
        ) : !ev.data ? (
          <PageLoader />
        ) : ev.data.events.length === 0 ? (
          <Empty text={emptyText} />
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs text-slate-500 uppercase">
              <tr>
                <th className="px-4 py-3">IP</th>
                <th className="px-2">Domain</th>
                <th className="px-2">Reason</th>
                <th className="px-2">Request</th>
                <th className="px-2">Action</th>
                <th className="px-2">Time</th>
                {operator && <th className="px-2" />}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {ev.data.events.map((e) => (
                <tr key={e.id} className="align-top">
                  <td className="px-4 py-3 font-mono text-xs">
                    {e.ip}
                    {e.method && <div className="text-slate-400">{e.method}</div>}
                  </td>
                  <td className="px-2 py-3 break-all">{e.host || '–'}</td>
                  <td className="max-w-sm px-2 py-3">
                    <span className="text-slate-500">#{e.rule_id}</span> – {e.msg || 'ModSecurity rule'}
                  </td>
                  <td className="max-w-xs px-2 py-3 font-mono text-xs break-all">{e.uri}</td>
                  <td className="px-2 py-3 text-xs">
                    <span className={`rounded-full px-2 py-0.5 ${e.action.startsWith('Access denied') ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-600'}`}>
                      {e.action.startsWith('Access denied') ? e.action.replace('Access denied with code ', '') : 'logged'}
                    </span>
                  </td>
                  <td className="px-2 py-3 text-xs whitespace-nowrap text-slate-500">{fmtTime(e.at)}</td>
                  {operator && (
                    <td className="px-2 py-3 whitespace-nowrap">
                      <button className="mr-2 text-red-600 hover:text-red-800" title="Block this IP in the firewall" disabled={busy} onClick={() => blockIP(e.ip)}>
                        <Ban className="h-4 w-4" />
                      </button>
                      {admin && (
                        <button className="text-slate-500 hover:text-navy-900" title={`Disable rule ${e.rule_id} (false positive)`} disabled={busy} onClick={() => disableRule(e.rule_id)}>
                          <EyeOff className="h-4 w-4" />
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {ev.data && (
        <div className="flex flex-wrap items-center justify-end gap-3 text-sm">
          <label className="flex items-center gap-2 text-slate-500">
            Items per page
            <select className="input w-20" value={limit} onChange={(e) => (setOffset(0), setLimit(Number(e.target.value)))}>
              {[25, 50, 100].map((n) => (
                <option key={n}>{n}</option>
              ))}
            </select>
          </label>
          <Pager total={ev.data.total} limit={limit} offset={offset} onChange={setOffset} />
        </div>
      )}
    </div>
  );
}

function Stat({ v, l }: { v: number; l: string }) {
  return (
    <div className="card p-4">
      <div className="text-2xl font-semibold text-navy-900">{v.toLocaleString()}</div>
      <div className="text-sm text-slate-500">{l}</div>
    </div>
  );
}

export function WafLogs() {
  return (
    <WafEventsPage
      title="WAF Logs"
      categories={[
        { v: 'waf', l: 'Blocked attacks' },
        { v: 'login', l: 'Failed CMS logins' },
        { v: '', l: 'All events' },
      ]}
      emptyText="No web attacks recorded yet"
    />
  );
}

export function BotAttacks() {
  return <WafEventsPage title="Bot Attacks" categories={[{ v: 'bot', l: 'Bots' }]} emptyText="No bot attacks recorded yet" />;
}
