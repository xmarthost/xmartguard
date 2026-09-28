import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { Ban, Download, EyeOff, Search, ShieldAlert, Trash2 } from 'lucide-react';
import { can, useAuth } from '../auth';
import { Breadcrumb, Empty, ErrorBox, PageLoader, SectionLoader } from '../components/ui';
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
  detail?: string;
}

interface WafStatus {
  status: { available: boolean; enabled: boolean; web_server: string; error: string; warning: string; rules: number };
  stats: { blocked_24h: number; bots_24h: number; logins_24h: number; total: number };
}

function toCSV(rows: WafEvent[]): string {
  const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const head = ['rule_id', 'ip', 'method', 'uri', 'host', 'user', 'reason', 'justification', 'action', 'time'];
  return [
    head.join(','),
    ...rows.map((r) => [r.rule_id, r.ip, r.method, r.uri, r.host, r.user, r.msg, r.detail ?? '', r.action, new Date(r.at * 1000).toISOString()].map(esc).join(',')),
  ].join('\n');
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
  const [sel, setSel] = useState<number[]>([]);
  const [exporting, setExporting] = useState('');
  const rows = ev.data?.events ?? [];
  const allSel = rows.length > 0 && rows.every((r) => sel.includes(r.id));

  /** Exports every matching entry, not just the page on screen. */
  const exportAll = async () => {
    const all: WafEvent[] = [];
    const total = ev.data?.total ?? 0;
    try {
      for (let off = 0; off < total; off += 1000) {
        setExporting(`${Math.min(off, total).toLocaleString()} / ${total.toLocaleString()}`);
        const r = await agentCall<{ events: WafEvent[] }>(id!, 'waf.events', { category: cat, q: query, limit: 1000, offset: off });
        all.push(...r.events);
        if (r.events.length < 1000) break;
      }
      download(`${title.toLowerCase().replace(/ /g, '-')}-${host}-${new Date().toISOString().slice(0, 10)}.csv`, toCSV(all));
    } catch (e: any) {
      alert(e.message || 'Export failed');
    } finally {
      setExporting('');
    }
  };
  const deleteSelected = async () => {
    if (!confirm(`Remove ${sel.length} entr${sel.length === 1 ? 'y' : 'ies'} from the xPGuard logs?`)) return;
    const r = await run(() => agentCall<{ deleted: number }>(id!, 'waf.event_delete', { ids: sel }), (x) => `${x.deleted} removed`);
    if (r) {
      setSel([]);
      ev.reload();
    }
  };

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
          <button className="btn-outline" title="Export all matching entries (CSV)" disabled={!ev.data?.total || !!exporting} onClick={exportAll}>
            <Download className="h-4 w-4" />
            {exporting && <span className="text-xs">{exporting}</span>}
          </button>
        </div>
      </div>

      {st && !st.available && (
        <div className="flex items-start gap-3 rounded-lg bg-amber-50 p-4 text-sm text-amber-800">
          <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0" />
          <div>
            <b>ModSecurity is not available on this server</b> ({st.web_server}). On cPanel install it in WHM » EasyApache 4 (package{' '}
            <code>ea-apache24-mod_security2</code>); xPGuard loads its rules automatically afterwards.
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

      <div className="relative">
        {operator && sel.length > 0 && (
          <div className="absolute inset-x-0 -top-2 z-20 mx-auto w-full max-w-xl -translate-y-full rounded-xl bg-white p-4 shadow-xl ring-1 ring-slate-200 sm:top-2 sm:translate-y-0">
            <div className="mb-3 font-semibold text-navy-900">{sel.length} Rows Selected</div>
            <div className="grid grid-cols-2 gap-3">
              <button className="btn-outline" disabled={busy} onClick={deleteSelected}>
                <Trash2 className="h-4 w-4" /> Delete
              </button>
              <button className="btn-primary" onClick={() => setSel([])}>
                Deselect All
              </button>
            </div>
            <div className="mt-3 rounded-md bg-sky-50 px-3 py-2 text-xs text-slate-600">*The selected rows will be removed from the xPGuard logs</div>
          </div>
        )}
        <div className="card overflow-hidden p-0">
          {ev.error && !ev.data ? (
            <div className="p-4">
              <ErrorBox message={ev.error} />
            </div>
          ) : !ev.data ? (
            <SectionLoader />
          ) : rows.length === 0 ? (
            <Empty text={emptyText} />
          ) : (
            <div className="max-h-[70vh] overflow-auto">
              <table className="w-full min-w-[900px] text-sm">
                <thead className="sticky top-0 z-10 bg-slate-50 text-left text-xs text-slate-500 uppercase shadow-[0_1px_0_#e2e8f0]">
                  <tr>
                    {operator && (
                      <th className="w-10 py-3 pl-4">
                        <input type="checkbox" className="h-4 w-4" checked={allSel} onChange={(e) => setSel(e.target.checked ? rows.map((r) => r.id) : [])} />
                      </th>
                    )}
                    <th className="px-4 py-3">IP &amp; Method</th>
                    <th className="px-2">Reason</th>
                    <th className="px-2">Request</th>
                    <th className="px-2">Action</th>
                    <th className="px-2">Time</th>
                    {operator && <th className="px-2" />}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {rows.map((e) => (
                    <tr key={e.id} className={`align-top ${sel.includes(e.id) ? 'bg-sky-50/60' : ''}`}>
                      {operator && (
                        <td className="py-3 pl-4">
                          <input type="checkbox" className="h-4 w-4" checked={sel.includes(e.id)} onChange={(x) => setSel(x.target.checked ? [...sel, e.id] : sel.filter((i) => i !== e.id))} />
                        </td>
                      )}
                      <td className="px-4 py-3 font-mono text-xs">
                        {e.ip}
                        {e.method && <div className="text-slate-400">{e.method}</div>}
                      </td>
                      <td className="max-w-md px-2 py-3">
                        <div>
                          <span className="text-slate-500">#{e.rule_id}</span> – {e.msg || 'ModSecurity rule'}
                        </div>
                        {e.detail && <div className="mt-0.5 truncate text-xs text-slate-400" title={e.detail}>{e.detail}</div>}
                      </td>
                      <td className="max-w-xs px-2 py-3 text-xs break-all">
                        <div className="text-navy-900">{e.host || '–'}</div>
                        <div className="font-mono text-slate-500">{e.uri}</div>
                      </td>
                      <td className="px-2 py-3 text-xs">
                        {e.action.startsWith('Access denied') ? (
                          <>
                            <span className="rounded-full bg-amber-100 px-2 py-0.5 text-amber-800">{e.action.match(/\d{3}/)?.[0] ?? 'denied'}</span>
                            <div className="mt-1 text-slate-500">{e.action}</div>
                          </>
                        ) : (
                          <span className="rounded-full bg-slate-100 px-2 py-0.5 text-slate-600">logged</span>
                        )}
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
            </div>
          )}
        </div>
      </div>
      {ev.data && (
        <div className="flex flex-wrap items-center justify-end gap-3 text-sm">
          <label className="flex items-center gap-2 text-slate-500">
            Items per page
            <select className="input w-24" value={limit} onChange={(e) => (setOffset(0), setSel([]), setLimit(Number(e.target.value)))}>
              {[25, 50, 100, 200].map((n) => (
                <option key={n}>{n}</option>
              ))}
            </select>
          </label>
          <Pager total={ev.data.total} limit={limit} offset={offset} onChange={(o) => (setSel([]), setOffset(o))} />
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
