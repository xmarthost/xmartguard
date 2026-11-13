import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, Search } from 'lucide-react';
import { useApi } from '../hooks';
import { Breadcrumb, Empty, PageLoader } from '../components/ui';
import { Card, Pager } from '../components/controls';

interface Counts {
  updated: number | null;
  shielded: number | null;
  deactivated: number | null;
  not_fixed: number | null;
  gone: number | null;
  sites: number | null;
}
interface Dispatch extends Counts {
  id: number;
  created_at: string;
  source: string;
  note: string;
  count: number;
  servers: number;
}
interface ServerRow extends Counts {
  server_id: string;
  hostname: string;
  received_at: string | null;
  advisories: number;
}
interface Advisory {
  id: string;
  kind: string;
  slug: string;
  title: string;
  cvss: number;
  published: string | null;
  sites: number;
  updated: number;
  not_fixed: number;
}
interface ResultRow {
  at: string;
  hostname: string;
  domain: string;
  site_path: string;
  account: string;
  kind: string;
  slug: string;
  title: string;
  cvss: number;
  version: string;
  action: string;
  to_version: string;
  detail: string;
}

const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : '—');
const n = (v: number | null | undefined) => v ?? 0;
const SOURCE: Record<string, string> = { feed: 'Feed download', webhook: 'Webhook (instant)', resend: 'Sent by hand' };
const ACTION: Record<string, { label: string; cls: string }> = {
  updated: { label: 'Updated', cls: 'bg-green-50 text-green-700' },
  shielded: { label: 'Shielded', cls: 'bg-amber-50 text-amber-700' },
  shielded_deactivated: { label: 'Shielded + deactivated', cls: 'bg-orange-50 text-orange-700' },
  deactivated: { label: 'Deactivated', cls: 'bg-orange-50 text-orange-700' },
  manual: { label: 'Update by hand', cls: 'bg-red-50 text-red-700' },
  failed: { label: 'Not updated', cls: 'bg-red-50 text-red-700' },
  gone: { label: 'Removed since', cls: 'bg-slate-100 text-slate-600' },
};
const FILTERS = [
  ['', 'All'],
  ['updated', 'Updated'],
  ['shielded', 'Shielded'],
  ['deactivated', 'Deactivated'],
  ['not_fixed', 'Not updated'],
  ['gone', 'Removed'],
] as const;

function Cnt({ v, cls }: { v: number | null | undefined; cls: string }) {
  return <td className={`px-3 py-2 text-right tabular-nums ${n(v) > 0 ? cls : 'text-slate-400'}`}>{n(v).toLocaleString()}</td>;
}
const head = 'px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-slate-500';
const headR = head + ' text-right';

/** Master » Plugin Vulnerabilities » Sent to servers: what was sent when, and what each server did. */
export default function VulnSent() {
  const { id } = useParams();
  return id ? <Detail id={id} /> : <List />;
}

function List() {
  const [offset, setOffset] = useState(0);
  const st = useApi<{ dispatches: Dispatch[]; total: number }>(`/api/vuln-feed/dispatches?limit=50&offset=${offset}`, 60_000);
  if (!st.data) return <PageLoader />;
  const rows = st.data.dispatches;
  return (
    <div className="space-y-5">
      <Breadcrumb items={['Web Protection', 'Plugin Vulnerabilities', 'Sent to servers']} />
      <Link to="/vuln-feed" className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-800">
        <ArrowLeft className="h-4 w-4" /> Plugin Vulnerabilities
      </Link>
      <Card
        title="Vulnerabilities sent to the servers"
        desc="Every feed download, webhook delivery or resend that sent new vulnerabilities, and what the servers did with them. Counts are per site and vulnerability; a server reports its results after it has worked through them (updates can take a while)."
      >
        {rows.length === 0 ? (
          <Empty text="Nothing sent yet" />
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200">
                  <th className={head}>Sent</th>
                  <th className={head}>How</th>
                  <th className={headR}>Vulnerabilities</th>
                  <th className={headR}>Servers</th>
                  <th className={headR}>Sites</th>
                  <th className={headR}>Updated</th>
                  <th className={headR}>Shielded</th>
                  <th className={headR}>Deactivated</th>
                  <th className={headR}>Not updated</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((d) => (
                  <tr key={d.id} className="border-b border-slate-100 hover:bg-slate-50">
                    <td className="px-3 py-2 whitespace-nowrap">
                      <Link className="font-medium text-blue-700 hover:underline" to={`/vuln-feed/sent/${d.id}`}>
                        {when(d.created_at)}
                      </Link>
                    </td>
                    <td className="px-3 py-2">
                      {SOURCE[d.source] ?? d.source}
                      {d.note && <span className="block text-xs text-slate-500">{d.note}</span>}
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums">{d.count.toLocaleString()}</td>
                    <td className="px-3 py-2 text-right tabular-nums">{d.servers}</td>
                    <Cnt v={d.sites} cls="text-slate-800" />
                    <Cnt v={d.updated} cls="text-green-700" />
                    <Cnt v={d.shielded} cls="text-amber-700" />
                    <Cnt v={d.deactivated} cls="text-orange-700" />
                    <Cnt v={d.not_fixed} cls="text-red-700" />
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Pager total={st.data.total} limit={50} offset={offset} onChange={setOffset} />
      </Card>
    </div>
  );
}

function Detail({ id }: { id: string }) {
  const st = useApi<{ dispatch: Dispatch; servers: ServerRow[]; advisories: Advisory[] }>(`/api/vuln-feed/dispatches/${id}`, 60_000);
  const [server, setServer] = useState('');
  const [action, setAction] = useState('');
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const [showAll, setShowAll] = useState(false);
  const params = new URLSearchParams({ limit: '100', offset: String(offset) });
  if (server) params.set('server', server);
  if (action) params.set('action', action);
  if (query) params.set('q', query);
  const res = useApi<{ results: ResultRow[]; total: number }>(`/api/vuln-feed/dispatches/${id}/results?${params}`, 60_000);
  if (st.error) return <Empty text={st.error} />;
  if (!st.data) return <PageLoader />;
  const { dispatch: d, servers, advisories } = st.data;
  const hit = advisories.filter((a) => a.sites > 0);
  const listed = showAll ? advisories : hit;
  const pick = (f: () => void) => {
    f();
    setOffset(0);
  };
  return (
    <div className="space-y-5">
      <Breadcrumb items={['Web Protection', 'Plugin Vulnerabilities', 'Sent to servers']} />
      <Link to="/vuln-feed/sent" className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-800">
        <ArrowLeft className="h-4 w-4" /> All sent
      </Link>
      <Card
        title={`Sent ${when(d.created_at)}`}
        desc={`${SOURCE[d.source] ?? d.source}${d.note ? ` (${d.note})` : ''}: ${d.count.toLocaleString()} vulnerabilities; ${hit.length.toLocaleString()} of them were found on a site.`}
      >
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200">
                <th className={head}>Server</th>
                <th className={head}>Received</th>
                <th className={headR}>Sites</th>
                <th className={headR}>Updated</th>
                <th className={headR}>Shielded</th>
                <th className={headR}>Deactivated</th>
                <th className={headR}>Not updated</th>
              </tr>
            </thead>
            <tbody>
              {servers.map((s) => (
                <tr
                  key={s.server_id}
                  className={`cursor-pointer border-b border-slate-100 hover:bg-slate-50 ${server === s.server_id ? 'bg-blue-50' : ''}`}
                  onClick={() => pick(() => setServer(server === s.server_id ? '' : s.server_id))}
                >
                  <td className="px-3 py-2 font-medium">{s.hostname}</td>
                  <td className="px-3 py-2 whitespace-nowrap text-slate-600">{s.received_at ? when(s.received_at) : <span className="text-red-600">not yet</span>}</td>
                  <Cnt v={s.sites} cls="text-slate-800" />
                  <Cnt v={s.updated} cls="text-green-700" />
                  <Cnt v={s.shielded} cls="text-amber-700" />
                  <Cnt v={s.deactivated} cls="text-orange-700" />
                  <Cnt v={s.not_fixed} cls="text-red-700" />
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-2 text-xs text-slate-500">Click a server to see only its websites below.</p>
      </Card>

      <Card title="Websites" desc="Each website a sent vulnerability was found on, and what was done there.">
        <div className="mb-3 flex flex-wrap items-center gap-2 text-sm">
          {FILTERS.map(([v, label]) => (
            <button key={v} className={action === v ? 'btn-primary' : 'btn-outline'} onClick={() => pick(() => setAction(v))}>
              {label}
            </button>
          ))}
          {server && (
            <button className="btn-outline" onClick={() => pick(() => setServer(''))}>
              Server: {servers.find((s) => s.server_id === server)?.hostname} ✕
            </button>
          )}
          <form
            className="ml-auto flex items-center gap-1"
            onSubmit={(e) => {
              e.preventDefault();
              pick(() => setQuery(q.trim()));
            }}
          >
            <input className="input w-56" placeholder="Domain, account or plugin" value={q} onChange={(e) => setQ(e.target.value)} />
            <button className="btn-outline" type="submit" aria-label="Search">
              <Search className="h-4 w-4" />
            </button>
          </form>
        </div>
        {!res.data ? (
          <PageLoader />
        ) : res.data.results.length === 0 ? (
          <Empty text="No websites" />
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200">
                  <th className={head}>Website</th>
                  <th className={head}>Server</th>
                  <th className={head}>Plugin / theme</th>
                  <th className={head}>Vulnerability</th>
                  <th className={head}>Result</th>
                  <th className={head}>When</th>
                </tr>
              </thead>
              <tbody>
                {res.data.results.map((r, i) => {
                  const a = ACTION[r.action] ?? { label: r.action, cls: 'bg-slate-100 text-slate-700' };
                  return (
                    <tr key={i} className="border-b border-slate-100 align-top">
                      <td className="px-3 py-2">
                        <span className="font-medium">{r.domain || r.site_path}</span>
                        <span className="block text-xs text-slate-500">
                          {r.account && `${r.account} · `}
                          {r.site_path}
                        </span>
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap text-slate-600">{r.hostname}</td>
                      <td className="px-3 py-2 whitespace-nowrap">
                        {r.slug} <span className="text-slate-500">{r.version}</span>
                        {r.to_version && <span className="text-green-700"> → {r.to_version}</span>}
                        <span className="block text-xs text-slate-500">{r.kind}</span>
                      </td>
                      <td className="max-w-md px-3 py-2">
                        <span className="text-slate-700">{r.title || '—'}</span>
                        {r.cvss > 0 && <span className="block text-xs text-slate-500">CVSS {r.cvss.toFixed(1)}</span>}
                      </td>
                      <td className="px-3 py-2">
                        <span className={`whitespace-nowrap rounded px-2 py-0.5 text-xs font-semibold ${a.cls}`}>{a.label}</span>
                        {r.detail && <span className="mt-1 block max-w-xs text-xs text-slate-500">{r.detail}</span>}
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap text-slate-600">{when(r.at)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {res.data && <Pager total={res.data.total} limit={100} offset={offset} onChange={setOffset} />}
      </Card>

      <Card
        title="Vulnerabilities in this send"
        desc={showAll ? 'All of them, the ones found on websites first.' : 'Only the ones found on at least one website.'}
        right={
          <button className="btn-outline text-sm" onClick={() => setShowAll(!showAll)}>
            {showAll ? 'Only found on sites' : `Show all ${advisories.length.toLocaleString()}`}
          </button>
        }
      >
        {listed.length === 0 ? (
          <Empty text="None was found on a website (yet)" />
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200">
                  <th className={head}>Plugin / theme</th>
                  <th className={head}>Vulnerability</th>
                  <th className={headR}>CVSS</th>
                  <th className={head}>Published</th>
                  <th className={headR}>Sites</th>
                  <th className={headR}>Updated</th>
                  <th className={headR}>Not updated</th>
                </tr>
              </thead>
              <tbody>
                {listed.map((a) => (
                  <tr key={a.id} className="border-b border-slate-100 align-top">
                    <td className="px-3 py-2 whitespace-nowrap">
                      {a.slug} <span className="block text-xs text-slate-500">{a.kind}</span>
                    </td>
                    <td className="max-w-lg px-3 py-2 text-slate-700">{a.title}</td>
                    <td className="px-3 py-2 text-right tabular-nums">{a.cvss > 0 ? a.cvss.toFixed(1) : '—'}</td>
                    <td className="px-3 py-2 whitespace-nowrap text-slate-600">{a.published ? new Date(a.published).toLocaleDateString() : '—'}</td>
                    <Cnt v={a.sites} cls="text-slate-800" />
                    <Cnt v={a.updated} cls="text-green-700" />
                    <Cnt v={a.not_fixed} cls="text-red-700" />
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
