import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronLeft, ChevronRight, Search, Server as ServerIcon } from 'lucide-react';
import { useApi } from '../hooks';
import { Breadcrumb, Empty, ErrorBox, PageLoader, StatusDot } from '../components/ui';
import { Tabs } from '../components/controls';

interface Row {
  id: string;
  hostname: string;
  primary_ip: string;
  os_name: string;
  control_panel: string;
  agent_version: string;
  tags: string[];
  last_seen_at: string | null;
  created_at: string;
  online: boolean;
  account: {
    id: string;
    name: string;
    platform: boolean;
    owner_email: string;
    plan: string;
    plan_name: string;
    trial: boolean;
    licence_status: string | null;
    period_end: string | null;
  };
}

interface Resp {
  page: number;
  per: number;
  total: number;
  pages: number;
  counts: { all: number; customer: number; trial: number; paid: number; online: number };
  servers: Row[];
}

type Filter = 'all' | 'customer' | 'trial' | 'paid' | 'platform' | 'online' | 'offline';

function PlanBadge({ a }: { a: Row['account'] }) {
  if (a.platform) return <span className="rounded-full bg-navy-600 px-2.5 py-0.5 text-xs font-medium text-white">Own</span>;
  const expired = a.licence_status && a.licence_status !== 'active';
  const cls = expired ? 'bg-red-100 text-red-700' : a.trial ? 'bg-amber-100 text-amber-800' : a.plan === 'none' ? 'bg-slate-100 text-slate-600' : 'bg-green-100 text-green-700';
  const label = a.trial ? 'Trial' : a.plan === 'none' ? 'No licence' : a.plan_name || a.plan;
  return (
    <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${cls}`}>
      {label}
      {expired ? ` · ${a.licence_status}` : ''}
    </span>
  );
}

/** Master access: every server of every account, 20 per page, searchable. */
export default function CustomerServers() {
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const [filter, setFilter] = useState<Filter>('all');
  useEffect(() => {
    const t = setTimeout(() => {
      setQuery(q.trim());
      setPage(1);
    }, 300);
    return () => clearTimeout(t);
  }, [q]);
  const res = useApi<Resp>(`/api/admin/servers?q=${encodeURIComponent(query)}&page=${page}&filter=${filter}`, 30_000);
  const d = res.data;

  if (res.loading && !d) return <PageLoader />;
  if (res.error && !d) return <ErrorBox message={res.error} />;

  const c = d?.counts;
  return (
    <div className="space-y-5">
      <Breadcrumb items={['All Servers']} />
      <div>
        <h1 className="h-title flex items-center gap-2">
          <ServerIcon className="h-6 w-6" /> All Servers
        </h1>
        <p className="text-sm text-slate-500">Every server of every customer (trial and paid) and your own. Open any server for full access.</p>
      </div>

      <div className="card p-4 sm:p-6">
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <form
            className="relative w-full sm:w-80"
            onSubmit={(e) => {
              e.preventDefault();
              setQuery(q.trim());
              setPage(1);
            }}
          >
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <input className="input pl-9" placeholder="Search hostname, IP, customer email, tag…" value={q} onChange={(e) => setQ(e.target.value)} />
          </form>
          <div className="overflow-x-auto">
            <Tabs<Filter>
              tabs={[
                { v: 'all', l: `All (${c?.all ?? 0})` },
                { v: 'customer', l: `Customers (${c?.customer ?? 0})` },
                { v: 'paid', l: `Paid (${c?.paid ?? 0})` },
                { v: 'trial', l: `Trial (${c?.trial ?? 0})` },
                { v: 'platform', l: 'Own' },
                { v: 'online', l: `Online (${c?.online ?? 0})` },
                { v: 'offline', l: 'Offline' },
              ]}
              value={filter}
              onChange={(v) => {
                setFilter(v);
                setPage(1);
              }}
            />
          </div>
        </div>

        {!d || d.servers.length === 0 ? (
          <Empty text={query ? `No server matches "${query}"` : 'No servers'} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-left text-xs uppercase tracking-wide text-slate-500">
                  <th className="py-2 pr-3">Server</th>
                  <th className="py-2 pr-3">Customer</th>
                  <th className="py-2 pr-3">Plan</th>
                  <th className="py-2 pr-3">Expires</th>
                  <th className="py-2 pr-3">Agent</th>
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {d.servers.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-50">
                    <td className="py-2.5 pr-3">
                      <Link to={`/servers/${s.id}`} className="font-medium text-navy-900 hover:underline">
                        {s.hostname}
                      </Link>
                      <div className="text-xs text-slate-500">
                        {s.primary_ip}
                        {s.control_panel ? ` · ${s.control_panel}` : ''}
                      </div>
                    </td>
                    <td className="py-2.5 pr-3">
                      <div className="text-navy-900">{s.account.platform ? 'Your account' : s.account.owner_email || s.account.name}</div>
                      {!s.account.platform && s.account.name && <div className="text-xs text-slate-500">{s.account.name}</div>}
                    </td>
                    <td className="py-2.5 pr-3">
                      <PlanBadge a={s.account} />
                    </td>
                    <td className="py-2.5 pr-3 text-xs text-slate-500">{s.account.period_end ? new Date(s.account.period_end).toLocaleDateString() : '–'}</td>
                    <td className="py-2.5 pr-3 text-xs text-slate-500">{s.agent_version || '–'}</td>
                    <td className="py-2.5 pr-3">
                      <StatusDot online={s.online} />
                    </td>
                    <td className="py-2.5 text-right">
                      <Link to={`/servers/${s.id}`} className="btn-outline whitespace-nowrap px-3 py-1 text-xs">
                        Open
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {d && d.total > 0 && (
          <div className="flex items-center justify-end gap-3 pt-4 text-sm text-slate-500">
            <span>
              {(d.page - 1) * d.per + 1} – {Math.min(d.total, d.page * d.per)} of {d.total} · page {d.page} of {d.pages}
            </span>
            <button className="rounded p-1 hover:bg-slate-100 disabled:opacity-30" disabled={d.page <= 1} onClick={() => setPage(d.page - 1)} aria-label="previous">
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button className="rounded p-1 hover:bg-slate-100 disabled:opacity-30" disabled={d.page >= d.pages} onClick={() => setPage(d.page + 1)} aria-label="next">
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
