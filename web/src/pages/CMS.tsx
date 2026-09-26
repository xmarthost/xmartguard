import { Fragment, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Archive, ChevronDown, ChevronRight, Database, Download, RefreshCw, Search } from 'lucide-react';
import { can, useAuth } from '../auth';
import { Breadcrumb, Empty, ErrorBox, PageLoader, StatCard } from '../components/ui';
import { Pager, agentCall, fmtTime, useAction, useAgent } from '../components/controls';
import { useServerName } from './Scanner';

interface Component {
  slug: string;
  name: string;
  version: string;
  latest: string;
  outdated: boolean;
}

interface Site {
  id: number;
  type: 'wordpress' | 'joomla' | 'opencart';
  path: string;
  user: string;
  domain: string;
  version: string;
  latest: string;
  plugins: Component[];
  themes: Component[];
  mu_plugins: string[];
  outdated_plugins: number;
  outdated_themes: number;
  core: { checked: number; modified: string[]; unknown: string[]; error?: string };
  core_issues: number;
  db_issues: number;
  risk: 'critical' | 'high' | 'medium' | 'ok';
  scanned_at: number;
}

interface CmsStatus {
  status: { running: boolean; last_scan: number; error: string };
  counts: { with_issues: number; wordpress: number; joomla: number; opencart: number; outdated: number; db_infected: number };
}

const RISK: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-amber-100 text-amber-700',
  ok: 'bg-green-100 text-green-700',
};

const TYPE_LABEL: Record<string, string> = { wordpress: 'WordPress', joomla: 'Joomla', opencart: 'OpenCart' };

function RiskBadge({ risk }: { risk: string }) {
  return <span className={`rounded-full px-3 py-1 text-xs font-medium capitalize ${RISK[risk] ?? ''}`}>{risk === 'ok' ? 'Secure' : risk}</span>;
}

export function CMSThreats() {
  const { id } = useParams();
  const host = useServerName(id);
  const { user } = useAuth();
  const [type, setType] = useState('');
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState<number | null>(null);
  const limit = 25;
  const status = useAgent<CmsStatus>(id, 'cms.status', {}, 5000);
  const list = useAgent<{ sites: Site[]; total: number }>(id, 'cms.sites', { type, q: query, limit, offset });
  const { run, busy } = useAction();
  const running = status.data?.status.running;

  if (status.loading && !status.data) return <PageLoader />;
  if (status.error && !status.data) return <ErrorBox message={status.error} />;
  const c = status.data!.counts;

  const update = async (s: Site, what: string, slug = '') => {
    const label = what === 'core-repair' ? 'Reinstall the official WordPress core files' : `Update ${slug || 'WordPress core'}`;
    if (!confirm(`${label} on ${s.domain || s.path}?`)) return;
    const r = await run(() => agentCall<{ output: string }>(id!, 'cms.update', { path: s.path, what, slug }), 'Done');
    if (r) list.reload();
  };

  return (
    <div className="space-y-5">
      <Breadcrumb items={[host, 'CMS threats']} />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={<Database />} value={c.with_issues} label="CMS with issues" accent={c.with_issues ? 'text-red-600' : 'text-green-600'} />
        <StatCard icon={<span className="text-lg font-bold">W</span>} value={c.wordpress} label="WordPress installations" />
        <StatCard icon={<span className="text-lg font-bold">J</span>} value={c.joomla} label="Joomla installations" />
        <StatCard icon={<span className="text-lg font-bold">OC</span>} value={c.opencart} label="OpenCart installations" />
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="h-title">CMS Threat Alerts</h1>
          <p className="text-sm text-slate-500">
            {running ? 'Scanning websites…' : status.data!.status.last_scan ? `Last scan ${fmtTime(status.data!.status.last_scan)}` : 'Not scanned yet'}
            {status.data!.status.error && <span className="text-red-600"> · {status.data!.status.error}</span>}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select className="input w-40" value={type} onChange={(e) => (setOffset(0), setType(e.target.value))}>
            <option value="">All CMS</option>
            <option value="wordpress">WordPress</option>
            <option value="joomla">Joomla</option>
            <option value="opencart">OpenCart</option>
          </select>
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              setOffset(0);
              setQuery(q.trim());
            }}
          >
            <input className="input w-52" placeholder="Type to filter" value={q} onChange={(e) => setQ(e.target.value)} />
            <button className="btn-outline">
              <Search className="h-4 w-4" />
            </button>
          </form>
          {can(user, 'operator') && (
            <button className="btn-primary" disabled={busy || running} onClick={() => run(() => agentCall(id!, 'cms.scan'), 'CMS scan started').then(() => status.reload())}>
              <RefreshCw className={`h-4 w-4 ${running ? 'animate-spin' : ''}`} /> Scan now
            </button>
          )}
        </div>
      </div>

      <div className="card overflow-x-auto p-0">
        {!list.data ? (
          <PageLoader />
        ) : list.data.sites.length === 0 ? (
          <Empty text={running ? 'Scanning…' : 'No CMS installations found yet. Run a scan.'} />
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs text-slate-500 uppercase">
              <tr>
                <th className="px-4 py-3">CMS</th>
                <th className="px-2">User</th>
                <th className="px-2">Version</th>
                <th className="px-2">Plugins</th>
                <th className="px-2">Themes</th>
                <th className="px-2">Issues</th>
                <th className="px-2">Risk</th>
                <th className="px-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {list.data.sites.map((s) => (
                <Fragment key={s.id}>
                  <tr className="cursor-pointer hover:bg-slate-50" onClick={() => setOpen(open === s.id ? null : s.id)}>
                    <td className="px-4 py-3">
                      <div className="font-medium text-navy-900">{s.domain || s.path.split('/').slice(-2).join('/')}</div>
                      <div className="text-xs text-slate-500">
                        {TYPE_LABEL[s.type]} · {s.path.replace(/^\/home\//, '')}
                      </div>
                    </td>
                    <td className="px-2">{s.user}</td>
                    <td className="px-2">
                      {s.version || '?'}
                      {s.latest && s.version && s.version !== s.latest && <div className="text-xs text-red-600">latest {s.latest}</div>}
                    </td>
                    <td className="px-2">
                      {s.plugins.length}{' '}
                      {s.outdated_plugins > 0 && <span className="ml-1 rounded bg-red-50 px-1.5 text-xs text-red-600">{s.outdated_plugins} outdated</span>}
                    </td>
                    <td className="px-2">
                      {s.themes.length}{' '}
                      {s.outdated_themes > 0 && <span className="ml-1 rounded bg-red-50 px-1.5 text-xs text-red-600">{s.outdated_themes} outdated</span>}
                    </td>
                    <td className="px-2">
                      {s.core_issues + s.db_issues}
                      {s.core_issues > 0 && <div className="text-xs text-red-600">{s.core_issues} core files</div>}
                      {s.db_issues > 0 && <div className="text-xs text-red-600">{s.db_issues} in database</div>}
                    </td>
                    <td className="px-2">
                      <RiskBadge risk={s.risk} />
                    </td>
                    <td className="px-2 text-slate-400">{open === s.id ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}</td>
                  </tr>
                  {open === s.id && (
                    <tr>
                      <td colSpan={8} className="bg-slate-50 px-4 py-4">
                        <SiteDetail site={s} admin={can(user, 'admin')} busy={busy} onUpdate={update} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {list.data && <Pager total={list.data.total} limit={limit} offset={offset} onChange={setOffset} />}
      <p className="text-xs text-slate-400">
        Risk: <b>critical</b> = modified/foreign WordPress core files, database infection or a whole major version behind; <b>high</b> = core
        update available or 5+ outdated plugins; <b>medium</b> = outdated plugins/themes.
      </p>
    </div>
  );
}

function SiteDetail({ site: s, admin, busy, onUpdate }: { site: Site; admin: boolean; busy: boolean; onUpdate: (s: Site, what: string, slug?: string) => void }) {
  const wp = s.type === 'wordpress';
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <div>
        <h3 className="mb-2 font-semibold text-navy-900">Core</h3>
        <div className="text-sm">
          Version {s.version || '?'}
          {s.latest && ` (latest ${s.latest})`}
          {admin && wp && s.latest && s.version !== s.latest && (
            <button className="btn-outline ml-3 px-2 py-1 text-xs" disabled={busy} onClick={() => onUpdate(s, 'core')}>
              Update core
            </button>
          )}
        </div>
        {wp && (
          <div className="mt-2 text-sm">
            {s.core.error ? (
              <span className="text-slate-500">Core integrity not checked: {s.core.error}</span>
            ) : s.core.modified.length + s.core.unknown.length === 0 ? (
              <span className="text-green-700">All {s.core.checked} core files match the official WordPress release.</span>
            ) : (
              <div className="rounded bg-red-50 p-3 text-red-800">
                <div className="font-medium">
                  {s.core.modified.length} modified and {s.core.unknown.length} foreign files in WordPress core
                </div>
                <ul className="mt-1 max-h-40 overflow-y-auto font-mono text-xs">
                  {s.core.modified.map((f) => (
                    <li key={f}>modified: {f}</li>
                  ))}
                  {s.core.unknown.map((f) => (
                    <li key={f}>not part of WordPress: {f}</li>
                  ))}
                </ul>
                {admin && (
                  <button className="btn-danger mt-2 px-2 py-1 text-xs" disabled={busy} onClick={() => onUpdate(s, 'core-repair')}>
                    Reinstall official core files
                  </button>
                )}
                <p className="mt-1 text-xs">Reinstalling replaces modified files; foreign files must be reviewed and removed (Manual Scans can quarantine them).</p>
              </div>
            )}
          </div>
        )}
        {s.mu_plugins.length > 0 && (
          <div className="mt-3 text-sm">
            <span className="font-medium">Must-use plugins</span> (always loaded; check they are expected):{' '}
            <span className="font-mono text-xs">{s.mu_plugins.join(', ')}</span>
          </div>
        )}
        <div className="mt-3 text-xs text-slate-500">Scanned {fmtTime(s.scanned_at)}</div>
      </div>
      {wp && (
        <div className="space-y-4">
          <ComponentTable title="Plugins" kind="plugin" items={s.plugins} site={s} admin={admin} busy={busy} onUpdate={onUpdate} />
          <ComponentTable title="Themes" kind="theme" items={s.themes} site={s} admin={admin} busy={busy} onUpdate={onUpdate} />
        </div>
      )}
    </div>
  );
}

function ComponentTable({ title, kind, items, site, admin, busy, onUpdate }: { title: string; kind: string; items: Component[]; site: Site; admin: boolean; busy: boolean; onUpdate: (s: Site, what: string, slug?: string) => void }) {
  return (
    <div>
      <h3 className="mb-1 font-semibold text-navy-900">{title}</h3>
      {items.length === 0 ? (
        <div className="text-sm text-slate-400">None</div>
      ) : (
        <table className="w-full text-sm">
          <tbody className="divide-y divide-slate-200">
            {items.map((c) => (
              <tr key={c.slug}>
                <td className="py-1.5">
                  {c.name} <span className="text-xs text-slate-400">({c.slug})</span>
                </td>
                <td className="py-1.5 text-xs">
                  {c.version || '?'}
                  {c.outdated && <span className="ml-1 text-red-600">→ {c.latest}</span>}
                  {!c.latest && <span className="ml-1 text-slate-400">not on wordpress.org</span>}
                </td>
                <td className="py-1.5 text-right">
                  {admin && c.outdated && (
                    <button className="btn-outline px-2 py-0.5 text-xs" disabled={busy} onClick={() => onUpdate(site, kind, c.slug)}>
                      Update
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

interface DBRow {
  id: number;
  at: number;
  site_path: string;
  user: string;
  database: string;
  table: string;
  row: string;
  signature: string;
  status: string;
}

export function DBScanner() {
  const { id } = useParams();
  const host = useServerName(id);
  const { user } = useAuth();
  const [status, setStatus] = useState('detected');
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const [sel, setSel] = useState<number[]>([]);
  const limit = 25;
  const list = useAgent<{ findings: DBRow[]; total: number }>(id, 'db.findings', { status, q: query, limit, offset });
  const { run, busy } = useAction();

  const csv = () => {
    const rows = list.data?.findings ?? [];
    const text = ['database,table,row,signature,user,site,date', ...rows.map((r) => [r.database, r.table, r.row, r.signature, r.user, r.site_path, new Date(r.at * 1000).toISOString()].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(','))].join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: 'text/csv' }));
    a.download = 'db-scanner.csv';
    a.click();
  };

  return (
    <div className="space-y-5">
      <Breadcrumb items={[host, 'DB Scanner']} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="h-title">DB Scanner Logs</h1>
          <p className="text-sm text-slate-500">WordPress databases are scanned for injected scripts, hidden iframes and PHP code during CMS scans.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select className="input w-36" value={status} onChange={(e) => (setOffset(0), setStatus(e.target.value))}>
            <option value="detected">Detected</option>
            <option value="cleaned">Cleaned</option>
            <option value="archived">Archived</option>
            <option value="">All</option>
          </select>
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              setOffset(0);
              setQuery(q.trim());
            }}
          >
            <input className="input w-52" placeholder="Type to filter" value={q} onChange={(e) => setQ(e.target.value)} />
            <button className="btn-outline">
              <Search className="h-4 w-4" />
            </button>
          </form>
          <button className="btn-outline" title="Download CSV" onClick={csv} disabled={!list.data?.findings.length}>
            <Download className="h-4 w-4" />
          </button>
          {can(user, 'operator') && (
            <button
              className="btn-outline"
              disabled={busy || sel.length === 0}
              onClick={() =>
                run(() => agentCall(id!, 'db.archive', { ids: sel }), `${sel.length} archived`).then(() => {
                  setSel([]);
                  list.reload();
                })
              }
            >
              <Archive className="h-4 w-4" /> Archive
            </button>
          )}
        </div>
      </div>
      <div className="card overflow-x-auto p-0">
        {!list.data ? (
          list.error ? (
            <ErrorBox message={list.error} />
          ) : (
            <PageLoader />
          )
        ) : list.data.findings.length === 0 ? (
          <Empty text="No records to display" />
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs text-slate-500 uppercase">
              <tr>
                <th className="px-4 py-3">
                  <input
                    type="checkbox"
                    checked={sel.length === list.data.findings.length}
                    onChange={(e) => setSel(e.target.checked ? list.data!.findings.map((f) => f.id) : [])}
                  />
                </th>
                <th className="px-2">Database</th>
                <th className="px-2">Table</th>
                <th className="px-2">Signature Name</th>
                <th className="px-2">User</th>
                <th className="px-2">Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {list.data.findings.map((f) => (
                <tr key={f.id}>
                  <td className="px-4 py-3">
                    <input type="checkbox" checked={sel.includes(f.id)} onChange={(e) => setSel(e.target.checked ? [...sel, f.id] : sel.filter((x) => x !== f.id))} />
                  </td>
                  <td className="px-2 font-mono text-xs">{f.database}</td>
                  <td className="px-2 font-mono text-xs">
                    {f.table}
                    <div className="text-slate-400">{f.row}</div>
                  </td>
                  <td className="px-2 text-red-700">{f.signature}</td>
                  <td className="px-2">{f.user}</td>
                  <td className="px-2 text-xs text-slate-500">{fmtTime(f.at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {list.data && <Pager total={list.data.total} limit={limit} offset={offset} onChange={setOffset} />}
    </div>
  );
}
