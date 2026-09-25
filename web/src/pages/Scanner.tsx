import { useEffect, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { Download, FileSearch, FolderSearch, RefreshCw, ScanSearch, Square, Trash2 } from 'lucide-react';
import { can, useAuth } from '../auth';
import { bytes } from '../format';
import { Breadcrumb, Empty, ErrorBox, PageLoader } from '../components/ui';
import { Badge, Modal, Pager, agentCall, fmtTime, useAction, useAgent } from '../components/controls';
import { useApi } from '../hooks';
import type { Server } from '../api';

interface Scan {
  id: number;
  kind: string;
  target: string;
  status: string;
  files: number;
  infected: number;
  initiator: string;
  started_at: number;
  finished_at: number;
  error: string;
}

interface Finding {
  id: number;
  scan_id: number;
  source: string;
  path: string;
  owner: string;
  category: string;
  signature: string;
  sha256: string;
  size: number;
  status: string;
  created_at: number;
}

interface HostingUser {
  name: string;
  home: string;
  web_root: string;
}

export function useServerName(id?: string) {
  const { data } = useApi<{ server: Server }>(id ? `/api/servers/${id}` : null);
  return data?.server.hostname ?? '';
}

export function ManualScans() {
  const { id } = useParams();
  const host = useServerName(id);
  const { user } = useAuth();
  const scans = useAgent<{ scans: Scan[] }>(id, 'scan.list', {}, 4000);
  const paths = useAgent<{ users: HostingUser[] }>(id, 'scanner.paths');
  const { run, busy } = useAction();
  const [quick, setQuick] = useState('');
  const [path, setPath] = useState('');
  const canRun = can(user, 'operator');
  const lastFull = scans.data?.scans.find((s) => s.kind === 'full' && s.status === 'completed');
  const lastOf = (target: string) => scans.data?.scans.find((s) => s.target === target && s.status === 'completed');

  const start = (kind: string, p = '') =>
    run(async () => {
      const r = await agentCall<{ id: number }>(id!, 'scan.start', { kind, path: p });
      scans.reload();
      return r;
    }, 'Scan started');

  return (
    <div className="space-y-5">
      <div>
        <Breadcrumb items={[host, 'Manual Scans']} />
        <h1 className="h-title">Manual Scans</h1>
      </div>
      <div className="grid gap-5 lg:grid-cols-3">
        <div className="card p-6">
          <div className="mb-1 flex items-center gap-2 text-lg font-semibold text-navy-900"><ScanSearch className="h-5 w-5" /> Full Scan</div>
          <p className="mb-4 text-sm text-slate-500">Start a full scan on all accounts</p>
          <button className="btn-primary w-full" disabled={!canRun || busy} onClick={() => start('full')}>Run Scan</button>
          <p className="mt-3 text-xs text-slate-500">{lastFull ? `Last scanned on ${fmtTime(lastFull.finished_at)}` : 'No full scan has been performed yet'}</p>
        </div>
        <div className="card p-6">
          <div className="mb-1 flex items-center gap-2 text-lg font-semibold text-navy-900"><FolderSearch className="h-5 w-5" /> Quick Scan</div>
          <p className="mb-4 text-sm text-slate-500">Choose a website directory</p>
          <div className="flex gap-2">
            <select className="input" value={quick} onChange={(e) => setQuick(e.target.value)}>
              <option value="">Choose Path</option>
              {paths.data?.users.filter((u) => u.web_root).map((u) => (
                <option key={u.name} value={u.web_root}>{u.name} — {u.web_root}</option>
              ))}
            </select>
            <button className="btn-primary" disabled={!canRun || busy || !quick} onClick={() => start('quick', quick)}>Scan</button>
          </div>
          <p className="mt-3 text-xs text-slate-500">{quick && lastOf(quick) ? `Last scanned on ${fmtTime(lastOf(quick)!.finished_at)}` : 'No scan has been performed yet'}</p>
        </div>
        <div className="card p-6">
          <div className="mb-1 flex items-center gap-2 text-lg font-semibold text-navy-900"><FileSearch className="h-5 w-5" /> Path Scan</div>
          <p className="mb-4 text-sm text-slate-500">Absolute path of the directory or file you wish to scan</p>
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (path.trim()) start('path', path.trim());
            }}
          >
            <input className="input" placeholder="/home/user/public_html" value={path} onChange={(e) => setPath(e.target.value)} />
            <button className="btn-primary" disabled={!canRun || busy || !path.trim()}>Scan</button>
          </form>
          <p className="mt-3 text-xs text-slate-500">{path && lastOf(path) ? `Last scanned on ${fmtTime(lastOf(path)!.finished_at)}` : 'No scan has been performed yet'}</p>
        </div>
      </div>

      <div className="card overflow-x-auto p-5">
        {scans.error && <ErrorBox message={scans.error} />}
        {scans.loading && !scans.data ? (
          <PageLoader />
        ) : !scans.data?.scans.length ? (
          <Empty text="No scans yet" />
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left text-slate-500">
                <th className="py-3 font-medium">Scan Type</th>
                <th className="py-3 font-medium">Target</th>
                <th className="py-3 font-medium">Tested Files</th>
                <th className="py-3 font-medium">Infected Files</th>
                <th className="py-3 font-medium">User</th>
                <th className="py-3 font-medium">Status</th>
                <th className="py-3 font-medium">Time</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {scans.data.scans.map((s) => (
                <tr key={s.id} className="border-b border-slate-100 last:border-0">
                  <td className="py-3 capitalize">{s.kind}</td>
                  <td className="max-w-xs py-3 break-all">{s.target}</td>
                  <td className="py-3">{s.files.toLocaleString()}</td>
                  <td className={`py-3 ${s.infected ? 'font-semibold text-red-600' : ''}`}>{s.infected}</td>
                  <td className="py-3">{s.initiator}</td>
                  <td className="py-3">
                    <Badge value={s.status} />
                    {s.error && <div className="text-xs text-red-500">{s.error}</div>}
                  </td>
                  <td className="py-3 whitespace-nowrap">{fmtTime(s.finished_at || s.started_at)}</td>
                  <td className="py-3 text-right whitespace-nowrap text-slate-400">
                    <Link to={`../scanner-logs?scan=${s.id}`} relative="path" title="View detections" className="mr-3 inline-block hover:text-navy-700">
                      <FileSearch className="h-4 w-4" />
                    </Link>
                    {canRun && (s.status === 'running' || s.status === 'queued') && (
                      <button title="Stop scan" className="mr-3 hover:text-amber-600" onClick={() => run(() => agentCall(id!, 'scan.stop', { id: s.id }).then(scans.reload), 'Stopping scan')}>
                        <Square className="h-4 w-4" />
                      </button>
                    )}
                    {canRun && s.status !== 'running' && s.status !== 'queued' && (
                      <button title="Delete record" className="hover:text-red-600" onClick={() => run(() => agentCall(id!, 'scan.delete', { id: s.id }).then(scans.reload))}>
                        <Trash2 className="h-4 w-4" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

const ACTIONS: { v: string; l: string; confirm?: string }[] = [
  { v: 'quarantine', l: 'Quarantine' },
  { v: 'restore', l: 'Restore' },
  { v: 'disable', l: 'Disable (chmod 000)' },
  { v: 'ignore', l: 'Ignore & whitelist' },
  { v: 'delete', l: 'Delete permanently', confirm: 'Permanently delete the selected files? This cannot be undone.' },
];

function toCSV(rows: Finding[]): string {
  const esc = (v: unknown) => `"${String(v).replace(/"/g, '""')}"`;
  const head = ['time', 'path', 'owner', 'category', 'signature', 'status', 'sha256', 'size'];
  return [head.join(','), ...rows.map((f) => [fmtTime(f.created_at), f.path, f.owner, f.category, f.signature, f.status, f.sha256, f.size].map(esc).join(','))].join('\n');
}

export function ScannerLogs() {
  const { id } = useParams();
  const host = useServerName(id);
  const { user } = useAuth();
  const [sp, setSp] = useSearchParams();
  const scanId = Number(sp.get('scan') || 0);
  const [category, setCategory] = useState('');
  const [status, setStatus] = useState('');
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const [sel, setSel] = useState<number[]>([]);
  const [detail, setDetail] = useState<Finding | null>(null);
  const limit = 25;
  const params = { scan_id: scanId, category, status, q: query, limit, offset };
  const list = useAgent<{ findings: Finding[]; total: number }>(id, 'findings.list', params, 15_000);
  const { run, busy } = useAction();
  const canAct = can(user, 'operator');
  useEffect(() => setSel([]), [list.data]);
  useEffect(() => setOffset(0), [category, status, query, scanId]);

  const act = async (action: string) => {
    const a = ACTIONS.find((x) => x.v === action)!;
    if (a.confirm && !confirm(a.confirm)) return;
    const r = await run(
      () => agentCall<{ done: number; failed: Record<string, string> }>(id!, 'finding.action', { ids: sel, action }),
      (r) => `${a.l}: ${r.done} done${Object.keys(r.failed).length ? `, ${Object.keys(r.failed).length} failed` : ''}`,
    );
    if (r && Object.keys(r.failed).length) alert(Object.entries(r.failed).map(([k, v]) => `#${k}: ${v}`).join('\n'));
    list.reload();
  };

  const rows = list.data?.findings ?? [];
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <Breadcrumb items={[host, 'Scanner Logs']} />
          <h1 className="h-title">Virus Scanner Logs</h1>
          {scanId > 0 && (
            <div className="mt-1 text-sm text-slate-500">
              Showing detections of scan #{scanId}.{' '}
              <button className="text-navy-700 underline" onClick={() => setSp({})}>Show all</button>
            </div>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button className="btn border border-slate-300 bg-white" onClick={list.reload}><RefreshCw className="h-4 w-4" /> Refresh</button>
          <select className="input w-40" value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="">All categories</option>
            <option value="virus">Virus</option>
            <option value="suspicious">Suspicious</option>
            <option value="binary">Binary</option>
          </select>
          <select className="input w-40" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All statuses</option>
            {['detected', 'quarantined', 'disabled', 'restored', 'deleted', 'ignored'].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <form onSubmit={(e) => (e.preventDefault(), setQuery(q))}>
            <input className="input w-56" placeholder="Type to filter" value={q} onChange={(e) => setQ(e.target.value)} />
          </form>
          <button
            className="btn border border-slate-300 bg-white"
            title="Download CSV"
            onClick={() => {
              const url = URL.createObjectURL(new Blob([toCSV(rows)], { type: 'text/csv' }));
              const a = document.createElement('a');
              a.href = url;
              a.download = `xmartguard-detections-${host}.csv`;
              a.click();
              URL.revokeObjectURL(url);
            }}
          >
            <Download className="h-4 w-4" />
          </button>
        </div>
      </div>

      {canAct && sel.length > 0 && (
        <div className="card flex flex-wrap items-center gap-2 p-3">
          <span className="mr-2 text-sm text-slate-600">{sel.length} selected</span>
          {ACTIONS.map((a) => (
            <button key={a.v} className={a.v === 'delete' ? 'btn-danger' : 'btn-outline'} disabled={busy} onClick={() => act(a.v)}>{a.l}</button>
          ))}
        </div>
      )}

      <div className="card overflow-x-auto p-5">
        {list.error && <ErrorBox message={list.error} />}
        {list.loading && !list.data ? (
          <PageLoader />
        ) : rows.length === 0 ? (
          <Empty text="No detections — this server looks clean" />
        ) : (
          <>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-slate-500">
                  <th className="w-8 py-3">
                    {canAct && (
                      <input type="checkbox" checked={sel.length === rows.length} onChange={(e) => setSel(e.target.checked ? rows.map((r) => r.id) : [])} />
                    )}
                  </th>
                  <th className="py-3 font-medium">Filename</th>
                  <th className="py-3 font-medium">Category</th>
                  <th className="py-3 font-medium">Signature</th>
                  <th className="py-3 font-medium">User</th>
                  <th className="py-3 font-medium">Action</th>
                  <th className="py-3 font-medium">Time</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((f) => (
                  <tr key={f.id} className="cursor-pointer border-b border-slate-100 last:border-0 hover:bg-slate-50" onClick={() => setDetail(f)}>
                    <td className="py-3" onClick={(e) => e.stopPropagation()}>
                      {canAct && (
                        <input type="checkbox" checked={sel.includes(f.id)} onChange={(e) => setSel(e.target.checked ? [...sel, f.id] : sel.filter((x) => x !== f.id))} />
                      )}
                    </td>
                    <td className="max-w-xs py-3">
                      <div className="font-medium break-all text-navy-900">{f.path.split('/').pop()}</div>
                      <div className="text-xs break-all text-slate-400">{f.path}</div>
                    </td>
                    <td className="py-3"><Badge value={f.category} /></td>
                    <td className="py-3 font-mono text-xs">{f.signature}</td>
                    <td className="py-3">{f.owner}</td>
                    <td className="py-3"><Badge value={f.status} /></td>
                    <td className="py-3 whitespace-nowrap">{fmtTime(f.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pager total={list.data?.total ?? 0} limit={limit} offset={offset} onChange={setOffset} />
          </>
        )}
      </div>

      {detail && (
        <Modal title="Detection details" onClose={() => setDetail(null)}>
          <dl className="grid grid-cols-[140px_1fr] gap-y-2 text-sm">
            {[
              ['File', detail.path], ['Owner', detail.owner], ['Category', detail.category], ['Signature', detail.signature],
              ['Status', detail.status], ['Found by', `${detail.source} scan${detail.scan_id ? ` #${detail.scan_id}` : ''}`],
              ['Size', bytes(detail.size)], ['SHA-256', detail.sha256], ['Detected', fmtTime(detail.created_at)],
            ].map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-slate-500">{k}</dt>
                <dd className="font-mono break-all text-navy-900">{v}</dd>
              </div>
            ))}
          </dl>
          {canAct && (
            <div className="mt-6 flex flex-wrap gap-2">
              {ACTIONS.map((a) => (
                <button
                  key={a.v}
                  className={a.v === 'delete' ? 'btn-danger' : 'btn-outline'}
                  disabled={busy}
                  onClick={async () => {
                    setSel([detail.id]);
                    if (a.confirm && !confirm(a.confirm)) return;
                    await run(() => agentCall(id!, 'finding.action', { ids: [detail.id], action: a.v }), `${a.l} done`);
                    setDetail(null);
                    list.reload();
                  }}
                >
                  {a.l}
                </button>
              ))}
            </div>
          )}
        </Modal>
      )}
    </div>
  );
}
