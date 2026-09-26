import { useEffect, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { Download, FileCode2, FileSearch, FolderSearch, RefreshCw, ScanSearch, Scissors, Sparkles, Square, Trash2 } from 'lucide-react';
import { can, useAuth } from '../auth';
import { bytes } from '../format';
import { Breadcrumb, Empty, ErrorBox, PageLoader } from '../components/ui';
import { Badge, Modal, Pager, agentCall, fmtTime, useAction, useAgent, useToast } from '../components/controls';
import { useApi } from '../hooks';
import type { Server } from '../api';

interface Scan {
  id: number;
  kind: string;
  target: string;
  status: string;
  files: number;
  total?: number;
  current?: string;
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
  ai_verdict?: string;
  ai_reason?: string;
  ai_confidence?: number;
  ai_model?: string;
  ai_injected?: boolean;
}

interface AIResult {
  verdict: string;
  confidence: number;
  reason: string;
  model: string;
  source?: string;
  injected?: boolean;
  cut?: { from: number; to: number; text?: string }[];
}

const AI_STYLE: Record<string, string> = {
  malicious: 'bg-red-100 text-red-700',
  suspicious: 'bg-amber-100 text-amber-800',
  clean: 'bg-green-100 text-green-700',
  error: 'bg-slate-100 text-slate-500',
};

/** The AI verdict with its confidence; a "clean" verdict below the restore
 * threshold says why the file stayed in quarantine. */
function AIBadge({ v, reason, confidence, status }: { v?: string; reason?: string; confidence?: number; status?: string }) {
  if (!v) return <span className="text-xs text-slate-300">–</span>;
  const held = v === 'clean' && (status === 'quarantined' || status === 'disabled') && (confidence ?? 0) < 90;
  const tip = [reason, held ? `Kept in ${status}: the AI must be at least 90% sure to restore a file automatically. Use Restore or False positive if you agree.` : '']
    .filter(Boolean)
    .join('\n\n');
  return (
    <span title={tip} className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium capitalize ${AI_STYLE[v] ?? AI_STYLE.error} ${held ? 'ring-1 ring-amber-300' : ''}`}>
      <Sparkles className="h-3 w-3" /> {v}
      {confidence ? <span className="font-normal opacity-70">{confidence}%</span> : null}
    </span>
  );
}

interface HostingUser {
  name: string;
  home: string;
  web_root: string;
}

/** Live progress of a running scan: files checked of the files counted. */
function ScanProgress({ s }: { s: Scan }) {
  const total = s.total ?? 0;
  const pct = total > 0 ? Math.min(99, Math.floor((s.files / total) * 100)) : 0;
  const secs = Math.max(1, Date.now() / 1000 - s.started_at);
  const rate = Math.round(s.files / secs);
  return (
    <div className="min-w-[220px]">
      <div className="flex justify-between text-xs">
        <span className="font-medium text-navy-900">
          {s.files.toLocaleString()} {total > 0 ? `/ ${total.toLocaleString()}` : ''} files
        </span>
        <span className="text-slate-500">{total > 0 ? `${pct}%` : 'counting…'}</span>
      </div>
      <div className="mt-1 h-2 overflow-hidden rounded-full bg-slate-100">
        {total > 0 ? (
          <div className="h-2 rounded-full bg-gradient-to-r from-blue-500 to-navy-600 transition-all duration-700" style={{ width: `${Math.max(2, pct)}%` }} />
        ) : (
          <div className="h-2 w-1/3 animate-pulse rounded-full bg-blue-300" />
        )}
      </div>
      <div className="mt-1 text-[11px] text-slate-400">
        {rate.toLocaleString()} files/s
        {total > 0 && rate > 0 && ` · about ${Math.max(1, Math.ceil((total - s.files) / rate / 60))} min left`}
      </div>
    </div>
  );
}

export function useServerName(id?: string) {
  const { data } = useApi<{ server: Server }>(id ? `/api/servers/${id}` : null);
  return data?.server.hostname ?? '';
}

export function ManualScans() {
  const { id } = useParams();
  const host = useServerName(id);
  const { user } = useAuth();
  const scans = useAgent<{ scans: Scan[] }>(id, 'scan.list', {}, 2000);
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
                  <td className="py-3">
                    {s.status === 'running' ? <ScanProgress s={s} /> : s.files.toLocaleString()}
                  </td>
                  <td className={`py-3 ${s.infected ? 'font-semibold text-red-600' : ''}`}>{s.infected}</td>
                  <td className="py-3">{s.initiator}</td>
                  <td className="py-3">
                    <Badge value={s.status} />
                    {s.error && <div className="text-xs text-red-500">{s.error}</div>}
                  </td>
                  <td className="py-3 whitespace-nowrap">{fmtTime(s.finished_at || s.started_at)}</td>
                  <td className="py-3 text-right whitespace-nowrap">
                    <div className="inline-flex items-center gap-1.5">
                      <Link
                        to={`../scanner-logs?scan=${s.id}`}
                        relative="path"
                        title="View detections"
                        className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 bg-white text-navy-800 shadow-sm transition hover:border-navy-300 hover:bg-navy-50"
                      >
                        <FileSearch className="h-[18px] w-[18px]" />
                      </Link>
                      {canRun && (s.status === 'running' || s.status === 'queued') && (
                        <button
                          title="Stop scan"
                          className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-amber-200 bg-amber-50 text-amber-700 shadow-sm transition hover:bg-amber-100"
                          onClick={() => run(() => agentCall(id!, 'scan.stop', { id: s.id }).then(scans.reload), 'Stopping scan')}
                        >
                          <Square className="h-4 w-4 fill-current" />
                        </button>
                      )}
                      {canRun && s.status !== 'running' && s.status !== 'queued' && (
                        <button
                          title="Delete record"
                          className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-500 shadow-sm transition hover:border-red-200 hover:bg-red-50 hover:text-red-600"
                          onClick={() => run(() => agentCall(id!, 'scan.delete', { id: s.id }).then(scans.reload))}
                        >
                          <Trash2 className="h-[18px] w-[18px]" />
                        </button>
                      )}
                    </div>
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
  { v: 'clear', l: 'False positive' },
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
  const [aiRes, setAiRes] = useState<AIResult | null>(null);
  const [viewing, setViewing] = useState<Finding | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const toast = useToast();
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
          <button
            className="btn border border-slate-300 bg-white"
            disabled={refreshing}
            onClick={async () => {
              setRefreshing(true);
              await list.reload();
              setRefreshing(false);
              toast('ok', 'Logs refreshed');
            }}
          >
            <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} /> Refresh
          </button>
          <select className="input w-40" value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="">All categories</option>
            <option value="virus">Virus</option>
            <option value="suspicious">Suspicious</option>
            <option value="binary">Binary</option>
            <option value="symlink">Symbolic link</option>
          </select>
          <select className="input w-40" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All statuses</option>
            {['detected', 'quarantined', 'disabled', 'trimmed', 'cleaned', 'cleared', 'restored', 'deleted', 'ignored'].map((s) => <option key={s} value={s}>{s}</option>)}
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
                  <th className="py-3 font-medium">AI</th>
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
                    <td className="py-3"><AIBadge v={f.ai_verdict} reason={f.ai_reason} confidence={f.ai_confidence} status={f.status} /></td>
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
        <Modal title="Detection details" onClose={() => (setDetail(null), setAiRes(null))}>
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
          <div className="mt-4 rounded-lg bg-slate-50 p-3 text-sm">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 font-medium text-navy-900">
                <Sparkles className="h-4 w-4" /> AI scanner
                {(aiRes?.verdict ?? detail.ai_verdict) && <AIBadge v={aiRes?.verdict ?? detail.ai_verdict} />}
                {aiRes && <span className="text-xs text-slate-500">{aiRes.confidence}% · {aiRes.model}</span>}
              </div>
              {canAct && detail.status !== 'deleted' && detail.category !== 'symlink' && (
                <button className="btn-outline px-3 py-1 text-xs" disabled={busy} onClick={async () => {
                  const r = await run(() => agentCall<AIResult>(id!, 'ai.check', { id: detail.id }));
                  if (r) {
                    setAiRes(r);
                    list.reload();
                  }
                }}>
                  {busy ? 'Checking…' : 'Check with AI'}
                </button>
              )}
            </div>
            {(aiRes?.reason ?? detail.ai_reason) && <p className="mt-2 text-slate-600">{aiRes?.reason ?? detail.ai_reason}</p>}
            {(aiRes?.injected ?? detail.ai_injected) && (
              <p className="mt-2 text-blue-800">
                The AI found code injected into an otherwise legitimate file
                {aiRes?.cut?.length ? ` (lines ${aiRes.cut.map((c) => (c.from === c.to ? c.from : `${c.from}-${c.to}`)).join(', ')})` : ''}. Trim removes only that
                code and keeps the site running.
              </p>
            )}
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            {canAct && detail.status !== 'deleted' && detail.category !== 'symlink' && (
              <button className="btn-outline" onClick={() => setViewing(detail)}>
                <FileCode2 className="h-4 w-4" /> View file
              </button>
            )}
            {canAct && (aiRes?.injected ?? detail.ai_injected) && ['detected', 'quarantined', 'disabled'].includes(detail.status) && (
              <button
                className="btn-primary"
                disabled={busy}
                onClick={async () => {
                  if (!confirm('Remove only the injected code the AI located and put the cleaned file live? The original stays in quarantine.')) return;
                  const r = await run(() => agentCall<{ done: number; failed: Record<string, string> }>(id!, 'finding.action', { ids: [detail.id], action: 'trim' }));
                  if (r && Object.keys(r.failed).length) alert(Object.values(r.failed)[0]);
                  else if (r) {
                    setDetail(null);
                    list.reload();
                  }
                }}
              >
                <Scissors className="h-4 w-4" /> Trim injected code
              </button>
            )}
          </div>
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
      {viewing && <FileViewer serverId={id!} finding={viewing} onClose={() => setViewing(null)} />}
    </div>
  );
}

interface Content {
  content: string;
  truncated: boolean;
  binary: boolean;
  ai?: AIResult;
}

/** Shows a detected file (from quarantine when it was moved there) with the AI's injected lines marked. */
function FileViewer({ serverId, finding, onClose }: { serverId: string; finding: Finding; onClose: () => void }) {
  const [data, setData] = useState<Content | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [wrap, setWrap] = useState(true);
  useEffect(() => {
    agentCall<Content>(serverId, 'finding.content', { id: finding.id }).then(setData, (e) => setErr(e.message));
  }, [serverId, finding.id]);
  const marked = new Map<number, string | undefined>();
  for (const c of data?.ai?.cut ?? []) for (let n = c.from; n <= c.to; n++) marked.set(n, c.text);
  const lines = data?.content.split('\n') ?? [];
  return (
    <Modal title={finding.path.split('/').pop() ?? 'File'} onClose={onClose} wide>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
        <span className="break-all">
          {finding.path}
          {finding.status === 'quarantined' && ' · shown from quarantine'}
          {finding.status === 'trimmed' && ' · original before trimming'}
        </span>
        <label className="flex items-center gap-1">
          <input type="checkbox" checked={wrap} onChange={(e) => setWrap(e.target.checked)} /> wrap long lines
        </label>
      </div>
      {marked.size > 0 && (
        <div className="mb-2 flex items-center gap-2 text-xs text-red-700">
          <span className="inline-block h-3 w-3 rounded-sm bg-red-200" /> lines the AI marked as injected code
        </div>
      )}
      {err && <ErrorBox message={err} />}
      {!data && !err && <PageLoader />}
      {data?.binary && <Empty text="Binary file: it cannot be shown as text." />}
      {data && !data.binary && (
        <div className="max-h-[65vh] overflow-auto rounded-lg border border-slate-200 bg-slate-950 text-[12px] leading-5 text-slate-100">
          <table className="w-full border-collapse font-mono">
            <tbody>
              {lines.map((l, i) => (
                <tr key={i} className={marked.has(i + 1) ? 'bg-red-900/60' : ''}>
                  <td className="w-12 border-r border-slate-800 pr-2 text-right align-top text-slate-500 select-none">{i + 1}</td>
                  <td className={`pl-3 align-top ${wrap ? 'break-all whitespace-pre-wrap' : 'whitespace-pre'}`}>{l || ' '}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data?.truncated && <p className="mt-2 text-xs text-amber-700">Only the first 512 KB are shown.</p>}
    </Modal>
  );
}
