import { useEffect, useState } from 'react';
import { Brain, Download, FileCheck2, Fingerprint, Search, Server as ServerIcon, ShieldOff, Trash2 } from 'lucide-react';
import { api } from '../api';
import { useApi } from '../hooks';
import { useAuth, can } from '../auth';
import { Breadcrumb, Empty, ErrorBox, PageLoader, StatCard } from '../components/ui';
import { Modal, Pager, useAction } from '../components/controls';

type Decision = 'review' | 'off' | 'keep' | null;

interface SigRow {
  signature: string;
  files: number;
  servers: number;
  events: number;
  confidence: number;
  malicious: number;
  last_at: string;
  action: Decision;
  auto: boolean | null;
  note: string | null;
  can_override: boolean;
}

interface Summary {
  totals: { files: number; servers: number; events: number; signatures: number; review: number; off: number; keep: number };
  signatures: SigRow[];
  rules: { min_confidence: number; auto_review_files: number };
}

interface FileRow {
  id: number;
  sha256: string;
  signature: string;
  path: string;
  name: string;
  size: number;
  line: number;
  snippet: string;
  reason: string;
  confidence: number;
  model: string;
  source: string;
  count: number;
  last_at: string;
  server: string | null;
}

const DECISION: Record<string, { label: string; cls: string }> = {
  review: { label: 'AI review', cls: 'bg-amber-100 text-amber-800' },
  off: { label: 'Off', cls: 'bg-red-100 text-red-700' },
  keep: { label: 'Keep as is', cls: 'bg-slate-100 text-slate-600' },
};

function DecisionBadge({ r }: { r: SigRow }) {
  if (!r.action) return <span className="text-xs text-slate-400">Active</span>;
  const d = DECISION[r.action];
  return (
    <span className={`whitespace-nowrap rounded-full px-2.5 py-0.5 text-xs font-medium ${d.cls}`}>
      {d.label}
      {r.auto ? ' · auto' : ''}
    </span>
  );
}

function ago(ts: string): string {
  const s = (Date.now() - new Date(ts).getTime()) / 1000;
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function Files({ sig, onClose }: { sig: string; onClose: () => void }) {
  const [offset, setOffset] = useState(0);
  const res = useApi<{ total: number; files: FileRow[] }>(`/api/ai/learning/files?signature=${encodeURIComponent(sig)}&limit=20&offset=${offset}`);
  return (
    <Modal title={`Files flagged by ${sig}`} onClose={onClose} wide>
      {res.loading && !res.data ? (
        <PageLoader />
      ) : !res.data?.files.length ? (
        <Empty text="No files" />
      ) : (
        <div className="space-y-3">
          {res.data.files.map((f) => (
            <div key={f.id} className="rounded-lg border border-slate-200 p-3 text-sm">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <span className="break-all font-mono text-xs font-medium text-navy-900">{f.path || f.name}</span>
                <span className="text-xs text-slate-500">
                  {f.server ?? 'removed server'} · seen {f.count}× · {ago(f.last_at)}
                </span>
              </div>
              <div className="mt-2 grid gap-2 md:grid-cols-2">
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Why the scanner flagged it</div>
                  <div className="mt-1 text-xs">
                    Signature <b>{f.signature}</b>
                    {f.line ? ` matched line ${f.line}` : ' (heuristic or hash: no single line)'}
                  </div>
                  {f.snippet && <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-50 p-2 text-[11px] leading-snug">{f.snippet}</pre>}
                </div>
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Why the AI restored it</div>
                  <p className="mt-1 text-xs">{f.reason || '–'}</p>
                  <p className="mt-1 text-xs text-slate-500">
                    Clean, {f.confidence}% sure · {f.model || f.source} · <span className="font-mono">{f.sha256.slice(0, 16)}…</span>
                  </p>
                </div>
              </div>
            </div>
          ))}
          <Pager total={res.data.total} limit={20} offset={offset} onChange={setOffset} />
        </div>
      )}
    </Modal>
  );
}

/** Master: the scanner's false positives the AI restored, by signature, with decisions and an export. */
export default function AILearning() {
  const { user } = useAuth();
  const admin = !!user && can(user, 'admin');
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [days, setDays] = useState(30);
  const [open, setOpen] = useState<string | null>(null);
  const { run, busy } = useAction();
  useEffect(() => {
    const t = setTimeout(() => setQuery(q.trim()), 300);
    return () => clearTimeout(t);
  }, [q]);
  const qs = `q=${encodeURIComponent(query)}&days=${days}`;
  const res = useApi<Summary>(`/api/ai/learning?${qs}`, 60_000);
  const d = res.data;

  if (res.loading && !d) return <PageLoader />;
  if (res.error && !d) return <ErrorBox message={res.error} />;

  const decide = (signature: string, action: 'review' | 'off' | 'keep' | 'none') => {
    const text: Record<string, string> = {
      review: `Put "${signature}" on AI review on every server?\n\nIts matches are reported as suspicious and wait for the AI; a confident "malicious" still quarantines them.`,
      off: `Turn "${signature}" off on every server?\n\nIt will flag nothing. Use this only when it never catches real malware.`,
      keep: `Keep "${signature}" as it is? It will not be moved to review automatically.`,
      none: `Reset "${signature}" to normal on every server?`,
    };
    if (!confirm(text[action])) return;
    void run(() => api('PUT', '/api/ai/learning/signature', { signature, action }), (r: { pushed: number }) => `Saved; sent to ${r.pushed} online server(s)`).then(() => res.reload());
  };

  const t = d?.totals;
  return (
    <div className="space-y-5">
      <Breadcrumb items={['AI', 'AI Learning']} />
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="h-title flex items-center gap-2">
            <Brain className="h-6 w-6" /> AI Learning
          </h1>
          <p className="max-w-3xl text-sm text-slate-500">
            Files the scanner flagged and the AI then restored as clean (false positives), grouped by signature: why the scanner flagged each file, the code
            it matched, and why the AI restored it. Export the report and share it to get the signatures fixed in the next update.
          </p>
        </div>
        <div className="flex gap-2">
          <a className="btn-outline" href={`/api/ai/learning/export?format=json&${qs}`}>
            <Download className="h-4 w-4" /> Export JSON
          </a>
          <a className="btn-outline" href={`/api/ai/learning/export?format=csv&${qs}`}>
            <Download className="h-4 w-4" /> CSV
          </a>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard icon={<FileCheck2 />} value={t?.files ?? 0} label="Files restored by the AI" accent="text-green-600" />
        <StatCard icon={<Fingerprint />} value={t?.signatures ?? 0} label="Signatures involved" />
        <StatCard icon={<ServerIcon />} value={t?.servers ?? 0} label="Servers" />
        <StatCard icon={<ShieldOff />} value={`${t?.review ?? 0} / ${t?.off ?? 0}`} label="On AI review / off" accent="text-red-600" />
      </div>

      <div className="card p-4 text-sm text-slate-600 sm:p-5">
        <b className="text-navy-900">How the scanner learns.</b> The same file content is never flagged again on any server once the AI found it clean. When a
        signature flags {d?.rules.auto_review_files ?? 5} different files the AI finds clean (at least {d?.rules.min_confidence ?? 90}% sure) and never a file the
        AI finds malicious, it is put on <b>AI review</b> on every server automatically: its matches wait for the AI instead of being quarantined and restored
        again and again. You can also put a signature on review, turn it off, or keep it as it is.
      </div>

      <div className="card p-4 sm:p-6">
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <div className="relative w-full sm:w-80">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <input className="input pl-9" placeholder="Search signature, path, AI reason…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <select className="input w-auto" value={days} onChange={(e) => setDays(Number(e.target.value))}>
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
            <option value={0}>All time</option>
          </select>
          {admin && !!t?.files && (
            <button
              className="btn-outline ml-auto text-red-600"
              disabled={busy}
              onClick={() => {
                if (!confirm('Delete these records? Signature decisions stay.')) return;
                void run(() => api<{ deleted: number }>('DELETE', `/api/ai/learning?${qs}`), (r) => `${r.deleted} records deleted`).then(() => res.reload());
              }}
            >
              <Trash2 className="h-4 w-4" /> Clear records
            </button>
          )}
        </div>
        {!d?.signatures.length ? (
          <Empty text="No false positives yet: files the AI restores will show here." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-left text-xs uppercase tracking-wide text-slate-500">
                  <th className="py-2 pr-3">Signature</th>
                  <th className="py-2 pr-3 text-right">Clean files</th>
                  <th className="py-2 pr-3 text-right">Servers</th>
                  <th className="py-2 pr-3 text-right">Times flagged</th>
                  <th className="py-2 pr-3 text-right" title="Files with this signature the AI found malicious">Malware caught</th>
                  <th className="py-2 pr-3">Last</th>
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {d.signatures.map((r) => (
                  <tr key={r.signature} className="hover:bg-slate-50">
                    <td className="py-2.5 pr-3">
                      <button className="break-all text-left font-mono text-xs font-medium text-navy-900 hover:underline" onClick={() => setOpen(r.signature)}>
                        {r.signature}
                      </button>
                    </td>
                    <td className="py-2.5 pr-3 text-right font-semibold">{r.files}</td>
                    <td className="py-2.5 pr-3 text-right">{r.servers}</td>
                    <td className="py-2.5 pr-3 text-right">{r.events}</td>
                    <td className={`py-2.5 pr-3 text-right ${r.malicious ? 'font-semibold text-red-600' : 'text-slate-400'}`}>{r.malicious}</td>
                    <td className="py-2.5 pr-3 text-xs text-slate-500">{ago(r.last_at)}</td>
                    <td className="py-2.5 pr-3">
                      <DecisionBadge r={r} />
                    </td>
                    <td className="py-2.5 text-right">
                      <div className="flex justify-end gap-1.5">
                        <button className="btn-outline whitespace-nowrap px-2.5 py-1 text-xs" onClick={() => setOpen(r.signature)}>
                          Files
                        </button>
                        {admin && r.can_override && (
                          <select
                            className="input w-auto py-1 text-xs"
                            value=""
                            disabled={busy}
                            onChange={(e) => e.target.value && decide(r.signature, e.target.value as 'review')}
                          >
                            <option value="">Decide…</option>
                            {r.action !== 'review' && <option value="review">AI review</option>}
                            {r.action !== 'off' && <option value="off">Turn off</option>}
                            {r.action !== 'keep' && <option value="keep">Keep as is</option>}
                            {r.action && <option value="none">Reset</option>}
                          </select>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {open && <Files sig={open} onClose={() => setOpen(null)} />}
    </div>
  );
}
