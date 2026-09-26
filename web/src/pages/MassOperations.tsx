import { useMemo, useState } from 'react';
import { CheckCircle2, Layers, Play, XCircle } from 'lucide-react';
import { api, type Server } from '../api';
import { useApi } from '../hooks';
import { Breadcrumb, Empty, ErrorBox, PageLoader, StatusDot } from '../components/ui';
import { Card, useAction } from '../components/controls';

interface Op {
  id: string;
  label: string;
  role: string;
  needs_addr: boolean;
}

interface RunResult {
  op: string;
  total: number;
  ok: number;
  results: { server_id: string; hostname: string; ok: boolean; error?: string }[];
}

export default function MassOperations() {
  const servers = useApi<{ servers: Server[] }>('/api/servers');
  const ops = useApi<{ operations: Op[] }>('/api/mass/operations');
  const [sel, setSel] = useState<string[]>([]);
  const [filter, setFilter] = useState('');
  const [onlineOnly, setOnlineOnly] = useState(true);
  const [op, setOp] = useState('');
  const [addr, setAddr] = useState('');
  const [comment, setComment] = useState('');
  const [result, setResult] = useState<RunResult | null>(null);
  const { run, busy } = useAction();

  const list = useMemo(
    () =>
      (servers.data?.servers ?? []).filter(
        (s) =>
          (!onlineOnly || s.online) &&
          (!filter || s.hostname.toLowerCase().includes(filter.toLowerCase()) || s.primary_ip.includes(filter) || s.tags.some((t) => t.toLowerCase().includes(filter.toLowerCase()))),
      ),
    [servers.data, filter, onlineOnly],
  );
  const chosen = ops.data?.operations.find((o) => o.id === op);

  if (servers.loading && !servers.data) return <PageLoader />;
  if (servers.error && !servers.data) return <ErrorBox message={servers.error} />;

  const start = async () => {
    if (!chosen) return;
    const names = list.filter((s) => sel.includes(s.id)).map((s) => s.hostname);
    if (!confirm(`${chosen.label}${chosen.needs_addr ? ` (${addr})` : ''} on ${sel.length} server(s)?\n\n${names.slice(0, 15).join('\n')}${names.length > 15 ? '\n…' : ''}`)) return;
    const r = await run(() => api<RunResult>('POST', '/api/mass/run', { op, server_ids: sel, params: { addr: addr.trim(), comment } }), (x) => `${x.ok} of ${x.total} servers succeeded`);
    if (r) setResult(r);
  };

  return (
    <div className="space-y-5">
      <Breadcrumb items={['Mass Operations']} />
      <div>
        <h1 className="h-title flex items-center gap-2">
          <Layers className="h-6 w-6" /> Mass Operations
        </h1>
        <p className="text-sm text-slate-500">Run the same action on many servers at once. Every run is recorded in the Security Log.</p>
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <Card title={`1. Choose servers (${sel.length} selected)`}>
          <div className="mb-3 flex flex-wrap items-center gap-3">
            <input className="input w-64" placeholder="Filter by name, IP or tag" value={filter} onChange={(e) => setFilter(e.target.value)} />
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={onlineOnly} onChange={(e) => setOnlineOnly(e.target.checked)} /> Online only
            </label>
            <button className="btn-outline ml-auto" onClick={() => setSel(Array.from(new Set([...sel, ...list.map((s) => s.id)])))}>
              Select all shown
            </button>
            <button className="btn-outline" onClick={() => setSel([])}>
              Clear
            </button>
          </div>
          {list.length === 0 ? (
            <Empty text="No servers match" />
          ) : (
            <div className="max-h-[420px] overflow-y-auto">
              <table className="w-full text-sm">
                <tbody className="divide-y divide-slate-100">
                  {list.map((s) => (
                    <tr key={s.id} className="cursor-pointer hover:bg-slate-50" onClick={() => setSel(sel.includes(s.id) ? sel.filter((x) => x !== s.id) : [...sel, s.id])}>
                      <td className="py-2 pr-2">
                        <input type="checkbox" readOnly checked={sel.includes(s.id)} />
                      </td>
                      <td className="py-2 font-medium text-navy-900">{s.hostname}</td>
                      <td className="py-2 text-slate-500">{s.primary_ip}</td>
                      <td className="py-2 text-xs text-slate-500">{s.agent_version}</td>
                      <td className="py-2">
                        <StatusDot online={s.online} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <div className="space-y-5">
          <Card title="2. Choose operation">
            <select className="input" value={op} onChange={(e) => setOp(e.target.value)}>
              <option value="">Select…</option>
              {ops.data?.operations.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.label}
                </option>
              ))}
            </select>
            {chosen?.needs_addr && (
              <div className="mt-3 space-y-2">
                <input className="input" placeholder="IP address or CIDR" value={addr} onChange={(e) => setAddr(e.target.value)} />
                {chosen.id !== 'unblock_ip' && <input className="input" placeholder="Comment (optional)" value={comment} onChange={(e) => setComment(e.target.value)} />}
              </div>
            )}
            <button className="btn-primary mt-4 w-full" disabled={busy || !chosen || sel.length === 0 || (chosen.needs_addr && !addr.trim())} onClick={start}>
              <Play className="h-4 w-4" /> {busy ? 'Running…' : `Run on ${sel.length} server${sel.length === 1 ? '' : 's'}`}
            </button>
          </Card>

          {result && (
            <Card title={`3. Results: ${result.ok} of ${result.total} succeeded`}>
              <ul className="divide-y divide-slate-100 text-sm">
                {result.results.map((r) => (
                  <li key={r.server_id} className="flex items-start gap-2 py-2">
                    {r.ok ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-green-600" /> : <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-600" />}
                    <span className="font-medium">{r.hostname}</span>
                    {!r.ok && <span className="text-red-600">{r.error}</span>}
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
