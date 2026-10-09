import { useMemo, useState } from 'react';
import { CheckCircle2, Layers, Play, XCircle } from 'lucide-react';
import { api, type Server } from '../api';
import { useApi } from '../hooks';
import { useAuth } from '../auth';
import { Breadcrumb, Empty, ErrorBox, PageLoader, StatusDot } from '../components/ui';
import { Card, useAction } from '../components/controls';

interface Op {
  id: string;
  label: string;
  role: string;
  needs_addr: boolean;
  ip_list?: boolean;
  modes?: ('add' | 'delete')[];
}

interface AddrFail {
  addr: string;
  error?: string;
}

type Row = Server & { account?: { platform: boolean; owner_email: string } };

interface RunResult {
  op: string;
  total: number;
  ok: number;
  results: { server_id: string; hostname: string; ok: boolean; error?: string; data?: { done?: number; total?: number; failed?: AddrFail[] } }[];
}

export default function MassOperations() {
  const { user } = useAuth();
  const master = user?.platform !== false;
  const [customers, setCustomers] = useState(false);
  const own = useApi<{ servers: Server[] }>(customers ? null : '/api/servers');
  // The master can run operations on customers' servers too.
  const all = useApi<{ servers: Row[] }>(customers ? '/api/admin/servers?per=500' : null);
  const servers = customers ? all : own;
  const ops = useApi<{ operations: Op[] }>('/api/mass/operations');
  const [sel, setSel] = useState<string[]>([]);
  const [filter, setFilter] = useState('');
  const [onlineOnly, setOnlineOnly] = useState(true);
  const [op, setOp] = useState('');
  const [addrs, setAddrs] = useState('');
  const [mode, setMode] = useState<'add' | 'delete'>('add');
  const [reason, setReason] = useState('');
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
  const lines = useMemo(() => addrs.split(/\r?\n/).flatMap((l) => l.replace(/#.*/, '').split(/[\s,;]+/)).filter(Boolean), [addrs]);
  const modes = chosen?.modes ?? ['add'];
  const curMode = modes.includes(mode) ? mode : modes[0];

  if (servers.loading && !servers.data) return <PageLoader />;
  if (servers.error && !servers.data) return <ErrorBox message={servers.error} />;

  const start = async () => {
    if (!chosen) return;
    const names = list.filter((s) => sel.includes(s.id)).map((s) => s.hostname);
    const what = chosen.needs_addr ? ` — ${curMode === 'add' ? 'add' : 'delete'} ${lines.length} IP${lines.length === 1 ? '' : 's'}` : '';
    if (!confirm(`${chosen.label}${what} on ${sel.length} server(s)?\n\n${names.slice(0, 15).join('\n')}${names.length > 15 ? '\n…' : ''}`)) return;
    const params = chosen.needs_addr ? { addrs, mode: curMode, reason } : {};
    const r = await run(() => api<RunResult>('POST', '/api/mass/run', { op, server_ids: sel, params }), (x) => `${x.ok} of ${x.total} servers succeeded`);
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
            {master && (
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={customers}
                  onChange={(e) => {
                    setCustomers(e.target.checked);
                    setSel([]);
                  }}
                />{' '}
                Customers' servers too
              </label>
            )}
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
            <div className="max-h-[420px] overflow-auto">
              <table className="w-full min-w-[480px] text-sm">
                <tbody className="divide-y divide-slate-100">
                  {list.map((s) => (
                    <tr key={s.id} className="cursor-pointer hover:bg-slate-50" onClick={() => setSel(sel.includes(s.id) ? sel.filter((x) => x !== s.id) : [...sel, s.id])}>
                      <td className="py-2 pr-2">
                        <input type="checkbox" readOnly checked={sel.includes(s.id)} />
                      </td>
                      <td className="py-2 font-medium text-navy-900">
                        {s.hostname}
                        {(s as Row).account?.platform === false && <div className="text-xs font-normal text-slate-500">{(s as Row).account!.owner_email}</div>}
                      </td>
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
              <div className="mt-3 space-y-3">
                {modes.length > 1 && (
                  <div className="flex gap-5 text-sm">
                    {modes.map((m) => (
                      <label key={m} className="flex items-center gap-2">
                        <input type="radio" name="mass-mode" checked={curMode === m} onChange={() => setMode(m)} /> {m === 'add' ? 'Add' : 'Delete'}
                      </label>
                    ))}
                  </div>
                )}
                <div>
                  <label className="mb-1 block text-sm font-medium">Enter the IPs one per line</label>
                  <textarea
                    className="input min-h-[150px] font-mono text-xs"
                    placeholder={'203.0.113.10\n198.51.100.0/24\n2001:db8::1'}
                    value={addrs}
                    onChange={(e) => setAddrs(e.target.value)}
                  />
                  <p className="mt-1 text-xs text-slate-500">
                    {lines.length} address{lines.length === 1 ? '' : 'es'} · IPv4, IPv6 or CIDR · up to 1000 · lines starting with # are skipped
                  </p>
                </div>
                {curMode === 'add' && <input className="input" placeholder="Reason (optional)" maxLength={200} value={reason} onChange={(e) => setReason(e.target.value)} />}
              </div>
            )}
            <button className="btn-primary mt-4 w-full" disabled={busy || !chosen || sel.length === 0 || (chosen.needs_addr && lines.length === 0)} onClick={start}>
              <Play className="h-4 w-4" /> {busy ? 'Running…' : `Run on ${sel.length} server${sel.length === 1 ? '' : 's'}`}
            </button>
          </Card>

          {result && (
            <Card title={`3. Results: ${result.ok} of ${result.total} succeeded`}>
              <ul className="divide-y divide-slate-100 text-sm">
                {result.results.map((r) => (
                  <li key={r.server_id} className="flex items-start gap-2 py-2">
                    {r.ok ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-green-600" /> : <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-600" />}
                    <div className="min-w-0">
                      <span className="font-medium">{r.hostname}</span>
                      {r.data?.total !== undefined && (
                        <span className="ml-2 text-slate-500">
                          {r.data.done} of {r.data.total} addresses
                        </span>
                      )}
                      {!r.ok && <span className="ml-2 text-red-600">{r.error}</span>}
                      {r.data?.failed && r.data.failed.length > 0 && (
                        <ul className="mt-1 space-y-0.5 font-mono text-xs text-red-600">
                          {r.data.failed.slice(0, 20).map((f) => (
                            <li key={f.addr}>
                              {f.addr}: {f.error}
                            </li>
                          ))}
                          {r.data.failed.length > 20 && <li>… {r.data.failed.length - 20} more</li>}
                        </ul>
                      )}
                    </div>
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
