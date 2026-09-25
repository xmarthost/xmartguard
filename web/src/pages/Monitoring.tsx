import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Clock, Cpu, Info, MemoryStick, Monitor, Radio, Settings2 } from 'lucide-react';
import { api, type MetricPoint, type Server } from '../api';
import { useApi } from '../hooks';
import { bytes, duration, loadLevel, pct } from '../format';
import { Bar, Breadcrumb, Empty, ErrorBox, PageLoader } from '../components/ui';

const RANGES = [
  { v: '1h', l: 'Last hour' },
  { v: '4h', l: 'Last 4 Hours' },
  { v: '24h', l: 'Last 24 Hours' },
  { v: '7d', l: 'Last 7 Days' },
  { v: '30d', l: 'Last 30 Days' },
];

function Chart({ title, data, dataKey, color, unit = '', domain }: {
  title: string;
  data: MetricPoint[];
  dataKey: keyof MetricPoint;
  color: string;
  unit?: string;
  domain?: [number, number | 'auto'];
}) {
  const fmt = (t: number) => {
    const d = new Date(t * 1000);
    return data.length && data[data.length - 1].t - data[0].t > 86400
      ? `${d.getDate()}/${d.getMonth() + 1}`
      : `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  };
  return (
    <div className="card p-5">
      <h3 className="mb-3 font-semibold text-navy-900">{title}</h3>
      {data.length === 0 ? (
        <Empty text="Collecting data…" />
      ) : (
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ left: -10, right: 10, top: 5 }}>
              <defs>
                <linearGradient id={`g-${String(dataKey)}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={color} stopOpacity={0.35} />
                  <stop offset="100%" stopColor={color} stopOpacity={0.05} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#eef0f5" vertical={false} />
              <XAxis dataKey="t" tickFormatter={fmt} tick={{ fontSize: 11, fill: '#64748b' }} minTickGap={30} />
              <YAxis tick={{ fontSize: 11, fill: '#64748b' }} domain={domain ?? [0, 'auto']} />
              <Tooltip labelFormatter={(t) => new Date(Number(t) * 1000).toLocaleString()} formatter={(v) => [`${v}${unit}`, title]} />
              <Area type="monotone" dataKey={dataKey} stroke={color} strokeWidth={2} fill={`url(#g-${String(dataKey)})`} dot={false} isAnimationActive={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}

export default function Monitoring() {
  const { id } = useParams();
  const [range, setRange] = useState('4h');
  const [live, setLive] = useState(false);
  const [liveError, setLiveError] = useState('');
  const srv = useApi<{ server: Server }>(`/api/servers/${id}`, live ? 5000 : 30_000);
  const hist = useApi<{ points: MetricPoint[] }>(`/api/servers/${id}/metrics?range=${range}`, 60_000);

  // Live mode asks the agent for 5-second samples; renew every 100s.
  useEffect(() => {
    if (!live) return;
    const on = () =>
      api('POST', `/api/servers/${id}/live`, {}).then(
        () => setLiveError(''),
        (e) => setLiveError(e.message),
      );
    on();
    const t = setInterval(on, 100_000);
    return () => clearInterval(t);
  }, [live, id]);

  if (srv.loading && !srv.data) return <PageLoader />;
  if (srv.error && !srv.data) return <ErrorBox message={srv.error} />;
  const s = srv.data!.server;
  const m = s.last_metrics;
  const inv = s.inventory;
  const points = hist.data?.points ?? [];

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <Breadcrumb items={[s.hostname, 'System Monitoring']} />
          <h1 className="h-title">System Monitoring</h1>
        </div>
        <div className="flex items-center gap-2">
          <select className="input w-44" value={range} onChange={(e) => setRange(e.target.value)}>
            {RANGES.map((r) => <option key={r.v} value={r.v}>{r.l}</option>)}
          </select>
          <button className={`btn border ${live ? 'border-green-500 text-green-700' : 'border-slate-300 text-slate-600'}`} onClick={() => setLive((l) => !l)}>
            <Radio className="h-4 w-4" /> Live
            <span className={`h-2 w-2 rounded-full ${live ? 'animate-pulse bg-green-500' : 'bg-slate-300'}`} />
          </button>
        </div>
      </div>
      {liveError && <ErrorBox message={`Live mode: ${liveError}`} />}

      <div className="grid gap-5 lg:grid-cols-3">
        <div className="card p-5">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-2">
              <Cpu className="h-5 w-5 text-navy-700" />
              <div>
                <div className="font-semibold text-navy-900">Processor</div>
                <div className="text-xs text-slate-500">{inv.cpu_model}</div>
              </div>
            </div>
            <div className="text-right">
              <div className="text-2xl font-semibold text-blue-500">{inv.cpu_cores}</div>
              <div className="text-xs text-slate-500">Cores</div>
            </div>
          </div>
          <div className="mt-4 mb-2 text-sm font-medium text-navy-900">Load Average</div>
          <div className="grid grid-cols-3 gap-2">
            {(['1m', '5m', '15m'] as const).map((k, i) => {
              const v = m ? [m.load1, m.load5, m.load15][i] : 0;
              const lvl = loadLevel(v, inv.cpu_cores);
              return (
                <div key={k} className={`rounded-lg border-l-4 p-3 ${lvl.cls}`}>
                  <div className="text-xs">{k}</div>
                  <div className="text-2xl font-semibold">{v.toFixed(2)}</div>
                  <div className="text-xs">{lvl.label}</div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="card p-5">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-2">
              <MemoryStick className="h-5 w-5 text-navy-700" />
              <div>
                <div className="font-semibold text-navy-900">Memory</div>
                <div className="text-xs text-slate-500">{bytes(m?.mem_total)} Total</div>
              </div>
            </div>
            <div className="text-right">
              <div className="text-2xl font-semibold text-green-600">{pct(m?.mem_used, m?.mem_total)}%</div>
              <div className="text-xs text-slate-500">{bytes(m?.mem_used)} Used</div>
            </div>
          </div>
          <div className="mt-5 mb-1 text-sm text-navy-900">Memory Usage</div>
          <Bar value={pct(m?.mem_used, m?.mem_total)} />
          <div className="mt-4 mb-1 text-sm text-navy-900">Swap Memory Usage</div>
          <Bar value={pct(m?.swap_used, m?.swap_total)} />
          <div className="mt-2 flex justify-between text-xs text-slate-500">
            <span>Used {bytes(m?.swap_used)} / {bytes(m?.swap_total)}</span>
            <span>Available {bytes((m?.swap_total ?? 0) - (m?.swap_used ?? 0))}</span>
          </div>
        </div>

        <div className="card p-5">
          <div className="mb-3 flex items-center gap-2 font-semibold text-navy-900">
            <Info className="h-5 w-5 text-green-600" /> System Info
          </div>
          {[
            [<Monitor key="i" className="h-4 w-4" />, 'OS', `${inv.os_name} ${inv.os_version}`],
            [<Cpu key="i" className="h-4 w-4" />, 'Architecture', inv.arch],
            [<Settings2 key="i" className="h-4 w-4" />, 'Kernel', inv.kernel],
            [<Clock key="i" className="h-4 w-4" />, 'Uptime', duration(m?.uptime_seconds)],
          ].map(([icon, k, v], i) => (
            <div key={i} className="mb-2 flex items-center justify-between gap-2 rounded-lg bg-slate-50 px-3 py-2 text-sm">
              <span className="flex items-center gap-2 text-slate-600">{icon} {k}</span>
              <span className={`text-right font-medium ${k === 'Uptime' ? 'text-green-600' : 'text-navy-900'}`}>{v}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="card overflow-x-auto p-5">
        <h3 className="mb-3 font-semibold text-navy-900">Top Processes</h3>
        {m?.top_processes?.length ? (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left text-slate-500">
                <th className="py-2 font-medium">Process</th>
                <th className="py-2 font-medium">PID</th>
                <th className="py-2 font-medium">User</th>
                <th className="py-2 font-medium">CPU Usage</th>
                <th className="py-2 font-medium">Memory Usage</th>
                <th className="py-2 font-medium">Time</th>
              </tr>
            </thead>
            <tbody>
              {m.top_processes.map((p) => (
                <tr key={p.pid} className="border-b border-slate-100 last:border-0">
                  <td className="py-2 font-medium text-navy-900">{p.name}</td>
                  <td className="py-2 text-slate-500">{p.pid}</td>
                  <td className="py-2 text-purple-600">{p.user}</td>
                  <td className="py-2 text-orange-600">{p.cpu_percent}%</td>
                  <td className="py-2 text-blue-600">{bytes(p.mem_bytes)}</td>
                  <td className="py-2">{duration(p.run_seconds)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty text="No process data yet" />
        )}
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Chart title="CPU Usage" data={points} dataKey="cpu" color="#ec4899" unit="%" domain={[0, 100]} />
        <Chart title="Load Average" data={points} dataKey="load1" color="#eab308" />
        <Chart title="Memory Usage" data={points} dataKey="mem_pct" color="#ef4444" unit="%" domain={[0, 100]} />
        <Chart title="Disk Usage" data={points} dataKey="disk_pct" color="#22c55e" unit="%" domain={[0, 100]} />
        <Chart title="Live Connections" data={points} dataKey="connections" color="#6366f1" />
      </div>
    </div>
  );
}
