import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { AlertTriangle, Bug, Database, Globe, Info, LayoutTemplate, ShieldBan, ShieldCheck, TrendingDown, TrendingUp, Wifi } from 'lucide-react';
import { useAgent } from './controls';

interface Period {
  current: number;
  previous: number;
  overall: number;
}
interface DayPoint {
  day: string;
  n: number;
}
interface Dash {
  days: number;
  threats: Period;
  web_attacks: Period;
  blocked_connections: Period;
  attacks_daily: DayPoint[];
  web_daily: DayPoint[];
  infections_daily: Record<'virus' | 'suspicious' | 'binary', DayPoint[]>;
  summary: { outdated_cms: number; cms_issues: number; ips_blacklisted: number; domains_blacklisted: number; db_infections: number };
  alerts: { level: 'danger' | 'warning' | 'info'; text: string; link: string }[];
}

export function compact(n: number): string {
  if (n >= 1e9) return (n / 1e9).toFixed(1).replace(/\.0$/, '') + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'K';
  return String(n);
}

function change(p: Period): { pct: number; up: boolean } {
  if (p.previous === 0) return { pct: p.current > 0 ? 100 : 0, up: p.current > 0 };
  const d = ((p.current - p.previous) / p.previous) * 100;
  return { pct: Math.round(Math.abs(d)), up: d >= 0 };
}

function Metric({ icon, p, label }: { icon: React.ReactNode; p: Period; label: string }) {
  const c = change(p);
  return (
    <div className="card relative overflow-hidden p-5">
      <div className="absolute -top-2 -left-2 text-slate-100 [&>svg]:h-24 [&>svg]:w-24">{icon}</div>
      <div className="relative flex items-start justify-between">
        <div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-semibold text-navy-900">{compact(p.current)}</span>
            <span className={`flex items-center text-xs ${c.up ? 'text-green-600' : 'text-slate-500'}`}>
              {c.pct}% {c.up ? <TrendingUp className="ml-0.5 h-3 w-3" /> : <TrendingDown className="ml-0.5 h-3 w-3" />}
            </span>
          </div>
          <div className="text-sm text-slate-500">{label}</div>
        </div>
        <div className="text-right">
          <div className="text-sm font-semibold text-navy-900">{compact(p.overall)}</div>
          <div className="text-xs text-slate-400">Overall</div>
        </div>
      </div>
    </div>
  );
}

const ALERT_STYLE = {
  danger: 'bg-red-50 text-red-800',
  warning: 'bg-amber-50 text-amber-800',
  info: 'bg-blue-50 text-blue-800',
};

const shortDay = (d: string) => d.slice(8);

/** cPGuard-style security overview for one server. */
export default function AttackOverview({ serverId, online }: { serverId: string; online: boolean }) {
  const [days, setDays] = useState(30);
  const { data, error } = useAgent<Dash>(online ? serverId : undefined, 'dashboard.get', { days }, 60_000);
  if (!online) return null;
  if (error && !data) return <div className="card p-4 text-sm text-slate-500">Security overview unavailable: {error}</div>;
  if (!data) return <div className="card p-6 text-sm text-slate-400">Loading security overview…</div>;

  const total = data.threats.current + data.web_attacks.current + data.blocked_connections.current;
  const prevTotal = data.threats.previous + data.web_attacks.previous + data.blocked_connections.previous;
  const donut = [
    { name: `${days} days`, value: total || 1, fill: '#4ade80' },
    { name: `Previous ${days} days`, value: prevTotal, fill: '#64748b' },
  ];
  const bars = [
    { name: 'Threats Stopped', current: data.threats.current, previous: data.threats.previous },
    { name: 'Web Attacks Blocked', current: data.web_attacks.current, previous: data.web_attacks.previous },
    { name: 'Blocked Connections', current: data.blocked_connections.current, previous: data.blocked_connections.previous },
  ];
  const attacks = data.attacks_daily.map((p, i) => ({ day: shortDay(p.day), n: p.n + (data.web_daily[i]?.n ?? 0) }));
  const infections = data.infections_daily.virus.map((p, i) => ({
    day: shortDay(p.day),
    Virus: p.n,
    Suspicious: data.infections_daily.suspicious[i]?.n ?? 0,
    Binary: data.infections_daily.binary[i]?.n ?? 0,
  }));
  const web = data.web_daily.map((p) => ({ day: shortDay(p.day), n: p.n }));
  const s = data.summary;
  const summary = [
    { icon: <LayoutTemplate className="h-4 w-4" />, l: 'Outdated CMS', v: s.outdated_cms, to: 'cms' },
    { icon: <Globe className="h-4 w-4" />, l: 'CMS Issues', v: s.cms_issues, to: 'cms' },
    { icon: <AlertTriangle className="h-4 w-4" />, l: 'IPs Blacklisted', v: s.ips_blacklisted, to: 'ip-reputation' },
    { icon: <Globe className="h-4 w-4" />, l: 'Domains Blacklisted', v: s.domains_blacklisted, to: 'domain-reputation' },
    { icon: <Database className="h-4 w-4" />, l: 'Database Infections', v: s.db_infections, to: 'db-scanner' },
  ];
  const webChange = change(data.web_attacks);

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-end gap-2 text-sm text-slate-500">
        View
        <select className="input w-32" value={days} onChange={(e) => setDays(Number(e.target.value))}>
          <option value={7}>7 Days</option>
          <option value={30}>30 Days</option>
          <option value={90}>90 Days</option>
        </select>
      </div>
      <div className="grid gap-4 md:grid-cols-3">
        <Metric icon={<Bug />} p={data.threats} label="Threats Stopped" />
        <Metric icon={<ShieldBan />} p={data.web_attacks} label="Web Attacks Blocked" />
        <Metric icon={<Wifi />} p={data.blocked_connections} label="Blocked Connections" />
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="card p-6">
          <h2 className="mb-2 text-lg font-semibold text-navy-900">Attacks Overview</h2>
          <div className="grid items-center gap-6 md:grid-cols-[220px_1fr]">
            <div>
              <div className="relative h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={donut} dataKey="value" innerRadius={60} outerRadius={80} startAngle={90} endAngle={-270} isAnimationActive={false}>
                      {donut.map((d) => (
                        <Cell key={d.name} fill={d.fill} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex items-center justify-center text-xl font-semibold text-navy-900">{compact(total)}</div>
              </div>
              <div className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <span className="flex items-center gap-2">
                    <span className="h-3 w-3 rounded-sm bg-green-400" /> {days} days
                  </span>
                  <b>{compact(total)}</b>
                </div>
                <div className="flex justify-between">
                  <span className="flex items-center gap-2">
                    <span className="h-3 w-3 rounded-sm bg-slate-500" /> Previous {days} days
                  </span>
                  <b>{compact(prevTotal)}</b>
                </div>
              </div>
            </div>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={bars} layout="vertical" margin={{ left: 20 }}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="name" width={130} fontSize={12} />
                  <Tooltip formatter={(v) => Number(v).toLocaleString()} />
                  <Legend />
                  <Bar dataKey="current" name="Current" fill="#1e2a5a" radius={[0, 4, 4, 0]} isAnimationActive={false} />
                  <Bar dataKey="previous" name="Previous" fill="#93c5fd" radius={[0, 4, 4, 0]} isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
        <div className="card p-6">
          <h2 className="mb-3 text-lg font-semibold text-navy-900">Alerts</h2>
          {data.alerts.length === 0 ? (
            <div className="flex items-center gap-2 rounded-lg bg-green-50 p-3 text-sm text-green-800">
              <ShieldCheck className="h-5 w-5" /> No active alerts
            </div>
          ) : (
            <div className="space-y-2">
              {data.alerts.map((a) => (
                <Link key={a.text} to={a.link} className={`flex items-center gap-2 rounded-lg p-3 text-sm hover:opacity-80 ${ALERT_STYLE[a.level]}`}>
                  {a.level === 'info' ? <Info className="h-4 w-4 shrink-0" /> : <AlertTriangle className="h-4 w-4 shrink-0" />}
                  {a.text}
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <div className="card p-6">
          <h2 className="mb-3 text-lg font-semibold text-navy-900">Attacks Blocked - {days} days</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={attacks}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="day" fontSize={11} />
                <YAxis fontSize={11} width={50} tickFormatter={compact} />
                <Tooltip formatter={(v) => Number(v).toLocaleString()} />
                <Bar dataKey="n" name="Attacks blocked" fill="#1e2a5a" isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="card p-6">
          <h2 className="mb-3 text-lg font-semibold text-navy-900">Virus Infections</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={infections}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="day" fontSize={11} />
                <YAxis fontSize={11} width={40} allowDecimals={false} />
                <Tooltip />
                <Legend />
                <Bar dataKey="Suspicious" stackId="a" fill="#1e2a5a" isAnimationActive={false} />
                <Bar dataKey="Virus" stackId="a" fill="#64748b" isAnimationActive={false} />
                <Bar dataKey="Binary" stackId="a" fill="#93c5fd" isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="card p-6">
          <h2 className="mb-3 text-lg font-semibold text-navy-900">Web Attacks</h2>
          <div className="grid items-center gap-4 md:grid-cols-[200px_1fr]">
            <div>
              <div className="text-5xl font-bold text-green-500">{compact(data.web_attacks.current)}</div>
              <div className="mt-1 text-slate-500">Total attacks blocked</div>
              <div className="mt-6 text-sm text-slate-500">
                There is a {webChange.pct}% {webChange.up ? 'increase' : 'decrease'} in comparison with the previous {days} days
              </div>
            </div>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={web}>
                  <XAxis dataKey="day" fontSize={11} />
                  <YAxis fontSize={11} width={40} tickFormatter={compact} />
                  <Tooltip />
                  <Area type="monotone" dataKey="n" name="Web attacks" stroke="#1e2a5a" fill="#1e2a5a88" isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
        <div className="card p-6">
          <h2 className="mb-2 text-lg font-semibold text-navy-900">Summary</h2>
          <ul className="divide-y divide-slate-100">
            {summary.map((x) => (
              <li key={x.l}>
                <Link to={x.to} className="flex items-center justify-between py-3 hover:text-blue-700">
                  <span className="flex items-center gap-3 text-sm text-slate-700">
                    {x.icon}
                    {x.l}
                  </span>
                  <span className={`text-xl font-semibold ${x.v > 0 ? 'text-red-600' : 'text-navy-900'}`}>{compact(x.v)}</span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
