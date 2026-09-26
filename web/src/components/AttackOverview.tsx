import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import {
  AlertTriangle, BookOpen, ChevronDown, Clock, Database, Globe, LineChart, Lock, Settings2, ShieldCheck, TrendingDown, TrendingUp,
} from 'lucide-react';
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
interface Alert {
  level: 'danger' | 'warning' | 'info';
  text: string;
  link: string;
  details: string[] | null;
}
export interface Dash {
  days: number;
  threats: Period;
  web_attacks: Period;
  blocked_connections: Period;
  attacks_daily: DayPoint[];
  web_daily: DayPoint[];
  infections_daily: Partial<Record<'virus' | 'suspicious' | 'binary' | 'symlink', DayPoint[]>>;
  summary: { outdated_cms: number; cms_issues: number; ips_blacklisted: number; domains_blacklisted: number; db_infections: number };
  alerts: Alert[];
  services?: Service[];
}
interface Service {
  name: string;
  ok: boolean;
  off: boolean;
  problem: string;
  link: string;
}

/** One chip per protection: green running, red stopped, grey switched off. */
function ServiceStrip({ services }: { services: Service[] }) {
  return (
    <div className="card flex flex-wrap items-center gap-2 px-5 py-3">
      <span className="mr-2 text-sm font-semibold text-navy-900">Protection status</span>
      {services.map((sv) => {
        const tone = sv.off ? 'bg-slate-100 text-slate-500' : sv.ok ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-700';
        const dot = sv.off ? 'bg-slate-400' : sv.ok ? 'bg-green-500' : 'bg-red-500 animate-pulse';
        const label = sv.off ? 'Off' : sv.ok ? 'Running' : 'Not running';
        return (
          <Link key={sv.name} to={sv.off ? 'settings' : sv.link} title={sv.problem || label} className={`flex items-center gap-2 rounded-full px-3 py-1.5 text-sm hover:opacity-80 ${tone}`}>
            <span className={`h-2 w-2 rounded-full ${dot}`} />
            {sv.name}
            <span className="text-xs opacity-75">· {label}</span>
          </Link>
        );
      })}
    </div>
  );
}

export function compact(n: number): string {
  if (n >= 1e9) return (n / 1e9).toFixed(1).replace(/\.0$/, '') + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'K';
  return String(n);
}

function change(cur: number, prev: number): { pct: number; up: boolean } {
  if (prev === 0) return { pct: cur > 0 ? 100 : 0, up: cur > 0 };
  const d = ((cur - prev) / prev) * 100;
  return { pct: Math.round(Math.abs(d)), up: d >= 0 };
}

/** KPI card: big number with change, overall on the right, a faded icon behind. */
function Metric({ icon, p, label }: { icon: React.ReactNode; p: Period; label: string }) {
  const c = change(p.current, p.previous);
  return (
    <div className="card relative overflow-hidden px-6 py-5">
      <div className="pointer-events-none absolute top-1/2 -left-5 -translate-y-1/2 text-slate-100 [&>svg]:h-28 [&>svg]:w-28 [&>svg]:stroke-[1.5]">{icon}</div>
      <div className="relative flex items-center justify-between gap-3 pl-10">
        <div>
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-semibold text-navy-900">{compact(p.current)}</span>
            <span className={`flex items-center text-sm ${c.up ? 'text-green-500' : 'text-slate-400'}`}>
              {c.pct}% {c.up ? <TrendingUp className="ml-0.5 h-3.5 w-3.5" /> : <TrendingDown className="ml-0.5 h-3.5 w-3.5" />}
            </span>
          </div>
          <div className="mt-1 text-slate-500">{label}</div>
        </div>
        <div className="text-right">
          <div className="flex items-center justify-end gap-1 font-semibold text-navy-900">
            <LineChart className="h-4 w-4" /> {compact(p.overall)}
          </div>
          <div className="text-sm text-slate-400">Overall</div>
        </div>
      </div>
    </div>
  );
}

function ChangeNote({ cur, prev, text }: { cur: number; prev: number; text: string }) {
  const c = change(cur, prev);
  return (
    <div className="flex items-start gap-3 text-slate-500">
      <span className={`mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${c.up ? 'bg-red-50 text-red-400' : 'bg-green-50 text-green-500'}`}>
        {c.up ? <TrendingUp className="h-4 w-4" /> : <TrendingDown className="h-4 w-4" />}
      </span>
      <span>
        There is a {c.pct}% {c.up ? 'increase' : 'decrease'}
        {text}
      </span>
    </div>
  );
}

/** Horizontal current/previous bars with numbers, like the cPGuard overview. */
function CompareBars({ rows, max }: { rows: { name: string; current: number; previous: number }[]; max: number }) {
  return (
    <div className="space-y-6">
      {rows.map((r) => (
        <div key={r.name} className="grid grid-cols-[110px_minmax(0,1fr)_64px] items-center gap-3">
          <div className="text-sm leading-snug text-slate-500">{r.name}</div>
          <div className="space-y-2 border-l border-slate-200 pl-1">
            <div className="h-3 rounded-full bg-navy-900" style={{ width: `${Math.max(1.5, (r.current / max) * 100)}%` }} title={r.current.toLocaleString()} />
            <div className="h-1.5 rounded-full bg-blue-300" style={{ width: `${Math.max(0.5, (r.previous / max) * 100)}%` }} title={r.previous.toLocaleString()} />
          </div>
          <div className="text-right text-sm">
            <div className="font-semibold text-navy-900">{compact(r.current)}</div>
            <div className="text-blue-400">{compact(r.previous)}</div>
          </div>
        </div>
      ))}
      <div className="flex justify-center gap-5 text-sm text-slate-600">
        <span className="flex items-center gap-1.5"><span className="h-3.5 w-3.5 bg-navy-900" /> Current</span>
        <span className="flex items-center gap-1.5"><span className="h-3.5 w-3.5 bg-blue-300" /> Previous</span>
      </div>
    </div>
  );
}

function AlertItem({ a }: { a: Alert }) {
  const [open, setOpen] = useState(false);
  const tone = a.level === 'danger' ? 'bg-blue-50 text-navy-900' : a.level === 'warning' ? 'bg-amber-50 text-amber-900' : 'bg-slate-50 text-slate-700';
  return (
    <div className={`rounded-xl ${tone}`}>
      <button className="flex w-full items-center gap-3 px-4 py-3.5 text-left text-sm" onClick={() => setOpen(!open)}>
        {a.level === 'danger' ? <ShieldCheck className="h-5 w-5 shrink-0" /> : <AlertTriangle className="h-5 w-5 shrink-0" />}
        <span className="flex-1">{a.text}</span>
        <ChevronDown className={`h-4 w-4 transition ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="space-y-1 border-t border-white/60 px-4 pt-2 pb-3 text-sm">
          {(a.details ?? []).map((d) => (
            <div key={d} className="break-all text-slate-600">{d}</div>
          ))}
          <Link to={a.link} className="inline-block pt-1 font-medium text-blue-700 hover:underline">
            Open →
          </Link>
        </div>
      )}
    </div>
  );
}

const shortDay = (d: string) => d.slice(8);
const tick = { fontSize: 11, fill: '#64748b' };

/** cPGuard-style security overview for one server. */
export default function AttackOverview({ serverId, online, days }: { serverId: string; online: boolean; days: number }) {
  const { data, error } = useAgent<Dash>(online ? serverId : undefined, 'dashboard.get', { days }, 60_000);
  const [allAlerts, setAllAlerts] = useState(false);
  if (!online) return <div className="card p-6 text-sm text-slate-500">The server is offline; the security overview appears when the agent reconnects.</div>;
  if (error && !data) return <div className="card p-4 text-sm text-slate-500">Security overview unavailable: {error}</div>;
  if (!data) return <div className="card p-6 text-sm text-slate-400">Loading security overview…</div>;

  const total = data.threats.current + data.web_attacks.current + data.blocked_connections.current;
  const prevTotal = data.threats.previous + data.web_attacks.previous + data.blocked_connections.previous;
  const donut = prevTotal > 0 ? [
    { name: 'current', value: total, fill: '#4ade80' },
    { name: 'previous', value: prevTotal, fill: '#64748b' },
  ] : [{ name: 'current', value: 1, fill: total > 0 ? '#4ade80' : '#e2e8f0' }];
  const bars = [
    { name: 'Threats Stopped', current: data.threats.current, previous: data.threats.previous },
    { name: 'Web Attacks Blocked', current: data.web_attacks.current, previous: data.web_attacks.previous },
    { name: 'Blocked Connections', current: data.blocked_connections.current, previous: data.blocked_connections.previous },
  ];
  const max = Math.max(1, ...bars.flatMap((b) => [b.current, b.previous]));
  const attacks = data.attacks_daily.map((p) => ({ day: shortDay(p.day), n: p.n }));
  const inf = data.infections_daily;
  const infections = (inf.virus ?? []).map((p, i) => ({
    day: shortDay(p.day),
    Suspicious: inf.suspicious?.[i]?.n ?? 0,
    Virus: p.n,
    Binary: inf.binary?.[i]?.n ?? 0,
    Symbolic: inf.symlink?.[i]?.n ?? 0,
  }));
  const web = data.web_daily.map((p) => ({ day: shortDay(p.day), n: p.n }));
  const s = data.summary;
  const summary = [
    { icon: <BookOpen className="h-5 w-5" />, l: 'Outdated CMS', v: s.outdated_cms, to: 'cms' },
    { icon: <Globe className="h-5 w-5" />, l: 'CMS Issues', v: s.cms_issues, to: 'cms' },
    { icon: <AlertTriangle className="h-5 w-5" />, l: 'IPs Blacklisted', v: s.ips_blacklisted, to: 'ip-reputation' },
    { icon: <Globe className="h-5 w-5" />, l: 'Domains Blacklisted', v: s.domains_blacklisted, to: 'domain-reputation' },
    { icon: <Database className="h-5 w-5" />, l: 'Database Infections', v: s.db_infections, to: 'db-scanner' },
  ];
  const period = `previous ${days} days`;
  const shownAlerts = allAlerts ? data.alerts : data.alerts.slice(0, 5);

  return (
    <div className="space-y-5">
      {data.services && data.services.length > 0 && <ServiceStrip services={data.services} />}
      <div className="grid gap-4 md:grid-cols-3">
        <Metric icon={<Settings2 />} p={data.threats} label="Threats Stopped" />
        <Metric icon={<Lock />} p={data.web_attacks} label="Web Attacks Blocked" />
        <Metric icon={<Clock />} p={data.blocked_connections} label="Blocked Connections" />
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="card p-7">
          <h2 className="mb-5 text-lg font-semibold text-navy-900">Attacks Overview</h2>
          <div className="grid items-center gap-8 md:grid-cols-[230px_minmax(0,1fr)]">
            <div className="space-y-4">
              <div className="relative mx-auto h-52 w-52">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={donut} dataKey="value" innerRadius={70} outerRadius={100} startAngle={90} endAngle={-270} stroke="none" isAnimationActive={false}>
                      {donut.map((d) => (
                        <Cell key={d.name} fill={d.fill} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex items-center justify-center text-xl font-semibold text-navy-900">{compact(total)}</div>
              </div>
              <div className="space-y-1.5 text-sm">
                <div className="flex justify-between">
                  <span className="flex items-center gap-2 text-slate-600"><span className="h-4 w-4 bg-green-400" /> {days} days</span>
                  <b className="text-navy-900">{compact(total)}</b>
                </div>
                <div className="flex justify-between">
                  <span className="flex items-center gap-2 text-slate-600"><span className="h-4 w-4 bg-slate-500" /> Previous {days} days</span>
                  <b className="text-navy-900">{compact(prevTotal)}</b>
                </div>
              </div>
              <ChangeNote cur={total} prev={prevTotal} text="" />
            </div>
            <CompareBars rows={bars} max={max} />
          </div>
        </div>
        <div className="card flex flex-col p-6">
          <h2 className="mb-3 text-lg font-semibold text-navy-900">Alerts</h2>
          {data.alerts.length === 0 ? (
            <div className="flex items-center gap-2 rounded-xl bg-green-50 p-3.5 text-sm text-green-800">
              <ShieldCheck className="h-5 w-5" /> No active alerts
            </div>
          ) : (
            <div className="space-y-2">
              {shownAlerts.map((a) => (
                <AlertItem key={a.text} a={a} />
              ))}
            </div>
          )}
          {data.alerts.length > 5 && (
            <button className="mt-auto self-end pt-4 text-sm text-navy-800 hover:underline" onClick={() => setAllAlerts(!allAlerts)}>
              {allAlerts ? 'Show less' : 'View All'}
            </button>
          )}
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <div className="card p-6">
          <h2 className="mb-4 text-lg font-semibold text-navy-900">Attacks Blocked - {days} days</h2>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={attacks}>
                <CartesianGrid vertical={false} stroke="#f1f5f9" />
                <XAxis dataKey="day" tick={tick} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} interval="preserveStartEnd" minTickGap={18} />
                <YAxis tick={tick} width={52} tickFormatter={compact} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip formatter={(v) => Number(v).toLocaleString()} cursor={{ fill: '#f1f5f9' }} />
                <Bar dataKey="n" name="Blocked connections" fill="#1e2a5a" isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="card p-6">
          <h2 className="mb-2 text-lg font-semibold text-navy-900">Virus Infections</h2>
          <div className="mb-2 flex flex-wrap justify-center gap-4 text-sm text-slate-600">
            {[['Suspicious', '#1e2a5a'], ['Virus', '#64748b'], ['Binary', '#bfdbfe'], ['Symbolic', '#818cf8']].map(([l, c]) => (
              <span key={l} className="flex items-center gap-1.5"><span className="h-3.5 w-3.5" style={{ background: c }} /> {l}</span>
            ))}
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={infections}>
                <CartesianGrid vertical={false} stroke="#f1f5f9" />
                <XAxis dataKey="day" tick={tick} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} interval="preserveStartEnd" minTickGap={18} />
                <YAxis tick={tick} width={44} tickFormatter={compact} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip cursor={{ fill: '#f1f5f9' }} />
                <Bar dataKey="Suspicious" stackId="a" fill="#1e2a5a" isAnimationActive={false} />
                <Bar dataKey="Virus" stackId="a" fill="#64748b" isAnimationActive={false} />
                <Bar dataKey="Binary" stackId="a" fill="#bfdbfe" isAnimationActive={false} />
                <Bar dataKey="Symbolic" stackId="a" fill="#818cf8" isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="card p-6">
          <h2 className="mb-4 text-lg font-semibold text-navy-900">Web Attacks</h2>
          <div className="grid items-center gap-6 md:grid-cols-[220px_minmax(0,1fr)]">
            <div className="space-y-6">
              <div>
                <div className="text-6xl font-bold text-green-400">{compact(data.web_attacks.current)}</div>
                <div className="mt-2 text-slate-500">Total attacks blocked</div>
              </div>
              <ChangeNote cur={data.web_attacks.current} prev={data.web_attacks.previous} text={` in comparison with the ${period}`} />
            </div>
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={web}>
                  <defs>
                    <linearGradient id="webFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#1e2a5a" stopOpacity={0.9} />
                      <stop offset="100%" stopColor="#1e2a5a" stopOpacity={0.35} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="day" tick={tick} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} interval="preserveStartEnd" minTickGap={18} />
                  <YAxis tick={tick} width={48} tickFormatter={compact} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip formatter={(v) => Number(v).toLocaleString()} />
                  <Area type="linear" dataKey="n" name="Web attacks" stroke="#1e2a5a" fill="url(#webFill)" isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
        <div className="card overflow-hidden p-0">
          <h2 className="px-6 pt-6 pb-3 text-lg font-semibold text-navy-900">Summary</h2>
          <ul>
            {summary.map((x, i) => (
              <li key={x.l} className={i % 2 === 0 ? 'bg-slate-50' : ''}>
                <Link to={x.to} className="flex items-center justify-between px-8 py-5 hover:bg-blue-50/60">
                  <span className="flex items-center gap-4 text-navy-900">
                    {x.icon}
                    {x.l}
                  </span>
                  <span className={`text-2xl font-semibold ${x.v > 0 ? 'text-red-600' : 'text-navy-900'}`}>{compact(x.v)}</span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
