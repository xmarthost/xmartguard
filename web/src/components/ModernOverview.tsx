import { useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import {
  AlertTriangle, BarChart3, BookOpen, CalendarDays, ChevronDown, ChevronRight, Database, Globe, Info, LineChart, ShieldAlert, ShieldCheck, TrendingDown, TrendingUp, Waypoints,
} from 'lucide-react';
import { useAgent } from './controls';
import { PageLoader } from './ui';
import { ServiceStrip, change, compact, type Alert, type Dash } from './AttackOverview';
import { IconTile, Sparkline, TONES, type Tone } from './ModernBits';

const tick = { fontSize: 11, fill: '#94a3b8' };
const shortDay = (d: string) => d.slice(8);

function Trend({ cur, prev }: { cur: number; prev: number }) {
  const c = change(cur, prev);
  return (
    <span className={`flex items-center text-sm font-medium ${c.up ? 'text-green-600' : 'text-slate-400'}`}>
      {c.pct}% {c.up ? <TrendingUp className="ml-0.5 h-3.5 w-3.5" /> : <TrendingDown className="ml-0.5 h-3.5 w-3.5" />}
    </span>
  );
}

function Kpi({ tone, icon, p, label, series }: { tone: Tone; icon: ReactNode; p: Dash['threats']; label: string; series: number[] }) {
  return (
    <div className="card overflow-hidden p-5 pb-3">
      <div className="flex items-start gap-4">
        <IconTile tone={tone} size="lg">
          {icon}
        </IconTile>
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-2">
            <span className="text-[28px] leading-none font-bold text-slate-900">{compact(p.current)}</span>
            <Trend cur={p.current} prev={p.previous} />
          </div>
          <div className="mt-1.5 text-sm leading-tight text-slate-500">{label}</div>
        </div>
        <div className="text-right">
          <div className="flex items-center justify-end gap-1 text-sm font-semibold text-slate-900">
            <LineChart className="h-3.5 w-3.5" /> {compact(p.overall)}
          </div>
          <div className="text-xs text-slate-400">Overall</div>
        </div>
      </div>
      <Sparkline points={series} tone={tone} className="mt-3 h-12 w-full" />
    </div>
  );
}

function RangeSelect({ days, setDays }: { days: number; setDays?: (d: number) => void }) {
  if (!setDays) return null;
  return (
    <label className="xg-m-range relative flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-sm text-slate-600">
      <CalendarDays className="h-4 w-4 text-slate-400" />
      <select className="cursor-pointer appearance-none bg-transparent pr-5 outline-none" value={days} onChange={(e) => setDays(Number(e.target.value))}>
        <option value={7}>Last 7 Days</option>
        <option value={30}>Last 30 Days</option>
        <option value={90}>Last 90 Days</option>
      </select>
      <ChevronDown className="pointer-events-none absolute right-2.5 h-4 w-4 text-slate-400" />
    </label>
  );
}

function AlertRow({ a }: { a: Alert }) {
  const [open, setOpen] = useState(false);
  const tone =
    a.level === 'danger'
      ? { box: 'bg-red-50/80', icon: <AlertTriangle className="h-5 w-5 text-red-500" />, text: 'text-red-700' }
      : a.level === 'warning'
        ? { box: 'bg-amber-50/80', icon: <AlertTriangle className="h-5 w-5 text-amber-500" />, text: 'text-slate-800' }
        : { box: 'bg-blue-50/70', icon: <Info className="h-5 w-5 text-blue-500" />, text: 'text-slate-800' };
  return (
    <div className={`xg-m-alert rounded-xl ${tone.box}`}>
      <button className="flex w-full items-center gap-3 px-4 py-3 text-left text-sm" onClick={() => setOpen(!open)}>
        {tone.icon}
        <span className={`flex-1 font-medium ${tone.text}`}>{a.text}</span>
        <ChevronRight className={`h-4 w-4 text-slate-400 transition ${open ? 'rotate-90' : ''}`} />
      </button>
      {open && (
        <div className="space-y-1 px-4 pb-3 pl-12 text-sm">
          {(a.details ?? []).map((d) => (
            <div key={d} className="break-all text-slate-600">
              {d}
            </div>
          ))}
          <Link to={a.link} className="inline-block pt-1 font-medium text-[var(--xg-primary)] hover:underline">
            Open →
          </Link>
        </div>
      )}
    </div>
  );
}

/** Daily or weekly totals of a day series. */
function bucket<T extends { day: string }>(rows: T[], weekly: boolean, keys: (keyof T)[]): T[] {
  if (!weekly) return rows;
  const out: T[] = [];
  for (let i = 0; i < rows.length; i += 7) {
    const chunk = rows.slice(i, i + 7);
    const agg = { ...chunk[0] } as T;
    for (const k of keys) (agg as Record<string, unknown>)[k as string] = chunk.reduce((a, r) => a + Number(r[k] ?? 0), 0);
    out.push(agg);
  }
  return out;
}

function ChartHead({ title, weekly, setWeekly, line, setLine, legend }: { title: string; weekly: boolean; setWeekly: (v: boolean) => void; line: boolean; setLine: (v: boolean) => void; legend?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-center gap-3">
      <h2 className="text-lg font-bold text-slate-900">{title}</h2>
      <div className="ml-auto flex items-center gap-2">
        <label className="xg-m-range relative flex items-center rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-sm text-slate-600">
          <select className="cursor-pointer appearance-none bg-transparent pr-6 outline-none" value={weekly ? 'w' : 'd'} onChange={(e) => setWeekly(e.target.value === 'w')}>
            <option value="d">Daily</option>
            <option value="w">Weekly</option>
          </select>
          <ChevronDown className="pointer-events-none absolute right-2.5 h-4 w-4 text-slate-400" />
        </label>
        <button className="xg-m-range rounded-xl border border-slate-200 bg-white p-2 text-slate-500 hover:text-slate-800" title={line ? 'Bars' : 'Line'} onClick={() => setLine(!line)}>
          {line ? <BarChart3 className="h-4 w-4" /> : <LineChart className="h-4 w-4" />}
        </button>
      </div>
      {legend && <div className="w-full">{legend}</div>}
    </div>
  );
}

function SeriesChart({ data, color, name, line, height = 'h-64' }: { data: { day: string; n: number }[]; color: string; name: string; line: boolean; height?: string }) {
  return (
    <div className={height}>
      <ResponsiveContainer width="100%" height="100%">
        {line ? (
          <AreaChart data={data}>
            <defs>
              <linearGradient id={`f-${name}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={color} stopOpacity={0.25} />
                <stop offset="100%" stopColor={color} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid vertical={false} stroke="#eef2f7" />
            <XAxis dataKey="day" tick={tick} tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={14} />
            <YAxis tick={tick} width={44} tickFormatter={compact} axisLine={false} tickLine={false} allowDecimals={false} />
            <Tooltip formatter={(v) => Number(v).toLocaleString()} />
            <Area type="monotone" dataKey="n" name={name} stroke={color} strokeWidth={2} fill={`url(#f-${name})`} isAnimationActive={false} />
          </AreaChart>
        ) : (
          <BarChart data={data}>
            <CartesianGrid vertical={false} stroke="#eef2f7" />
            <XAxis dataKey="day" tick={tick} tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={14} />
            <YAxis tick={tick} width={44} tickFormatter={compact} axisLine={false} tickLine={false} allowDecimals={false} />
            <Tooltip formatter={(v) => Number(v).toLocaleString()} cursor={{ fill: '#f1f5f9' }} />
            <Bar dataKey="n" name={name} fill={color} radius={[4, 4, 0, 0]} maxBarSize={14} isAnimationActive={false} />
          </BarChart>
        )}
      </ResponsiveContainer>
    </div>
  );
}

/** The Modern style's server dashboard (same data as AttackOverview). */
export default function ModernOverview({ serverId, online, days, setDays }: { serverId: string; online: boolean; days: number; setDays?: (d: number) => void }) {
  const { data, error } = useAgent<Dash>(online ? serverId : undefined, 'dashboard.get', { days }, 60_000, { cache: true });
  const [allAlerts, setAllAlerts] = useState(false);
  const [wk1, setWk1] = useState(false);
  const [ln1, setLn1] = useState(false);
  const [wk2, setWk2] = useState(false);
  const [ln2, setLn2] = useState(false);
  const [wk3, setWk3] = useState(false);
  const [ln3, setLn3] = useState(false);
  if (!online) return <div className="card p-6 text-sm text-slate-500">The server is offline; the security overview appears when the agent reconnects.</div>;
  if (error && !data) return <div className="card p-4 text-sm text-slate-500">Security overview unavailable: {error}</div>;
  if (!data) return <PageLoader />;

  const total = data.threats.current + data.web_attacks.current + data.blocked_connections.current;
  const prevTotal = data.threats.previous + data.web_attacks.previous + data.blocked_connections.previous;
  const donut = prevTotal > 0 ? [
    { name: 'current', value: total, fill: '#22c55e' },
    { name: 'previous', value: prevTotal, fill: '#cbd5e1' },
  ] : [{ name: 'current', value: 1, fill: total > 0 ? '#22c55e' : '#e2e8f0' }];
  const inf = data.infections_daily;
  const infections = (inf.virus ?? []).map((p, i) => ({
    day: shortDay(p.day),
    Suspicious: inf.suspicious?.[i]?.n ?? 0,
    Virus: p.n,
    Binary: inf.binary?.[i]?.n ?? 0,
    Symbolic: inf.symlink?.[i]?.n ?? 0,
  }));
  const threatSeries = infections.map((r) => r.Suspicious + r.Virus + r.Binary + r.Symbolic);
  const attacks = data.attacks_daily.map((p) => ({ day: shortDay(p.day), n: p.n }));
  const web = data.web_daily.map((p) => ({ day: shortDay(p.day), n: p.n }));
  const rows: { tone: Tone; icon: ReactNode; name: string; p: Dash['threats'] }[] = [
    { tone: 'red', icon: <ShieldAlert />, name: 'Threats Stopped', p: data.threats },
    { tone: 'blue', icon: <Globe />, name: 'Web Attacks Blocked', p: data.web_attacks },
    { tone: 'orange', icon: <Waypoints />, name: 'Blocked Connections', p: data.blocked_connections },
  ];
  const max = Math.max(1, ...rows.flatMap((r) => [r.p.current, r.p.previous]));
  const s = data.summary;
  const summary = [
    { icon: <BookOpen className="h-5 w-5" />, l: 'Outdated CMS', v: s.outdated_cms, to: 'cms' },
    { icon: <Globe className="h-5 w-5" />, l: 'CMS Issues', v: s.cms_issues, to: 'cms' },
    { icon: <AlertTriangle className="h-5 w-5" />, l: 'IPs Blacklisted', v: s.ips_blacklisted, to: 'ip-reputation' },
    { icon: <Globe className="h-5 w-5" />, l: 'Domains Blocklisted', v: s.domains_blacklisted, to: 'domain-reputation' },
    { icon: <Database className="h-5 w-5" />, l: 'Database Infections', v: s.db_infections, to: 'db-scanner' },
  ];
  const c = change(total, prevTotal);
  const cw = change(data.web_attacks.current, data.web_attacks.previous);
  const shownAlerts = allAlerts ? data.alerts : data.alerts.slice(0, 5);
  const infColors: [string, string][] = [
    ['Suspicious', '#1e3a8a'],
    ['Virus', '#60a5fa'],
    ['Binary', '#c7d2fe'],
    ['Symbolic', '#6366f1'],
  ];

  return (
    <div className="space-y-5">
      {data.services && data.services.length > 0 && <ServiceStrip services={data.services} />}
      <div className="grid gap-5 md:grid-cols-3">
        <Kpi tone="red" icon={<ShieldAlert />} p={data.threats} label="Threats Stopped" series={threatSeries} />
        <Kpi tone="blue" icon={<Globe />} p={data.web_attacks} label="Web Attacks Blocked" series={web.map((r) => r.n)} />
        <Kpi tone="orange" icon={<Waypoints />} p={data.blocked_connections} label="Blocked Connections" series={attacks.map((r) => r.n)} />
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.75fr)_minmax(0,1fr)]">
        <div className="card p-4 sm:p-6">
          <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-lg font-bold whitespace-nowrap text-slate-900">Attacks Overview</h2>
            <RangeSelect days={days} setDays={setDays} />
          </div>
          <div className="grid items-center gap-8 md:grid-cols-[220px_minmax(0,1fr)]">
            <div className="space-y-4">
              <div className="relative mx-auto h-48 w-48">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={donut} dataKey="value" innerRadius={68} outerRadius={90} startAngle={90} endAngle={-270} stroke="none" isAnimationActive={false}>
                      {donut.map((d) => (
                        <Cell key={d.name} fill={d.fill} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-2xl font-bold text-slate-900">{compact(total)}</span>
                  <span className="text-xs text-slate-500">Total Threats</span>
                </div>
              </div>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="flex items-center gap-2 text-slate-600">
                    <span className="h-3 w-3 rounded-full bg-green-500" /> Current Period
                  </span>
                  <b className="text-slate-900">{compact(total)}</b>
                </div>
                <div className="flex justify-between">
                  <span className="flex items-center gap-2 text-slate-600">
                    <span className="h-3 w-3 rounded-full bg-slate-400" /> Previous {days} Days
                  </span>
                  <b className="text-slate-900">{compact(prevTotal)}</b>
                </div>
              </div>
            </div>
            <div className="space-y-5">
              {rows.map((r) => (
                <div key={r.name} className="flex items-center gap-4">
                  <IconTile tone={r.tone}>{r.icon}</IconTile>
                  <div className="min-w-0 flex-1">
                    <div className="mb-2 flex items-center justify-between gap-3">
                      <span className="text-sm text-slate-500">{r.name}</span>
                      <span className="text-sm font-bold text-slate-900">{compact(r.p.current)}</span>
                    </div>
                    <div className="h-2.5 rounded-full bg-slate-100">
                      <div className="h-2.5 rounded-full" style={{ width: `${Math.max(1.5, (r.p.current / max) * 100)}%`, background: TONES[r.tone].line }} />
                    </div>
                    <div className="mt-1 text-right text-xs text-blue-500">{compact(r.p.previous)}</div>
                  </div>
                </div>
              ))}
              <div className="flex justify-end gap-5 text-sm text-slate-500">
                <span className="flex items-center gap-1.5">
                  <span className="h-3 w-3 rounded-sm bg-blue-900" /> Current
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="h-3 w-3 rounded-sm bg-blue-300" /> Previous
                </span>
              </div>
            </div>
          </div>
          <div className={`mt-5 flex items-center gap-3 rounded-xl px-4 py-3 text-sm ${c.up ? 'bg-green-50 text-slate-700' : 'bg-slate-50 text-slate-600'}`}>
            <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-white ${c.up ? 'text-green-600' : 'text-slate-400'}`}>
              {c.up ? <TrendingUp className="h-5 w-5" /> : <TrendingDown className="h-5 w-5" />}
            </span>
            <span>
              There is a {c.pct}% {c.up ? 'increase' : 'decrease'} in comparison with the previous {days} days.
            </span>
          </div>
        </div>

        <div className="card flex flex-col p-6">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-lg font-bold text-slate-900">Alerts</h2>
            {data.alerts.length > 5 && (
              <button className="text-sm font-medium text-[var(--xg-primary)] hover:underline" onClick={() => setAllAlerts(!allAlerts)}>
                {allAlerts ? 'Show less' : 'View All'}
              </button>
            )}
          </div>
          {data.alerts.length === 0 ? (
            <div className="flex items-center gap-3 rounded-xl bg-green-50 p-4 text-sm font-medium text-green-800">
              <ShieldCheck className="h-5 w-5" /> No active alerts
            </div>
          ) : (
            <div className="space-y-2.5">
              {shownAlerts.map((a) => (
                <AlertRow key={a.text} a={a} />
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <div className="card p-6">
          <ChartHead title={`Attacks Blocked - ${days} days`} weekly={wk1} setWeekly={setWk1} line={ln1} setLine={setLn1} />
          <SeriesChart data={bucket(attacks, wk1, ['n'])} color="#1e3a8a" name="Blocked connections" line={ln1} />
        </div>
        <div className="card p-6">
          <ChartHead
            title="Virus Infections"
            weekly={wk2}
            setWeekly={setWk2}
            line={ln2}
            setLine={setLn2}
            legend={
              <div className="flex flex-wrap justify-center gap-4 text-xs text-slate-500">
                {infColors.map(([l, col]) => (
                  <span key={l} className="flex items-center gap-1.5">
                    <span className="h-3 w-3 rounded-sm" style={{ background: col }} /> {l}
                  </span>
                ))}
              </div>
            }
          />
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              {ln2 ? (
                <AreaChart data={bucket(infections, wk2, ['Suspicious', 'Virus', 'Binary', 'Symbolic'])}>
                  <CartesianGrid vertical={false} stroke="#eef2f7" />
                  <XAxis dataKey="day" tick={tick} tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={14} />
                  <YAxis tick={tick} width={40} tickFormatter={compact} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip />
                  {infColors.map(([k, col]) => (
                    <Area key={k} type="monotone" dataKey={k} stackId="a" stroke={col} fill={col} fillOpacity={0.35} isAnimationActive={false} />
                  ))}
                </AreaChart>
              ) : (
                <BarChart data={bucket(infections, wk2, ['Suspicious', 'Virus', 'Binary', 'Symbolic'])}>
                  <CartesianGrid vertical={false} stroke="#eef2f7" />
                  <XAxis dataKey="day" tick={tick} tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={14} />
                  <YAxis tick={tick} width={40} tickFormatter={compact} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip cursor={{ fill: '#f1f5f9' }} />
                  {infColors.map(([k, col]) => (
                    <Bar key={k} dataKey={k} stackId="a" fill={col} maxBarSize={14} isAnimationActive={false} />
                  ))}
                </BarChart>
              )}
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.75fr)_minmax(0,1fr)]">
        <div className="card p-6">
          <ChartHead title="Web Attacks" weekly={wk3} setWeekly={setWk3} line={ln3} setLine={setLn3} />
          <div className="grid items-center gap-6 md:grid-cols-[200px_minmax(0,1fr)]">
            <div className="space-y-5">
              <div>
                <div className="text-5xl font-bold text-green-500">{compact(data.web_attacks.current)}</div>
                <div className="mt-2 text-slate-500">Total attacks blocked</div>
              </div>
              <div className="flex items-start gap-3 text-sm text-slate-500">
                <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${cw.up ? 'bg-green-50 text-green-600' : 'bg-slate-50 text-slate-400'}`}>
                  {cw.up ? <TrendingUp className="h-4 w-4" /> : <TrendingDown className="h-4 w-4" />}
                </span>
                <span>
                  There is a {cw.pct}% {cw.up ? 'increase' : 'decrease'} in comparison with the previous {days} days.
                </span>
              </div>
            </div>
            <SeriesChart data={bucket(web, wk3, ['n'])} color="#3b82f6" name="Web attacks" line={ln3} />
          </div>
        </div>
        <div className="card p-6">
          <h2 className="mb-3 text-lg font-bold text-slate-900">Summary</h2>
          <ul className="divide-y divide-slate-100">
            {summary.map((x) => (
              <li key={x.l}>
                <Link to={x.to} className="flex items-center justify-between rounded-lg px-2 py-3.5 transition hover:bg-slate-50">
                  <span className="flex items-center gap-3 text-slate-700">
                    <span className="text-slate-500">{x.icon}</span>
                    {x.l}
                  </span>
                  <span className={`text-xl font-bold ${x.v > 0 ? 'text-red-500' : 'text-slate-900'}`}>{compact(x.v)}</span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
