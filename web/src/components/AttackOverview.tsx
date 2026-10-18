import { Link } from 'react-router-dom';

interface Period {
  current: number;
  previous: number;
  overall: number;
}
interface DayPoint {
  day: string;
  n: number;
}
export interface Alert {
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
export function ServiceStrip({ services }: { services: Service[] }) {
  return (
    <div className="card flex flex-wrap items-center gap-2 px-5 py-3">
      <span className="mr-2 text-sm font-semibold text-navy-900">Protection status</span>
      {services.map((sv) => {
        const tone = sv.off ? 'bg-slate-100 text-slate-500' : sv.ok ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-700';
        const dot = sv.off ? 'bg-slate-400' : sv.ok ? 'bg-green-500' : 'bg-red-500 animate-pulse';
        const label = sv.off ? 'Off' : sv.ok ? 'Running' : 'Not working';
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

export function change(cur: number, prev: number): { pct: number; up: boolean } {
  if (prev === 0) return { pct: cur > 0 ? 100 : 0, up: cur > 0 };
  const d = ((cur - prev) / prev) * 100;
  return { pct: Math.round(Math.abs(d)), up: d >= 0 };
}
