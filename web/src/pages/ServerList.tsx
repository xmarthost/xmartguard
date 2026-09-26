import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Bell, Gauge, Info, LayoutGrid, Plus, Server as ServerIcon, Tag, Trash2 } from 'lucide-react';
import { api, type Server } from '../api';
import { can, useAuth } from '../auth';
import { useApi } from '../hooks';
import { ago, panelName, pct } from '../format';
import { Empty, ErrorBox, PageLoader, StatusDot } from '../components/ui';
import { compact } from '../components/AttackOverview';

function TagEditor({ server, onSaved }: { server: Server; onSaved: () => void }) {
  const [value, setValue] = useState(server.tags.join(', '));
  const [open, setOpen] = useState(false);
  if (!open) {
    return (
      <button className="flex items-center gap-2 text-slate-400 transition hover:text-navy-700" onClick={() => setOpen(true)}>
        <Tag className="h-5 w-5" /> {server.tags.length ? 'Edit Tags' : 'Assign Tag'}
      </button>
    );
  }
  return (
    <form
      className="flex gap-1"
      onSubmit={async (e) => {
        e.preventDefault();
        const tags = value.split(',').map((t) => t.trim()).filter(Boolean);
        await api('PATCH', `/api/servers/${server.id}`, { tags });
        setOpen(false);
        onSaved();
      }}
    >
      <input className="input py-1 text-xs" value={value} onChange={(e) => setValue(e.target.value)} placeholder="tag1, tag2" autoFocus />
      <button className="btn-primary px-2 py-1 text-xs">Save</button>
    </form>
  );
}

interface Card {
  virus_attacks?: number;
  web_attacks?: number;
  ipdb_hourly?: number[];
  domains_blacklisted?: number;
  domains?: number;
}

/** 24-hour IPDB blocks as a small area sparkline. */
function Sparkline({ points }: { points: number[] }) {
  const w = 96;
  const h = 34;
  const max = Math.max(1, ...points);
  const step = w / Math.max(1, points.length - 1);
  const y = (v: number) => h - 3 - (v / max) * (h - 8);
  const line = points.map((v, i) => `${i ? 'L' : 'M'}${(i * step).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="h-9 w-24" aria-hidden>
      <path d={`${line} L${w},${h} L0,${h} Z`} fill="#dcfce7" />
      <path d={line} fill="none" stroke="#4ade80" strokeWidth="2" strokeLinejoin="round" />
    </svg>
  );
}

function PanelBadge({ panel }: { panel: string }) {
  if (panel === 'cpanel') return <span className="text-[22px] leading-none font-black tracking-tighter text-orange-500 italic">cP</span>;
  return <ServerIcon className="h-6 w-6 text-navy-700" />;
}

function Stat({ value, label, tone }: { value: React.ReactNode; label: string; tone: 'green' | 'amber' | 'navy' | 'red' }) {
  const color = { green: 'text-green-500', amber: 'text-amber-500', navy: 'text-navy-800', red: 'text-red-500' }[tone];
  return (
    <div>
      <div className={`text-[26px] leading-tight font-medium ${color}`}>{value}</div>
      <div className="mt-1 text-sm text-slate-500">{label}</div>
    </div>
  );
}

function ServerCard({ s, onChange }: { s: Server; onChange: () => void }) {
  const { user } = useAuth();
  const [info, setInfo] = useState(false);
  const m = s.last_metrics;
  const sec = (m as any)?.security;
  const card: Card = sec?.card ?? {};
  const alerts = (sec?.scanner?.open_findings ?? 0) + (sec?.blacklisted_ips ?? 0) + (card.domains_blacklisted ?? 0);
  const iconBtn = 'text-slate-400 transition hover:text-navy-700 [&>svg]:h-5 [&>svg]:w-5';
  return (
    <div className={`card flex flex-col p-6 transition hover:shadow-md ${s.online ? '' : 'opacity-80'}`}>
      <div className="flex items-start gap-3">
        <PanelBadge panel={s.control_panel} />
        <Link to={`/servers/${s.id}`} className="min-w-0 flex-1 truncate text-lg font-medium text-navy-900 hover:underline" title={s.hostname}>
          {s.hostname || '(unknown host)'}
        </Link>
        <Link to={`/servers/${s.id}`} title={alerts ? `${alerts} alert(s)` : 'No alerts'} className="relative text-amber-400 hover:text-amber-500">
          <Bell className="h-6 w-6" />
          {alerts > 0 && <span className="absolute -top-0.5 -right-0.5 h-2.5 w-2.5 rounded-full bg-red-500 ring-2 ring-white" />}
        </Link>
      </div>
      {!s.online && (
        <div className="mt-2 flex items-center gap-2 text-xs text-slate-400">
          <StatusDot online={false} /> offline · last seen {ago(s.last_seen_at)}
        </div>
      )}
      <div className="mt-6 grid grid-cols-3 gap-x-4 gap-y-6">
        <Stat value={compact(card.virus_attacks ?? sec?.scanner?.threats_30d ?? 0)} label="Virus Attacks" tone="green" />
        <Stat value={compact(card.web_attacks ?? 0)} label="Web Attacks" tone="green" />
        <div>
          <Sparkline points={card.ipdb_hourly ?? Array(24).fill(0)} />
          <div className="mt-1 text-sm text-slate-500">IPDB Firewall</div>
        </div>
        <Stat value={sec?.blacklisted_ips ?? 0} label="IP Blacklist" tone={sec?.blacklisted_ips ? 'red' : 'amber'} />
        <Stat value={card.domains_blacklisted ?? 0} label="Domain Blacklist" tone={card.domains_blacklisted ? 'red' : 'amber'} />
        <Stat value={compact(card.domains ?? 0)} label="Domains" tone="navy" />
      </div>
      {s.tags.length > 0 && (
        <div className="mt-4 flex flex-wrap gap-1">
          {s.tags.map((t) => (
            <span key={t} className="rounded-full bg-navy-100 px-2 py-0.5 text-xs text-navy-800">{t}</span>
          ))}
        </div>
      )}
      <div className="mt-auto flex items-center justify-between pt-6">
        <div className="flex items-center gap-5">
          <Link to={`/servers/${s.id}`} title="Dashboard" className={iconBtn}><LayoutGrid /></Link>
          <button title="Server information" className={iconBtn} onClick={() => setInfo(!info)}><Info /></button>
          <Link to={`/servers/${s.id}/monitoring`} title="System Monitoring" className={iconBtn}><Gauge /></Link>
        </div>
        {can(user, 'operator') ? <TagEditor server={s} onSaved={onChange} /> : null}
      </div>
      {info && (
        <div className="mt-4 space-y-1 border-t pt-3 text-xs text-slate-500">
          <div>{panelName(s.control_panel)} · {s.web_server || 'web server unknown'}</div>
          <div>{s.primary_ip} · {s.os_name}</div>
          <div>Agent {s.agent_version} · {s.online ? 'online' : `last seen ${ago(s.last_seen_at)}`}</div>
          {m && <div>CPU {m.cpu_percent}% · memory {pct(m.mem_used, m.mem_total)}% · disk {pct(m.disk_used, m.disk_total)}%</div>}
          {can(user, 'admin') && (
            <button
              className="mt-1 inline-flex items-center gap-1 text-red-500 hover:text-red-700"
              onClick={async () => {
                if (!confirm(`Remove ${s.hostname} from XMart Guard? The agent on the server will stop.`)) return;
                await api('DELETE', `/api/servers/${s.id}`);
                onChange();
              }}
            >
              <Trash2 className="h-3.5 w-3.5" /> Remove server
            </button>
          )}
        </div>
      )}
    </div>
  );
}

export default function ServerList() {
  const [q, setQ] = useState('');
  const { user } = useAuth();
  const { data, error, loading, reload } = useApi<{ servers: Server[] }>(`/api/servers?q=${encodeURIComponent(q)}`, 30_000);
  return (
    <div>
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <h1 className="h-title">All Servers</h1>
        <input className="input max-w-xs" placeholder="filter by hostname, IP or tag" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {error && <ErrorBox message={error} />}
      {loading && !data ? (
        <PageLoader />
      ) : (
        <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
          {data?.servers.map((s) => <ServerCard key={s.id} s={s} onChange={reload} />)}
          {can(user, 'admin') && (
            <Link to="/servers/add" className="card flex min-h-72 flex-col items-center justify-center gap-2 text-slate-500 transition hover:text-navy-800 hover:shadow-md">
              <Plus className="h-10 w-10" />
              Add Server
            </Link>
          )}
          {data?.servers.length === 0 && !can(user, 'admin') && <Empty text="No servers found" />}
        </div>
      )}
    </div>
  );
}
