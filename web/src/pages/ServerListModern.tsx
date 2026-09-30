import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  BrickWall, Database, Gauge, Globe, Info, LayoutDashboard, LayoutGrid, List, MoreVertical, Plus, Search, Server as ServerIcon, ShieldAlert, ShieldCheck, Tag, Trash2, UserX, Users,
} from 'lucide-react';
import { api, type Server } from '../api';
import { can, useAuth } from '../auth';
import { useApi } from '../hooks';
import { ago, panelName, pct } from '../format';
import { Empty, ErrorBox, SectionLoader } from '../components/ui';
import { compact } from '../components/AttackOverview';
import { ThreatDotMap, threatTier } from '../components/WorldMap';
import { IconTile, MiniBars, PanelMark, Sparkline, StatusPill, type Tone } from '../components/ModernBits';
import { TagEditor } from './ServerList';

interface Card {
  virus_attacks?: number;
  web_attacks?: number;
  ipdb_hourly?: number[];
  virus_daily?: number[];
  web_daily?: number[];
  domains_blacklisted?: number;
  domains?: number;
}

interface Info_ {
  s: Server;
  card: Card;
  blacklisted: number;
  problems: { name: string; problem: string }[];
}

function info(s: Server): Info_ {
  const sec = (s.last_metrics as any)?.security;
  return { s, card: sec?.card ?? {}, blacklisted: sec?.blacklisted_ips ?? 0, problems: s.online ? sec?.problems ?? [] : [] };
}

function SummaryTile({ tone, icon, value, label }: { tone: Tone; icon: React.ReactNode; value: string; label: string }) {
  return (
    <div className="card @container p-4 sm:p-5">
      {/* Two tiles per row on phones: the icon sits above the number. */}
      <div className="flex flex-col items-start gap-3 @[15rem]:flex-row @[15rem]:items-center @[15rem]:gap-4">
        <IconTile tone={tone} size="lg">
          {icon}
        </IconTile>
        <div className="min-w-0 flex-1">
          <div className="text-2xl font-bold text-slate-900">{value}</div>
          <div className="text-sm leading-tight text-slate-500">{label}</div>
        </div>
        <span className="hidden @[15rem]:block">
          <MiniBars tone={tone} />
        </span>
      </div>
    </div>
  );
}

function StatBox({ tone, icon, value, label, spark }: { tone: Tone; icon: React.ReactNode; value: string; label: string; spark?: number[] }) {
  return (
    <div className="xg-m-stat @container min-w-0 rounded-xl border border-slate-100 bg-slate-50/60 p-2.5 sm:p-3">
      {/* Narrow tiles (phones): the icon sits above the number. */}
      <div className="flex flex-col items-start gap-1.5 @[9.5rem]:flex-row @[9.5rem]:items-center @[9.5rem]:gap-2.5">
        <IconTile tone={tone} size="sm">
          {icon}
        </IconTile>
        <div className="min-w-0">
          <div className="text-[15px] leading-tight font-bold text-slate-900">{value}</div>
          <div className="text-[11px] leading-tight [overflow-wrap:anywhere] text-slate-500">{label}</div>
        </div>
      </div>
      {spark && <Sparkline points={spark} tone={tone} className="mt-2 h-8 w-full" />}
    </div>
  );
}

function CardMenu({ s, onChange, onInfo }: { s: Server; onChange: () => void; onInfo: () => void }) {
  const { user } = useAuth();
  const [open, setOpen] = useState(false);
  const item = 'flex w-full items-center gap-2 px-3.5 py-2 text-left text-sm text-slate-700 hover:bg-slate-50';
  return (
    <div className="relative">
      <button className="rounded-lg p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700" onClick={() => setOpen(!open)} aria-label="Server menu">
        <MoreVertical className="h-5 w-5" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute right-0 z-20 mt-1 w-52 overflow-hidden rounded-xl border border-slate-200 bg-white py-1 shadow-xl">
            <Link className={item} to={`/servers/${s.id}`}>
              <LayoutDashboard className="h-4 w-4" /> Dashboard
            </Link>
            <button
              className={item}
              onClick={() => {
                setOpen(false);
                onInfo();
              }}
            >
              <Info className="h-4 w-4" /> Server information
            </button>
            <Link className={item} to={`/servers/${s.id}/monitoring`}>
              <Gauge className="h-4 w-4" /> System Monitoring
            </Link>
            {can(user, 'admin') && (
              <button
                className={`${item} text-red-600`}
                onClick={async () => {
                  setOpen(false);
                  if (!confirm(`Remove ${s.hostname} from xPGuard? The agent on the server will stop.`)) return;
                  await api('DELETE', `/api/servers/${s.id}`);
                  onChange();
                }}
              >
                <Trash2 className="h-4 w-4" /> Remove server
              </button>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function ServerCard({ x, onChange }: { x: Info_; onChange: () => void }) {
  const { user } = useAuth();
  const [showInfo, setShowInfo] = useState(false);
  const { s, card } = x;
  const m = s.last_metrics;
  return (
    <div className={`card flex min-w-0 flex-col p-4 transition hover:shadow-lg sm:p-5 ${s.online ? '' : 'opacity-80'}`}>
      <div className="flex items-start gap-3">
        <PanelMark panel={s.control_panel} />
        {s.control_panel !== 'cpanel' && (
          <IconTile tone="blue" size="sm">
            <ServerIcon />
          </IconTile>
        )}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <Link to={`/servers/${s.id}`} className="truncate font-semibold text-slate-900 hover:text-[var(--xg-primary)]" title={s.hostname}>
              {s.hostname || '(unknown host)'}
            </Link>
            <StatusPill online={s.online} attention={x.problems.length > 0} />
          </div>
          <div className="mt-0.5 text-sm text-slate-500">{s.primary_ip}</div>
        </div>
        <CardMenu s={s} onChange={onChange} onInfo={() => setShowInfo(!showInfo)} />
      </div>
      {!s.online && <div className="mt-2 text-xs text-slate-400">offline · last seen {ago(s.last_seen_at)}</div>}
      {x.problems.length > 0 && (
        <Link to={`/servers/${s.id}`} className="mt-2 block truncate rounded-lg bg-red-50 px-2.5 py-1.5 text-xs text-red-700" title={x.problems.map((p) => `${p.name}: ${p.problem}`).join('\n')}>
          {x.problems.map((p) => p.name).join(', ')} not working
        </Link>
      )}
      <div className="mt-4 grid grid-cols-3 gap-2 sm:gap-2.5">
        <StatBox tone="red" icon={<ShieldAlert />} value={compact(card.virus_attacks ?? 0)} label="Virus Attacks" spark={card.virus_daily ?? []} />
        <StatBox tone="blue" icon={<Globe />} value={compact(card.web_attacks ?? 0)} label="Web Attacks" spark={card.web_daily ?? []} />
        <StatBox tone="green" icon={<BrickWall />} value={compact((card.ipdb_hourly ?? []).reduce((a, b) => a + b, 0))} label="IPDB Firewall" spark={card.ipdb_hourly ?? []} />
      </div>
      <div className="mt-2 grid grid-cols-3 gap-2 sm:mt-2.5 sm:gap-2.5">
        <StatBox tone="orange" icon={<UserX />} value={String(x.blacklisted)} label="IP Blocklist" />
        <StatBox tone="purple" icon={<Users />} value={String(card.domains_blacklisted ?? 0)} label="Domain Blacklist" />
        <StatBox tone="sky" icon={<Database />} value={compact(card.domains ?? 0)} label="Domains" />
      </div>
      {showInfo && (
        <div className="mt-3 space-y-1 rounded-xl bg-slate-50 p-3 text-xs text-slate-500">
          <div>
            {panelName(s.control_panel)} · {s.web_server || 'web server unknown'}
          </div>
          <div>
            {s.primary_ip} · {s.os_name}
          </div>
          <div>
            Agent {s.agent_version} · {s.online ? 'online' : `last seen ${ago(s.last_seen_at)}`}
          </div>
          {m && (
            <div>
              CPU {m.cpu_percent}% · memory {pct(m.mem_used, m.mem_total)}% · disk {pct(m.disk_used, m.disk_total)}%
            </div>
          )}
        </div>
      )}
      <div className="mt-auto flex items-center justify-between gap-2 border-t border-slate-100 pt-4">
        {s.tags.length ? (
          <div className="flex min-w-0 flex-wrap gap-1">
            {s.tags.map((t) => (
              <span key={t} className="rounded-full bg-blue-50 px-2 py-0.5 text-xs text-blue-700">
                {t}
              </span>
            ))}
          </div>
        ) : (
          <span className="flex items-center gap-1.5 text-sm text-slate-400">
            <Tag className="h-4 w-4" /> No tags assigned
          </span>
        )}
        {can(user, 'operator') && <TagEditor server={s} onSaved={onChange} modern />}
      </div>
    </div>
  );
}

function ServerRow({ x }: { x: Info_ }) {
  const { s, card } = x;
  return (
    <tr className="border-t border-slate-100 hover:bg-slate-50/70">
      <td className="px-4 py-3">
        <Link to={`/servers/${s.id}`} className="font-medium text-slate-900 hover:text-[var(--xg-primary)]">
          {s.hostname}
        </Link>
        <div className="text-xs text-slate-500">{s.primary_ip}</div>
      </td>
      <td className="px-4 py-3">
        <StatusPill online={s.online} attention={x.problems.length > 0} />
      </td>
      <td className="px-4 py-3 text-right font-medium text-slate-900">{compact(card.virus_attacks ?? 0)}</td>
      <td className="px-4 py-3 text-right font-medium text-slate-900">{compact(card.web_attacks ?? 0)}</td>
      <td className="px-4 py-3 text-right">{x.blacklisted}</td>
      <td className="px-4 py-3 text-right">{card.domains_blacklisted ?? 0}</td>
      <td className="px-4 py-3 text-right">{compact(card.domains ?? 0)}</td>
      <td className="px-4 py-3 text-xs text-slate-500">{s.tags.join(', ') || '–'}</td>
    </tr>
  );
}

function HealthRing({ pct: p }: { pct: number }) {
  const r = 44;
  const c = 2 * Math.PI * r;
  const color = p >= 100 ? '#22c55e' : p >= 70 ? '#f59e0b' : '#ef4444';
  return (
    <svg viewBox="0 0 110 110" className="h-28 w-28 shrink-0">
      <circle cx="55" cy="55" r={r} fill="none" stroke="#e2e8f0" strokeWidth="10" className="xg-ring-bg" />
      <circle cx="55" cy="55" r={r} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round" strokeDasharray={`${(c * p) / 100} ${c}`} transform="rotate(-90 55 55)" />
      <text x="55" y="61" textAnchor="middle" className="fill-slate-900 text-[20px] font-bold">
        {p}%
      </text>
    </svg>
  );
}

const VIEW_KEY = 'xg-servers-view';

export default function ModernServerList() {
  const { user } = useAuth();
  const { data, error, loading, reload } = useApi<{ servers: Server[] }>('/api/servers', 30_000);
  const geo = useApi<{ countries: { country: string; hits: number }[] }>('/api/ipdb/summary', 120_000);
  const [q, setQ] = useState('');
  const [status, setStatus] = useState('');
  const [tag, setTag] = useState('');
  const [sort, setSort] = useState('name');
  const [view, setView] = useState<'grid' | 'list'>(() => {
    try {
      return localStorage.getItem(VIEW_KEY) === 'list' ? 'list' : 'grid';
    } catch {
      return 'grid';
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(VIEW_KEY, view);
    } catch {
      /* ignore */
    }
  }, [view]);

  const all = useMemo(() => (data?.servers ?? []).map(info), [data]);
  const tags = useMemo(() => [...new Set(all.flatMap((x) => x.s.tags))].sort(), [all]);
  const needle = q.trim().toLowerCase();
  const shown = all
    .filter((x) => !needle || x.s.hostname.toLowerCase().includes(needle) || x.s.primary_ip.includes(needle) || x.s.tags.some((t) => t.toLowerCase().includes(needle)))
    .filter((x) => !status || (status === 'online' ? x.s.online && !x.problems.length : status === 'offline' ? !x.s.online : x.problems.length > 0))
    .filter((x) => !tag || x.s.tags.includes(tag))
    .sort((a, b) =>
      sort === 'virus'
        ? (b.card.virus_attacks ?? 0) - (a.card.virus_attacks ?? 0)
        : sort === 'web'
          ? (b.card.web_attacks ?? 0) - (a.card.web_attacks ?? 0)
          : sort === 'domains'
            ? (b.card.domains ?? 0) - (a.card.domains ?? 0)
            : a.s.hostname.localeCompare(b.s.hostname),
    );

  const online = all.filter((x) => x.s.online).length;
  const attention = all.filter((x) => x.problems.length > 0).length;
  const healthy = all.filter((x) => x.s.online && !x.problems.length).length;
  const healthPct = all.length ? Math.round((healthy / all.length) * 100) : 100;
  const sum = (f: (x: Info_) => number) => all.reduce((a, x) => a + f(x), 0);
  const countries: Record<string, number> = {};
  for (const c of geo.data?.countries ?? []) if (c.country) countries[c.country] = c.hits;
  const max = Math.max(1, ...Object.values(countries));
  const tiers = { high: 0, medium: 0, low: 0 };
  for (const n of Object.values(countries)) if (n > 0) tiers[threatTier(n, max)]++;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-[28px] leading-tight font-bold text-slate-900">All Servers</h1>
            <span className="rounded-full bg-blue-50 px-3 py-1 text-sm font-medium text-[var(--xg-primary)]">
              {all.length} Server{all.length === 1 ? '' : 's'}
            </span>
          </div>
          <p className="mt-1 text-slate-500">Monitor, secure and manage all your servers from one place.</p>
        </div>
        {can(user, 'admin') && (
          <Link to="/servers/add" className="btn-primary px-5 py-2.5">
            <Plus className="h-5 w-5" /> Add Server
          </Link>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
        <SummaryTile tone="blue" icon={<ServerIcon />} value={String(all.length)} label="Total Servers" />
        <SummaryTile tone="green" icon={<ShieldCheck />} value={compact(sum((x) => x.card.virus_attacks ?? 0))} label="Total Virus Attacks" />
        <SummaryTile tone="orange" icon={<Globe />} value={compact(sum((x) => x.card.web_attacks ?? 0))} label="Total Web Attacks" />
        <SummaryTile tone="purple" icon={<Database />} value={compact(sum((x) => x.card.domains ?? 0))} label="Total Domains" />
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,2.2fr)_minmax(0,1fr)]">
        <div className="card grid items-center gap-4 p-6 md:grid-cols-[250px_minmax(0,1fr)]">
          <div>
            <h2 className="text-xl font-bold text-slate-900">Global Threat Overview</h2>
            <p className="mt-1 text-sm text-slate-500">Attack origins blocked across all servers (30 days).</p>
            <ul className="mt-5 space-y-2.5 text-sm">
              {(
                [
                  ['High Threat', 'bg-red-500', tiers.high],
                  ['Medium Threat', 'bg-amber-500', tiers.medium],
                  ['Low Threat', 'bg-green-500', tiers.low],
                ] as const
              ).map(([l, c, n]) => (
                <li key={l} className="flex items-center gap-2.5 text-slate-600">
                  <span className={`h-3 w-3 rounded-full ${c}`} />
                  {l}
                  <span className="ml-1 text-slate-500">
                    {n} location{n === 1 ? '' : 's'}
                  </span>
                </li>
              ))}
            </ul>
          </div>
          <ThreatDotMap values={countries} />
        </div>
        <div className="card flex flex-col justify-between gap-5 p-6">
          <div className="flex items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-3">
                <IconTile tone={attention || online < all.length ? 'orange' : 'green'} size="lg">
                  {attention || online < all.length ? <ShieldAlert /> : <ShieldCheck />}
                </IconTile>
                <div className="text-lg leading-snug font-bold text-slate-900">{attention || online < all.length ? 'Needs Attention' : 'All Systems Protected'}</div>
              </div>
              <p className="mt-3 text-sm text-slate-500">
                {attention || online < all.length
                  ? `${attention + (all.length - online)} server${attention + (all.length - online) === 1 ? '' : 's'} with a problem`
                  : 'No critical issues detected'}
              </p>
            </div>
            <HealthRing pct={healthPct} />
          </div>
          <div className="grid grid-cols-3 text-center">
            {(
              [
                ['Online', 'bg-green-500', online],
                ['Offline', 'bg-orange-500', all.length - online],
                ['Attention', 'bg-blue-500', attention],
              ] as const
            ).map(([l, c, n]) => (
              <div key={l}>
                <div className="flex items-center justify-center gap-2 text-lg font-bold text-slate-900">
                  <span className={`h-2.5 w-2.5 rounded-full ${c}`} />
                  {n}
                </div>
                <div className="text-sm text-slate-500">{l}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 sm:gap-3">
        <div className="relative w-full sm:w-auto sm:min-w-60 sm:flex-1">
          <Search className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input className="input pl-10" placeholder="Filter by hostname, IP or tag..." value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <select className="input min-w-0 basis-[calc(50%-0.25rem)] sm:w-auto sm:basis-auto" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All Status</option>
          <option value="online">Online</option>
          <option value="offline">Offline</option>
          <option value="attention">Needs attention</option>
        </select>
        <select className="input min-w-0 basis-[calc(50%-0.25rem)] sm:w-auto sm:basis-auto" value={tag} onChange={(e) => setTag(e.target.value)}>
          <option value="">All Tags</option>
          {tags.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <select className="input min-w-0 flex-1 sm:w-auto sm:flex-none" value={sort} onChange={(e) => setSort(e.target.value)}>
          <option value="name">Sort By: Name</option>
          <option value="virus">Sort By: Virus attacks</option>
          <option value="web">Sort By: Web attacks</option>
          <option value="domains">Sort By: Domains</option>
        </select>
        <div className="xg-m-seg inline-flex overflow-hidden rounded-xl border border-slate-200 bg-white">
          <button className={`px-3 py-2 ${view === 'grid' ? 'bg-[var(--xg-primary)] text-white' : 'text-slate-500 hover:bg-slate-50'}`} onClick={() => setView('grid')} title="Cards">
            <LayoutGrid className="h-5 w-5" />
          </button>
          <button className={`px-3 py-2 ${view === 'list' ? 'bg-[var(--xg-primary)] text-white' : 'text-slate-500 hover:bg-slate-50'}`} onClick={() => setView('list')} title="List">
            <List className="h-5 w-5" />
          </button>
        </div>
      </div>

      {error && <ErrorBox message={error} />}
      {loading && !data ? (
        <SectionLoader />
      ) : view === 'list' ? (
        <div className="card overflow-x-auto p-0">
          <table className="w-full min-w-[820px] text-sm">
            <thead className="text-left text-xs text-slate-500 uppercase">
              <tr>
                <th className="px-4 py-3 font-medium">Server</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 text-right font-medium">Virus attacks</th>
                <th className="px-4 py-3 text-right font-medium">Web attacks</th>
                <th className="px-4 py-3 text-right font-medium">IP blocklist</th>
                <th className="px-4 py-3 text-right font-medium">Domain blacklist</th>
                <th className="px-4 py-3 text-right font-medium">Domains</th>
                <th className="px-4 py-3 font-medium">Tags</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((x) => (
                <ServerRow key={x.s.id} x={x} />
              ))}
            </tbody>
          </table>
          {shown.length === 0 && <Empty text="No servers match" />}
        </div>
      ) : (
        <div className="grid gap-5 md:grid-cols-2 2xl:grid-cols-3">
          {shown.map((x) => (
            <ServerCard key={x.s.id} x={x} onChange={reload} />
          ))}
          {can(user, 'admin') && (
            <Link
              to="/servers/add"
              className="xg-m-add flex min-h-40 flex-col items-center justify-center gap-2 rounded-2xl border-2 border-dashed border-slate-200 bg-white/60 p-6 text-center transition hover:border-blue-300 hover:bg-white"
            >
              <span className="flex h-12 w-12 items-center justify-center rounded-full bg-[var(--xg-primary)] text-white shadow-lg shadow-blue-500/30">
                <Plus className="h-6 w-6" />
              </span>
              <span className="text-lg font-semibold text-slate-900">Add New Server</span>
              <span className="text-sm text-slate-500">Connect and start monitoring a new server</span>
            </Link>
          )}
          {shown.length === 0 && !can(user, 'admin') && <Empty text="No servers found" />}
        </div>
      )}
    </div>
  );
}
