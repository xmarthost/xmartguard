import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link, NavLink, useLocation, useMatch, useNavigate } from 'react-router-dom';
import {
  BookOpen,
  Activity, BrainCircuit, Cpu, HeartPulse, ScanSearch as ScanSearchIcon, ArrowLeft, Bot, Globe, MailWarning, DatabaseZap, LayoutTemplate, Globe2, ShieldAlert, Bug, ChevronDown, FileWarning, ListX, Radar, Flame, Gauge, KeyRound, LayoutDashboard, Layers, LifeBuoy,
  LogOut, Menu, Server as ServerIcon, Settings, ShieldCheck, Users, X,
} from 'lucide-react';
import { useAuth, can } from '../auth';
import { useApi } from '../hooks';
import type { Server } from '../api';
import { Logo } from './ui';

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
  end?: boolean;
}

function NavGroup({ title, items, onNavigate }: { title?: string; items: NavItem[]; onNavigate: () => void }) {
  return (
    <div className="mb-4">
      {title && <div className="mb-1 px-4 text-[11px] font-semibold tracking-wider text-white/40 uppercase">{title}</div>}
      {items.map((it) => (
        <NavLink
          key={it.to}
          to={it.to}
          end={it.end}
          onClick={onNavigate}
          className={({ isActive }) =>
            `mx-2 my-0.5 flex items-center gap-3 rounded-l-full rounded-r-lg px-4 py-2.5 text-sm transition ${
              isActive ? 'bg-white font-medium text-navy-900' : 'text-white/80 hover:bg-white/10 hover:text-white'
            }`
          }
        >
          <span className="h-5 w-5 [&>svg]:h-5 [&>svg]:w-5">{it.icon}</span>
          {it.label}
        </NavLink>
      ))}
    </div>
  );
}

interface RailEntry {
  label: string;
  icon: ReactNode;
  to?: string;
  end?: boolean;
  children?: NavItem[];
}

/**
 * The desktop sidebar: an icon rail that widens when the mouse is over it;
 * groups open their pages in a flyout to the right.
 */
function Rail({ entries, bottom }: { entries: RailEntry[]; bottom: RailEntry[] }) {
  const loc = useLocation();
  const [open, setOpen] = useState<string | null>(null);
  const isActive = (e: RailEntry) =>
    e.children ? e.children.some((c) => loc.pathname === c.to || loc.pathname.startsWith(c.to + '/')) : e.end ? loc.pathname === e.to : loc.pathname.startsWith(e.to!);
  const item = (e: RailEntry) => {
    const active = isActive(e);
    const cls = `relative mx-2 my-1 flex h-12 items-center gap-4 rounded-l-full rounded-r-2xl px-5 text-sm transition ${
      active ? 'bg-white font-medium text-navy-900' : 'text-white/80 hover:bg-white/10 hover:text-white'
    }`;
    const body = (
      <>
        <span className="h-5 w-5 shrink-0 [&>svg]:h-5 [&>svg]:w-5">{e.icon}</span>
        <span className="whitespace-nowrap opacity-0 transition-opacity duration-150 group-hover/rail:opacity-100">{e.label}</span>
      </>
    );
    if (!e.children) {
      return (
        <NavLink key={e.label} to={e.to!} end={e.end} className={cls} onMouseEnter={() => setOpen(null)}>
          {body}
        </NavLink>
      );
    }
    return (
      <div key={e.label} className="relative" onMouseEnter={() => setOpen(e.label)}>
        <div className={`${cls} cursor-default`}>
          {body}
          {open === e.label && <span className="absolute top-1/2 -right-2 hidden -translate-y-1/2 border-y-8 border-r-8 border-y-transparent border-r-navy-800 group-hover/rail:block" />}
        </div>
        {open === e.label && (
          <div className="absolute top-0 left-full z-40 ml-0 hidden w-64 rounded-2xl bg-navy-800 p-3 shadow-2xl group-hover/rail:block">
            {e.children.map((c) => (
              <NavLink
                key={c.to}
                to={c.to}
                end={c.end}
                onClick={() => setOpen(null)}
                className={({ isActive: a }) =>
                  `flex items-center gap-3 rounded-full px-4 py-2.5 text-sm transition ${a ? 'bg-white/15 font-medium text-white' : 'text-white/85 hover:bg-white/10 hover:text-white'}`
                }
              >
                <span className="h-4 w-4 [&>svg]:h-4 [&>svg]:w-4">{c.icon}</span>
                {c.label}
              </NavLink>
            ))}
          </div>
        )}
      </div>
    );
  };
  return (
    <aside
      className="group/rail fixed top-16 bottom-0 left-0 z-30 hidden w-20 flex-col bg-gradient-to-b from-navy-900 to-navy-700 py-4 transition-[width] duration-200 hover:w-60 hover:shadow-2xl md:flex"
      onMouseLeave={() => setOpen(null)}
    >
      <nav className="flex-1">{entries.map(item)}</nav>
      <div className="border-t border-white/10 pt-3">{bottom.map(item)}</div>
    </aside>
  );
}

function JumpToServer() {
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const nav = useNavigate();
  const { data } = useApi<{ servers: Server[] }>(open ? '/api/servers' : null);
  const matches = (data?.servers ?? [])
    .filter((s) => !q || s.hostname.toLowerCase().includes(q.toLowerCase()) || s.primary_ip.includes(q))
    .slice(0, 8);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const close = (e: MouseEvent) => box.current && !box.current.contains(e.target as Node) && setOpen(false);
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, []);
  return (
    <div ref={box} className="relative hidden w-80 md:block">
      <input
        className="w-full rounded-lg border border-white/10 bg-navy-950/60 px-4 py-2 text-sm text-white outline-none placeholder:text-white/50 focus:border-white/30"
        placeholder="jump to server..."
        value={q}
        onFocus={() => setOpen(true)}
        onChange={(e) => setQ(e.target.value)}
      />
      {open && (
        <div className="absolute top-11 right-0 left-0 z-30 overflow-hidden rounded-lg bg-white shadow-xl">
          {matches.length === 0 ? (
            <div className="px-4 py-3 text-sm text-slate-500">No servers found</div>
          ) : (
            matches.map((s) => (
              <button
                key={s.id}
                className="flex w-full items-center justify-between px-4 py-2.5 text-left text-sm hover:bg-slate-50"
                onClick={() => {
                  setOpen(false);
                  setQ('');
                  nav(`/servers/${s.id}`);
                }}
              >
                <span className="font-medium text-navy-900">{s.hostname}</span>
                <span className="text-xs text-slate-400">{s.primary_ip}</span>
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}

function UserMenu() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const nav = useNavigate();
  if (!user) return null;
  return (
    <div className="relative">
      <button className="flex items-center gap-2 text-sm text-white" onClick={() => setOpen((o) => !o)}>
        <span className="flex h-8 w-8 items-center justify-center rounded-full bg-green-500 font-semibold text-white">
          {(user.name || user.email)[0]?.toUpperCase()}
        </span>
        <span className="hidden sm:inline">{user.name || user.email}</span>
        <ChevronDown className="h-4 w-4" />
      </button>
      {open && (
        <div className="absolute top-11 right-0 z-30 w-56 overflow-hidden rounded-lg bg-white py-1 text-sm shadow-xl" onMouseLeave={() => setOpen(false)}>
          <div className="border-b px-4 py-2 text-xs text-slate-500">
            {user.email}
            <div className="capitalize">{user.role}</div>
          </div>
          {can(user, 'owner') && (
            <Link className="flex items-center gap-2 px-4 py-2 hover:bg-slate-50" to="/users" onClick={() => setOpen(false)}>
              <Users className="h-4 w-4" /> Users
            </Link>
          )}
          <Link className="flex items-center gap-2 px-4 py-2 hover:bg-slate-50" to="/account" onClick={() => setOpen(false)}>
            <KeyRound className="h-4 w-4" /> Account
          </Link>
          <button
            className="flex w-full items-center gap-2 px-4 py-2 text-left text-red-600 hover:bg-slate-50"
            onClick={async () => {
              await logout();
              nav('/login');
            }}
          >
            <LogOut className="h-4 w-4" /> Logout
          </button>
        </div>
      )}
    </div>
  );
}

export default function Layout({ children }: { children: ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const serverMatch = useMatch('/servers/:id/*');
  const serverId = serverMatch?.params.id && serverMatch.params.id !== 'add' ? serverMatch.params.id : null;
  const { data } = useApi<{ server: Server }>(serverId ? `/api/servers/${serverId}` : null);
  const close = () => setMobileOpen(false);

  const base = `/servers/${serverId}`;
  const entries: RailEntry[] = serverId
    ? [
        { label: 'Server List', icon: <ServerIcon />, to: '/servers', end: true },
        { label: 'Dashboard', icon: <LayoutDashboard />, to: base, end: true },
        {
          label: 'Virus Scanner',
          icon: <Bug />,
          children: [
            { to: `${base}/scanner`, label: 'Manual Scans', icon: <ScanSearchIcon /> },
            { to: `${base}/scanner-logs`, label: 'Scanner Logs', icon: <FileWarning /> },
            { to: `${base}/cms`, label: 'CMS Threats', icon: <LayoutTemplate /> },
            { to: `${base}/db-scanner`, label: 'DB Scanner', icon: <DatabaseZap /> },
          ],
        },
        {
          label: 'Protection',
          icon: <ShieldAlert />,
          children: [
            { to: `${base}/firewall`, label: 'Firewall', icon: <Flame /> },
            { to: `${base}/firewall-logs`, label: 'Firewall Logs', icon: <ListX /> },
            { to: `${base}/waf-logs`, label: 'WAF Logs', icon: <ShieldCheck /> },
            { to: `${base}/ipdb`, label: 'IPDB', icon: <Globe2 /> },
            { to: `${base}/bot-attacks`, label: 'Bot Attacks', icon: <Bot /> },
            { to: `${base}/osm`, label: 'Outgoing Spam Monitor', icon: <MailWarning /> },
          ],
        },
        {
          label: 'Server Health',
          icon: <HeartPulse />,
          children: [
            { to: `${base}/monitoring`, label: 'System Monitoring', icon: <Activity /> },
            { to: `${base}/domain-reputation`, label: 'Domain Reputation', icon: <Globe /> },
            { to: `${base}/ip-reputation`, label: 'IP Reputation', icon: <Radar /> },
            { to: `${base}/security-monitor`, label: 'Process & Cron Monitor', icon: <Cpu /> },
          ],
        },
        { label: 'Settings', icon: <Settings />, to: `${base}/settings` },
      ]
    : [
        { label: 'Overview', icon: <LayoutDashboard />, to: '/', end: true },
        { label: 'Server List', icon: <ServerIcon />, to: '/servers', end: true },
        { label: 'AI Scanner', icon: <BrainCircuit />, to: '/ai' },
        { label: 'Mass Operations', icon: <Layers />, to: '/mass-operations' },
      ];
  const bottom: RailEntry[] = [
    { label: 'Security Log', icon: <ShieldCheck />, to: '/security' },
    { label: 'Knowledge Base', icon: <BookOpen />, to: '/kb' },
    { label: 'Support', icon: <LifeBuoy />, to: '/support' },
  ];

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-20 flex h-16 items-center justify-between gap-4 bg-gradient-to-r from-navy-900 to-navy-700 px-4 md:px-6">
        <div className="flex items-center gap-3">
          <button className="text-white md:hidden" onClick={() => setMobileOpen((o) => !o)} aria-label="menu">
            {mobileOpen ? <X /> : <Menu />}
          </button>
          <Link to="/">
            <Logo light />
          </Link>
          {serverId && data?.server && <span className="ml-4 hidden text-sm text-white/70 lg:inline">{data.server.hostname}</span>}
        </div>
        <div className="flex items-center gap-5">
          <JumpToServer />
          <UserMenu />
        </div>
      </header>
      <div className="flex flex-1">
        {/* Desktop: a slim icon rail that opens on hover (like cPGuard). */}
        <Rail entries={entries} bottom={bottom} />
        {/* Mobile: full drawer. */}
        <aside
          className={`fixed top-16 bottom-0 z-30 w-64 overflow-y-auto bg-gradient-to-b from-navy-900 to-navy-700 pt-4 transition-transform md:hidden ${
            mobileOpen ? 'translate-x-0' : '-translate-x-full'
          }`}
        >
          {[...entries, ...bottom].map((e) =>
            e.children ? (
              <NavGroup key={e.label} title={e.label} onNavigate={close} items={e.children} />
            ) : (
              <NavGroup key={e.label} onNavigate={close} items={[{ to: e.to!, label: e.label, icon: e.icon, end: e.end }]} />
            ),
          )}
        </aside>
        <main className="min-w-0 flex-1 p-4 md:ml-20 md:p-6">{children}</main>
      </div>
    </div>
  );
}
