import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom';
import { Bell, ChevronDown, KeyRound, LogOut, Menu, Moon, Search, Sun, Users, X } from 'lucide-react';
import { useAuth, can } from '../auth';
import { useApi } from '../hooks';
import type { Server } from '../api';
import { getModeOverride, setModeOverride } from '../theme';
import { Logo } from './ui';

export interface ModernEntry {
  label: string;
  icon: ReactNode;
  to?: string;
  end?: boolean;
  children?: { to: string; label: string; icon: ReactNode; end?: boolean }[];
}

const itemCls = (active: boolean) =>
  `xg-m-nav relative flex h-11 items-center gap-3 rounded-xl px-3.5 text-[15px] transition ${
    active ? 'xg-m-nav-on bg-blue-50 font-medium text-[var(--xg-primary)]' : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
  }`;

/** One sidebar entry: a link, or a group that opens its pages below it. */
function Entry({ e, onNavigate }: { e: ModernEntry; onNavigate: () => void }) {
  const loc = useLocation();
  const within = (to: string, end?: boolean) => (end ? loc.pathname === to : loc.pathname === to || loc.pathname.startsWith(to + '/'));
  const childActive = !!e.children?.some((c) => within(c.to, c.end));
  const [open, setOpen] = useState(childActive);
  useEffect(() => {
    if (childActive) setOpen(true);
  }, [childActive]);
  const icon = <span className="h-5 w-5 shrink-0 [&>svg]:h-5 [&>svg]:w-5">{e.icon}</span>;
  if (!e.children) {
    return (
      <NavLink to={e.to!} end={e.end} onClick={onNavigate} className={({ isActive }) => itemCls(isActive)}>
        {({ isActive }) => (
          <>
            {isActive && <span className="absolute top-2 bottom-2 -left-3 w-1 rounded-r bg-[var(--xg-primary)]" />}
            {icon}
            {e.label}
          </>
        )}
      </NavLink>
    );
  }
  return (
    <div>
      <button type="button" className={`${itemCls(childActive && !open)} w-full`} onClick={() => setOpen(!open)} aria-expanded={open}>
        {childActive && !open && <span className="absolute top-2 bottom-2 -left-3 w-1 rounded-r bg-[var(--xg-primary)]" />}
        {icon}
        <span className="flex-1 text-left">{e.label}</span>
        <ChevronDown className={`h-4 w-4 text-slate-400 transition ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="mt-0.5 mb-1 ml-5 space-y-0.5 border-l border-slate-200 pl-3">
          {e.children.map((c) => (
            <NavLink
              key={c.to}
              to={c.to}
              end={c.end}
              onClick={onNavigate}
              className={({ isActive }) =>
                `flex h-9 items-center gap-2.5 rounded-lg px-3 text-sm transition ${
                  isActive ? 'bg-blue-50 font-medium text-[var(--xg-primary)]' : 'text-slate-500 hover:bg-slate-50 hover:text-slate-900'
                }`
              }
            >
              <span className="h-4 w-4 shrink-0 [&>svg]:h-4 [&>svg]:w-4">{c.icon}</span>
              {c.label}
            </NavLink>
          ))}
        </div>
      )}
    </div>
  );
}

function Sidebar({ entries, bottom, onNavigate }: { entries: ModernEntry[]; bottom: ModernEntry[]; onNavigate: () => void }) {
  return (
    <div className="flex h-full flex-col">
      <Link to="/" className="flex h-20 shrink-0 items-center px-6" onClick={onNavigate}>
        <Logo tight />
      </Link>
      <nav className="flex-1 space-y-1 overflow-y-auto px-3 pt-2 pb-4">
        {entries.map((e) => (
          <Entry key={e.label} e={e} onNavigate={onNavigate} />
        ))}
      </nav>
      <div className="mx-3 space-y-1 border-t border-slate-200 py-4">
        {bottom.map((e) => (
          <Entry key={e.label} e={e} onNavigate={onNavigate} />
        ))}
      </div>
    </div>
  );
}

/** Header search: jump to a server by hostname, IP or tag. */
function ServerSearch() {
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const nav = useNavigate();
  const { data } = useApi<{ servers: Server[] }>(open ? '/api/servers' : null);
  const needle = q.toLowerCase();
  const matches = (data?.servers ?? [])
    .filter((s) => !q || s.hostname.toLowerCase().includes(needle) || s.primary_ip.includes(q) || s.tags.some((t) => t.toLowerCase().includes(needle)))
    .slice(0, 8);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const close = (e: MouseEvent) => box.current && !box.current.contains(e.target as Node) && setOpen(false);
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, []);
  return (
    <div ref={box} className="relative hidden w-full max-w-md md:block">
      <Search className="pointer-events-none absolute top-1/2 left-3.5 h-4 w-4 -translate-y-1/2 text-slate-400" />
      <input
        className="xg-m-search w-full rounded-xl border border-transparent bg-slate-100 py-2.5 pr-4 pl-10 text-sm text-slate-800 outline-none placeholder:text-slate-400 focus:border-blue-200 focus:bg-white focus:ring-4 focus:ring-blue-50"
        placeholder="Search servers by hostname, IP or tag..."
        value={q}
        onFocus={() => setOpen(true)}
        onChange={(e) => setQ(e.target.value)}
      />
      {open && (
        <div className="absolute top-12 right-0 left-0 z-40 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xl">
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
                <span className="font-medium text-slate-900">{s.hostname}</span>
                <span className="text-xs text-slate-400">{s.primary_ip}</span>
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}

/** The bell: red dot while a server is offline or has open alerts. */
function Alerts() {
  const { data } = useApi<{ servers_offline: number; security: { servers_with_alerts: number } }>('/api/overview', 60_000);
  const n = (data?.servers_offline ?? 0) + (data?.security?.servers_with_alerts ?? 0);
  return (
    <Link to="/servers" className="relative rounded-xl p-2 text-slate-500 transition hover:bg-slate-100 hover:text-slate-800" title={n ? `${n} server(s) need attention` : 'No alerts'}>
      <Bell className="h-5 w-5" />
      {n > 0 && <span className="absolute top-1.5 right-1.5 h-2.5 w-2.5 rounded-full bg-red-500 ring-2 ring-white" />}
    </Link>
  );
}

/** Light/dark for this browser only. */
function ModeButton() {
  const [dark, setDark] = useState(() => document.documentElement.dataset.mode === 'dark');
  return (
    <button
      className="rounded-xl p-2 text-slate-500 transition hover:bg-slate-100 hover:text-slate-800"
      title={dark ? 'Light mode (this browser)' : 'Dark mode (this browser)'}
      onClick={() => {
        const next = dark ? 'light' : 'dark';
        // Back to the portal's own mode clears the override.
        setModeOverride(getModeOverride() ? '' : next);
        setDark(document.documentElement.dataset.mode === 'dark');
      }}
    >
      {dark ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
    </button>
  );
}

function UserMenu() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const nav = useNavigate();
  if (!user) return null;
  const name = user.name || user.email;
  return (
    <div className="relative">
      <button className="flex items-center gap-2.5 rounded-xl py-1 pr-1 pl-1 text-sm text-slate-800 transition hover:bg-slate-100" onClick={() => setOpen((o) => !o)}>
        <span className="flex h-9 w-9 items-center justify-center rounded-full bg-green-500 font-semibold text-white">{name[0]?.toUpperCase()}</span>
        <span className="hidden font-medium sm:inline">{user.role === 'owner' ? 'Owner' : name}</span>
        <ChevronDown className="h-4 w-4 text-slate-500" />
      </button>
      {open && (
        <div className="absolute top-12 right-0 z-40 w-60 overflow-hidden rounded-xl border border-slate-200 bg-white py-1 text-sm shadow-xl" onMouseLeave={() => setOpen(false)}>
          <div className="border-b border-slate-100 px-4 py-2.5 text-xs text-slate-500">
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

/** The Modern style's frame: a light sidebar with labels and a white header. */
export default function ModernLayout({ entries, bottom, children }: { entries: ModernEntry[]; bottom: ModernEntry[]; children: ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const loc = useLocation();
  useEffect(() => setMobileOpen(false), [loc.pathname]);
  return (
    <div className="min-h-screen">
      <aside className="xg-m-side fixed inset-y-0 left-0 z-30 hidden w-64 border-r border-slate-200 bg-white lg:block">
        <Sidebar entries={entries} bottom={bottom} onNavigate={() => undefined} />
      </aside>
      {mobileOpen && <div className="fixed inset-0 z-30 bg-slate-900/40 lg:hidden" onClick={() => setMobileOpen(false)} />}
      <aside
        className={`xg-m-side fixed inset-y-0 left-0 z-40 w-72 border-r border-slate-200 bg-white transition-transform lg:hidden ${mobileOpen ? 'translate-x-0' : '-translate-x-full'}`}
      >
        <Sidebar entries={entries} bottom={bottom} onNavigate={() => setMobileOpen(false)} />
      </aside>
      <div className="lg:pl-64">
        <header className="xg-m-head sticky top-0 z-20 flex h-[72px] items-center gap-2 border-b sm:gap-4 border-slate-200 bg-white/90 px-4 backdrop-blur md:px-8">
          <button className="rounded-lg p-1.5 text-slate-600 hover:bg-slate-100 lg:hidden" onClick={() => setMobileOpen((o) => !o)} aria-label="menu">
            {mobileOpen ? <X /> : <Menu />}
          </button>
          <Link to="/" className="shrink-0 lg:hidden">
            <span className="hidden sm:block">
              <Logo tight />
            </span>
            <img src="/xpguard-mark.png" alt="xPGuard" className="h-8 w-auto sm:hidden" />
          </Link>
          <ServerSearch />
          <div className="ml-auto flex items-center gap-1 sm:gap-3">
            <Alerts />
            <ModeButton />
            <UserMenu />
          </div>
        </header>
        <main className="min-w-0 p-4 md:p-8">{children}</main>
      </div>
    </div>
  );
}
