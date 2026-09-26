import { useEffect, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Globe2, Search } from 'lucide-react';
import { api } from '../api';
import { Breadcrumb, Empty, ErrorBox, PageLoader } from '../components/ui';
import { Card, Modal, agentCall, useAction } from '../components/controls';
import { WorldMap, countryName, flag } from '../components/WorldMap';
import { useServerName } from './Scanner';

interface ConnEvent {
  id: number;
  at: number;
  kind: string;
  src: string;
  src_port: number;
  dst: string;
  dst_port: number;
  proto: string;
  country: string;
  entry: string;
}

interface Live {
  events: ConnEvent[];
  minutes: { at: number; packets: number }[];
  hourly: { at: number; packets: number }[];
  countries: Record<string, number>;
  logging: boolean;
}

interface Status {
  enabled: boolean;
  version: string;
  entries: number;
  hits_today: number;
  hits_total: number;
}

const two = (n: number) => String(n).padStart(2, '0');
const fmtClock = (ts: number) => {
  const d = new Date(ts * 1000);
  return `${two(d.getDate())}-${two(d.getMonth() + 1)}-${d.getFullYear()} ${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())}`;
};

/** Per-server IPDB blocklist stats with a live log of blocked connections. */
export default function ServerIPDB() {
  const { id } = useParams();
  const host = useServerName(id);
  const [live, setLive] = useState<Live | null>(null);
  const [status, setStatus] = useState<Status | null>(null);
  const [events, setEvents] = useState<ConnEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [reloaded, setReloaded] = useState<Date | null>(null);
  const [check, setCheck] = useState(false);
  const lastId = useRef(0);

  useEffect(() => {
    let alive = true;
    lastId.current = 0;
    setEvents([]);
    const load = async () => {
      try {
        const [l, s] = await Promise.all([
          agentCall<Live>(id!, 'ipdb.live', { since_id: lastId.current }),
          agentCall<Status>(id!, 'ipdb.status'),
        ]);
        if (!alive) return;
        setLive(l);
        setStatus(s);
        if (l.events.length) {
          lastId.current = Math.max(lastId.current, ...l.events.map((e) => e.id));
          setEvents((cur) => [...l.events, ...cur].slice(0, 150));
        }
        setReloaded(new Date());
        setError(null);
      } catch (e: any) {
        if (alive) setError(e.message);
      }
    };
    load();
    const t = setInterval(load, 3000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [id]);

  if (!live && error) return <ErrorBox message={error} />;
  if (!live || !status) return <PageLoader />;

  const minutes = live.minutes.map((p) => ({ t: new Date(p.at * 1000).getMinutes(), v: p.packets }));
  const hourly = live.hourly.map((p) => ({ t: two(new Date(p.at * 1000).getHours()), v: p.packets }));
  const countries = Object.entries(live.countries)
    .filter(([cc]) => cc)
    .sort((a, b) => b[1] - a[1]);
  const maxC = countries[0]?.[1] ?? 1;

  return (
    <div className="space-y-5">
      <Breadcrumb items={[host, 'IPDB']} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="h-title">IPDB Blocklist Stats</h1>
          <p className="text-sm text-slate-500">
            {status.enabled ? (
              <>
                Protecting with {status.entries.toLocaleString()} addresses from the shared{' '}
                <Link className="text-blue-600 hover:underline" to="/ipdb">
                  IPDB
                </Link>{' '}
                · {status.hits_today.toLocaleString()} packets dropped today
              </>
            ) : (
              <span className="text-amber-600">
                IPDB protection is off for this server (Settings » IPDB Protection).
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-3 text-sm text-slate-600">
          {reloaded && <span>Last reloaded at {reloaded.toLocaleString()}</span>}
          <button className="btn-primary" onClick={() => setCheck(true)}>
            <Search className="h-4 w-4" /> Check IP
          </button>
        </div>
      </div>
      {error && <ErrorBox message={error} />}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,0.85fr)_minmax(0,1.35fr)]">
        <div className="space-y-5">
          <Card title="Attacks Blocked - Live" desc="Packets dropped per minute, last 10 minutes">
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={minutes}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="t" fontSize={11} />
                  <YAxis fontSize={11} width={40} allowDecimals={false} />
                  <Tooltip />
                  <Area type="monotone" dataKey="v" name="Packets" stroke="#1e2a5a" fill="#1e2a5a33" strokeWidth={2} isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>
          <Card title="Attacks Blocked - Hourly" desc="Last 24 hours">
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={hourly}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="t" fontSize={11} />
                  <YAxis fontSize={11} width={48} allowDecimals={false} />
                  <Tooltip />
                  <Bar dataKey="v" name="Packets" fill="#1e2a5a" isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </div>
        <Card title="IPDB Live monitor" desc="Live log of connections from blacklisted IPs being blocked.">
          {!live.logging && (
            <p className="mb-2 rounded bg-amber-50 p-2 text-xs text-amber-700">
              Connection logging is off (Firewall » Log blocked connections). Counts and charts still work.
            </p>
          )}
          {events.length === 0 ? (
            <Empty text="No blocked connections yet. They appear here within seconds." />
          ) : (
            <div className="max-h-[520px] overflow-auto pr-1">
              <div className="min-w-[540px] space-y-1">
                {events.map((e) => (
                  <div
                    key={e.id}
                    className="grid grid-cols-[10px_9.5rem_minmax(0,1fr)_8.5rem_4.5rem] items-center gap-x-3 rounded-md bg-slate-50 px-3 py-2 text-[13px] whitespace-nowrap"
                  >
                    <span className="h-2.5 w-2.5 rounded-full bg-red-500" />
                    <span className="truncate" title={e.entry ? `${e.src} · listed as ${e.entry}` : e.src}>
                      <span className="font-semibold text-red-600">{e.src}</span>
                      {e.country && (
                        <span className="ml-1.5 text-[11px] text-slate-400" title={countryName(e.country)}>
                          {e.country}
                        </span>
                      )}
                    </span>
                    <span className="truncate text-slate-500" title={`${e.proto} ${e.src}:${e.src_port} → ${e.dst}:${e.dst_port}`}>
                      {e.src_port ? `Port ${e.src_port}` : e.proto} → <span className="text-blue-600">{e.dst}</span>
                      {e.dst_port ? ` : ${e.dst_port}` : ''}
                    </span>
                    <span className="text-xs text-slate-500 tabular-nums">{fmtClock(e.at)}</span>
                    <span className="text-xs font-semibold text-green-600">● BLOCKED</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Card>
      </div>

      <Card title="Attacks by country" desc="Last 7 days">
        <div className="grid gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
          <WorldMap values={Object.fromEntries(Object.entries(live.countries).filter(([cc]) => cc))} live={events.slice(0, 20).map((e) => e.country).filter(Boolean)} />
          <div>
            <h3 className="font-semibold text-navy-900">Top Countries by Attacks Blocked</h3>
            <p className="mb-3 text-sm text-slate-500">Showing data for the last 7 days</p>
            {countries.length === 0 ? (
              <Empty text="No data yet" />
            ) : (
              <ul className="space-y-3">
                {countries.slice(0, 10).map(([cc, n]) => (
                  <li key={cc}>
                    <div className="flex justify-between text-sm">
                      <span>
                        {flag(cc)} {countryName(cc)}
                      </span>
                      <span className="text-slate-600">{n.toLocaleString()}</span>
                    </div>
                    <div className="mt-1 h-1.5 rounded bg-slate-100">
                      <div className="h-1.5 rounded bg-blue-500" style={{ width: `${Math.max(3, (n / maxC) * 100)}%` }} />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </Card>
      {check && <CheckIPModal serverId={id!} onClose={() => setCheck(false)} />}
    </div>
  );
}

function CheckIPModal({ serverId, onClose }: { serverId: string; onClose: () => void }) {
  const [ip, setIp] = useState('');
  const [res, setRes] = useState<{ portal: any; local: any } | null>(null);
  const { run, busy } = useAction();
  return (
    <Modal title="Check IP" onClose={onClose}>
      <form
        className="flex gap-2"
        onSubmit={async (e) => {
          e.preventDefault();
          const r = await run(async () => ({
            portal: await api('GET', `/api/ipdb/check?ip=${encodeURIComponent(ip.trim())}`),
            local: await agentCall(serverId, 'fw.check', { ip: ip.trim() }),
          }));
          if (r) setRes(r);
        }}
      >
        <input className="input flex-1" placeholder="IP address" value={ip} onChange={(e) => setIp(e.target.value)} autoFocus />
        <button className="btn-primary" disabled={busy || !ip.trim()}>
          Check
        </button>
      </form>
      {res && (
        <div className="mt-4 space-y-2 text-sm">
          <div className="text-base font-semibold text-navy-900">
            {flag(res.portal.country)} {res.portal.ip} · {countryName(res.portal.country)}
          </div>
          <div className={res.portal.listed ? 'text-red-700' : 'text-green-700'}>
            <Globe2 className="mr-1 inline h-4 w-4" />
            {res.portal.listed ? 'Listed in the IPDB' : 'Not listed in the IPDB'} · {res.portal.reports} reports from{' '}
            {res.portal.reporters} server(s) in 30 days
          </div>
          <div>
            On this server: <b>{res.local.status}</b>
            {res.local.protected && ' (this server or the portal — never blocked)'}
          </div>
          {res.local.events?.length > 0 && (
            <div className="text-xs text-slate-500">Last block: {res.local.events[0].reason}</div>
          )}
        </div>
      )}
    </Modal>
  );
}
