import { useEffect, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Globe2, Search } from 'lucide-react';
import { api } from '../api';
import { Breadcrumb, Empty, ErrorBox, PageLoader } from '../components/ui';
import { Card, Modal, agentCall, useAction } from '../components/controls';
import { WorldMap, countryName, flag } from '../components/WorldMap';
import { useServerName } from './Scanner';
import { zoned } from '../timezone';

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
  packets?: number;
  now?: number;
}

/** The live chart: one point a second, the last 10 seconds (like cPGuard). */
const LIVE_POINTS = 10;
const LIVE_MS = 1000;

interface Status {
  enabled: boolean;
  version: string;
  entries: number;
  hits_today: number;
  hits_total: number;
}

const two = (n: number) => String(n).padStart(2, '0');
const fmtClock = (ts: number) => {
  const d = zoned(ts * 1000);
  return `${two(d.day)}-${two(d.month)}-${d.year} ${two(d.hour)}:${two(d.minute)}:${two(d.second)}`;
};

/** Y axis ticks in round steps (2, 5, 10, 20 …) with room above the highest point. */
function evenTicks(max: number): number[] {
  const top = Math.max(4, max * 1.1);
  // Smallest step of 1, 2 or 5 × 10^n that keeps about a dozen ticks.
  let step = 1;
  for (let e = 1; top / step > 13; e *= 10) step = [1, 2, 5].map((m) => m * e).find((c) => top / c <= 13) ?? 10 * e;
  const end = Math.ceil(top / step) * step;
  return Array.from({ length: end / step + 1 }, (_, i) => i * step);
}

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
  // Rows that arrived in the latest refresh slide in and flash green.
  const [fresh, setFresh] = useState<Set<number>>(new Set());
  // Rolling live series: packets dropped between refreshes.
  const [series, setSeries] = useState<{ k: number; t: number; v: number }[]>([]);
  // Seconds since the page opened: the chart's x axis.
  const second = useRef(0);
  // Bumped on every refresh that reached the agent: restarts the green light.
  const [beat, setBeat] = useState(0);
  const prev = useRef<{ packets: number; at: number } | null>(null);

  useEffect(() => {
    let alive = true;
    let busy = false;
    let tick = 0;
    lastId.current = 0;
    prev.current = null;
    second.current = 0;
    setEvents([]);
    setSeries([]);
    const load = async () => {
      if (busy) return; // never stack requests on a slow link
      busy = true;
      try {
        const wantStatus = tick++ % 10 === 0;
        const [l, s] = await Promise.all([
          agentCall<Live>(id!, 'ipdb.live', { since_id: lastId.current }),
          wantStatus ? agentCall<Status>(id!, 'ipdb.status') : Promise.resolve(null),
        ]);
        if (!alive) return;
        setLive(l);
        if (s) setStatus(s);
        const first = lastId.current === 0;
        if (l.events.length) {
          lastId.current = Math.max(lastId.current, ...l.events.map((e) => e.id));
          setEvents((cur) => [...l.events, ...cur].slice(0, 150));
          setFresh(first ? new Set() : new Set(l.events.map((e) => e.id)));
        } else {
          setFresh(new Set());
        }
        // Live chart: packets the IPDB dropped per second since the last
        // refresh (sampled log rows as a fallback without counters). A slow
        // refresh is spread over the seconds it took.
        const now = Date.now();
        let v = l.events.length && !first ? l.events.length : 0;
        if (l.packets !== undefined && prev.current) {
          const secs = Math.max(1, (now - prev.current.at) / 1000);
          v = Math.round(Math.max(0, l.packets - prev.current.packets) / secs);
        }
        if (l.packets !== undefined) prev.current = { packets: l.packets, at: now };
        const t = ++second.current;
        setSeries((cur) => {
          // Starts full, with the seconds before the page opened at zero.
          const base = cur.length ? cur : Array.from({ length: LIVE_POINTS - 1 }, (_, i) => ({ k: now - (LIVE_POINTS - 1 - i) * LIVE_MS, t: t - (LIVE_POINTS - 1 - i), v: 0 }));
          return [...base, { k: now, t, v }].slice(-LIVE_POINTS);
        });
        setBeat((b) => b + 1);
        setReloaded(new Date());
        setError(null);
      } catch (e: any) {
        if (alive) setError(e.message);
      } finally {
        busy = false;
      }
    };
    load();
    const t = setInterval(load, LIVE_MS);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [id]);

  if (!live && error) return <ErrorBox message={error} />;
  if (!live || !status) return <PageLoader />;

  const liveTicks = evenTicks(Math.max(0, ...series.map((p) => p.v)));
  const minutes = live.minutes.map((p) => ({ t: zoned(p.at * 1000).minute, v: p.packets }));
  const hourly = live.hourly.map((p) => ({ t: two(zoned(p.at * 1000).hour), v: p.packets }));
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
          <Card title="Attacks Blocked - Live" desc="Blocked packets per second, the last 10 seconds">
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                {/* A new point every second and the curve steps left, without a morphing animation. */}
                <AreaChart data={series} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                  <CartesianGrid horizontal={false} stroke="#e8eaf0" />
                  <XAxis dataKey="t" fontSize={11} interval={0} tickLine={false} axisLine={false} />
                  <YAxis fontSize={11} width={36} allowDecimals={false} tickLine={false} axisLine={false} domain={[0, liveTicks.at(-1)!]} ticks={liveTicks} interval={0} />
                  <Tooltip formatter={(v) => [Number(v).toLocaleString(), 'Packets / second']} labelFormatter={() => ''} />
                  <Area type="monotone" dataKey="v" name="Packets" stroke="#1e2a5a" strokeWidth={2} fill="#1e2a5a" fillOpacity={0.38} isAnimationActive={false} dot={false} activeDot={{ r: 3 }} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-1 flex items-center justify-end gap-1.5 text-[11px] text-slate-400">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-green-500" />
              </span>
              live · {minutes.reduce((a, p) => a + p.v, 0).toLocaleString()} packets in the last 10 minutes
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
        <Card
          title="IPDB Live monitor"
          desc="Live log of connections from blacklisted IPs being blocked."
          right={
            <span
              key={beat}
              className={`mt-1.5 inline-block h-3 w-3 shrink-0 rounded-full ${error ? 'bg-slate-300' : 'xg-live-light bg-green-500'}`}
              title={error ? 'Not receiving live data' : 'Receiving live data'}
              aria-label={error ? 'offline' : 'live'}
            />
          }
        >
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
                    className={`grid grid-cols-[10px_9.5rem_minmax(0,1fr)_8.5rem_4.5rem] items-center gap-x-3 rounded-md bg-slate-50 px-3 py-2 text-[13px] whitespace-nowrap ${
                      fresh.has(e.id) ? 'xg-live-new' : ''
                    }`}
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
