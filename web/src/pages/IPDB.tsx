import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Database, Globe2, RefreshCw, Search, ShieldBan, Trash2, Users as UsersIcon, Zap } from 'lucide-react';
import { api } from '../api';
import { useApi } from '../hooks';
import { Breadcrumb, Empty, ErrorBox, PageLoader, StatCard } from '../components/ui';
import { Card, Pager, Tabs, isIPorCIDR, useAction } from '../components/controls';
import { WorldMap, countryName, flag } from '../components/WorldMap';

interface Summary {
  version: string;
  listed: number;
  sources: Record<'community' | 'manual' | 'feed', number>;
  reports_24h: number;
  ips_24h: number;
  reporters_24h: number;
  hits_today: number;
  countries: { country: string; hits: number; ips: number }[];
  daily: { day: string; hits: number }[];
  top: { entry: string; country: string; hits: number; last_seen: string; servers: number }[];
  servers: { id: string; hostname: string; agent_version: string; connected: boolean; synced: boolean; ipdb_synced_at: string | null }[];
  geoip: boolean;
  can_manage: boolean;
}

interface LiveEvent {
  entry: string;
  country: string;
  hits: number;
  last_seen: string;
  server_id: string;
  hostname: string;
}

interface Entry {
  cidr: string;
  source: string;
  country: string;
  reporters: number;
  reports: number;
  reason: string;
  note: string;
  first_seen: string;
  last_seen: string;
  expires_at: string | null;
}

const ago = (iso: string) => {
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
};

const SOURCE_BADGE: Record<string, string> = {
  community: 'bg-red-50 text-red-700',
  manual: 'bg-navy-600 text-white',
  feed: 'bg-purple-50 text-purple-700',
};

export default function IPDBPage() {
  const sum = useApi<Summary>('/api/ipdb/summary', 30_000);
  const live = useApi<{ events: LiveEvent[] }>('/api/ipdb/live', 5_000);
  const [tab, setTab] = useState<'list' | 'whitelist' | 'check'>('list');

  if (sum.loading && !sum.data) return <PageLoader />;
  if (sum.error && !sum.data) return <ErrorBox message={sum.error} />;
  const s = sum.data!;
  const values = Object.fromEntries(s.countries.map((c) => [c.country, c.hits]));
  const events = live.data?.events ?? [];
  const activeCountries = events.filter((e) => Date.now() - new Date(e.last_seen).getTime() < 5 * 60_000).map((e) => e.country);
  const synced = s.servers.filter((x) => x.synced).length;

  return (
    <div className="space-y-5">
      <Breadcrumb items={['IPDB']} />
      <div>
        <h1 className="h-title flex items-center gap-2">
          <Globe2 className="h-6 w-6" /> IPDB — shared attacker blocklist
        </h1>
        <p className="text-sm text-slate-500">
          Every XMart Guard server reports the attackers it bans. An address reported by several servers (or repeatedly)
          joins the IPDB and is dropped at the firewall of every server, before it can attack the next one.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={<Database />} value={s.listed.toLocaleString()} label="Addresses in the IPDB" />
        <StatCard icon={<ShieldBan />} value={s.hits_today.toLocaleString()} label="Packets dropped today" accent="text-red-600" />
        <StatCard icon={<Zap />} value={`${s.reports_24h} / ${s.ips_24h}`} label="Reports / new IPs (24 h)" />
        <StatCard icon={<UsersIcon />} value={`${synced} / ${s.servers.length}`} label="Servers protected" accent={synced === s.servers.length ? 'text-green-600' : 'text-amber-600'} />
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Card title="Attack origins" desc="Traffic dropped by the IPDB on your servers, last 30 days">
          <WorldMap values={values} live={activeCountries} />
          {!s.geoip && <p className="mt-2 text-xs text-amber-600">The GeoIP database is still downloading; countries appear shortly.</p>}
        </Card>
        <Card title="Top countries">
          {s.countries.length === 0 ? (
            <Empty text="No blocked traffic yet" />
          ) : (
            <ul className="divide-y divide-slate-100 text-sm">
              {s.countries.slice(0, 12).map((c) => (
                <li key={c.country} className="flex items-center justify-between py-2">
                  <span>
                    <span className="mr-2">{flag(c.country)}</span>
                    {countryName(c.country)}
                  </span>
                  <span className="text-slate-500">
                    {c.hits.toLocaleString()} <span className="text-xs">({c.ips} IPs)</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <Card
          title="Live monitor"
          desc="Most recent drops on your servers (refreshes every 5 seconds)"
          right={
            <span className="flex items-center gap-2 text-xs font-semibold text-red-600">
              <span className="relative flex h-2.5 w-2.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75" />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-red-600" />
              </span>
              LIVE
            </span>
          }
        >
          {events.length === 0 ? (
            <Empty text="No blocked traffic in the last day" />
          ) : (
            <div className="max-h-96 overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-white text-left text-xs text-slate-500 uppercase">
                  <tr>
                    <th className="py-2">Address</th>
                    <th>Country</th>
                    <th>Server</th>
                    <th className="text-right">Packets</th>
                    <th className="text-right">Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {events.map((e) => (
                    <tr key={`${e.server_id}-${e.entry}`}>
                      <td className="py-2 font-mono text-xs">{e.entry}</td>
                      <td title={countryName(e.country)}>
                        {flag(e.country)} <span className="text-xs text-slate-500">{e.country || '??'}</span>
                      </td>
                      <td>
                        <Link className="text-blue-600 hover:underline" to={`/servers/${e.server_id}/firewall-logs`}>
                          {e.hostname}
                        </Link>
                      </td>
                      <td className="text-right">{e.hits.toLocaleString()}</td>
                      <td className="text-right text-xs text-slate-500">{ago(e.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card title="Blocked traffic" desc="Packets dropped per day, last 30 days">
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={s.daily}>
                <XAxis dataKey="day" tickFormatter={(d: string) => d.slice(5)} fontSize={11} />
                <YAxis fontSize={11} width={48} />
                <Tooltip />
                <Bar dataKey="hits" name="Packets" fill="#dc2626" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <h3 className="mt-4 mb-1 font-semibold text-navy-900">Top blocked attackers</h3>
          {s.top.length === 0 ? (
            <Empty text="Nothing yet" />
          ) : (
            <ul className="divide-y divide-slate-100 text-sm">
              {s.top.slice(0, 8).map((t) => (
                <li key={t.entry} className="flex justify-between py-1.5">
                  <span className="font-mono text-xs">
                    {flag(t.country)} {t.entry}
                  </span>
                  <span className="text-slate-500">
                    {t.hits.toLocaleString()} · {t.servers} server{t.servers === 1 ? '' : 's'}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title="Server status">
        {s.servers.length === 0 ? (
          <Empty text="No servers yet" />
        ) : (
          <div className="flex flex-wrap gap-2">
            {s.servers.map((x) => (
              <Link
                key={x.id}
                to={`/servers/${x.id}/settings?s=ipdb`}
                className={`rounded-lg border px-3 py-2 text-sm ${x.synced ? 'border-green-200 bg-green-50 text-green-800' : 'border-amber-200 bg-amber-50 text-amber-800'}`}
                title={x.synced ? 'Has the current IPDB list' : x.connected ? 'Waiting for sync (agent 0.3.0+ required)' : 'Offline'}
              >
                {x.hostname} · {x.synced ? 'protected' : x.connected ? 'syncing' : 'offline'}
              </Link>
            ))}
          </div>
        )}
      </Card>

      <div className="card p-6">
        <Tabs
          value={tab}
          onChange={setTab}
          tabs={[
            { v: 'list', l: `Blocklist (${s.listed.toLocaleString()})` },
            { v: 'whitelist', l: 'Whitelist' },
            { v: 'check', l: 'Check an IP' },
          ]}
        />
        <div className="mt-4">
          {tab === 'list' && <EntryList canManage={s.can_manage} sources={s.sources} onChange={sum.reload} />}
          {tab === 'whitelist' && <Whitelist canManage={s.can_manage} onChange={sum.reload} />}
          {tab === 'check' && <CheckIP />}
        </div>
      </div>
      <p className="text-xs text-slate-400">
        IP geolocation by{' '}
        <a className="underline" href="https://db-ip.com" target="_blank" rel="noreferrer">
          DB-IP
        </a>
        . List version {s.version || '–'}.
      </p>
    </div>
  );
}

function EntryList({ canManage, sources, onChange }: { canManage: boolean; sources: Summary['sources']; onChange: () => void }) {
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [source, setSource] = useState('');
  const [offset, setOffset] = useState(0);
  const limit = 50;
  const list = useApi<{ total: number; entries: Entry[] }>(
    `/api/ipdb/entries?limit=${limit}&offset=${offset}&source=${source}&q=${encodeURIComponent(query)}`,
  );
  const { run, busy } = useAction();
  const [add, setAdd] = useState({ cidr: '', note: '', days: 0 });
  const refresh = () => {
    list.reload();
    onChange();
  };

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            setOffset(0);
            setQuery(q.trim());
          }}
        >
          <input className="input w-64" placeholder="Search IP, network, country, reason" value={q} onChange={(e) => setQ(e.target.value)} />
          <button className="btn-outline">
            <Search className="h-4 w-4" />
          </button>
        </form>
        <select className="input w-48" value={source} onChange={(e) => (setOffset(0), setSource(e.target.value))}>
          <option value="">All sources</option>
          <option value="community">Community reports ({sources.community})</option>
          <option value="manual">Manual ({sources.manual})</option>
          <option value="feed">Public feeds ({sources.feed})</option>
        </select>
        {canManage && (
          <button className="btn-outline ml-auto" disabled={busy} onClick={() => run(() => api('POST', '/api/ipdb/feeds/refresh', {}), 'Feeds refreshed').then(refresh)}>
            <RefreshCw className="h-4 w-4" /> Refresh feeds
          </button>
        )}
      </div>

      {canManage && (
        <form
          className="mb-4 flex flex-wrap items-end gap-2 rounded-lg bg-slate-50 p-3"
          onSubmit={async (e) => {
            e.preventDefault();
            const err = isIPorCIDR(add.cidr.trim());
            if (err) return run(() => Promise.reject(new Error(err)));
            const r = await run(() => api('POST', '/api/ipdb/entries', { ...add, cidr: add.cidr.trim() }), `${add.cidr} added to the IPDB`);
            if (r) {
              setAdd({ cidr: '', note: '', days: 0 });
              refresh();
            }
          }}
        >
          <div>
            <div className="label">IP or network</div>
            <input className="input w-48" value={add.cidr} onChange={(e) => setAdd({ ...add, cidr: e.target.value })} placeholder="203.0.113.7" />
          </div>
          <div className="flex-1">
            <div className="label">Note</div>
            <input className="input" value={add.note} onChange={(e) => setAdd({ ...add, note: e.target.value })} placeholder="why it is blocked" />
          </div>
          <div>
            <div className="label">Expires</div>
            <select className="input" value={add.days} onChange={(e) => setAdd({ ...add, days: Number(e.target.value) })}>
              <option value={0}>Never</option>
              <option value={1}>1 day</option>
              <option value={7}>7 days</option>
              <option value={30}>30 days</option>
              <option value={90}>90 days</option>
            </select>
          </div>
          <button className="btn-primary" disabled={busy || !add.cidr.trim()}>
            Add to IPDB
          </button>
        </form>
      )}

      {list.error && <ErrorBox message={list.error} />}
      {list.data && list.data.entries.length === 0 ? (
        <Empty text="No entries" />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-slate-500 uppercase">
              <tr>
                <th className="py-2">Address</th>
                <th>Country</th>
                <th>Source</th>
                <th>Reason</th>
                <th className="text-right">Reports</th>
                <th className="text-right">Last seen</th>
                <th className="text-right">Expires</th>
                {canManage && <th />}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {list.data?.entries.map((e) => (
                <tr key={e.cidr}>
                  <td className="py-2 font-mono text-xs">{e.cidr}</td>
                  <td title={countryName(e.country)}>
                    {flag(e.country)} <span className="text-xs text-slate-500">{e.country}</span>
                  </td>
                  <td>
                    <span className={`rounded-full px-2 py-0.5 text-xs capitalize ${SOURCE_BADGE[e.source] ?? ''}`}>{e.source}</span>
                  </td>
                  <td className="max-w-xs truncate text-xs text-slate-600" title={e.note || e.reason}>
                    {e.note || e.reason}
                  </td>
                  <td className="text-right text-xs">{e.source === 'community' ? `${e.reports} from ${e.reporters} server${e.reporters === 1 ? '' : 's'}` : '–'}</td>
                  <td className="text-right text-xs text-slate-500">{ago(e.last_seen)}</td>
                  <td className="text-right text-xs text-slate-500">{e.expires_at ? new Date(e.expires_at).toLocaleDateString() : 'never'}</td>
                  {canManage && (
                    <td className="text-right">
                      <button
                        className="text-red-600 hover:text-red-800"
                        title="Remove from the IPDB"
                        disabled={busy}
                        onClick={() => run(() => api('DELETE', `/api/ipdb/entries?cidr=${encodeURIComponent(e.cidr)}`), `${e.cidr} removed`).then(refresh)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {list.data && <Pager total={list.data.total} limit={limit} offset={offset} onChange={setOffset} />}
      {!canManage && <p className="mt-3 text-xs text-slate-500">The IPDB list is managed by the portal operator.</p>}
    </div>
  );
}

function Whitelist({ canManage, onChange }: { canManage: boolean; onChange: () => void }) {
  const wl = useApi<{ whitelist: { cidr: string; note: string; created_at: string }[] }>('/api/ipdb/whitelist');
  const { run, busy } = useAction();
  const [add, setAdd] = useState({ cidr: '', note: '' });
  const refresh = () => {
    wl.reload();
    onChange();
  };
  return (
    <div>
      <p className="mb-3 text-sm text-slate-500">Whitelisted addresses are never listed in the IPDB, whatever is reported about them.</p>
      {canManage && (
        <form
          className="mb-4 flex flex-wrap items-end gap-2 rounded-lg bg-slate-50 p-3"
          onSubmit={async (e) => {
            e.preventDefault();
            const r = await run(() => api('POST', '/api/ipdb/whitelist', { ...add, cidr: add.cidr.trim() }), `${add.cidr} whitelisted`);
            if (r) {
              setAdd({ cidr: '', note: '' });
              refresh();
            }
          }}
        >
          <div>
            <div className="label">IP or network</div>
            <input className="input w-48" value={add.cidr} onChange={(e) => setAdd({ ...add, cidr: e.target.value })} />
          </div>
          <div className="flex-1">
            <div className="label">Note</div>
            <input className="input" value={add.note} onChange={(e) => setAdd({ ...add, note: e.target.value })} placeholder="e.g. office IP, monitoring service" />
          </div>
          <button className="btn-primary" disabled={busy || !add.cidr.trim()}>
            Whitelist
          </button>
        </form>
      )}
      {wl.data?.whitelist.length === 0 ? (
        <Empty text="The whitelist is empty" />
      ) : (
        <ul className="divide-y divide-slate-100 text-sm">
          {wl.data?.whitelist.map((w) => (
            <li key={w.cidr} className="flex items-center justify-between py-2">
              <span>
                <span className="font-mono text-xs">{w.cidr}</span> <span className="text-xs text-slate-500">{w.note}</span>
              </span>
              {canManage && (
                <button className="text-red-600 hover:text-red-800" disabled={busy} onClick={() => run(() => api('DELETE', `/api/ipdb/whitelist?cidr=${encodeURIComponent(w.cidr)}`), 'Removed').then(refresh)}>
                  <Trash2 className="h-4 w-4" />
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function CheckIP() {
  const [ip, setIp] = useState('');
  const [res, setRes] = useState<any>(null);
  const { run, busy } = useAction();
  return (
    <div>
      <form
        className="mb-4 flex gap-2"
        onSubmit={async (e) => {
          e.preventDefault();
          const r = await run(() => api('GET', `/api/ipdb/check?ip=${encodeURIComponent(ip.trim())}`));
          if (r) setRes(r);
        }}
      >
        <input className="input w-64" placeholder="IP address" value={ip} onChange={(e) => setIp(e.target.value)} />
        <button className="btn-primary" disabled={busy || !ip.trim()}>
          Check
        </button>
      </form>
      {res && (
        <div className={`rounded-lg p-4 text-sm ${res.listed ? 'bg-red-50 text-red-800' : 'bg-green-50 text-green-800'}`}>
          <div className="text-base font-semibold">
            {flag(res.country)} {res.ip} is {res.listed ? 'listed in the IPDB' : 'not listed'}
          </div>
          <div className="mt-1">Country: {countryName(res.country)}</div>
          <div>
            Reports in the last 30 days: {res.reports} from {res.reporters} server{res.reporters === 1 ? '' : 's'}
          </div>
          {res.entries.map((e: Entry) => (
            <div key={e.cidr}>
              Matched entry {e.cidr} ({e.source}) — {e.note || e.reason}
            </div>
          ))}
          {res.whitelisted.length > 0 && <div>Whitelisted by {res.whitelisted.map((w: { cidr: string }) => w.cidr).join(', ')}</div>}
        </div>
      )}
    </div>
  );
}
