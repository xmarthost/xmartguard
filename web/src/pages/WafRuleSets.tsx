import { useEffect, useState } from 'react';
import { CheckCircle2, CircleAlert, CircleDashed, CircleOff, ExternalLink, Plus, RefreshCw, Rocket, Save, ShieldHalf, Trash2 } from 'lucide-react';
import { api } from '../api';
import { useApi } from '../hooks';
import { can, useAuth } from '../auth';
import { ago } from '../format';
import { Breadcrumb, ErrorBox, PageLoader, StatusDot } from '../components/ui';
import { Card, Toggle, useAction } from '../components/controls';

interface Vendor {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  servers?: string[];
}
interface Remote {
  id: string;
  name: string;
  key: string;
  url: string;
  enabled: boolean;
  servers?: string[];
  rbl?: string;
}
interface RemotePreset {
  id: string;
  name: string;
  url: string;
  rbl: string;
  key_hint: string;
  site: string;
  note: string;
  extras?: { id: string; name: string; desc: string }[];
}
interface Config {
  xmartguard: { enabled: boolean };
  crs: { enabled: boolean; version: string; paranoia: number; inbound_threshold: number; outbound_threshold: number; soft_block?: 'captcha' | 'off' };
  vendors: Vendor[];
  remote: Remote[];
  custom: { enabled: boolean; rules: string };
}
interface Preset {
  id: string;
  name: string;
  price: string;
  url_hint: string;
  default_url: string;
  site: string;
  note: string;
}
interface SetState {
  id: string;
  name: string;
  state: 'active' | 'off' | 'skipped' | 'error' | 'unsupported';
  detail?: string;
  version?: string;
}
interface ServerRow {
  id: string;
  hostname: string;
  online: boolean;
  agent_version: string;
  version: number | null;
  updated_at: string | null;
  status: {
    error?: string;
    rule_sets?: SetState[];
    vendors?: { vendor_id: string; name: string; enabled: boolean; update: boolean }[];
    status?: { web_server?: string; logs?: string[]; warning?: string };
  } | null;
}
interface Data {
  config: Config;
  version: number;
  updated_at: string | null;
  presets: Preset[];
  remote_presets?: RemotePreset[];
  crs: { releases: { version: string; published: string; files: number }[]; last_check: string | null; error: string; resolved: string | null; repo: string };
  servers: ServerRow[];
}

const PARANOIA = [
  { v: 1, l: 'Level 1 — recommended for shared hosting (few false positives)' },
  { v: 2, l: 'Level 2 — more rules, occasional false positives' },
  { v: 3, l: 'Level 3 — strict, needs tuning per site' },
  { v: 4, l: 'Level 4 — very strict, for single hardened apps' },
];

const STATE: Record<SetState['state'], { cls: string; icon: React.ReactNode; l: string }> = {
  active: { cls: 'bg-emerald-50 text-emerald-800 ring-emerald-200', icon: <CheckCircle2 className="h-3.5 w-3.5" />, l: 'active' },
  off: { cls: 'bg-slate-50 text-slate-500 ring-slate-200', icon: <CircleOff className="h-3.5 w-3.5" />, l: 'off' },
  skipped: { cls: 'bg-sky-50 text-sky-800 ring-sky-200', icon: <CircleDashed className="h-3.5 w-3.5" />, l: 'skipped' },
  error: { cls: 'bg-red-50 text-red-700 ring-red-200', icon: <CircleAlert className="h-3.5 w-3.5" />, l: 'error' },
  unsupported: { cls: 'bg-amber-50 text-amber-800 ring-amber-200', icon: <CircleAlert className="h-3.5 w-3.5" />, l: 'not supported' },
};

function Chip({ s }: { s: SetState }) {
  const st = STATE[s.state] ?? STATE.off;
  return (
    <span title={s.detail} className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs ring-1 ${st.cls}`}>
      {st.icon}
      {s.name}
      {s.version && s.id === 'owasp_crs' ? ` ${s.version}` : ''}: {st.l}
    </span>
  );
}

/** The feed URL without its &extra=… modules, and the modules it has. */
function splitExtra(url: string): { base: string; extras: string[] } {
  try {
    const u = new URL(url);
    const extras = (u.searchParams.get('extra') ?? '').split(',').filter(Boolean);
    u.searchParams.delete('extra');
    return { base: u.toString(), extras };
  } catch {
    return { base: url, extras: [] };
  }
}
function joinExtra(base: string, extras: string[]): string {
  return extras.length ? `${base}${base.includes('?') ? '&' : '?'}extra=${extras.join(',')}` : base;
}

/** Which servers a licensed feed goes to (empty list = all servers). */
function ServerPicker({ servers, value, disabled, onChange }: { servers: ServerRow[]; value: string[]; disabled: boolean; onChange: (v: string[]) => void }) {
  const [open, setOpen] = useState(value.length > 0);
  const some = open || value.length > 0;
  const names = servers.filter((s) => value.includes(s.id)).map((s) => s.hostname);
  return (
    <div className="mt-2 rounded-lg bg-slate-50 px-3 py-2 text-sm">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <span className="label mb-0">Linked servers</span>
        <label className="inline-flex items-center gap-1.5">
          <input type="radio" disabled={disabled} checked={!some} onChange={() => (setOpen(false), onChange([]))} /> All servers
        </label>
        <label className="inline-flex items-center gap-1.5">
          <input type="radio" disabled={disabled} checked={some} onChange={() => setOpen(true)} /> Only selected servers
        </label>
        {some && <span className="text-xs text-slate-500">{names.length ? names.join(', ') : 'none selected yet: the feed goes to no server'}</span>}
      </div>
      {some && (
        <div className="mt-2 grid gap-1 sm:grid-cols-2 lg:grid-cols-3">
          {servers.map((s) => (
            <label key={s.id} className="inline-flex items-center gap-2 truncate rounded-md border border-slate-200 bg-white px-2 py-1.5">
              <input
                type="checkbox"
                disabled={disabled}
                checked={value.includes(s.id)}
                onChange={(e) => onChange(e.target.checked ? [...value, s.id] : value.filter((x) => x !== s.id))}
              />
              <StatusDot online={s.online} />
              <span className="truncate">{s.hostname}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

export default function WafRuleSets() {
  const { user } = useAuth();
  const isAdmin = can(user, 'admin');
  const { data, error, loading, reload } = useApi<Data>('/api/waf/rulesets', 15_000);
  const [cfg, setCfg] = useState<Config | null>(null);
  const [dirty, setDirty] = useState(false);
  const [adding, setAdding] = useState('');
  const [addingFeed, setAddingFeed] = useState('');
  const [showVendors, setShowVendors] = useState(false);
  const { run, busy } = useAction();

  useEffect(() => {
    if (data && !dirty) setCfg(data.config);
  }, [data, dirty]);

  if (loading && !data) return <PageLoader />;
  if (error && !data) return <ErrorBox message={error} />;
  if (!data || !cfg) return null;

  const set = (next: Config) => (setCfg(next), setDirty(true));
  const save = async () => {
    const r = await run(() => api<{ version: number; pushed: number; offline: number }>('PUT', '/api/waf/rulesets', cfg), (x) =>
      `Saved (version ${x.version}). Rolling out to ${x.pushed} online server(s)${x.offline ? `; ${x.offline} offline will follow when they connect` : ''}.`,
    );
    if (r) {
      setDirty(false);
      reload();
    }
  };
  const addVendor = (p: Preset) => {
    const id = p.id === 'custom' ? `vendor${cfg.vendors.length + 1}` : p.id;
    if (cfg.vendors.some((v) => v.id === id)) return;
    set({ ...cfg, vendors: [...cfg.vendors, { id, name: p.id === 'custom' ? 'Vendor' : p.name, url: p.default_url, enabled: true }] });
    setAdding('');
  };
  const addFeed = (id: string) => {
    const p = data.remote_presets?.find((x) => x.id === id);
    const feeds = cfg.remote ?? [];
    let fid = p ? p.id : `feed${feeds.length + 1}`;
    for (let n = 2; feeds.some((f) => f.id === fid); n++) fid = `${p ? p.id : 'feed'}${n}`;
    // Licensed per server IP: start linked to one server, never to all.
    const first = data.servers[0]?.id;
    set({
      ...cfg,
      remote: [...feeds, { id: fid, name: p?.name ?? 'Remote feed', key: '', url: p?.url ?? '', enabled: true, rbl: p?.rbl ?? '', servers: p && first ? [first] : [] }],
    });
    setAddingFeed('');
  };
  const linked = (s: ServerRow) => [
    ...cfg.vendors.filter((v) => v.enabled && (!v.servers?.length || v.servers.includes(s.id))).map((v) => v.name),
    ...(cfg.remote ?? []).filter((r) => r.enabled && (!r.servers?.length || r.servers.includes(s.id))).map((r) => r.name),
  ];
  const isME = (x: { id?: string; url: string }) => x.id === 'malware_expert' || /^https:\/\/(?:rules|vendor)\.malware\.expert\//i.test(x.url);
  const meServers = data.servers.filter((s) =>
    [...cfg.vendors, ...(cfg.remote ?? [])].some((x) => x.enabled && isME(x) && (!x.servers?.length || x.servers.includes(s.id))),
  );
  const current = (s: ServerRow) => s.version != null && s.version === data.version;
  const latest = data.crs.releases[0];

  return (
    <div className="mx-auto max-w-6xl space-y-5 pb-24">
      <Breadcrumb items={['WAF Rule Sets']} />
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="h-title flex items-center gap-2">
            <ShieldHalf className="h-6 w-6" /> WAF Rule Sets
          </h1>
          <p className="mt-1 max-w-3xl text-sm text-slate-500">
            One ModSecurity configuration for all servers. Saving rolls it out to every online server at once (the rest within 15 minutes). Blocked
            requests show in each server's WAF Logs, in the Web Attacks counters and in WHM » ModSecurity Tools.
          </p>
        </div>
        {isAdmin && (
          <button className="btn-outline" disabled={busy} onClick={() => run(() => api<{ pushed: number }>('POST', '/api/waf/rulesets/rollout'), (x) => `Sent to ${x.pushed} server(s)`).then(reload)}>
            <Rocket className="h-4 w-4" /> Roll out again
          </button>
        )}
      </div>

      <Card title="xPGuard rules" desc="Built in, free. Web shells and exploit probes, sensitive files, WordPress hardening, bad bots, upload scanning with the malware engine, login brute force.">
        <div className="mt-3 flex items-center justify-between gap-3">
          <span className="text-sm text-slate-600">Individual rules can still be switched per server in Settings » WAF.</span>
          <Toggle on={cfg.xmartguard.enabled} disabled={!isAdmin} onChange={(v) => set({ ...cfg, xmartguard: { enabled: v } })} />
        </div>
      </Card>

      <Card
        title="OWASP Core Rule Set (CRS)"
        desc="Open source (Apache 2.0) generic attack detection: SQL injection, XSS, remote code execution, local/remote file inclusion, scanners. Downloaded by the portal from the official GitHub releases and sent to every server."
        right={<Toggle on={cfg.crs.enabled} disabled={!isAdmin} onChange={(v) => set({ ...cfg, crs: { ...cfg.crs, enabled: v } })} />}
      >
        <div className="mt-3 grid gap-4 md:grid-cols-3">
          <label className="text-sm">
            <span className="label">Release</span>
            <select className="input" disabled={!isAdmin} value={cfg.crs.version} onChange={(e) => set({ ...cfg, crs: { ...cfg.crs, version: e.target.value } })}>
              <option value="latest">Latest release{latest ? ` (now ${latest.version})` : ''}</option>
              {data.crs.releases.map((r) => (
                <option key={r.version} value={r.version}>
                  {r.version} (pinned)
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm md:col-span-2">
            <span className="label">Paranoia level</span>
            <select className="input" disabled={!isAdmin} value={cfg.crs.paranoia} onChange={(e) => set({ ...cfg, crs: { ...cfg.crs, paranoia: +e.target.value } })}>
              {PARANOIA.map((p) => (
                <option key={p.v} value={p.v}>
                  {p.l}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            <span className="label">Block at anomaly score</span>
            <input
              className="input"
              type="number"
              min={3}
              max={1000}
              disabled={!isAdmin}
              value={cfg.crs.inbound_threshold}
              onChange={(e) => set({ ...cfg, crs: { ...cfg.crs, inbound_threshold: +e.target.value || 5 } })}
            />
          </label>
          <label className="text-sm">
            <span className="label">One weak signal in a page view</span>
            <select
              className="input"
              disabled={!isAdmin}
              value={cfg.crs.soft_block ?? 'captcha'}
              onChange={(e) => set({ ...cfg, crs: { ...cfg.crs, soft_block: e.target.value as 'captcha' | 'off' } })}
            >
              <option value="captcha">CAPTCHA page for clean visitors (recommended)</option>
              <option value="off">Block (403) like every other match</option>
            </select>
          </label>
          <div className="text-sm text-slate-500 md:col-span-2">
            5 blocks a request after one critical match (CRS default). Most false positives are exactly that: one rule in a page view of a real visitor (a
            cookie or search text that looks like code). With the CAPTCHA option such a GET request from a visitor who is not on the IPDB, Tor or ban lists
            gets the CAPTCHA page (Overview » CAPTCHA Page) instead of a 403; after solving it the visitor needs twice the score to be blocked. POST requests,
            real attacks (several rules) and listed addresses are blocked as before.
          </div>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3 rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-500">
          <span>
            {latest ? (
              <>
                Newest stored release <b className="text-navy-900">{latest.version}</b> ({latest.files} files{latest.published ? `, published ${new Date(latest.published).toLocaleDateString()}` : ''})
              </>
            ) : (
              'No release downloaded yet'
            )}
            {data.crs.last_check && ` · checked ${ago(data.crs.last_check)}`} · github.com/{data.crs.repo}
          </span>
          {data.crs.error && <span className="text-red-600">{data.crs.error}</span>}
          {isAdmin && (
            <button className="ml-auto inline-flex items-center gap-1 text-navy-800 hover:underline" disabled={busy} onClick={() => run(() => api('POST', '/api/waf/crs/sync'), 'Checked GitHub for CRS releases').then(reload)}>
              <RefreshCw className="h-3.5 w-3.5" /> Check for updates
            </button>
          )}
        </div>
        {cfg.crs.enabled && meServers.length > 0 && (
          <p className="mt-2 rounded-lg bg-sky-50 px-3 py-2 text-xs text-sky-800">
            Turned off automatically on the server(s) that use Malware.Expert, so two generic rule sets never run together: {meServers.map((s) => s.hostname).join(', ')}.
          </p>
        )}
        <p className="mt-2 text-xs text-slate-500">
          Where the server already loads its own CRS (cPanel's OWASP vendor, Debian's modsecurity-crs or RHEL's mod_security_crs package), the portal's copy is skipped: loading CRS twice would fail.
        </p>
      </Card>

      <Card
        title="Third-party rule sets (Malware.Expert)"
        desc="ModSecurity downloads the vendor's rules itself with your license key (SecRemoteRules), on cPanel, LiteSpeed and plain Apache servers alike. Link each feed to the servers its license covers."
      >
        <div className="mt-3 space-y-3">
          {(cfg.remote ?? []).length === 0 && <div className="text-sm text-slate-400">No remote feeds.</div>}
          {(cfg.remote ?? []).map((r, i) => {
            const upd = (x: Partial<Remote>) => set({ ...cfg, remote: cfg.remote.map((y, j) => (j === i ? { ...y, ...x } : y)) });
            const cur = splitExtra(r.url);
            const p = data.remote_presets?.find((x) => splitExtra(x.url).base === cur.base);
            return (
              <div key={r.id} className="rounded-xl border border-slate-200 p-3">
                <div className="flex flex-wrap items-center gap-3">
                  <input className="input w-full font-medium sm:w-64" value={r.name} disabled={!isAdmin} onChange={(e) => upd({ name: e.target.value })} />
                  {p && <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-600">licensed per server IP</span>}
                  <div className="ml-auto flex items-center gap-2">
                    <Toggle on={r.enabled} disabled={!isAdmin} onChange={(on) => upd({ enabled: on })} />
                    {isAdmin && (
                      <button className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 text-red-600 hover:bg-red-50" title="Remove" onClick={() => set({ ...cfg, remote: cfg.remote.filter((_, j) => j !== i) })}>
                        <Trash2 className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                </div>
                <div className="mt-2 grid gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
                  <label className="text-sm">
                    <span className="label">License / serial key</span>
                    <input className="input font-mono text-xs" placeholder={p?.key_hint ?? 'License key'} value={r.key} disabled={!isAdmin} onChange={(e) => upd({ key: e.target.value.trim() })} />
                  </label>
                  <label className="text-sm">
                    <span className="label">Rules URL</span>
                    <input className="input font-mono text-xs" placeholder="https://…/rules URL" value={r.url} disabled={!isAdmin} onChange={(e) => upd({ url: e.target.value.trim() })} />
                  </label>
                </div>
                <label className="mt-2 flex flex-wrap items-center gap-2 text-sm">
                  <input type="checkbox" disabled={!isAdmin} checked={!!r.rbl} onChange={(e) => upd({ rbl: e.target.checked ? p?.rbl || 'rbl.example.com' : '' })} />
                  Drop POST requests (logins, comments, uploads) from IPs listed on
                  <input className="input h-8 w-56 font-mono text-xs" placeholder="rbl.example.com" disabled={!isAdmin || !r.rbl} value={r.rbl ?? ''} onChange={(e) => upd({ rbl: e.target.value.trim().toLowerCase() })} />
                </label>
                {!!p?.extras?.length && (
                  <div className="mt-2 rounded-lg border border-slate-200 px-3 py-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="label mb-0">Extra rules by {p.name}</span>
                      {isAdmin && (
                        <span className="flex gap-3 text-xs">
                          <button className="text-blue-700 hover:underline" onClick={() => upd({ url: joinExtra(cur.base, p.extras!.map((e) => e.id)) })}>
                            All
                          </button>
                          <button className="text-blue-700 hover:underline" onClick={() => upd({ url: cur.base })}>
                            None
                          </button>
                        </span>
                      )}
                    </div>
                    <div className="mt-1 grid gap-x-4 sm:grid-cols-2">
                      {p.extras.map((e) => (
                        <label key={e.id} className="flex items-start gap-2 py-1 text-sm">
                          <input
                            type="checkbox"
                            className="mt-1"
                            disabled={!isAdmin}
                            checked={cur.extras.includes(e.id)}
                            onChange={(ev) => {
                              const next = p.extras!.map((x) => x.id).filter((id) => (id === e.id ? ev.target.checked : cur.extras.includes(id)));
                              upd({ url: joinExtra(cur.base, next) });
                            }}
                          />
                          <span>
                            <span className="font-medium text-navy-900">{e.name}</span>
                            <span className="block text-xs text-slate-500">{e.desc}</span>
                          </span>
                        </label>
                      ))}
                    </div>
                    <p className="mt-1 text-xs text-slate-500">
                      Extra rules give more protection but can block some legitimate traffic (false positives); whitelist affected paths or report them to the vendor.
                    </p>
                  </div>
                )}
                <ServerPicker servers={data.servers} value={r.servers ?? []} disabled={!isAdmin} onChange={(sv) => upd({ servers: sv })} />
                {p && !r.servers?.length && data.servers.length > 1 && (
                  <p className="mt-1.5 text-xs text-amber-700">This feed now goes to all {data.servers.length} servers. Servers whose IP is not on your license will be refused by the vendor.</p>
                )}
                {p && (
                  <p className="mt-1.5 text-xs text-slate-500">
                    {p.note}{' '}
                    <a href={p.site} target="_blank" rel="noreferrer" className="inline-flex items-center gap-0.5 text-blue-700 hover:underline">
                      website <ExternalLink className="h-3 w-3" />
                    </a>
                  </p>
                )}
              </div>
            );
          })}
          {isAdmin && (
            <div className="flex flex-wrap items-center gap-2">
              <select className="input w-full sm:w-72" value={addingFeed} onChange={(e) => setAddingFeed(e.target.value)}>
                <option value="">Add a remote feed…</option>
                {data.remote_presets?.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} (SecRemoteRules)
                  </option>
                ))}
                <option value="other">Other feed (key + URL)</option>
              </select>
              <button className="btn-outline" disabled={!addingFeed} onClick={() => addFeed(addingFeed)}>
                <Plus className="h-4 w-4" /> Add
              </button>
            </div>
          )}
          <p className="text-xs text-slate-500">
            The license key is shown masked here and sent only to the linked servers. Only the account owner can add a feed.
            {cfg.vendors.length === 0 && !showVendors && (
              <>
                {' '}
                <button className="text-blue-700 hover:underline" onClick={() => setShowVendors(true)}>
                  Add through WHM ModSecurity vendors instead (older method)
                </button>
              </>
            )}
          </p>
        </div>
      </Card>

      {(cfg.vendors.length > 0 || showVendors) && (
      <Card
        title="WHM ModSecurity vendors (older method)"
        desc="The same rule sets installed through WHM » Security Center » ModSecurity Vendors instead of a remote feed; cPanel servers only. Use a remote feed above for Malware.Expert; keep a vendor here only if you already use one. Never use both for the same rules on a server."
      >
        <div className="mt-3 space-y-3">
          {cfg.vendors.length === 0 && <div className="text-sm text-slate-400">No vendors yet.</div>}
          {cfg.vendors.map((v, i) => {
            const p = data.presets.find((x) => x.id === v.id);
            return (
              <div key={v.id} className="rounded-xl border border-slate-200 p-3">
                <div className="flex flex-wrap items-center gap-3">
                  <input
                    className="input w-full font-medium sm:w-64"
                    value={v.name}
                    disabled={!isAdmin}
                    onChange={(e) => set({ ...cfg, vendors: cfg.vendors.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)) })}
                  />
                  {p && <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-600">{p.price}</span>}
                  <div className="ml-auto flex items-center gap-2">
                    <Toggle on={v.enabled} disabled={!isAdmin} onChange={(on) => set({ ...cfg, vendors: cfg.vendors.map((x, j) => (j === i ? { ...x, enabled: on } : x)) })} />
                    {isAdmin && (
                      <button className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 text-red-600 hover:bg-red-50" title="Remove" onClick={() => set({ ...cfg, vendors: cfg.vendors.filter((_, j) => j !== i) })}>
                        <Trash2 className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                </div>
                <input
                  className="input mt-2 font-mono text-xs"
                  placeholder={p?.url_hint ?? 'https://…/meta_vendor.yaml'}
                  value={v.url}
                  disabled={!isAdmin}
                  onChange={(e) => set({ ...cfg, vendors: cfg.vendors.map((x, j) => (j === i ? { ...x, url: e.target.value.trim() } : x)) })}
                />
                <ServerPicker
                  servers={data.servers}
                  value={v.servers ?? []}
                  disabled={!isAdmin}
                  onChange={(sv) => set({ ...cfg, vendors: cfg.vendors.map((x, j) => (j === i ? { ...x, servers: sv } : x)) })}
                />
                {p && (
                  <p className="mt-1.5 text-xs text-slate-500">
                    {p.note}{' '}
                    {p.site && (
                      <a href={p.site} target="_blank" rel="noreferrer" className="inline-flex items-center gap-0.5 text-blue-700 hover:underline">
                        website <ExternalLink className="h-3 w-3" />
                      </a>
                    )}
                  </p>
                )}
              </div>
            );
          })}
          {isAdmin && (
            <div className="flex flex-wrap items-center gap-2">
              <select className="input w-full sm:w-72" value={adding} onChange={(e) => setAdding(e.target.value)}>
                <option value="">Add a vendor…</option>
                {data.presets.map((p) => (
                  <option key={p.id} value={p.id} disabled={p.id !== 'custom' && cfg.vendors.some((v) => v.id === p.id)}>
                    {p.name} — {p.price}
                  </option>
                ))}
              </select>
              <button className="btn-outline" disabled={!adding} onClick={() => addVendor(data.presets.find((p) => p.id === adding)!)}>
                <Plus className="h-4 w-4" /> Add
              </button>
            </div>
          )}
          <p className="text-xs text-slate-500">Vendors are a cPanel/WHM feature; other servers report them as not supported. Only the account owner can add a vendor that is not in the list.</p>
        </div>
      </Card>
      )}

      <Card
        title="Custom rules"
        desc="Your own ModSecurity rules for all servers (SecRule, SecAction, SecRuleRemoveById …). Apache directives and exec actions are not accepted. Use ids 1000000–1999999."
        right={<Toggle on={cfg.custom.enabled} disabled={!isAdmin} onChange={(v) => set({ ...cfg, custom: { ...cfg.custom, enabled: v } })} />}
      >
        <textarea
          className="input mt-3 h-44 font-mono text-xs"
          spellCheck={false}
          disabled={!isAdmin}
          placeholder={'SecRule REQUEST_URI "@beginsWith /wp-json/gravitysmtp/v1/tests/mock-data" \\\n  "id:1000001,phase:1,deny,status:403,log,msg:\'Gravity SMTP data exposure\'"'}
          value={cfg.custom.rules}
          onChange={(e) => set({ ...cfg, custom: { ...cfg.custom, rules: e.target.value } })}
        />
      </Card>

      <Card title="Rollout" desc={`Configuration version ${data.version || '—'}${data.updated_at ? `, saved ${ago(data.updated_at)}` : ''}. Each server reports what it applied.`}>
        <div className="mt-2 divide-y divide-slate-100">
          {data.servers.map((s) => (
            <div key={s.id} className="py-3">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <StatusDot online={s.online} />
                <span className="font-medium text-navy-900">{s.hostname}</span>
                <span className="text-xs text-slate-400">{s.status?.status?.web_server ?? ''}</span>
                <span className={`ml-auto rounded-full px-2 py-0.5 text-xs ${current(s) ? 'bg-emerald-50 text-emerald-700' : 'bg-amber-50 text-amber-700'}`}>
                  {s.version == null ? 'not reported yet' : current(s) ? `version ${s.version} applied` : `has version ${s.version}, pending ${data.version}`}
                </span>
                {s.updated_at && <span className="text-xs text-slate-400">{ago(s.updated_at)}</span>}
              </div>
              <div className="mt-1 text-xs text-slate-500">Linked rule feeds: {linked(s).join(', ') || 'none'}</div>
              {!!s.status?.rule_sets?.length && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {s.status.rule_sets.map((r) => (
                    <Chip key={r.id} s={r} />
                  ))}
                </div>
              )}
              {s.status?.rule_sets?.filter((r) => r.detail && r.state !== 'skipped' && (r.state !== 'active' || r.id.startsWith('remote:'))).map((r) => (
                <div key={r.id} className={`mt-1 text-xs ${r.state === 'error' || r.state === 'unsupported' ? 'text-red-700' : r.state === 'active' ? 'text-emerald-700' : 'text-slate-500'}`}>
                  {r.name}: {r.detail}
                </div>
              ))}
              {!!s.status?.vendors?.length && (
                <div className="mt-1.5 text-xs text-slate-500">
                  WHM vendors on this server: {s.status.vendors.map((v) => `${v.name || v.vendor_id} (${v.enabled ? 'on' : 'off'}${v.update ? ', auto-update' : ''})`).join(', ')}
                </div>
              )}
              {!!s.status?.status?.logs?.length && <div className="mt-1 text-xs text-slate-400">Reads hits from: {s.status.status.logs.join(', ')}</div>}
              {s.status?.status?.warning && <div className="mt-1 text-xs text-amber-700">{s.status.status.warning}</div>}
              {s.status?.error && <div className="mt-1 text-xs text-red-700">{s.status.error}</div>}
            </div>
          ))}
        </div>
      </Card>

      {isAdmin && dirty && (
        <div className="fixed inset-x-0 bottom-0 z-30 border-t border-slate-200 bg-white/95 px-4 py-3 shadow-lg backdrop-blur">
          <div className="mx-auto flex max-w-6xl items-center justify-end gap-3">
            <span className="text-sm text-slate-500">Unsaved changes</span>
            <button className="btn-outline" onClick={() => (setDirty(false), setCfg(data.config))}>
              Discard
            </button>
            <button className="btn-primary" disabled={busy} onClick={save}>
              <Save className="h-4 w-4" /> Save and roll out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
