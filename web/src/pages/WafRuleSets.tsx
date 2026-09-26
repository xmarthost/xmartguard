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
}
interface Config {
  xmartguard: { enabled: boolean };
  crs: { enabled: boolean; version: string; paranoia: number; inbound_threshold: number; outbound_threshold: number };
  vendors: Vendor[];
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

export default function WafRuleSets() {
  const { user } = useAuth();
  const isAdmin = can(user, 'admin');
  const { data, error, loading, reload } = useApi<Data>('/api/waf/rulesets', 15_000);
  const [cfg, setCfg] = useState<Config | null>(null);
  const [dirty, setDirty] = useState(false);
  const [adding, setAdding] = useState('');
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

      <Card title="XMart Guard rules" desc="Built in, free. Web shells and exploit probes, sensitive files, WordPress hardening, bad bots, upload scanning with the malware engine, login brute force.">
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
          <div className="text-sm text-slate-500 md:col-span-2">
            5 blocks a request after one critical match (CRS default). Raise it (10–20) for a gentler start on sites with many false positives.
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
        <p className="mt-2 text-xs text-slate-500">
          Where the server already loads its own CRS (cPanel's OWASP vendor, Debian's modsecurity-crs or RHEL's mod_security_crs package), the portal's copy is skipped: loading CRS twice would fail.
        </p>
      </Card>

      <Card
        title="cPanel ModSecurity vendors"
        desc="Commercial and free rule feeds that WHM installs and keeps updated itself (WHM » Security Center » ModSecurity Vendors). The agent adds each vendor from its configuration URL, enables it with automatic updates, and disables vendors you switch off here."
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
              {!!s.status?.rule_sets?.length && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {s.status.rule_sets.map((r) => (
                    <Chip key={r.id} s={r} />
                  ))}
                </div>
              )}
              {s.status?.rule_sets?.filter((r) => r.state === 'error' || r.state === 'unsupported').map((r) => (
                <div key={r.id} className="mt-1 text-xs text-red-700">
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
