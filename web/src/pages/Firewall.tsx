import { useEffect, useState, type ReactNode } from 'react';
import { useParams } from 'react-router-dom';
import { CheckCircle2, Globe, RefreshCw, Settings as Gear, ShieldAlert, XCircle } from 'lucide-react';
import { can, useAuth } from '../auth';
import { Breadcrumb, Empty, ErrorBox, PageLoader } from '../components/ui';
import { Badge, Modal, Pager, SettingRow, Toggle, agentCall, fmtTime, isIPorCIDR, useAction, useAgent } from '../components/controls';
import { useServerName } from './Scanner';

// ISO 3166-1 alpha-2 codes; names come from the browser (Intl.DisplayNames).
const CODES =
  'AF AX AL DZ AS AD AO AI AQ AG AR AM AW AU AT AZ BS BH BD BB BY BE BZ BJ BM BT BO BQ BA BW BR IO BN BG BF BI CV KH CM CA KY CF TD CL CN CO KM CG CD CK CR CI HR CU CW CY CZ DK DJ DM DO EC EG SV GQ ER EE SZ ET FK FO FJ FI FR GF PF GA GM GE DE GH GI GR GL GD GP GU GT GG GN GW GY HT VA HN HK HU IS IN ID IR IQ IE IM IL IT JM JP JE JO KZ KE KI KP KR KW KG LA LV LB LS LR LY LI LT LU MO MG MW MY MV ML MT MH MQ MR MU YT MX FM MD MC MN ME MS MA MZ MM NA NR NP NL NC NZ NI NE NG NU NF MK MP NO OM PK PW PS PA PG PY PE PH PN PL PT PR QA RE RO RU RW BL SH KN LC MF PM VC WS SM ST SA SN RS SC SL SG SX SK SI SB SO ZA GS SS ES LK SD SR SJ SE CH SY TW TJ TZ TH TL TG TK TO TT TN TR TM TC TV UG UA AE GB US UM UY UZ VU VE VN VG VI WF EH YE ZM ZW'.split(' ');
const regionNames = (() => {
  try {
    return new Intl.DisplayNames(['en'], { type: 'region' });
  } catch {
    return null;
  }
})();
export const countryName = (cc: string) => regionNames?.of(cc) ?? cc;
const COUNTRIES = CODES.map((c) => ({ code: c, name: countryName(c) })).sort((a, b) => a.name.localeCompare(b.name));

interface Rule {
  kind: string;
  cidr: string;
  comment: string;
  created_at: number;
  expires_at: number;
}

interface FwSettings {
  enabled: boolean;
  provider: 'iptables' | 'nftables';
  bruteforce: boolean;
  bf_threshold: number;
  bf_window_minutes: number;
  ban_minutes: number;
  dos: boolean;
  dos_threshold: number;
  blocked_countries: string[];
  allowed_countries: string[];
}

interface FwStatus {
  available: boolean;
  enabled: boolean;
  provider: string;
  providers: Record<string, string>;
  healthy: boolean;
  error: string;
}

function Section({ title, desc, children }: { title: string; desc: string; children: ReactNode }) {
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)]">
      <div>
        <h2 className="text-lg font-semibold text-navy-900">{title}</h2>
        <p className="text-sm text-slate-500">{desc}</p>
      </div>
      <div className="card space-y-1 p-6">{children}</div>
    </div>
  );
}

function Row({ title, desc, children }: { title: string; desc: string; children: ReactNode }) {
  return (
    <div className="grid gap-3 border-b border-slate-100 py-4 last:border-0 md:grid-cols-2">
      <div>
        <div className="font-medium text-navy-900">{title}</div>
        <div className="text-sm text-slate-500">{desc}</div>
      </div>
      <div className="space-y-2">{children}</div>
    </div>
  );
}

function ListModal({ serverId, kind, title, onClose }: { serverId: string; kind: string; title: string; onClose: () => void }) {
  const list = useAgent<{ rules: Rule[] }>(serverId, 'fw.list', { kind });
  const { run } = useAction();
  const { user } = useAuth();
  return (
    <Modal title={title} onClose={onClose}>
      {list.loading && !list.data ? (
        <PageLoader />
      ) : !list.data?.rules.length ? (
        <Empty text="The list is empty" />
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-slate-500">
              <th className="py-2 font-medium">Address</th>
              <th className="py-2 font-medium">Comment</th>
              <th className="py-2 font-medium">Added</th>
              <th className="py-2 font-medium">Expires</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {list.data.rules.map((r) => (
              <tr key={r.cidr} className="border-b border-slate-100 last:border-0">
                <td className="py-2 font-mono">{r.cidr}</td>
                <td className="py-2">{r.comment || '–'}</td>
                <td className="py-2 whitespace-nowrap">{fmtTime(r.created_at)}</td>
                <td className="py-2 whitespace-nowrap">{r.expires_at ? fmtTime(r.expires_at) : 'never'}</td>
                <td className="py-2 text-right">
                  {can(user, 'operator') && (
                    <button className="text-sm text-red-600 hover:underline" onClick={() => run(() => agentCall(serverId, 'fw.remove', { kind, addr: r.cidr }).then(list.reload), `${r.cidr} removed`)}>
                      Remove
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Modal>
  );
}

function AddRemove({ serverId, kind, label, placeholder = 'Enter IP or CIDR range', withComment, withDuration, removeLabel, onChanged }: {
  serverId: string; kind: string; label: string; placeholder?: string; withComment?: boolean; withDuration?: boolean; removeLabel: string; onChanged?: () => void;
}) {
  const [addr, setAddr] = useState('');
  const [comment, setComment] = useState('');
  const [dur, setDur] = useState('60');
  const [unit, setUnit] = useState('60'); // minutes multiplier
  const [raddr, setRaddr] = useState('');
  const { run, busy } = useAction();
  const { user } = useAuth();
  const disabled = !can(user, 'operator') || busy;
  return (
    <>
      <Row title={label} desc={withDuration ? 'Temporarily for a specified duration' : `Add an IP or CIDR to the ${kind} list`}>
        {withDuration && (
          <div className="flex gap-2">
            <input className="input" type="number" min={1} value={dur} onChange={(e) => setDur(e.target.value)} placeholder="Expiry time" />
            <select className="input w-36" value={unit} onChange={(e) => setUnit(e.target.value)}>
              <option value="1">minutes</option>
              <option value="60">hours</option>
              <option value="1440">days</option>
            </select>
          </div>
        )}
        <input className="input" value={addr} onChange={(e) => setAddr(e.target.value)} placeholder={withDuration ? 'Enter IP address' : placeholder} />
        {withComment && <input className="input" value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Comment" />}
        <div className="flex justify-end">
          <button
            className="btn-primary px-6"
            disabled={disabled || !addr.trim()}
            onClick={async () => {
              const err = isIPorCIDR(addr.trim());
              if (err) return alert(err);
              const minutes = withDuration ? Number(dur) * Number(unit) : 0;
              const r = await run(() => agentCall(serverId, 'fw.add', { kind, addr: addr.trim(), comment, minutes }), `${addr.trim()} added`);
              if (r) {
                setAddr('');
                setComment('');
                onChanged?.();
              }
            }}
          >
            {label.split(' ')[0]}
          </button>
        </div>
      </Row>
      <Row title={removeLabel} desc={`Remove an IP or CIDR from the ${kind} list`}>
        <div className="flex gap-2">
          <input className="input" value={raddr} onChange={(e) => setRaddr(e.target.value)} placeholder={placeholder} />
          <button
            className="btn-primary px-6"
            disabled={disabled || !raddr.trim()}
            onClick={async () => {
              const r = await run(() => agentCall(serverId, kind === 'tempban' ? 'fw.unblock' : 'fw.remove', { kind, addr: raddr.trim() }), `${raddr.trim()} removed`);
              if (r) {
                setRaddr('');
                onChanged?.();
              }
            }}
          >
            Remove
          </button>
        </div>
      </Row>
    </>
  );
}

function CountryPicker({ value, onChange, disabled }: { value: string[]; onChange: (v: string[]) => void; disabled?: boolean }) {
  return (
    <div className="rounded-lg border border-slate-300 p-2">
      <div className="mb-2 flex flex-wrap gap-1">
        {value.length === 0 && <span className="text-sm text-slate-400">None</span>}
        {value.map((c) => (
          <span key={c} className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-sm">
            {countryName(c)}
            {!disabled && (
              <button className="text-slate-400 hover:text-red-600" onClick={() => onChange(value.filter((x) => x !== c))} aria-label={`remove ${c}`}>
                ×
              </button>
            )}
          </span>
        ))}
      </div>
      <select className="input" value="" disabled={disabled} onChange={(e) => e.target.value && onChange([...value, e.target.value])}>
        <option value="">+ Add country</option>
        {COUNTRIES.filter((c) => !value.includes(c.code)).map((c) => (
          <option key={c.code} value={c.code}>{c.name}</option>
        ))}
      </select>
    </div>
  );
}

export function FirewallPage() {
  const { id } = useParams();
  const host = useServerName(id);
  const { user } = useAuth();
  const s = useAgent<{ settings: { firewall: FwSettings }; meta: { firewall: FwStatus } }>(id, 'settings.get');
  const [fw, setFw] = useState<FwSettings | null>(null);
  const [check, setCheck] = useState('');
  const [checkRes, setCheckRes] = useState<any>(null);
  const [view, setView] = useState<{ kind: string; title: string } | null>(null);
  const [providerOpen, setProviderOpen] = useState(false);
  const [provider, setProvider] = useState<'iptables' | 'nftables'>('iptables');
  const { run, busy } = useAction();
  const isAdmin = can(user, 'admin');
  useEffect(() => {
    if (s.data) {
      setFw(s.data.settings.firewall);
      setProvider(s.data.settings.firewall.provider);
    }
  }, [s.data]);
  if (s.loading && !s.data) return <PageLoader />;
  if (s.error && !s.data) return <ErrorBox message={s.error} />;
  if (!fw || !s.data) return null;
  const status = s.data.meta.firewall;

  const save = (patch: Partial<FwSettings>, msg = 'Firewall settings saved') =>
    run(async () => {
      const r = await agentCall(id!, 'settings.set', { firewall: patch });
      await s.reload();
      return r;
    }, msg);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <Breadcrumb items={[host, 'Firewall']} />
          <h1 className="h-title">Firewall</h1>
          <p className="text-sm text-slate-500">
            Manage server firewall settings · provider <strong>{status.provider}</strong>
            {status.enabled && (status.healthy ? <span className="ml-2 text-green-600">● rules active</span> : <span className="ml-2 text-red-600">● rules not loaded</span>)}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Toggle on={fw.enabled} disabled={!isAdmin || busy} onChange={(v) => save({ enabled: v }, v ? 'Firewall enabled' : 'Firewall disabled')} />
          <button className="btn-primary" disabled={!isAdmin || busy} onClick={() => run(() => agentCall(id!, 'fw.apply').then(s.reload), 'Firewall reloaded')}>
            <RefreshCw className="h-4 w-4" /> Restart
          </button>
          <button className="text-slate-500 hover:text-navy-800" title="Firewall provider" onClick={() => setProviderOpen(true)}>
            <Gear className="h-6 w-6" />
          </button>
        </div>
      </div>
      {status.error && <ErrorBox message={`Firewall error: ${status.error}`} />}
      {!status.available && <ErrorBox message={`The ${status.provider} provider is not available on this server: ${status.providers[status.provider]}`} />}

      <Section title="Quick Actions" desc="IP block management">
        <Row title="Check IP" desc="Check the status of an IP in the firewall">
          <form
            className="flex gap-2"
            onSubmit={async (e) => {
              e.preventDefault();
              const r = await run(() => agentCall(id!, 'fw.check', { ip: check.trim() }));
              if (r) setCheckRes(r);
            }}
          >
            <input className="input" value={check} onChange={(e) => setCheck(e.target.value)} placeholder="Enter IP address" />
            <button className="btn-primary px-6" disabled={!check.trim()}>Check IP</button>
          </form>
          {checkRes && (
            <div className="rounded-lg bg-slate-50 p-3 text-sm">
              <div className="flex items-center gap-2 font-medium">
                {checkRes.status.includes('block') ? <XCircle className="h-4 w-4 text-red-600" /> : <CheckCircle2 className="h-4 w-4 text-green-600" />}
                {checkRes.ip}: {checkRes.status === 'none' ? 'not listed' : checkRes.status}
                {checkRes.protected && <span className="text-xs text-slate-500">(protected server/portal address)</span>}
              </div>
              {checkRes.matches.map((m: Rule) => (
                <div key={m.kind + m.cidr} className="text-slate-600">
                  {m.kind}: {m.cidr} {m.comment && `— ${m.comment}`} {m.expires_at ? `(until ${fmtTime(m.expires_at)})` : ''}
                </div>
              ))}
            </div>
          )}
        </Row>
      </Section>

      <Section title="Whitelist" desc="Addresses that XMart Guard will never block">
        <AddRemove serverId={id!} kind="allow" label="Allow IP" removeLabel="Allow remove" withComment />
        <div className="text-right"><button className="text-sm text-navy-700 hover:underline" onClick={() => setView({ kind: 'allow', title: 'Whitelist' })}>View whitelist</button></div>
      </Section>

      <Section title="Blacklist" desc="Permanently blocked addresses">
        <AddRemove serverId={id!} kind="deny" label="Deny IP" removeLabel="Deny remove" withComment />
        <div className="text-right"><button className="text-sm text-navy-700 hover:underline" onClick={() => setView({ kind: 'deny', title: 'Blacklist' })}>View blacklist</button></div>
      </Section>

      <Section title="Temporary ban" desc="Manage temporarily blocked IP addresses">
        <AddRemove serverId={id!} kind="tempban" label="Block IP" removeLabel="Unblock IP" withDuration withComment />
        <div className="text-right"><button className="text-sm text-navy-700 hover:underline" onClick={() => setView({ kind: 'tempban', title: 'Temporarily blocked' })}>View temporary list</button></div>
      </Section>

      <Section title="Temporary allow" desc="Manage temporarily allowed IP addresses">
        <AddRemove serverId={id!} kind="tempallow" label="Allow IP" removeLabel="Remove temporary allow" withDuration />
        <div className="text-right"><button className="text-sm text-navy-700 hover:underline" onClick={() => setView({ kind: 'tempallow', title: 'Temporarily allowed' })}>View temporary list</button></div>
      </Section>

      <Section title="Ignore IPs" desc="IPs excluded from automatic blocking (brute force, DoS)">
        <AddRemove serverId={id!} kind="ignore" label="Ignore IP" removeLabel="Remove ignored IP" withComment />
        <div className="text-right"><button className="text-sm text-navy-700 hover:underline" onClick={() => setView({ kind: 'ignore', title: 'Ignored IPs' })}>View ignored list</button></div>
      </Section>

      <Section title="Brute-force protection (LFD)" desc="Watch SSH, cPanel/WHM/Webmail, mail and FTP logins and temporarily ban abusive IPs">
        <SettingRow title="Intrusion Defense" desc="Temporarily block IPs with repeated failed logins" recommended>
          <Toggle on={fw.bruteforce} disabled={!isAdmin || busy} onChange={(v) => save({ bruteforce: v })} />
        </SettingRow>
        <div className="grid gap-3 py-4 sm:grid-cols-3">
          <label className="text-sm">
            <span className="label">Failed logins</span>
            <input className="input" type="number" min={2} value={fw.bf_threshold} disabled={!isAdmin} onChange={(e) => setFw({ ...fw, bf_threshold: Number(e.target.value) })} />
          </label>
          <label className="text-sm">
            <span className="label">Within (minutes)</span>
            <input className="input" type="number" min={1} value={fw.bf_window_minutes} disabled={!isAdmin} onChange={(e) => setFw({ ...fw, bf_window_minutes: Number(e.target.value) })} />
          </label>
          <label className="text-sm">
            <span className="label">Ban for (minutes)</span>
            <input className="input" type="number" min={1} value={fw.ban_minutes} disabled={!isAdmin} onChange={(e) => setFw({ ...fw, ban_minutes: Number(e.target.value) })} />
          </label>
        </div>
        <div className="flex justify-end">
          <button className="btn-primary" disabled={!isAdmin || busy} onClick={() => save({ bf_threshold: fw.bf_threshold, bf_window_minutes: fw.bf_window_minutes, ban_minutes: fw.ban_minutes })}>Save</button>
        </div>
      </Section>

      <Section title="DoS Protection" desc="Configure DoS protection settings">
        <SettingRow title="DoS Mitigation" desc="Temporarily block IPs that open too many new connections">
          <Toggle on={fw.dos} disabled={!isAdmin || busy} onChange={(v) => save({ dos: v })} />
        </SettingRow>
        <SettingRow title="DoS Threshold" desc="Maximum new connections per minute per IP before blocking">
          <input className="input w-28" type="number" min={20} value={fw.dos_threshold} disabled={!isAdmin} onChange={(e) => setFw({ ...fw, dos_threshold: Number(e.target.value) })} onBlur={() => save({ dos_threshold: fw.dos_threshold })} />
        </SettingRow>
      </Section>

      <Section title="Country filtering" desc="Restrict inbound traffic based on geographic location (IPv4)">
        <Row title="Allowed Countries" desc="IPs of these countries bypass country blocking">
          <CountryPicker value={fw.allowed_countries} disabled={!isAdmin} onChange={(v) => setFw({ ...fw, allowed_countries: v })} />
        </Row>
        <Row title="Blocked Countries" desc="Block connections from these countries">
          <CountryPicker value={fw.blocked_countries} disabled={!isAdmin} onChange={(v) => setFw({ ...fw, blocked_countries: v })} />
        </Row>
        <div className="flex justify-end gap-2">
          <button className="btn-outline" disabled={!isAdmin} onClick={() => setFw(s.data!.settings.firewall)}>Reset</button>
          <button className="btn-primary" disabled={!isAdmin || busy} onClick={() => save({ allowed_countries: fw.allowed_countries, blocked_countries: fw.blocked_countries }, 'Country rules saved')}>
            <Globe className="h-4 w-4" /> Save
          </button>
        </div>
      </Section>

      {view && <ListModal serverId={id!} kind={view.kind} title={view.title} onClose={() => setView(null)} />}

      {providerOpen && (
        <Modal title="Firewall Provider" onClose={() => setProviderOpen(false)}>
          <p className="mb-4 text-slate-600">Choose the underlying packet filtering provider for your server's firewall.</p>
          <div className="grid gap-4 md:grid-cols-2">
            {([
              ['iptables', 'Stable and reliable filtering with ipset. Proven for real-world production loads and compatible with CSF and cPanel.', true],
              ['nftables', 'Modern kernel packet filter. Use it on servers that no longer ship iptables.', false],
            ] as const).map(([name, desc, rec]) => (
              <label key={name} className={`cursor-pointer rounded-xl border p-4 ${provider === name ? 'border-navy-600 bg-navy-100/40' : 'border-slate-200'}`}>
                <div className="flex items-start gap-3">
                  <input type="radio" className="mt-1" checked={provider === name} onChange={() => setProvider(name)} />
                  <div>
                    <div className="font-semibold text-navy-900">{name}</div>
                    <div className="mt-1 text-sm text-slate-600">{desc}</div>
                    <div className="mt-2 flex gap-2">
                      {status.provider === name && <span className="rounded bg-green-50 px-2 py-0.5 text-xs text-green-700">current</span>}
                      {rec && <span className="rounded bg-blue-50 px-2 py-0.5 text-xs text-blue-700">Recommended</span>}
                      {status.providers[name] && <span className="rounded bg-red-50 px-2 py-0.5 text-xs text-red-700">{status.providers[name]}</span>}
                    </div>
                  </div>
                </div>
              </label>
            ))}
          </div>
          <div className="mt-6 flex justify-end">
            <button
              className="btn-primary"
              disabled={!isAdmin || busy || provider === status.provider}
              onClick={async () => {
                const r = await save({ provider }, `Switched to ${provider}`);
                if (r) setProviderOpen(false);
              }}
            >
              <RefreshCw className="h-4 w-4" /> Switch to {provider}
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

interface FwEvent {
  id: number;
  ip: string;
  reason: string;
  source: string;
  created_at: number;
  expires_at: number;
  status: string;
}

export function FirewallLogs() {
  const { id } = useParams();
  const host = useServerName(id);
  const { user } = useAuth();
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('');
  const [offset, setOffset] = useState(0);
  const limit = 25;
  const list = useAgent<{ events: FwEvent[]; total: number }>(id, 'fw.events', { q: query, status, limit, offset }, 15_000);
  const { run } = useAction();
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <Breadcrumb items={[host, 'Firewall Logs']} />
          <h1 className="h-title">Firewall Logs</h1>
        </div>
        <div className="flex gap-2">
          <select className="input w-40" value={status} onChange={(e) => (setStatus(e.target.value), setOffset(0))}>
            <option value="">All</option>
            <option value="blocked">Blocked</option>
            <option value="expired">Expired</option>
            <option value="unblocked">Unblocked</option>
          </select>
          <form onSubmit={(e) => (e.preventDefault(), setQuery(q), setOffset(0))}>
            <input className="input w-56" placeholder="Type to filter" value={q} onChange={(e) => setQ(e.target.value)} />
          </form>
        </div>
      </div>
      <div className="card overflow-x-auto p-5">
        {list.error && <ErrorBox message={list.error} />}
        {list.loading && !list.data ? (
          <PageLoader />
        ) : !list.data?.events.length ? (
          <Empty text="No blocked addresses yet" />
        ) : (
          <>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-slate-500">
                  <th className="py-3 font-medium">IP Address</th>
                  <th className="py-3 font-medium">Reason</th>
                  <th className="py-3 font-medium">Source</th>
                  <th className="py-3 font-medium">Expiry</th>
                  <th className="py-3 font-medium">Time</th>
                  <th className="py-3 font-medium">Status</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {list.data.events.map((e) => (
                  <tr key={e.id} className="border-b border-slate-100 last:border-0">
                    <td className="py-3 font-mono">{e.ip}</td>
                    <td className="py-3">{e.reason}</td>
                    <td className="py-3 capitalize">{e.source}</td>
                    <td className="py-3 whitespace-nowrap">{e.expires_at ? fmtTime(e.expires_at) : 'permanent'}</td>
                    <td className="py-3 whitespace-nowrap">{fmtTime(e.created_at)}</td>
                    <td className="py-3"><Badge value={e.status} /></td>
                    <td className="py-3 text-right">
                      {e.status === 'blocked' && can(user, 'operator') && (
                        <button className="text-sm text-navy-700 hover:underline" onClick={() => run(() => agentCall(id!, 'fw.unblock', { addr: e.ip }).then(list.reload), `${e.ip} unblocked`)}>
                          Unblock
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pager total={list.data.total} limit={limit} offset={offset} onChange={setOffset} />
          </>
        )}
      </div>
    </div>
  );
}

interface Listing {
  rbl: string;
  listed: boolean;
  answer?: string;
  error?: string;
}
interface Report {
  ip: string;
  checked_at: number;
  duration_ms: number;
  listed_on: number;
  checked: number;
  results: Listing[];
}

export function IPReputation() {
  const { id } = useParams();
  const host = useServerName(id);
  const { user } = useAuth();
  const rep = useAgent<{ ips: string[]; reports: Record<string, Report | null>; rbls: string[] }>(id, 'reputation.get');
  const [sel, setSel] = useState('');
  const [q, setQ] = useState('');
  const { run, busy } = useAction();
  useEffect(() => {
    if (rep.data && !sel && rep.data.ips.length) setSel(rep.data.ips[0]);
  }, [rep.data, sel]);
  if (rep.loading && !rep.data) return <PageLoader />;
  if (rep.error && !rep.data) return <ErrorBox message={rep.error} />;
  const r = sel ? rep.data?.reports[sel] ?? null : null;
  const pct = r && r.checked ? Math.round((r.listed_on / r.checked) * 100) : 0;
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <Breadcrumb items={[host, 'IP Reputation']} />
          <h1 className="h-title">IP Reputation{sel && <span className="ml-3 text-slate-500">IP {sel}</span>}</h1>
        </div>
        <button
          className="btn-primary"
          disabled={!can(user, 'operator') || busy || !sel}
          onClick={() => run(() => agentCall(id!, 'reputation.check', { ip: sel }).then(rep.reload), 'Check complete')}
        >
          {busy ? 'Checking…' : 'Check Now'}
        </button>
      </div>
      <div className="grid gap-5 lg:grid-cols-[260px_1fr]">
        <div className="card p-4">
          <input className="input mb-3" placeholder="Search IP" value={q} onChange={(e) => setQ(e.target.value)} />
          {rep.data!.ips.filter((ip) => ip.includes(q)).map((ip) => {
            const x = rep.data!.reports[ip];
            return (
              <button key={ip} onClick={() => setSel(ip)} className={`block w-full rounded-lg px-3 py-2 text-left font-semibold ${sel === ip ? 'bg-navy-100' : ''} ${x?.listed_on ? 'text-red-600' : 'text-green-600'}`}>
                {ip}
              </button>
            );
          })}
          {rep.data!.ips.length === 0 && <p className="text-sm text-slate-500">No public IPv4 addresses found. Add IPs under Settings → RBL &amp; IP Reputation.</p>}
        </div>
        <div className="space-y-5">
          {!r ? (
            <div className="card p-10 text-center text-slate-500">This IP has not been checked yet. Click <strong>Check Now</strong>.</div>
          ) : (
            <>
              <div className="grid gap-4 md:grid-cols-3">
                <div className="card p-5">
                  <div className={`text-2xl font-bold ${r.listed_on ? 'text-red-600' : 'text-green-600'}`}>{r.listed_on ? 'BLACKLISTED' : 'ITS GOOD'}</div>
                  <div className="text-sm text-slate-500">{r.listed_on ? `listed on ${r.listed_on} DNSBL host(s)` : 'the IP is not blacklisted by any DNSBL hosts'}</div>
                </div>
                <div className="card p-5">
                  <div className="text-2xl font-bold text-navy-900">{pct}%</div>
                  <div className="text-sm text-slate-500">DNSBL hosts reported IP in the blacklist</div>
                </div>
                <div className="card p-5">
                  <div className="text-lg font-semibold text-navy-900">{fmtTime(r.checked_at)}</div>
                  <div className="text-sm text-slate-500">Scan time · {(r.duration_ms / 1000).toFixed(1)}s duration</div>
                </div>
              </div>
              <div className="card p-5">
                <h3 className="mb-3 font-semibold text-navy-900">DNSBL Report — {r.results.length} DNSBL hosts</h3>
                <div className="grid gap-x-6 gap-y-1 sm:grid-cols-2 xl:grid-cols-3">
                  {r.results.map((l) => (
                    <div key={l.rbl} className="flex items-center gap-2 text-sm" title={l.error || l.answer || ''}>
                      {l.listed ? <XCircle className="h-4 w-4 text-red-600" /> : l.error ? <ShieldAlert className="h-4 w-4 text-slate-400" /> : <CheckCircle2 className="h-4 w-4 text-green-600" />}
                      <span className={l.listed ? 'font-medium text-red-600' : l.error ? 'text-slate-400' : 'text-navy-900'}>{l.rbl}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
