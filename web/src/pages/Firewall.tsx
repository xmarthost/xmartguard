import { useEffect, useState, type ReactNode } from 'react';
import { useParams } from 'react-router-dom';
import { CheckCircle2, Download, Globe, RefreshCw, Search, Settings as Gear, ShieldAlert, Trash2, XCircle } from 'lucide-react';
import { downloadCSV, useCountries } from '../components/geo';
import { flag } from '../components/WorldMap';
import { can, useAuth } from '../auth';
import { Breadcrumb, Empty, ErrorBox, PageLoader } from '../components/ui';
import { Modal, Pager, SettingRow, Toggle, agentCall, fmtTime, isIPorCIDR, useAction, useAgent } from '../components/controls';
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
  log_blocked: boolean;
  blocked_countries: string[];
  allowed_countries: string[];
  ignored_countries: string[];
  ddns: string[];
  excluded_jails: string[];
  waf_ban: boolean;
  waf_ban_threshold: number;
  captcha: boolean;
  port_filter: boolean;
  tcp_in: string;
  udp_in: string;
  tcp_out: string;
  udp_out: string;
}

interface CaptchaSettings {
  provider: 'builtin' | 'turnstile' | 'recaptcha';
  site_key: string;
  secret_key: string;
  allow_minutes: number;
  http_port: number;
  https_port: number;
}

interface FwMeta {
  jails: string[];
  ddns: Record<string, string[]>;
  ssh_ports: number[];
  portal: number[];
  captcha: boolean;
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
  const s = useAgent<{
    settings: { firewall: FwSettings; ipdb: { enabled: boolean; report: boolean; log: boolean; captcha: boolean }; waf: { ai_bots: boolean; enabled: boolean }; captcha: CaptchaSettings };
    meta: { firewall: FwStatus };
  }>(id, 'settings.get');
  const meta = useAgent<FwMeta>(id, 'fw.meta');
  const [cap, setCap] = useState<CaptchaSettings | null>(null);
  const [ddnsHost, setDdnsHost] = useState('');
  const [jail, setJail] = useState('');
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
      setCap(s.data.settings.captcha);
      setProvider(s.data.settings.firewall.provider);
    }
  }, [s.data]);
  if (s.loading && !s.data) return <PageLoader />;
  if (s.error && !s.data) return <ErrorBox message={s.error} />;
  if (!fw || !s.data) return null;
  const status = s.data.meta.firewall;

  const save = (patch: Partial<FwSettings>, msg = 'Firewall settings saved') => saveAny({ firewall: patch }, msg);
  const saveAny = (patch: Record<string, unknown>, msg = 'Settings saved') =>
    run(async () => {
      const r = await agentCall(id!, 'settings.set', patch);
      await Promise.all([s.reload(), meta.reload()]);
      return r;
    }, msg);
  const all = s.data.settings;

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
        <SettingRow title="Show CAPTCHA for blocked IPs" desc="Temporarily blocked visitors see a CAPTCHA page on the websites instead of a dead connection; solving it lifts the ban for their address">
          <Toggle on={fw.captcha} disabled={!isAdmin || busy} onChange={(v) => save({ captcha: v }, v ? 'CAPTCHA enabled' : 'CAPTCHA disabled')} />
        </SettingRow>
        <SettingRow title="WAF Temporary IP Ban" desc={`Temporarily block addresses that the Web Application Firewall blocks ${fw.waf_ban_threshold} times within ${fw.bf_window_minutes} minutes`}>
          <input className="input w-20" type="number" min={3} value={fw.waf_ban_threshold} disabled={!isAdmin} onChange={(e) => setFw({ ...fw, waf_ban_threshold: Number(e.target.value) })} onBlur={() => fw.waf_ban_threshold !== all.firewall.waf_ban_threshold && save({ waf_ban_threshold: fw.waf_ban_threshold })} />
          <Toggle on={fw.waf_ban} disabled={!isAdmin || busy} onChange={(v) => save({ waf_ban: v })} />
        </SettingRow>
      </Section>

      <Section title="Temporary allow" desc="Manage temporarily allowed IP addresses">
        <AddRemove serverId={id!} kind="tempallow" label="Allow IP" removeLabel="Remove temporary allow" withDuration />
        <div className="text-right"><button className="text-sm text-navy-700 hover:underline" onClick={() => setView({ kind: 'tempallow', title: 'Temporarily allowed' })}>View temporary list</button></div>
      </Section>

      <Section title="Dynamic DNS (DDNS) Allowlist" desc="Automatically update the IP allowlist using a Dynamic DNS hostname (resolved every 5 minutes)">
        <Row title="Allow Dynamic DNS hostname" desc="Enter your fully qualified DDNS hostname">
          <div className="flex gap-2">
            <input className="input" value={ddnsHost} onChange={(e) => setDdnsHost(e.target.value)} placeholder="Enter DDNS hostname" />
            <button
              className="btn-primary px-6"
              disabled={!isAdmin || busy || !ddnsHost.trim()}
              onClick={async () => {
                const r = await save({ ddns: [...fw.ddns, ddnsHost.trim().toLowerCase()] }, `${ddnsHost.trim()} added`);
                if (r) setDdnsHost('');
              }}
            >
              Add
            </button>
          </div>
        </Row>
        {fw.ddns.map((h) => (
          <div key={h} className="flex items-center justify-between border-b border-slate-100 py-2 text-sm last:border-0">
            <span>
              <span className="font-mono">{h}</span>
              <span className="ml-3 text-slate-500">{meta.data?.ddns[h]?.length ? meta.data.ddns[h].join(', ') : 'not resolved yet'}</span>
            </span>
            {isAdmin && (
              <button className="text-sm text-red-600 hover:underline" onClick={() => save({ ddns: fw.ddns.filter((x) => x !== h) }, `${h} removed`)}>
                Remove
              </button>
            )}
          </div>
        ))}
      </Section>

      <Section title="Ignore IPs" desc="IPs excluded from automatic blocking (brute force, DoS)">
        <AddRemove serverId={id!} kind="ignore" label="Ignore IP" removeLabel="Remove ignored IP" withComment />
        <div className="text-right"><button className="text-sm text-navy-700 hover:underline" onClick={() => setView({ kind: 'ignore', title: 'Ignored IPs' })}>View ignored list</button></div>
        <Row title="Ignore Countries" desc="IPs of these countries are never blocked by any firewall rule">
          <CountryPicker value={fw.ignored_countries} disabled={!isAdmin} onChange={(v) => setFw({ ...fw, ignored_countries: v })} />
          <div className="flex justify-end gap-2">
            <button className="btn-outline" disabled={!isAdmin} onClick={() => setFw({ ...fw, ignored_countries: all.firewall.ignored_countries })}>Reset</button>
            <button className="btn-primary" disabled={!isAdmin || busy} onClick={() => save({ ignored_countries: fw.ignored_countries }, 'Ignored countries saved')}>Save</button>
          </div>
        </Row>
      </Section>

      <Section title="IPDB distributed firewall" desc="IPDB is the shared blocklist of all your servers: an attacker banned on one server is dropped on every server">
        <SettingRow title="IPDB Switch" desc="Enable or disable the IPDB firewall" recommended>
          <Toggle on={all.ipdb.enabled} disabled={!isAdmin || busy} onChange={(v) => saveAny({ ipdb: { enabled: v } })} />
        </SettingRow>
        <SettingRow title="IPDB Log Switch" desc="Enable or disable logging for the IPDB firewall (the live monitor)">
          <Toggle on={all.ipdb.log} disabled={!isAdmin || busy} onChange={(v) => saveAny({ ipdb: { log: v } })} />
        </SettingRow>
        <SettingRow title="IPDB CAPTCHA" desc="Show a CAPTCHA challenge for IPDB-blocked IP addresses on the websites">
          <Toggle on={all.ipdb.captcha} disabled={!isAdmin || busy} onChange={(v) => saveAny({ ipdb: { captcha: v } })} />
        </SettingRow>
        <SettingRow title="Share bans" desc="Report this server's automatic bans to the IPDB">
          <Toggle on={all.ipdb.report} disabled={!isAdmin || busy} onChange={(v) => saveAny({ ipdb: { report: v } })} />
        </SettingRow>
      </Section>

      <Section title="AI Bots" desc="Configure AI bot protection settings">
        <SettingRow title="AI Bots" desc="Block AI training crawlers (GPTBot, CCBot, Bytespider…) with the WAF">
          <Toggle on={all.waf.ai_bots} disabled={!isAdmin || busy} onChange={(v) => saveAny({ waf: { ai_bots: v } })} />
        </SettingRow>
      </Section>

      <Section title="Intrusion Defense (LFD)" desc="Monitor logs for suspicious activity and automatically temporary-ban abusive IP addresses">
        <SettingRow title="Intrusion Defense" desc="Detect and temporarily block abusive IP addresses based on log activity and security thresholds" recommended>
          <Toggle on={fw.bruteforce} disabled={!isAdmin || busy} onChange={(v) => save({ bruteforce: v })} />
        </SettingRow>
        <Row title="Excluded Protection Rules" desc="Exclude selected detection rules from monitoring and temporary bans">
          <div className="flex gap-2">
            <select className="input" value={jail} onChange={(e) => setJail(e.target.value)} disabled={!isAdmin}>
              <option value="">Select rules to exclude</option>
              {(meta.data?.jails ?? []).filter((j) => !fw.excluded_jails.includes(j)).map((j) => (
                <option key={j}>{j}</option>
              ))}
            </select>
            <button className="btn-primary px-5" disabled={!isAdmin || busy || !jail} onClick={async () => (await save({ excluded_jails: [...fw.excluded_jails, jail] }, `${jail} excluded`)) && setJail('')}>
              Exclude
            </button>
          </div>
          {fw.excluded_jails.length === 0 ? (
            <div className="text-sm text-slate-400">No rules excluded.</div>
          ) : (
            fw.excluded_jails.map((j) => (
              <div key={j} className="flex items-center justify-between text-sm">
                {j}
                {isAdmin && (
                  <button className="text-red-600 hover:underline" onClick={() => save({ excluded_jails: fw.excluded_jails.filter((x) => x !== j) }, `${j} monitored again`)}>
                    Remove
                  </button>
                )}
              </div>
            ))
          )}
        </Row>
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

      <Section title="Monitoring" desc="Live logs of blocked connections">
        <SettingRow title="Log blocked connections" desc="Record a sample of dropped connections (up to 10 per second per rule) for the IPDB live monitor. Written at kernel debug level, so system logs stay clean." recommended>
          <Toggle on={fw.log_blocked ?? true} disabled={!isAdmin || busy} onChange={(v) => save({ log_blocked: v })} />
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

      <Section title="Port filter configuration" desc="Set allowed TCP/UDP ports for in/out traffic">
        <SettingRow title="Port filter" desc="Enable or disable firewall port filtering">
          <Toggle on={fw.port_filter} disabled={!isAdmin || busy} onChange={(v) => {
            if (v && !confirm('Enable the port filter? Every port not listed below will be closed.')) return;
            save({ port_filter: v, tcp_in: fw.tcp_in, udp_in: fw.udp_in, tcp_out: fw.tcp_out, udp_out: fw.udp_out }, v ? 'Port filter enabled' : 'Port filter disabled');
          }} />
        </SettingRow>
        {([
          ['tcp_in', 'TCP IN', 'Allowed incoming TCP ports'],
          ['udp_in', 'UDP IN', 'Allowed incoming UDP ports'],
          ['tcp_out', 'TCP OUT', 'Allowed outgoing TCP ports'],
          ['udp_out', 'UDP OUT', 'Allowed outgoing UDP ports'],
        ] as const).map(([k, t, d]) => (
          <Row key={k} title={t} desc={d}>
            <textarea className="input h-20 font-mono text-sm" value={fw[k]} disabled={!isAdmin} onChange={(e) => setFw({ ...fw, [k]: e.target.value })} />
          </Row>
        ))}
        <div className="rounded-lg bg-amber-50 p-3 text-sm text-amber-800">
          Warning: you are about to change critical network port configurations (TCP/UDP). This can affect network connectivity and security.
          SSH port{(meta.data?.ssh_ports.length ?? 0) > 1 ? 's' : ''} {meta.data?.ssh_ports.join(', ')} and the portal port {meta.data?.portal.join(', ')} always stay open.
        </div>
        <div className="flex justify-end gap-2 pt-2">
          <button className="btn-outline" disabled={!isAdmin} onClick={() => setFw({ ...fw, tcp_in: all.firewall.tcp_in, udp_in: all.firewall.udp_in, tcp_out: all.firewall.tcp_out, udp_out: all.firewall.udp_out })}>Reset</button>
          <button className="btn-primary" disabled={!isAdmin || busy} onClick={() => save({ tcp_in: fw.tcp_in, udp_in: fw.udp_in, tcp_out: fw.tcp_out, udp_out: fw.udp_out }, 'Ports saved')}>Save</button>
        </div>
      </Section>

      {cap && (
        <Section title="CAPTCHA page" desc="The page banned visitors see when CAPTCHA is on. The built-in challenge needs no third-party service.">
          <Row title="Provider" desc="Built-in image challenge, Cloudflare Turnstile or Google reCAPTCHA v2">
            <select className="input" value={cap.provider} disabled={!isAdmin} onChange={(e) => setCap({ ...cap, provider: e.target.value as CaptchaSettings['provider'] })}>
              <option value="builtin">Built-in (no third party)</option>
              <option value="turnstile">Cloudflare Turnstile</option>
              <option value="recaptcha">Google reCAPTCHA v2</option>
            </select>
            {cap.provider !== 'builtin' && (
              <>
                <input className="input" placeholder="Site key" value={cap.site_key} onChange={(e) => setCap({ ...cap, site_key: e.target.value })} />
                <input className="input" placeholder="Secret key" value={cap.secret_key} onChange={(e) => setCap({ ...cap, secret_key: e.target.value })} />
              </>
            )}
          </Row>
          <Row title="Allow after solving" desc="How long an address stays allowed after solving the CAPTCHA (minutes)">
            <input className="input w-28" type="number" min={5} value={cap.allow_minutes} onChange={(e) => setCap({ ...cap, allow_minutes: Number(e.target.value) })} />
          </Row>
          <div className="flex items-center justify-between gap-2">
            <span className="text-sm text-slate-500">{meta.data?.captcha ? `CAPTCHA server running on ports ${cap.http_port}/${cap.https_port}` : 'CAPTCHA server is off (no CAPTCHA option enabled)'}</span>
            <button className="btn-primary" disabled={!isAdmin || busy} onClick={() => saveAny({ captcha: cap }, 'CAPTCHA settings saved')}>Save</button>
          </div>
        </Section>
      )}

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

const FW_FILTERS = [
  { v: '', l: 'Filter All' },
  { v: 'blocked', l: 'Blocked' },
  { v: 'captcha', l: 'Captcha solved' },
  { v: 'expired', l: 'Expired' },
  { v: 'unblocked', l: 'Unblocked' },
];

const STATUS_STYLE: Record<string, string> = {
  blocked: 'bg-navy-600 text-white',
  captcha: 'bg-amber-200 text-amber-900',
  expired: 'bg-slate-100 text-slate-500',
  unblocked: 'bg-slate-100 text-slate-600',
};

export function FirewallLogs() {
  const { id } = useParams();
  const host = useServerName(id);
  const { user } = useAuth();
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('');
  const [offset, setOffset] = useState(0);
  const [limit, setLimit] = useState(25);
  const list = useAgent<{ events: FwEvent[]; total: number }>(id, 'fw.events', { q: query, status, limit, offset }, 15_000);
  const cc = useCountries(list.data?.events.map((e) => e.ip) ?? []);
  const { run, busy } = useAction();
  const del = (e: FwEvent) => {
    if (e.status === 'blocked' && !confirm(`${e.ip} is still blocked. Delete the entry and unblock it?`)) return;
    run(() => agentCall(id!, 'fw.event_delete', { id: e.id }).then(list.reload), e.status === 'blocked' ? `${e.ip} unblocked` : 'Entry deleted');
  };
  const csv = async () => {
    const r = await run(() => agentCall<{ events: FwEvent[] }>(id!, 'fw.events', { q: query, status, limit: 500, offset: 0 }));
    if (r)
      downloadCSV(`firewall-logs-${host}.csv`, ['ip', 'country', 'reason', 'source', 'expiry', 'time', 'status'],
        r.events.map((e) => [e.ip, cc[e.ip] ?? '', e.reason, e.source, e.expires_at ? new Date(e.expires_at * 1000).toISOString() : 'permanent', new Date(e.created_at * 1000).toISOString(), e.status]));
  };
  return (
    <div className="space-y-5">
      <Breadcrumb items={[host, 'Firewall Logs']} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="h-title">Firewall Logs</h1>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center rounded-lg border border-slate-300 bg-white">
            <select className="rounded-l-lg bg-transparent px-3 py-2 text-sm outline-none" value={status} onChange={(e) => (setStatus(e.target.value), setOffset(0))}>
              {FW_FILTERS.map((f) => (
                <option key={f.v} value={f.v}>{f.l}</option>
              ))}
            </select>
            <form className="flex items-center border-l border-slate-200" onSubmit={(e) => (e.preventDefault(), setQuery(q.trim()), setOffset(0))}>
              <input className="w-56 bg-transparent px-3 py-2 text-sm outline-none" placeholder="Type to filter" value={q} onChange={(e) => setQ(e.target.value)} />
              <button className="px-3 text-slate-500" aria-label="search"><Search className="h-4 w-4" /></button>
            </form>
          </div>
          <button className="btn-outline" title="Download CSV" disabled={busy || !list.data?.events.length} onClick={csv}>
            <Download className="h-4 w-4" />
          </button>
        </div>
      </div>
      <div className="card overflow-x-auto p-0">
        {list.error && <div className="p-4"><ErrorBox message={list.error} /></div>}
        {list.loading && !list.data ? (
          <PageLoader />
        ) : !list.data?.events.length ? (
          <Empty text="No blocked addresses yet" />
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-slate-600">
              <tr>
                <th className="px-5 py-3 font-medium">IP Address</th>
                <th className="py-3 font-medium">Reason</th>
                <th className="py-3 font-medium">Expiry</th>
                <th className="py-3 font-medium">Time</th>
                <th className="py-3 font-medium">Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.data.events.map((e) => (
                <tr key={e.id} className="border-b border-slate-100 last:border-0">
                  <td className="px-5 py-3.5 whitespace-nowrap">
                    <span className="mr-2" title={cc[e.ip] ? countryName(cc[e.ip]) : ''}>{cc[e.ip] ? flag(cc[e.ip]) : '🏳️'}</span>
                    <span className="font-mono">{e.ip}</span>
                  </td>
                  <td className="py-3.5" title={`source: ${e.source}`}>{e.reason}</td>
                  <td className="py-3.5 whitespace-nowrap">{e.expires_at ? fmtTime(e.expires_at) : e.status === 'blocked' ? 'permanent' : ''}</td>
                  <td className="py-3.5 whitespace-nowrap">{fmtTime(e.created_at)}</td>
                  <td className="py-3.5">
                    <span className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${STATUS_STYLE[e.status] ?? 'bg-slate-100 text-slate-600'}`}>{e.status}</span>
                  </td>
                  <td className="px-4 py-3.5 text-right">
                    {can(user, 'operator') && (
                      <button className="text-slate-400 hover:text-red-600" title={e.status === 'blocked' ? 'Unblock and delete' : 'Delete'} disabled={busy} onClick={() => del(e)}>
                        <Trash2 className="h-4 w-4" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {list.data && (
        <div className="flex flex-wrap items-center justify-end gap-3 text-sm">
          <label className="flex items-center gap-2 text-slate-500">
            Items per page:
            <select className="input w-20" value={limit} onChange={(e) => (setOffset(0), setLimit(Number(e.target.value)))}>
              {[25, 50, 100].map((n) => <option key={n}>{n}</option>)}
            </select>
          </label>
          <Pager total={list.data.total} limit={limit} offset={offset} onChange={setOffset} />
        </div>
      )}
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
  const [newIP, setNewIP] = useState('');
  const { run, busy } = useAction();
  const addIP = async () => {
    const ip = newIP.trim();
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return alert('Enter an IPv4 address');
    // An explicit list replaces "all public IPs", so keep the current ones.
    const ips = Array.from(new Set([...(rep.data?.ips ?? []), ip]));
    const r = await run(() => agentCall(id!, 'settings.set', { reputation: { ips } }).then(() => agentCall(id!, 'reputation.check', { ip })).then(rep.reload), `${ip} added and checked`);
    if (r !== undefined) {
      setNewIP('');
      setSel(ip);
    }
  };
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
          {rep.data!.ips.length === 0 && <p className="text-sm text-slate-500">No public IPv4 addresses found.</p>}
          {can(user, 'admin') && (
            <form className="mt-4 border-t border-slate-100 pt-3" onSubmit={(e) => (e.preventDefault(), addIP())}>
              <div className="mb-2 text-sm font-medium text-navy-900">Add a new IP to monitor</div>
              <div className="flex gap-2">
                <input className="input" placeholder="IPv4 address" value={newIP} onChange={(e) => setNewIP(e.target.value)} />
                <button className="btn-primary px-3" disabled={busy || !newIP.trim()}>Add</button>
              </div>
            </form>
          )}
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
