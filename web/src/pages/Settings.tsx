import { useEffect, useState, type ReactNode } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { Bell, Bug, CheckCircle2, Info, Lock, Settings as SettingsIcon } from 'lucide-react';
import { api, type Server } from '../api';
import { can, useAuth } from '../auth';
import { useApi } from '../hooks';
import { ErrorBox, PageLoader } from '../components/ui';
import { ListEditor, SettingRow, Tabs, Toggle, agentCall, useAction, useAgent } from '../components/controls';

interface ScannerS {
  enabled: boolean;
  realtime: boolean;
  virus_action: string;
  suspicious_action: string;
  binary_action: string;
  daily_scan: boolean;
  weekly_scan: boolean;
  use_clamav: boolean;
  max_file_size_mb: number;
  whitelist_users: string[];
  whitelist_paths: string[];
  blacklist_names: string[];
}
interface ReputationS {
  enabled: boolean;
  ips: string[];
  rbls: string[];
  interval_hours: number;
}
interface NotificationsS {
  email: string;
  on_virus: boolean;
  on_suspicious: boolean;
  on_binary: boolean;
  on_ban: boolean;
  on_blacklist: boolean;
}
interface AllSettings {
  scanner: ScannerS;
  reputation: ReputationS;
  notifications: NotificationsS;
}
interface Meta {
  clamav: string;
  users: { name: string }[];
  server_ips: string[];
  default_rbls: string[];
}

type Section = 'scanner' | 'rbl' | 'notifications' | 'about';
const NAV: { v: Section | string; l: string; icon: ReactNode; soon?: boolean }[] = [
  { v: 'scanner', l: 'Virus Scanner', icon: <Bug className="h-4 w-4" /> },
  { v: 'rbl', l: 'RBL & IP Reputation', icon: <Lock className="h-4 w-4" /> },
  { v: 'waf', l: 'WAF & Bruteforce', icon: <Lock className="h-4 w-4" />, soon: true },
  { v: 'cms', l: 'WordPress and CMS', icon: <Lock className="h-4 w-4" />, soon: true },
  { v: 'suspension', l: 'Automatic Suspension', icon: <Lock className="h-4 w-4" />, soon: true },
  { v: 'osm', l: 'Outgoing Spam Monitor', icon: <Lock className="h-4 w-4" />, soon: true },
  { v: 'notifications', l: 'Notifications', icon: <Bell className="h-4 w-4" /> },
  { v: 'about', l: 'About', icon: <Info className="h-4 w-4" /> },
];

const ACTIONS = [
  { v: 'notify', l: 'Email Only', d: 'Only report the file (and email if notifications are on). Handle it manually.' },
  { v: 'quarantine', l: 'Quarantine', d: 'Move the file securely to the quarantine directory. It can be restored.', rec: true },
  { v: 'disable', l: 'Disable File', d: 'Disables the detected file by setting its permission to 000.' },
];

export default function SettingsPage() {
  const { id } = useParams();
  const [sp, setSp] = useSearchParams();
  const section = (sp.get('s') as Section) || 'scanner';
  const { user } = useAuth();
  const res = useAgent<{ settings: AllSettings; meta: Meta }>(id, 'settings.get');
  const [st, setSt] = useState<AllSettings | null>(null);
  const { run, busy } = useAction();
  const admin = can(user, 'admin');
  useEffect(() => {
    if (res.data) setSt(res.data.settings);
  }, [res.data]);

  const save = async (patch: Partial<Record<keyof AllSettings, any>>, msg = 'Settings saved') => {
    const r = await run(() => agentCall<{ settings: AllSettings }>(id!, 'settings.set', patch), msg);
    if (r) setSt((cur) => ({ ...(cur as AllSettings), ...r.settings }));
    return r;
  };
  const setScanner = (p: Partial<ScannerS>) => save({ scanner: p });

  if (res.loading && !res.data) return <PageLoader />;
  if (res.error && !res.data) return <ErrorBox message={res.error} />;
  if (!st || !res.data) return null;
  const meta = res.data.meta;

  return (
    <div className="grid gap-5 lg:grid-cols-[240px_1fr]">
      <div className="card h-fit p-3">
        <div className="mb-3 flex items-center gap-2 px-2 text-lg font-semibold text-navy-900"><SettingsIcon className="h-5 w-5" /> Settings</div>
        {NAV.map((n) => (
          <button
            key={n.v}
            disabled={n.soon}
            onClick={() => setSp({ s: n.v })}
            className={`flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm ${section === n.v ? 'bg-navy-100 font-medium text-navy-900' : 'text-slate-600 hover:bg-slate-50'} disabled:cursor-not-allowed disabled:opacity-50`}
          >
            {n.icon} {n.l}
            {n.soon && <span className="ml-auto rounded bg-slate-100 px-1.5 text-[10px] text-slate-500">soon</span>}
          </button>
        ))}
      </div>

      <div className="card p-6">
        {!admin && <div className="mb-4 rounded-lg bg-amber-50 p-3 text-sm text-amber-800">You can view settings; only admins can change them.</div>}
        {section === 'scanner' && <ScannerSection s={st.scanner} meta={meta} admin={admin} busy={busy} onSave={setScanner} />}
        {section === 'rbl' && <RBLSection s={st.reputation} meta={meta} admin={admin} busy={busy} onSave={(p) => save({ reputation: p })} />}
        {section === 'notifications' && <NotificationsSection s={st.notifications} admin={admin} busy={busy} onSave={(p) => save({ notifications: p })} />}
        {section === 'about' && <About serverId={id!} />}
      </div>
    </div>
  );
}

function ScannerSection({ s, meta, admin, busy, onSave }: { s: ScannerS; meta: Meta; admin: boolean; busy: boolean; onSave: (p: Partial<ScannerS>) => void }) {
  const [tab, setTab] = useState<'virus_action' | 'suspicious_action' | 'binary_action'>('virus_action');
  const dis = !admin || busy;
  return (
    <div>
      <div className="mb-4 flex items-start justify-between">
        <div>
          <h2 className="text-lg font-semibold text-navy-900">Virus Scanner</h2>
          <div className="mt-1 flex items-center gap-2 text-sm text-slate-500">
            <CheckCircle2 className={`h-4 w-4 ${s.enabled ? 'text-green-600' : 'text-slate-300'}`} />
            {s.enabled ? 'XMart Guard scanner engine is running.' : 'The scanner is disabled.'}
            {meta.clamav ? ` ClamAV detected (${meta.clamav}).` : ' ClamAV not installed; built-in signatures only.'}
          </div>
        </div>
        <Toggle on={s.enabled} disabled={dis} onChange={(v) => onSave({ enabled: v })} />
      </div>

      <h3 className="mt-2 mb-2 font-semibold text-navy-900">What to do with</h3>
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { v: 'virus_action', l: 'Virus Files' },
          { v: 'suspicious_action', l: 'Suspicious Files' },
          { v: 'binary_action', l: 'Binary Files' },
        ]}
      />
      <div className="mt-3 space-y-2">
        {ACTIONS.map((a) => (
          <label key={a.v} className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 ${s[tab] === a.v ? 'border-navy-600 bg-navy-100/40' : 'border-slate-200'}`}>
            <input type="radio" className="mt-1" disabled={dis} checked={s[tab] === a.v} onChange={() => onSave({ [tab]: a.v } as Partial<ScannerS>)} />
            <div className="flex-1">
              <div className="text-sm font-medium text-navy-900">{a.l}</div>
              <div className="text-xs text-slate-500">{a.d}</div>
            </div>
            {a.rec && tab !== 'suspicious_action' && <span className="text-xs text-orange-500">★ recommended</span>}
          </label>
        ))}
      </div>

      <div className="mt-4">
        <SettingRow title="Realtime scanning" desc="Scan files in website directories as soon as they are written" recommended>
          <Toggle on={s.realtime} disabled={dis} onChange={(v) => onSave({ realtime: v })} />
        </SettingRow>
        <SettingRow title="Daily scan" desc="Scan all files modified in the last 24 hours (runs between 02:00 and 05:00)" recommended>
          <Toggle on={s.daily_scan} disabled={dis} onChange={(v) => onSave({ daily_scan: v })} />
        </SettingRow>
        <SettingRow title="Weekly scan" desc="Scan all files modified in the last 7 days (Sunday night)" recommended>
          <Toggle on={s.weekly_scan} disabled={dis} onChange={(v) => onSave({ weekly_scan: v })} />
        </SettingRow>
        <SettingRow title="Use ClamAV" desc="Also scan with ClamAV (clamdscan) when it is installed on the server">
          <Toggle on={s.use_clamav} disabled={dis} onChange={(v) => onSave({ use_clamav: v })} />
        </SettingRow>
        <SettingRow title="Maximum file size" desc="Larger files are skipped (MB)">
          <input className="input w-24" type="number" min={1} max={100} defaultValue={s.max_file_size_mb} disabled={dis} onBlur={(e) => Number(e.target.value) !== s.max_file_size_mb && onSave({ max_file_size_mb: Number(e.target.value) })} />
        </SettingRow>
        <ListEditor
          title="Whitelist Users"
          desc="Files owned by these users are not scanned"
          items={s.whitelist_users}
          options={meta.users.map((u) => u.name)}
          disabled={dis}
          empty="No whitelisted users"
          onChange={(v) => onSave({ whitelist_users: v })}
        />
        <ListEditor
          title="Whitelist Files"
          desc="File name, or absolute file/directory path, to exclude from the scanner"
          items={s.whitelist_paths}
          disabled={dis}
          empty="No whitelisted files"
          onChange={(v) => onSave({ whitelist_paths: v })}
        />
        <ListEditor
          title="Blacklist Files"
          desc="File names that are always treated as malware"
          items={s.blacklist_names}
          disabled={dis}
          empty="No blacklisted files"
          onChange={(v) => onSave({ blacklist_names: v })}
        />
      </div>
    </div>
  );
}

function RBLSection({ s, meta, admin, busy, onSave }: { s: ReputationS; meta: Meta; admin: boolean; busy: boolean; onSave: (p: Partial<ReputationS>) => void }) {
  const [rbls, setRbls] = useState(s.rbls);
  useEffect(() => setRbls(s.rbls), [s.rbls]);
  const all = Array.from(new Set([...meta.default_rbls, ...s.rbls]));
  const dis = !admin || busy;
  const publicIPs = meta.server_ips.filter((ip) => !ip.includes(':'));
  return (
    <div>
      <h2 className="text-lg font-semibold text-navy-900">RBL &amp; IP Reputation</h2>
      <p className="mb-2 text-sm text-slate-500">Check this server's IP addresses against DNS blocklists</p>
      <SettingRow title="IP Reputation Monitoring" desc={`Check automatically every ${s.interval_hours} hours and alert when an IP becomes listed`} recommended>
        <Toggle on={s.enabled} disabled={dis} onChange={(v) => onSave({ enabled: v })} />
      </SettingRow>
      <div className="border-b border-slate-100 py-4">
        <div className="font-medium text-navy-900">Monitored IPs</div>
        <div className="mb-2 text-sm text-slate-500">Leave all unchecked to monitor every public IPv4 address of the server</div>
        <div className="flex flex-wrap gap-2">
          {publicIPs.map((ip) => (
            <label key={ip} className="flex items-center gap-2 rounded border border-slate-300 px-3 py-1.5 text-sm">
              <input type="checkbox" disabled={dis} checked={s.ips.includes(ip)} onChange={(e) => onSave({ ips: e.target.checked ? [...s.ips, ip] : s.ips.filter((x) => x !== ip) })} />
              {ip}
            </label>
          ))}
        </div>
      </div>
      <div className="py-4">
        <div className="mb-2 flex items-center justify-between">
          <div>
            <div className="font-medium text-navy-900">Choose RBLs</div>
            <div className="text-sm text-slate-500">{rbls.length} of {all.length} selected</div>
          </div>
          <div className="flex gap-2">
            <button className="btn-primary" disabled={dis} onClick={() => setRbls(all)}>Select All</button>
            <button className="btn-outline" disabled={dis} onClick={() => setRbls([])}>Deselect All</button>
          </div>
        </div>
        <div className="grid gap-2 sm:grid-cols-2">
          {all.map((r) => (
            <label key={r} className="flex items-center gap-2 rounded border border-slate-200 px-3 py-2 text-sm">
              <input type="checkbox" disabled={dis} checked={rbls.includes(r)} onChange={(e) => setRbls(e.target.checked ? [...rbls, r] : rbls.filter((x) => x !== r))} />
              {r}
            </label>
          ))}
        </div>
        <ListEditor title="Custom RBL" desc="Add another DNSBL zone" items={[]} disabled={dis} validate={(v) => (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v) ? null : 'Enter a DNS zone like bl.example.org')} onChange={(v) => setRbls(Array.from(new Set([...rbls, ...v])))} />
        <div className="flex justify-end">
          <button className="btn-primary" disabled={dis} onClick={() => onSave({ rbls })}>Save RBLs</button>
        </div>
      </div>
    </div>
  );
}

function NotificationsSection({ s, admin, busy, onSave }: { s: NotificationsS; admin: boolean; busy: boolean; onSave: (p: Partial<NotificationsS>) => void }) {
  const [email, setEmail] = useState(s.email);
  const dis = !admin || busy;
  return (
    <div>
      <h2 className="text-lg font-semibold text-navy-900">Notifications</h2>
      <p className="mb-4 text-sm text-slate-500">Alerts are sent by the server's own mail system (sendmail/Exim). Bursts are combined into one email every 2 minutes.</p>
      <div className="flex gap-2 border-b border-slate-100 pb-4">
        <input className="input" type="email" placeholder="alerts@example.com" value={email} disabled={dis} onChange={(e) => setEmail(e.target.value)} />
        <button className="btn-primary" disabled={dis || email === s.email} onClick={() => onSave({ email })}>Save</button>
      </div>
      <SettingRow title="Virus detections">
        <Toggle on={s.on_virus} disabled={dis} onChange={(v) => onSave({ on_virus: v })} />
      </SettingRow>
      <SettingRow title="Suspicious pattern detections">
        <Toggle on={s.on_suspicious} disabled={dis} onChange={(v) => onSave({ on_suspicious: v })} />
      </SettingRow>
      <SettingRow title="Binary file detections">
        <Toggle on={s.on_binary} disabled={dis} onChange={(v) => onSave({ on_binary: v })} />
      </SettingRow>
      <SettingRow title="On IP blacklist" desc="When a server IP appears on a DNS blocklist">
        <Toggle on={s.on_blacklist} disabled={dis} onChange={(v) => onSave({ on_blacklist: v })} />
      </SettingRow>
      <SettingRow title="On automatic IP ban" desc="Brute-force and DoS bans (can be noisy)">
        <Toggle on={s.on_ban} disabled={dis} onChange={(v) => onSave({ on_ban: v })} />
      </SettingRow>
    </div>
  );
}

function About({ serverId }: { serverId: string }) {
  const { user } = useAuth();
  const { data, reload } = useApi<{ server: Server; latest_agent_version: string | null }>(`/api/servers/${serverId}`);
  const { run, busy } = useAction();
  if (!data) return <PageLoader />;
  const cur = data.server.agent_version;
  const latest = data.latest_agent_version;
  const outdated = latest && cur !== latest;
  return (
    <div>
      <h2 className="mb-4 text-lg font-semibold text-navy-900">About XMart Guard</h2>
      <div className="rounded-xl bg-slate-50 p-5 text-sm">
        <div className="grid grid-cols-[160px_1fr] gap-y-2">
          <span className="text-slate-500">Agent version</span>
          <span className="font-medium">{cur || 'unknown'}</span>
          <span className="text-slate-500">Latest version</span>
          <span className="font-medium">{latest ?? 'unknown'}</span>
          <span className="text-slate-500">Server</span>
          <span className="font-medium">{data.server.hostname}</span>
        </div>
        {outdated && can(user, 'admin') && (
          <button
            className="btn-primary mt-4"
            disabled={busy || !data.server.online}
            onClick={() => run(() => api('POST', `/api/servers/${serverId}/update-agent`, {}).then((r) => (setTimeout(reload, 8000), r)), 'Agent updated; it restarts in a few seconds')}
          >
            {busy ? 'Updating…' : `Update agent to ${latest}`}
          </button>
        )}
        {!outdated && <div className="mt-4 text-green-700">The agent is up to date. New versions are installed automatically.</div>}
      </div>
      <p className="mt-6 text-xs text-slate-400">XMart Guard is developed by XMartHost.</p>
    </div>
  );
}
