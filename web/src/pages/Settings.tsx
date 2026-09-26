import { useEffect, useState, type ReactNode } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { Bell, Bug, CheckCircle2, Globe2, Info, LayoutTemplate, Lock, Mail, Settings as SettingsIcon, Shield, UserX, Wrench } from 'lucide-react';
import { api, type Server } from '../api';
import { can, useAuth } from '../auth';
import { useApi } from '../hooks';
import { ErrorBox, PageLoader } from '../components/ui';
import { ListEditor, SettingRow, Tabs, Toggle, agentCall, isIPorCIDR, useAction, useAgent } from '../components/controls';

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
  delete_symlinks: boolean;
  auto_clean: boolean;
  trim: boolean;
  trim_max_percent: number;
  user_scans: boolean;
  yara: boolean;
  db_whitelist: { id: string; reason: string }[];
  keep_days: number;
}
interface AIS {
  enabled: boolean;
  provider: 'builtin' | 'portal';
  scope: 'suspicious' | 'all';
  max_per_hour: number;
  max_kb: number;
  act: boolean;
  learn: boolean;
}
interface ProcS {
  enabled: boolean;
  kill: boolean;
  whitelist_users: string[];
  whitelist_strings: string[];
}
interface CronS {
  enabled: boolean;
  whitelist_users: string[];
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
  extra_email: string;
  from: string;
  slack_webhook: string;
  telegram_token: string;
  telegram_chat: string;
  daily_report: boolean;
  user_infected: boolean;
  user_suspension: boolean;
  user_patches: boolean;
  user_outdated: 'never' | 'weekly' | 'monthly';
  exclude_users: string[];
}
interface WAFS {
  enabled: boolean;
  upload_scan: boolean;
  sensitive_files: boolean;
  wordpress: boolean;
  bad_bots: boolean;
  seo_bots: boolean;
  ai_bots: boolean;
  custom_bots: string[];
  bruteforce: boolean;
  bf_threshold: number;
  bf_window_minutes: number;
  disabled_rules: number[];
  whitelist_ips: string[];
  login_urls: string[];
  webshell: boolean;
  block_php_upload: boolean;
  whitelist_domains: string[];
}
interface CMSS {
  enabled: boolean;
  core_check: boolean;
  db_scan: boolean;
  interval_hours: number;
  vulns: boolean;
  auto_update: boolean;
  auto_update_cvss: number;
  auto_update_days: number;
  blacklist_plugins: string[];
  exclude_users: string[];
  wp_cron: boolean;
  wp_cron_hours: number;
}
interface OSMS {
  enabled: boolean;
  per_minute: number;
  per_hour: number;
  action: 'notify' | 'hold' | 'suspend';
  check_subjects: boolean;
  spam_patterns: string[];
  whitelist_senders: string[];
  whitelist_ips: string[];
  whitelist_paths: string[];
}
interface SuspendS {
  enabled: boolean;
  detections: number;
  window_hours: number;
  exclude_users: string[];
  on_domain_blacklist: boolean;
  whitelist_domains: string[];
}
interface DomainRepS {
  enabled: boolean;
  interval_hours: number;
  safe_browsing_key: string;
}
interface IPDBS {
  enabled: boolean;
  report: boolean;
}
interface AllSettings {
  scanner: ScannerS;
  ipdb: IPDBS;
  waf: WAFS;
  cms: CMSS;
  osm: OSMS;
  auto_suspend: SuspendS;
  domain_reputation: DomainRepS;
  reputation: ReputationS;
  notifications: NotificationsS;
  ai: AIS;
  processes: ProcS;
  cron: CronS;
  rootkit: { enabled: boolean };
}
interface Meta {
  clamav: string;
  users: { name: string }[];
  server_ips: string[];
  default_rbls: string[];
}

type Section = 'scanner' | 'waf' | 'cms' | 'suspension' | 'osm' | 'rbl' | 'ipdb' | 'additional' | 'notifications' | 'about';
const NAV: { v: Section | string; l: string; icon: ReactNode; soon?: boolean }[] = [
  { v: 'scanner', l: 'Virus Scanner', icon: <Bug className="h-4 w-4" /> },
  { v: 'rbl', l: 'RBL & IP Reputation', icon: <Lock className="h-4 w-4" /> },
  { v: 'ipdb', l: 'IPDB Protection', icon: <Globe2 className="h-4 w-4" /> },
  { v: 'waf', l: 'WAF & Bruteforce', icon: <Shield className="h-4 w-4" /> },
  { v: 'cms', l: 'WordPress and CMS', icon: <LayoutTemplate className="h-4 w-4" /> },
  { v: 'suspension', l: 'Automatic Suspension', icon: <UserX className="h-4 w-4" /> },
  { v: 'additional', l: 'Additional Settings', icon: <Wrench className="h-4 w-4" /> },
  { v: 'osm', l: 'Outgoing Spam Monitor', icon: <Mail className="h-4 w-4" /> },
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
        {section === 'scanner' && st.ai && <AISection s={st.ai} admin={admin} busy={busy} onSave={(p) => save({ ai: p })} />}
        {section === 'additional' && st.processes && (
          <AdditionalSection serverId={id!} st={st} meta={meta} admin={admin} busy={busy} save={save} />
        )}
        {section === 'rbl' && <RBLSection s={st.reputation} meta={meta} admin={admin} busy={busy} onSave={(p) => save({ reputation: p })} />}
        {section === 'rbl' && st.domain_reputation && <DomainRepSection s={st.domain_reputation} admin={admin} busy={busy} onSave={(p) => save({ domain_reputation: p })} />}
        {section === 'waf' && st.waf && <WAFSection serverId={id!} s={st.waf} admin={admin} busy={busy} onSave={(p) => save({ waf: p })} />}
        {section === 'cms' && st.cms && <CMSSection s={st.cms} meta={meta} admin={admin} busy={busy} onSave={(p) => save({ cms: p })} />}
        {section === 'osm' && st.osm && <OSMSection s={st.osm} admin={admin} busy={busy} onSave={(p) => save({ osm: p })} />}
        {section === 'suspension' && st.auto_suspend && <SuspendSection serverId={id!} s={st.auto_suspend} admin={admin} busy={busy} onSave={(p) => save({ auto_suspend: p })} />}
        {section === 'ipdb' && <IPDBSection s={st.ipdb ?? { enabled: true, report: true }} admin={admin} busy={busy} onSave={(p) => save({ ipdb: p })} />}
        {section === 'notifications' && <NotificationsSection s={st.notifications} meta={meta} admin={admin} busy={busy} onSave={(p) => save({ notifications: p })} />}
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
        <SettingRow title="Delete insecure symbolic links" desc="Remove links that point into another account's files, or to files the user could not read otherwise" recommended>
          <Toggle on={s.delete_symlinks} disabled={dis} onChange={(v) => onSave({ delete_symlinks: v })} />
        </SettingRow>
        <SettingRow title="Auto clean infected files" desc="When an infected file is a WordPress core file, restore the original from the official WordPress release (content, plugins and themes are not touched)" recommended>
          <Toggle on={s.auto_clean} disabled={dis} onChange={(v) => onSave({ auto_clean: v })} />
        </SettingRow>
        <SettingRow
          title="Trim injected code"
          desc="When the AI finds hacker code added to a legitimate file (e.g. a backdoor at the top of a plugin file), remove only that code and keep the site running instead of quarantining the whole file. The change is kept only if the file still passes a PHP syntax check and a rescan; the original stays in quarantine and can be restored. Needs the XMart Guard AI (portal) provider."
          recommended
        >
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-1 text-xs text-slate-500">
              max
              <input
                className="input w-16 !py-1"
                type="number"
                min={1}
                max={50}
                defaultValue={s.trim_max_percent}
                disabled={dis}
                onBlur={(e) => Number(e.target.value) !== s.trim_max_percent && onSave({ trim_max_percent: Number(e.target.value) })}
              />
              % of file
            </label>
            <Toggle on={s.trim} disabled={dis} onChange={(v) => onSave({ trim: v })} />
          </div>
        </SettingRow>
        <SettingRow title="YARA rules" desc="Also run YARA rules placed in /etc/xmartguard/yara/*.yar (requires the yara package)">
          <Toggle on={s.yara} disabled={dis} onChange={(v) => onSave({ yara: v })} />
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
        <DBWhitelistEditor items={s.db_whitelist ?? []} disabled={dis} onChange={(v) => onSave({ db_whitelist: v })} />
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

function DBWhitelistEditor({ items, disabled, onChange }: { items: { id: string; reason: string }[]; disabled: boolean; onChange: (v: { id: string; reason: string }[]) => void }) {
  const [sig, setSig] = useState('');
  const [reason, setReason] = useState('');
  return (
    <div className="border-b border-slate-100 py-4">
      <div className="font-medium text-navy-900">Whitelist DB scan signatures</div>
      <div className="mb-3 text-sm text-slate-500">Signature ids you wish to exclude from the database scanner</div>
      <div className="flex flex-wrap gap-3">
        <input className="input flex-1" placeholder="Type signature id here" value={sig} disabled={disabled} onChange={(e) => setSig(e.target.value)} />
        <input className="input flex-1" placeholder="Enter reason" value={reason} disabled={disabled} onChange={(e) => setReason(e.target.value)} />
        <button
          className="btn-primary px-6"
          disabled={disabled || !sig.trim()}
          onClick={() => {
            onChange([...items.filter((x) => x.id !== sig.trim()), { id: sig.trim().replace(/^DB\./, ''), reason: reason.trim() }]);
            setSig('');
            setReason('');
          }}
        >
          Add
        </button>
      </div>
      <div className="mt-3">
        {items.length === 0 ? (
          <div className="text-sm text-slate-400">No whitelisted signatures</div>
        ) : (
          items.map((x) => (
            <div key={x.id} className="flex items-center justify-between border-b border-slate-100 py-2 text-sm last:border-0">
              <span>
                <span className="font-mono">{x.id}</span> <span className="text-slate-500">{x.reason && `— ${x.reason}`}</span>
              </span>
              <button className="text-red-600 hover:underline" disabled={disabled} onClick={() => onChange(items.filter((y) => y.id !== x.id))}>
                Remove
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

const AI_PROVIDERS = [
  {
    v: 'builtin',
    l: 'Built-in AI model (free, offline)',
    d: 'XMart Guard’s own model runs on this server. Free, private, nothing is sent anywhere. It still learns from the fleet when "Learn from all servers" is on.',
  },
  {
    v: 'portal',
    l: 'XMart Guard AI (free AI APIs)',
    d: 'Files go to your portal, which asks the free AI APIs you added under AI Scanner (Gemini, Groq, OpenRouter, …) and switches to the next key when one reaches its limit. Needed for Trim and for "all new files".',
  },
] as const;

function AISection({ s, admin, busy, onSave }: { s: AIS; admin: boolean; busy: boolean; onSave: (p: Partial<AIS>) => void }) {
  const dis = !admin || busy;
  const portalAI = useApi<{ providers: { enabled: number; ready: number } }>('/api/ai/status');
  const pa = portalAI.data?.providers;
  const [f, setF] = useState(s);
  useEffect(() => setF(s), [s]);
  return (
    <div className="mt-6 border-t border-slate-200 pt-6">
      <SettingRow title="AI scanner" desc="Let AI check files. A confident “malicious” verdict can apply the virus action automatically." recommended>
        <Toggle on={s.enabled} disabled={dis} onChange={(v) => onSave({ enabled: v })} />
      </SettingRow>
      <div className="space-y-2 py-3">
        {AI_PROVIDERS.map((p) => (
          <label key={p.v} className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 ${f.provider === p.v ? 'border-navy-600 bg-navy-100/40' : 'border-slate-200'}`}>
            <input type="radio" className="mt-1" disabled={dis} checked={f.provider === p.v} onChange={() => setF({ ...f, provider: p.v })} />
            <div>
              <div className="text-sm font-medium text-navy-900">{p.l}</div>
              <div className="text-xs text-slate-500">{p.d}</div>
            </div>
          </label>
        ))}
      </div>
      {f.provider === 'portal' && (
        <>
          <div className={`mb-3 rounded-lg p-3 text-sm ${pa && pa.ready > 0 ? 'bg-green-50 text-green-800' : 'bg-amber-50 text-amber-800'}`}>
            {!pa ? (
              'Checking the portal AI keys…'
            ) : pa.enabled === 0 ? (
              <>
                No AI API keys yet. Add free keys under{' '}
                <Link className="font-medium underline" to="/ai">
                  AI Scanner
                </Link>
                ; until then this server uses its built-in model.
              </>
            ) : pa.ready === 0 ? (
              'All AI API keys are resting after reaching their limits; files wait for the next free key (the built-in model answers meanwhile).'
            ) : (
              <>
                Ready: {pa.ready} of {pa.enabled} AI API keys available.{' '}
                <Link className="font-medium underline" to="/ai">
                  Manage keys
                </Link>
              </>
            )}
          </div>
          <div className="mb-2 text-sm font-medium text-navy-900">Which files go to the AI</div>
          <div className="grid gap-2 pb-3 md:grid-cols-2">
            {[
              { v: 'suspicious', l: 'Detections only', d: 'Suspicious files and malware the scanner found (AI confirms, explains, and locates injected code for Trim). Uses few requests.' },
              { v: 'all', l: 'Every new or changed code file', d: 'Also checks clean-looking PHP/JS/HTML files as they are uploaded or changed (not inside archives), to catch what signatures miss and teach the scanner.' },
            ].map((o) => (
              <label key={o.v} className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 ${f.scope === o.v ? 'border-navy-600 bg-navy-100/40' : 'border-slate-200'}`}>
                <input type="radio" className="mt-1" disabled={dis} checked={f.scope === o.v} onChange={() => setF({ ...f, scope: o.v as AIS['scope'] })} />
                <div>
                  <div className="text-sm font-medium text-navy-900">{o.l}</div>
                  <div className="text-xs text-slate-500">{o.d}</div>
                </div>
              </label>
            ))}
          </div>
          {f.scope === 'all' && (
            <SettingRow title="Files per hour" desc="Cap on clean files sent in “every new file” mode (detections are never capped). Files already known to any server cost nothing.">
              <input className="input w-28" type="number" min={1} max={5000} value={f.max_per_hour} disabled={dis} onChange={(e) => setF({ ...f, max_per_hour: Number(e.target.value) })} />
            </SettingRow>
          )}
          <SettingRow title="Excerpt size" desc="How much of a big file is sent (KB). The start, end and risky parts are kept; smaller = fewer tokens.">
            <input className="input w-28" type="number" min={2} max={64} value={f.max_kb} disabled={dis} onChange={(e) => setF({ ...f, max_kb: Number(e.target.value) })} />
          </SettingRow>
        </>
      )}
      <SettingRow title="Learn from all servers" desc="Files any linked server’s AI found malicious are detected here immediately, and this server’s built-in model gets the fleet’s training updates." recommended>
        <Toggle on={f.learn} disabled={dis} onChange={(v) => setF({ ...f, learn: v })} />
      </SettingRow>
      <SettingRow title="Act on AI verdicts" desc="Quarantine or disable (per the virus action) files the AI is at least 80% sure are malicious">
        <Toggle on={f.act} disabled={dis} onChange={(v) => setF({ ...f, act: v })} />
      </SettingRow>
      <div className="flex justify-end">
        <button className="btn-primary" disabled={dis || JSON.stringify(f) === JSON.stringify(s)} onClick={() => onSave(f)}>
          Save AI scanner
        </button>
      </div>
    </div>
  );
}

function AdditionalSection({ serverId, st, meta, admin, busy, save }: { serverId: string; st: AllSettings; meta: Meta; admin: boolean; busy: boolean; save: (p: Partial<Record<keyof AllSettings, any>>, msg?: string) => Promise<unknown> }) {
  const dis = !admin || busy;
  const users = meta.users.map((u) => u.name);
  const mon = useAgent<{ status: { rkhunter: boolean; rkhunter_last: number; rkhunter_warnings: number } }>(serverId, 'monitor.events', { limit: 1 });
  const rk = mon.data?.status;
  return (
    <div>
      <h2 className="mb-2 text-lg font-semibold text-navy-900">Additional Settings</h2>
      <SettingRow
        title="Rootkit Scanner"
        desc={rk?.rkhunter ? `Weekly rkhunter check${rk.rkhunter_last ? ` · last run ${new Date(rk.rkhunter_last * 1000).toLocaleString()}, ${rk.rkhunter_warnings} warning(s)` : ''}` : 'Weekly rkhunter check (install rkhunter to enable: dnf install rkhunter)'}
        recommended
      >
        <Toggle on={st.rootkit.enabled} disabled={dis} onChange={(v) => save({ rootkit: { enabled: v } })} />
      </SettingRow>
      <SettingRow title="Manual scan access" desc="Allow cPanel users to start manual scans from the user panel">
        <Toggle on={st.scanner.user_scans} disabled={dis} onChange={(v) => save({ scanner: { user_scans: v } })} />
      </SettingRow>
      <div className="my-3 rounded-xl border border-slate-200 p-4">
        <SettingRow title="Proactive process monitor" desc="Periodically check processes running under hosting users for miners, reverse shells and programs run from temporary or hidden folders">
          <Toggle on={st.processes.enabled} disabled={dis} onChange={(v) => save({ processes: { enabled: v } })} />
        </SettingRow>
        <SettingRow title="Kill malicious processes" desc="Terminate detected processes instead of only alerting">
          <Toggle on={st.processes.kill} disabled={dis || !st.processes.enabled} onChange={(v) => save({ processes: { kill: v } })} />
        </SettingRow>
        <ListEditor title="Whitelist Users" desc="Processes running under these users will not be monitored or terminated" items={st.processes.whitelist_users} options={users} disabled={dis} onChange={(v) => void save({ processes: { whitelist_users: v } })} />
        <ListEditor title="Whitelist Strings" desc="Skip processes whose path or command line contains these strings" items={st.processes.whitelist_strings} disabled={dis} onChange={(v) => void save({ processes: { whitelist_strings: v } })} />
      </div>
      <div className="my-3 rounded-xl border border-slate-200 p-4">
        <SettingRow title="Cron monitor" desc="Monitor cron jobs and alert on suspicious cron activities">
          <Toggle on={st.cron.enabled} disabled={dis} onChange={(v) => save({ cron: { enabled: v } })} />
        </SettingRow>
        <ListEditor title="Whitelist Users" desc="Cron jobs from these users will not be monitored" items={st.cron.whitelist_users} options={users} disabled={dis} onChange={(v) => void save({ cron: { whitelist_users: v } })} />
      </div>
      <SettingRow title="Block PHP files upload" desc="Prevent uploading PHP files through website forms (WAF rule)">
        <Toggle on={st.waf.block_php_upload} disabled={dis} onChange={(v) => save({ waf: { block_php_upload: v } })} />
      </SettingRow>
      <SettingRow title="Keep logs for" desc="How long to keep XMart Guard logs and quarantined files on the server">
        <select className="input w-40" value={st.scanner.keep_days} disabled={dis} onChange={(e) => save({ scanner: { keep_days: Number(e.target.value) } })}>
          {[[7, '1 Week'], [30, '1 Month'], [60, '2 Months'], [90, '3 Months'], [180, '6 Months'], [365, '1 Year']].map(([d, l]) => (
            <option key={d} value={d}>{l}</option>
          ))}
        </select>
      </SettingRow>
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

interface WafRule {
  id: number;
  category: string;
  title: string;
  action: string;
  enabled: boolean;
}

function WAFSection({ serverId, s, admin, busy, onSave }: { serverId: string; s: WAFS; admin: boolean; busy: boolean; onSave: (p: Partial<WAFS>) => void }) {
  const info = useAgent<{ status: { available: boolean; web_server: string; error: string; warning: string }; rules: WafRule[] }>(serverId, 'waf.status');
  const [bf, setBf] = useState({ t: s.bf_threshold, w: s.bf_window_minutes });
  useEffect(() => setBf({ t: s.bf_threshold, w: s.bf_window_minutes }), [s.bf_threshold, s.bf_window_minutes]);
  const dis = !admin || busy;
  const st = info.data?.status;
  const row = (key: keyof WAFS, title: string, desc: string, rec?: boolean) => (
    <SettingRow title={title} desc={desc} recommended={rec}>
      <Toggle on={Boolean(s[key])} disabled={dis || !s.enabled} onChange={(v) => onSave({ [key]: v } as Partial<WAFS>)} />
    </SettingRow>
  );
  return (
    <div>
      <div className="mb-2 flex items-start justify-between">
        <div>
          <h2 className="text-lg font-semibold text-navy-900">WAF &amp; Bruteforce</h2>
          <p className="text-sm text-slate-500">
            XMart Guard ModSecurity rules for {st?.web_server ?? 'the web server'}.{' '}
            {st && !st.available && <span className="text-amber-600">ModSecurity is not installed (cPanel: EasyApache 4 » ea-apache24-mod_security2).</span>}
          </p>
          {st?.error && <p className="mt-1 text-sm text-red-600">{st.error}</p>}
          {st?.warning && <p className="mt-1 text-sm text-amber-700">{st.warning}</p>}
        </div>
        <Toggle on={s.enabled} disabled={dis} onChange={(v) => onSave({ enabled: v })} />
      </div>
      {row('upload_scan', 'Scan uploads for malware', 'Every file uploaded through a website is scanned by the XMart Guard engine before it is saved. PHP files uploaded through forms are refused.', true)}
      {row('sensitive_files', 'Protect sensitive files', 'Block web access to .env, .git, config backups, logs and SQL dumps', true)}
      {row('wordpress', 'WordPress hardening', 'Block running PHP inside wp-content/uploads and XML-RPC multicall', true)}
      {row('bad_bots', 'Block bad bots', 'Vulnerability scanners and abusive tools', true)}
      {row('seo_bots', 'Block SEO crawlers', 'Ahrefs, Semrush, MJ12, DotBot and similar aggressive crawlers')}
      {row('ai_bots', 'Block AI crawlers', 'GPTBot, CCBot, Bytespider, ClaudeBot and similar training crawlers')}
      {row('bruteforce', 'CMS login brute-force protection', 'Ban IPs that repeatedly fail WordPress, Joomla or OpenCart logins', true)}
      <div className="flex flex-wrap items-end gap-3 border-b border-slate-100 py-4">
        <label className="text-sm">
          <div className="label">Failed logins before ban</div>
          <input className="input w-32" type="number" min={3} value={bf.t} disabled={dis} onChange={(e) => setBf({ ...bf, t: Number(e.target.value) })} />
        </label>
        <label className="text-sm">
          <div className="label">Within (minutes)</div>
          <input className="input w-32" type="number" min={1} value={bf.w} disabled={dis} onChange={(e) => setBf({ ...bf, w: Number(e.target.value) })} />
        </label>
        <button className="btn-primary" disabled={dis} onClick={() => onSave({ bf_threshold: bf.t, bf_window_minutes: bf.w })}>
          Save
        </button>
      </div>
      {row('webshell', 'WEBSHELL protection', 'Block requests to well-known web shell files and their working folders', true)}
      {row('block_php_upload', 'Block PHP file uploads', 'Refuse any uploaded file with a PHP extension')}
      <ListEditor title="Protected login URLs" desc="Failed logins on these URLs count towards brute-force bans (with CAPTCHA on, banned visitors can unblock themselves)" items={s.login_urls ?? []} disabled={dis} placeholder="/wp-login.php" validate={(v) => (v.startsWith('/') ? null : 'Enter a path starting with /')} onChange={(v) => onSave({ login_urls: v })} />
      <ListEditor title="Whitelisted domains" desc="Websites XMart Guard's WAF rules never inspect (*.example.com allowed)" items={s.whitelist_domains ?? []} disabled={dis} placeholder="example.com" onChange={(v) => onSave({ whitelist_domains: v.map((x) => x.toLowerCase()) })} />
      <ListEditor title="Custom bots" desc="Block requests whose User-Agent contains any of these" items={s.custom_bots} disabled={dis} placeholder="e.g. badcrawler" onChange={(v) => onSave({ custom_bots: v })} />
      <ListEditor title="WAF whitelist" desc="These IPs are never inspected by XMart Guard rules" items={s.whitelist_ips} disabled={dis} placeholder="IP or CIDR" validate={isIPorCIDR} onChange={(v) => onSave({ whitelist_ips: v })} />
      <ListEditor
        title="Disabled rules"
        desc="ModSecurity rule ids switched off on this server (ours or any vendor's). Use the button in WAF Logs to disable a rule causing false positives."
        items={s.disabled_rules.map(String)}
        disabled={dis}
        placeholder="rule id"
        validate={(v) => (/^\d{1,8}$/.test(v) ? null : 'Enter a numeric rule id')}
        onChange={(v) => onSave({ disabled_rules: v.map(Number) })}
      />
      {info.data && (
        <div className="py-4">
          <div className="mb-2 font-medium text-navy-900">XMart Guard rules</div>
          <table className="w-full text-sm">
            <tbody className="divide-y divide-slate-100">
              {info.data.rules.map((r) => (
                <tr key={r.id}>
                  <td className="py-2 font-mono text-xs text-slate-500">{r.id}</td>
                  <td className="py-2">{r.title}</td>
                  <td className="py-2 text-xs text-slate-500">{r.action}</td>
                  <td className="py-2 text-right text-xs">{r.enabled ? <span className="text-green-600">active</span> : <span className="text-slate-400">off</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function CMSSection({ s, meta, admin, busy, onSave }: { s: CMSS; meta: Meta; admin: boolean; busy: boolean; onSave: (p: Partial<CMSS>) => void }) {
  const dis = !admin || busy;
  const [cvss, setCvss] = useState(s.auto_update_cvss);
  const [days, setDays] = useState(s.auto_update_days);
  useEffect(() => (setCvss(s.auto_update_cvss), setDays(s.auto_update_days)), [s.auto_update_cvss, s.auto_update_days]);
  return (
    <div>
      <div className="mb-2 flex items-start justify-between">
        <div>
          <h2 className="text-lg font-semibold text-navy-900">WordPress and CMS</h2>
          <p className="text-sm text-slate-500">Find WordPress, Joomla and OpenCart sites, track outdated plugins and themes, verify core files and scan databases.</p>
        </div>
        <Toggle on={s.enabled} disabled={dis} onChange={(v) => onSave({ enabled: v })} />
      </div>
      <SettingRow title="Verify WordPress core files" desc="Compare every core file with the official checksums from wordpress.org" recommended>
        <Toggle on={s.core_check} disabled={dis || !s.enabled} onChange={(v) => onSave({ core_check: v })} />
      </SettingRow>
      <SettingRow title="Scan WordPress databases" desc="Look for injected scripts, hidden iframes and PHP code in posts and options (read-only)" recommended>
        <Toggle on={s.db_scan} disabled={dis || !s.enabled} onChange={(v) => onSave({ db_scan: v })} />
      </SettingRow>
      <SettingRow title="Vulnerability database" desc="Look plugins, themes and WordPress core up in the free WPVulnerability database (CVE ids and CVSS scores)" recommended>
        <Toggle on={s.vulns} disabled={dis || !s.enabled} onChange={(v) => onSave({ vulns: v })} />
      </SettingRow>
      <SettingRow title="Override wordpress wp-cron.php" desc="Adds DISABLE_WP_CRON to wp-config and creates a cron job for the site owner">
        <Toggle on={s.wp_cron} disabled={dis || !s.enabled} onChange={(v) => onSave({ wp_cron: v })} />
      </SettingRow>
      <SettingRow title="Interval for running wp-cron.php" desc="How frequently wp-cron.php is executed">
        <select className="input w-40" value={s.wp_cron_hours} disabled={dis || !s.wp_cron} onChange={(e) => onSave({ wp_cron_hours: Number(e.target.value) })}>
          {[1, 2, 6, 12, 24].map((h) => (
            <option key={h} value={h}>Every {h} Hour{h > 1 ? 's' : ''}</option>
          ))}
        </select>
      </SettingRow>
      <div className="border-b border-slate-100 py-4">
        <div className="flex items-start justify-between gap-6">
          <div>
            <div className="font-medium text-navy-900">Auto Update Vulnerable WordPress Plugin or Theme</div>
            <div className="text-sm text-slate-500">Forcefully update plugins or themes that meet the conditions below (needs WP-CLI)</div>
          </div>
          <Toggle on={s.auto_update} disabled={dis || !s.enabled || !s.vulns} onChange={(v) => onSave({ auto_update: v })} />
        </div>
        <div className="mt-3 space-y-2 text-sm text-slate-600">
          <div className="flex flex-wrap items-center gap-2">
            if there are vulnerabilities with a CVSS score greater than
            <input className="input w-20" type="number" min={0} max={10} step={0.1} value={cvss} disabled={dis} onChange={(e) => setCvss(Number(e.target.value))} />
            (0 = any)
          </div>
          <div className="flex flex-wrap items-center gap-2">
            and it has been more than
            <input className="input w-20" type="number" min={0} value={days} disabled={dis} onChange={(e) => setDays(Number(e.target.value))} />
            days since the vulnerability was published
          </div>
          <button className="btn-outline" disabled={dis || (cvss === s.auto_update_cvss && days === s.auto_update_days)} onClick={() => onSave({ auto_update_cvss: cvss, auto_update_days: days })}>
            Save conditions
          </button>
        </div>
      </div>
      <ListEditor title="Blacklisted WordPress plugins" desc="Automatically deactivate these plugins (slug) during CMS checks" items={s.blacklist_plugins ?? []} disabled={dis} placeholder="plugin-slug" onChange={(v) => onSave({ blacklist_plugins: v.map((x) => x.toLowerCase()) })} />
      <ListEditor title="Exclude users from auto patches" desc="CMSs of these users won't be updated, patched or have plugins auto-disabled" items={s.exclude_users ?? []} options={meta.users.map((u) => u.name)} disabled={dis} onChange={(v) => onSave({ exclude_users: v })} />
      <SettingRow title="Scan interval" desc="How often all websites are re-checked">
        <select className="input w-40" value={s.interval_hours} disabled={dis || !s.enabled} onChange={(e) => onSave({ interval_hours: Number(e.target.value) })}>
          {[6, 12, 24, 48, 168].map((h) => (
            <option key={h} value={h}>
              {h < 24 ? `${h} hours` : h === 168 ? 'weekly' : `${h / 24} day${h > 24 ? 's' : ''}`}
            </option>
          ))}
        </select>
      </SettingRow>
    </div>
  );
}

function NumberSave({ label, value, min, disabled, onSave }: { label: string; value: number; min: number; disabled: boolean; onSave: (v: number) => void }) {
  const [v, setV] = useState(value);
  useEffect(() => setV(value), [value]);
  return (
    <div className="flex items-center gap-2">
      <input className="input w-28" type="number" min={min} value={v} disabled={disabled} onChange={(e) => setV(Number(e.target.value))} aria-label={label} />
      <button className="btn-outline px-3" disabled={disabled || v === value || v < min} onClick={() => onSave(v)}>
        Save
      </button>
    </div>
  );
}

function OSMSection({ s, admin, busy, onSave }: { s: OSMS; admin: boolean; busy: boolean; onSave: (p: Partial<OSMS>) => void }) {
  const dis = !admin || busy;
  const off = dis || !s.enabled;
  return (
    <div>
      <div className="mb-2 flex items-start justify-between">
        <div>
          <h2 className="text-lg font-semibold text-navy-900">Outgoing Spam Monitor</h2>
          <p className="text-sm text-slate-500">Watches the Exim mail log and reacts when an account or script sends too much mail.</p>
        </div>
        <Toggle on={s.enabled} disabled={dis} onChange={(v) => onSave({ enabled: v })} />
      </div>
      <SettingRow title="Messages per minute" desc="Per sender (email login or script)">
        <NumberSave label="per minute" value={s.per_minute} min={5} disabled={off} onSave={(v) => onSave({ per_minute: v })} />
      </SettingRow>
      <SettingRow title="Messages per hour" desc="Per sender">
        <NumberSave label="per hour" value={s.per_hour} min={20} disabled={off} onSave={(v) => onSave({ per_hour: v })} />
      </SettingRow>
      <SettingRow title="Action when a limit is crossed" desc="Hold/suspend apply to the whole cPanel account's outgoing mail and can be released from the Outgoing Spam Monitor page">
        <select className="input w-56" value={s.action} disabled={off} onChange={(e) => onSave({ action: e.target.value as OSMS['action'] })}>
          <option value="notify">Notify only</option>
          <option value="hold">Hold outgoing mail (queue)</option>
          <option value="suspend">Suspend outgoing mail</option>
        </select>
      </SettingRow>
      <SettingRow title="Check subjects" desc="Flag ALL CAPS subjects and the patterns below" recommended>
        <Toggle on={s.check_subjects} disabled={off} onChange={(v) => onSave({ check_subjects: v })} />
      </SettingRow>
      <ListEditor title="Spam subject patterns" desc="Case-insensitive text found in subjects" items={s.spam_patterns} disabled={off} onChange={(v) => onSave({ spam_patterns: v })} />
      <ListEditor title="Whitelisted senders" desc="Email addresses or logins never limited (newsletters, ticket systems)" items={s.whitelist_senders} disabled={off} placeholder="user@example.com" onChange={(v) => onSave({ whitelist_senders: v })} />
      <ListEditor title="Whitelisted IPs" desc="SMTP clients never limited" items={s.whitelist_ips} disabled={off} validate={isIPorCIDR} placeholder="IP or CIDR" onChange={(v) => onSave({ whitelist_ips: v })} />
      <ListEditor title="Whitelisted script paths" desc="Scripts under these directories are never limited" items={s.whitelist_paths} disabled={off} placeholder="/home/user/public_html/mailer" validate={(v) => (v.startsWith('/') ? null : 'Enter an absolute path')} onChange={(v) => onSave({ whitelist_paths: v })} />
    </div>
  );
}

interface SuspensionRow {
  id: number;
  at: number;
  user: string;
  reason: string;
  status: string;
  lifted_at: number;
}

function SuspendSection({ serverId, s, admin, busy, onSave }: { serverId: string; s: SuspendS; admin: boolean; busy: boolean; onSave: (p: Partial<SuspendS>) => void }) {
  const dis = !admin || busy;
  const list = useAgent<{ suspensions: SuspensionRow[] }>(serverId, 'suspend.list');
  const { run, busy: lifting } = useAction();
  const meta = useAgent<{ meta: { users: { name: string }[] } }>(serverId, 'settings.get');
  return (
    <div>
      <div className="mb-2 flex items-start justify-between">
        <div>
          <h2 className="text-lg font-semibold text-navy-900">Automatic Suspension</h2>
          <p className="text-sm text-slate-500">Suspend a cPanel account that keeps getting infected, to stop it attacking other sites and visitors.</p>
        </div>
        <Toggle on={s.enabled} disabled={dis} onChange={(v) => onSave({ enabled: v })} />
      </div>
      <SettingRow title="Malware detections" desc="Number of virus detections for one account that triggers a suspension">
        <NumberSave label="detections" value={s.detections} min={2} disabled={dis || !s.enabled} onSave={(v) => onSave({ detections: v })} />
      </SettingRow>
      <SettingRow title="Within (hours)" desc="Time window for counting detections">
        <NumberSave label="hours" value={s.window_hours} min={1} disabled={dis || !s.enabled} onSave={(v) => onSave({ window_hours: v })} />
      </SettingRow>
      <ListEditor
        title="Never suspend"
        desc="Accounts excluded from automatic suspension"
        items={s.exclude_users}
        options={(meta.data?.meta.users ?? []).map((u) => u.name)}
        disabled={dis}
        onChange={(v) => onSave({ exclude_users: v })}
      />
      <SettingRow title="Suspend on domain blacklist" desc="Automatically suspend an account when one of its domains becomes blacklisted">
        <Toggle on={s.on_domain_blacklist} disabled={dis} onChange={(v) => onSave({ on_domain_blacklist: v })} />
      </SettingRow>
      <ListEditor title="Whitelisted Domains" desc="Domains excluded from triggering automatic suspension" items={s.whitelist_domains ?? []} disabled={dis || !s.on_domain_blacklist} placeholder="example.com" onChange={(v) => onSave({ whitelist_domains: v.map((x) => x.toLowerCase()) })} />
      <div className="py-4">
        <div className="mb-2 font-medium text-navy-900">Suspension history</div>
        {!list.data?.suspensions.length ? (
          <div className="text-sm text-slate-400">No automatic suspensions</div>
        ) : (
          <table className="w-full text-sm">
            <tbody className="divide-y divide-slate-100">
              {list.data.suspensions.map((x) => (
                <tr key={x.id}>
                  <td className="py-2 font-medium">{x.user}</td>
                  <td className="py-2 text-xs">{x.reason}</td>
                  <td className="py-2 text-xs text-slate-500">{new Date(x.at * 1000).toLocaleString()}</td>
                  <td className="py-2 text-xs capitalize">{x.status}</td>
                  <td className="py-2 text-right">
                    {admin && x.status === 'suspended' && (
                      <button className="btn-outline px-2 py-1 text-xs" disabled={lifting} onClick={() => run(() => agentCall(serverId, 'suspend.lift', { id: x.id }), `${x.user} unsuspended`).then(() => list.reload())}>
                        Unsuspend
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function DomainRepSection({ s, admin, busy, onSave }: { s: DomainRepS; admin: boolean; busy: boolean; onSave: (p: Partial<DomainRepS>) => void }) {
  const dis = !admin || busy;
  const [key, setKey] = useState(s.safe_browsing_key);
  useEffect(() => setKey(s.safe_browsing_key), [s.safe_browsing_key]);
  return (
    <div className="mt-6 border-t border-slate-200 pt-6">
      <h2 className="text-lg font-semibold text-navy-900">Domain Reputation</h2>
      <p className="mb-2 text-sm text-slate-500">Check every hosted domain against Spamhaus DBL, SURBL and URIBL.</p>
      <SettingRow title="Domain reputation monitoring" desc={`Checked every ${s.interval_hours} hours; alerts when a domain becomes listed`} recommended>
        <Toggle on={s.enabled} disabled={dis} onChange={(v) => onSave({ enabled: v })} />
      </SettingRow>
      <SettingRow title="Google Safe Browsing API key" desc="Optional. Adds malware and phishing (SOCIAL_ENGINEERING) checks from Google.">
        <div className="flex gap-2">
          <input className="input w-72" type="password" value={key} disabled={dis} placeholder="AIza…" onChange={(e) => setKey(e.target.value)} />
          <button className="btn-outline" disabled={dis || key === s.safe_browsing_key} onClick={() => onSave({ safe_browsing_key: key.trim() })}>
            Save
          </button>
        </div>
      </SettingRow>
    </div>
  );
}

function IPDBSection({ s, admin, busy, onSave }: { s: IPDBS; admin: boolean; busy: boolean; onSave: (p: Partial<IPDBS>) => void }) {
  const dis = !admin || busy;
  return (
    <div>
      <h2 className="text-lg font-semibold text-navy-900">IPDB Protection</h2>
      <p className="mb-2 text-sm text-slate-500">
        The IPDB is a blocklist shared by every server on this portal. Attackers banned on one server are blocked on all of
        them. See the <Link className="text-blue-600 hover:underline" to="/ipdb">IPDB live monitor</Link>.
      </p>
      <SettingRow title="Block IPDB-listed addresses" desc="Drop all traffic from IPs in the shared IPDB list at the firewall" recommended>
        <Toggle on={s.enabled} disabled={dis} onChange={(v) => onSave({ enabled: v })} />
      </SettingRow>
      <SettingRow title="Report attackers to the IPDB" desc="Share this server's automatic brute-force and DoS bans so other servers can block them" recommended>
        <Toggle on={s.report} disabled={dis} onChange={(v) => onSave({ report: v })} />
      </SettingRow>
    </div>
  );
}

function NotificationsSection({ s, meta, admin, busy, onSave }: { s: NotificationsS; meta: Meta; admin: boolean; busy: boolean; onSave: (p: Partial<NotificationsS>) => void }) {
  const [f, setF] = useState(s);
  const [tab, setTab] = useState<'email' | 'slack' | 'telegram'>('email');
  useEffect(() => setF(s), [s]);
  const dis = !admin || busy;
  const changed = (keys: (keyof NotificationsS)[]) => keys.some((k) => f[k] !== s[k]);
  const pick = (keys: (keyof NotificationsS)[]) => Object.fromEntries(keys.map((k) => [k, f[k]])) as Partial<NotificationsS>;
  const emailKeys: (keyof NotificationsS)[] = ['email', 'extra_email', 'from'];
  return (
    <div>
      <h2 className="text-lg font-semibold text-navy-900">Notifications</h2>
      <p className="mb-4 text-sm text-slate-500">Settings to manage all notifications from XMart Guard. Email goes through the server's own mail system; bursts are combined every 2 minutes.</p>
      <Tabs value={tab} onChange={setTab} tabs={[{ v: 'email', l: 'Email' }, { v: 'slack', l: 'Slack' }, { v: 'telegram', l: 'Telegram' }]} />
      <div className="mt-4 border-b border-slate-100 pb-4">
        {tab === 'email' && (
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="text-sm">
              <div className="label">Main email address</div>
              <input className="input" type="email" placeholder="alerts@example.com" value={f.email} disabled={dis} onChange={(e) => setF({ ...f, email: e.target.value })} />
            </label>
            <label className="text-sm">
              <div className="label">Additional email address</div>
              <input className="input" type="email" placeholder="optional" value={f.extra_email ?? ''} disabled={dis} onChange={(e) => setF({ ...f, extra_email: e.target.value })} />
            </label>
            <label className="text-sm">
              <div className="label">From address</div>
              <input className="input" type="email" placeholder="xmartguard@hostname (default)" value={f.from ?? ''} disabled={dis} onChange={(e) => setF({ ...f, from: e.target.value })} />
            </label>
            <div className="flex items-end justify-end">
              <button className="btn-primary" disabled={dis || !changed(emailKeys)} onClick={() => onSave(pick(emailKeys))}>Save</button>
            </div>
          </div>
        )}
        {tab === 'slack' && (
          <div className="flex gap-2">
            <input className="input" type="password" placeholder="https://hooks.slack.com/services/…" value={f.slack_webhook ?? ''} disabled={dis} onChange={(e) => setF({ ...f, slack_webhook: e.target.value })} />
            <button className="btn-primary" disabled={dis || !changed(['slack_webhook'])} onClick={() => onSave(pick(['slack_webhook']))}>Save</button>
          </div>
        )}
        {tab === 'telegram' && (
          <div className="grid gap-3 sm:grid-cols-[1fr_1fr_auto]">
            <input className="input" type="password" placeholder="Bot token (from @BotFather)" value={f.telegram_token ?? ''} disabled={dis} onChange={(e) => setF({ ...f, telegram_token: e.target.value })} />
            <input className="input" placeholder="Chat id" value={f.telegram_chat ?? ''} disabled={dis} onChange={(e) => setF({ ...f, telegram_chat: e.target.value })} />
            <button className="btn-primary" disabled={dis || !changed(['telegram_token', 'telegram_chat'])} onClick={() => onSave(pick(['telegram_token', 'telegram_chat']))}>Save</button>
          </div>
        )}
      </div>
      <SettingRow title="Virus detections">
        <Toggle on={s.on_virus} disabled={dis} onChange={(v) => onSave({ on_virus: v })} />
      </SettingRow>
      <SettingRow title="Binary file detections">
        <Toggle on={s.on_binary} disabled={dis} onChange={(v) => onSave({ on_binary: v })} />
      </SettingRow>
      <SettingRow title="Suspicious pattern detections">
        <Toggle on={s.on_suspicious} disabled={dis} onChange={(v) => onSave({ on_suspicious: v })} />
      </SettingRow>
      <SettingRow title="On IP Blacklist" desc="When a server IP or hosted domain appears on a blocklist">
        <Toggle on={s.on_blacklist} disabled={dis} onChange={(v) => onSave({ on_blacklist: v })} />
      </SettingRow>
      <SettingRow title="On automatic IP ban" desc="Brute-force and DoS bans (can be noisy)">
        <Toggle on={s.on_ban} disabled={dis} onChange={(v) => onSave({ on_ban: v })} />
      </SettingRow>
      <SettingRow title="Daily Reports" desc="A summary of the last 24 hours every morning">
        <Toggle on={s.daily_report} disabled={dis} onChange={(v) => onSave({ daily_report: v })} />
      </SettingRow>
      <h3 className="mt-6 text-base font-semibold text-navy-900">User Notifications</h3>
      <p className="text-sm text-slate-500">Sent to the contact email of the cPanel account.</p>
      <SettingRow title="Infected files" desc="Send email notification to users when infected files are detected under their account">
        <Toggle on={s.user_infected} disabled={dis} onChange={(v) => onSave({ user_infected: v })} />
      </SettingRow>
      <SettingRow title="Account suspension" desc="Notify users when their account is auto suspended">
        <Toggle on={s.user_suspension} disabled={dis} onChange={(v) => onSave({ user_suspension: v })} />
      </SettingRow>
      <SettingRow title="Automatic CMS patches" desc="Notify users when automatic updates, security patches or plugin changes are applied">
        <Toggle on={s.user_patches} disabled={dis} onChange={(v) => onSave({ user_patches: v })} />
      </SettingRow>
      <SettingRow title="Outdated CMS" desc="Notify users about outdated CMS, plugins and themes under their account">
        <select className="input w-36" value={s.user_outdated ?? 'never'} disabled={dis} onChange={(e) => onSave({ user_outdated: e.target.value as NotificationsS['user_outdated'] })}>
          <option value="never">Never</option>
          <option value="weekly">Weekly</option>
          <option value="monthly">Monthly</option>
        </select>
      </SettingRow>
      <ListEditor title="Excluded users" desc="Selected users will not receive notifications" items={s.exclude_users ?? []} options={meta.users.map((u) => u.name)} disabled={dis} onChange={(v) => onSave({ exclude_users: v })} />
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
