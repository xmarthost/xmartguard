import { useEffect, useState, type ReactNode } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { Bell, Bug, CheckCircle2, ChevronDown, Info, LayoutTemplate, Lock, Mail, Settings as SettingsIcon, Shield, UserX, Wrench } from 'lucide-react';
import { api, type Server } from '../api';
import { can, useAuth } from '../auth';
import { useApi } from '../hooks';
import { ErrorBox, PageLoader } from '../components/ui';
import { ListEditor, SettingRow, Tabs, Toggle, agentCall, fmtTime, isIPorCIDR, useAction, useAgent } from '../components/controls';
import { LearnedExclusions, RuleExclusionsEditor, type LearnedExclusion, type RuleExclusion } from '../components/RuleExclusions';

interface ScannerS {
  enabled: boolean;
  realtime: boolean;
  virus_action: string;
  suspicious_action: string;
  binary_action: string;
  daily_scan: boolean;
  weekly_scan: boolean;
  max_file_size_mb: number;
  whitelist_users: string[];
  whitelist_paths: string[];
  blacklist_names: string[];
  delete_symlinks: boolean;
  auto_clean: boolean;
  wp_core_repair: boolean;
  feeds: boolean;
  clamav: boolean;
  clamav_urls: string;
  trim: boolean;
  trim_max_percent: number;
  user_scans: boolean;
  yara: boolean;
  db_whitelist: { id: string; reason: string }[];
  keep_days: number;
  scan_speed?: 'auto' | 'low' | 'fast';
  schedule_tz?: string;
}
interface AIS {
  enabled: boolean;
  provider: 'builtin' | 'portal';
  scope: 'suspicious' | 'all';
  max_per_hour: number;
  max_kb: number;
  act: boolean;
  learn: boolean;
  restore_clean: boolean;
}
interface ProcS {
  enabled: boolean;
  kill: boolean;
  whitelist_users: string[];
  whitelist_strings: string[];
}
interface CronS {
  enabled: boolean;
  disable?: boolean;
  whitelist_users: string[];
}
interface ReputationS {
  enabled: boolean;
  ips: string[];
  rbls: string[];
  interval_hours: number;
  exim_rbls?: boolean;
  phishing_filter?: boolean;
  spamhaus_dqs_key?: string;
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
  mail_method?: 'local' | 'smtp';
  smtp_host?: string;
  smtp_port?: number;
  smtp_security?: 'ssl' | 'starttls' | 'none';
  smtp_user?: string;
  smtp_password?: string;
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
  level?: 'low' | 'normal' | 'strict';
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
  bot_blocker: boolean;
  bot_list: string[];
  proxy_ip_check: boolean;
  generic: boolean;
  virtual_patches: boolean;
  ipdb_post: boolean;
  tor_action: 'off' | 'captcha' | 'post' | 'block';
  rule_exclusions?: RuleExclusion[];
  auto_exclusions?: 'auto' | 'suggest' | 'off';
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
  firewall?: { captcha: boolean };
  captcha?: { provider: string; site_key: string; login_gate?: boolean; allow_minutes?: number; http_port?: number; https_port?: number; central?: boolean; central_url?: string };
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
  users: { name: string }[];
  server_ips: string[];
  default_rbls: string[];
}

/** Time zones for the nightly scan schedule. */
const SCHEDULE_TZS: [string, string][] = [
  ['Asia/Karachi', 'Pakistan (PKT, UTC+5)'],
  ['Asia/Dubai', 'Gulf (UTC+4)'],
  ['Asia/Kolkata', 'India (UTC+5:30)'],
  ['Asia/Riyadh', 'Saudi Arabia (UTC+3)'],
  ['Europe/London', 'United Kingdom'],
  ['Europe/Berlin', 'Central Europe'],
  ['America/New_York', 'US Eastern'],
  ['America/Los_Angeles', 'US Pacific'],
  ['Australia/Sydney', 'Australia Eastern'],
  ['UTC', 'UTC'],
];
const tzLabel = (tz?: string) => (SCHEDULE_TZS.find(([v]) => v === (tz || 'Asia/Karachi'))?.[1] ?? tz ?? 'PKT');

type Section = 'scanner' | 'waf' | 'cms' | 'suspension' | 'osm' | 'rbl' | 'additional' | 'notifications' | 'about';
const NAV: { v: Section | string; l: string; icon: ReactNode; soon?: boolean }[] = [
  { v: 'scanner', l: 'Virus Scanner', icon: <Bug className="h-4 w-4" /> },
  { v: 'rbl', l: 'RBL & IP Reputation', icon: <Lock className="h-4 w-4" /> },
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
        {section === 'scanner' && (
          <>
            <ScannerSection s={st.scanner} meta={meta} admin={admin} busy={busy} onSave={setScanner} />
            <ClamAVSection serverId={id!} s={st.scanner} admin={admin} busy={busy} onSave={setScanner} />
          </>
        )}
        {section === 'scanner' && st.ai && <AISection s={st.ai} admin={admin} busy={busy} onSave={(p) => save({ ai: p })} />}
        {section === 'additional' && st.processes && (
          <AdditionalSection serverId={id!} st={st} meta={meta} admin={admin} busy={busy} save={save} />
        )}
        {section === 'rbl' && (
          <>
            <RBLSection s={st.reputation} meta={meta} admin={admin} busy={busy} onSave={(p) => save({ reputation: p })} />
            <EximRBLs serverId={id!} s={st.reputation} admin={admin} busy={busy} onSave={(p) => save({ reputation: p })} />
          </>
        )}
        {section === 'rbl' && st.domain_reputation && <DomainRepSection s={st.domain_reputation} admin={admin} busy={busy} onSave={(p) => save({ domain_reputation: p })} />}
        {section === 'waf' && st.waf && <WAFSection serverId={id!} s={st.waf} all={st} admin={admin} busy={busy} onSave={(p) => save({ waf: p })} saveAll={save} onReload={res.reload} />}
        {section === 'cms' && st.cms && <CMSSection s={st.cms} meta={meta} admin={admin} busy={busy} onSave={(p) => save({ cms: p })} />}
        {section === 'osm' && st.osm && <OSMSection s={st.osm} admin={admin} busy={busy} onSave={(p) => save({ osm: p })} />}
        {section === 'suspension' && st.auto_suspend && <SuspendSection serverId={id!} s={st.auto_suspend} admin={admin} busy={busy} onSave={(p) => save({ auto_suspend: p })} />}
        {section === 'notifications' && <NotificationsSection serverId={id!} s={st.notifications} meta={meta} admin={admin} busy={busy} onSave={(p) => save({ notifications: p })} />}
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
            {s.enabled ? 'xPGuard scanner engine is running.' : 'The scanner is disabled.'}
            {' xPGuard\'s own engine: behaviour rules, heuristics, signatures and YARA.'}
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
        <SettingRow title="Daily scan" desc={`Scan all files modified in the last 24 hours (every night after 12:00 AM, ${tzLabel(s.schedule_tz)})`} recommended>
          <Toggle on={s.daily_scan} disabled={dis} onChange={(v) => onSave({ daily_scan: v })} />
        </SettingRow>
        <SettingRow title="Weekly scan" desc={`Scan all files modified in the last 7 days (Saturday to Sunday night, after 12:00 AM, ${tzLabel(s.schedule_tz)}); replaces that night's daily scan`} recommended>
          <Toggle on={s.weekly_scan} disabled={dis} onChange={(v) => onSave({ weekly_scan: v })} />
        </SettingRow>
        <SettingRow title="Scan schedule time zone" desc="The nightly scans start between 12:00 AM and 3:00 AM in this time zone, whatever the server's own clock is set to.">
          <select className="input w-56" value={s.schedule_tz || 'Asia/Karachi'} disabled={dis} onChange={(e) => onSave({ schedule_tz: e.target.value })}>
            {SCHEDULE_TZS.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </SettingRow>
        <SettingRow
          title="Scan speed"
          desc="Scans run in their own process (xpguard-scan in the process list) at the lowest CPU and disk priority, so the websites always come first. Low: one CPU core, like other server scanners. Auto (recommended): up to a quarter of the cores while the server is quiet, one as soon as it gets busy or short of memory. Fast: up to half of the cores."
        >
          <select className="input w-56" value={s.scan_speed === 'low' || s.scan_speed === 'fast' ? s.scan_speed : 'auto'} disabled={dis} onChange={(e) => onSave({ scan_speed: e.target.value as ScannerS['scan_speed'] })}>
            <option value="auto">Auto (recommended)</option>
            <option value="low">Low</option>
            <option value="fast">Fast</option>
          </select>
        </SettingRow>
        <SettingRow title="Delete insecure symbolic links" desc="Remove links that point into another account's files, or to files the user could not read otherwise" recommended>
          <Toggle on={s.delete_symlinks} disabled={dis} onChange={(v) => onSave({ delete_symlinks: v })} />
        </SettingRow>
        <SettingRow
          title="Repair infected WordPress core files"
          desc="Replace an infected WordPress core file with the official file of the site's WordPress version (downloaded through the portal, checked against the official checksum). Official core files of every release since 5.8, betas included, are never flagged."
          recommended
        >
          <Toggle on={s.wp_core_repair || s.auto_clean} disabled={dis} onChange={(v) => onSave({ wp_core_repair: v, auto_clean: false })} />
        </SettingRow>
        <SettingRow
          title="Public malware signatures"
          desc="Also use the signatures the portal collects every day: Linux Malware Detect (MD5 and hex patterns) and web shell YARA rules (signature-base). Pattern and YARA hits are reported as suspicious and confirmed by the AI scanner."
          recommended
        >
          <Toggle on={s.feeds} disabled={dis} onChange={(v) => onSave({ feeds: v })} />
        </SettingRow>
        <SettingRow
          title="Trim injected code"
          desc="When the AI finds hacker code added to a legitimate file (e.g. a backdoor at the top of a plugin file), remove only that code and keep the site running instead of quarantining the whole file. The change is kept only if the file still passes a PHP syntax check and a rescan; the original stays in quarantine and can be restored. Needs the xPGuard AI (portal) provider."
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
        <SettingRow title="YARA rules" desc="Also run YARA rules placed in /etc/xpguard/yara/*.yar (requires the yara package)">
          <Toggle on={s.yara} disabled={dis} onChange={(v) => onSave({ yara: v })} />
        </SettingRow>
        <SettingRow title="Maximum file size" desc="Larger files are skipped (MB)">
          <input className="input w-24" type="number" min={1} max={100} defaultValue={s.max_file_size_mb} disabled={dis} onBlur={(e) => Number(e.target.value) !== s.max_file_size_mb && onSave({ max_file_size_mb: Number(e.target.value) })} />
        </SettingRow>
        <ListEditor
          title="Accounts not scanned"
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
    d: 'xPGuard’s own model runs on this server. Free, private, nothing is sent anywhere. It still learns from the fleet when "Learn from all servers" is on.',
  },
  {
    v: 'portal',
    l: 'xPGuard AI (free AI APIs)',
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
      <SettingRow
        title="Restore false positives"
        desc="When the AI is at least 90% sure a detected file is clean, put it back from quarantine (or re-enable it). The scanner then never flags that content again, on any server."
        recommended
      >
        <Toggle on={f.restore_clean} disabled={dis} onChange={(v) => setF({ ...f, restore_clean: v })} />
      </SettingRow>
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
        <SettingRow title="Proactive process monitor" desc="Every minute, check processes of hosting users for miners, reverse shells and programs run from temporary or hidden folders. Developer tools are normal: Node.js from nvm run by PM2, Bun, Volta, pip --user, Puppeteer's Chrome and programs in node_modules are not flagged.">
          <Toggle on={st.processes.enabled} disabled={dis} onChange={(v) => save({ processes: { enabled: v } })} />
        </SettingRow>
        <SettingRow title="Kill malicious processes" desc="Miners and reverse shells are killed at once. Programs that only run from an unusual place (temporary or hidden folder, deleted program) are killed only when they have run for 30 minutes and keep at least half a CPU core busy (like a miner); a short load spike never gets a process killed. Everything else is only alerted.">
          <Toggle on={st.processes.kill} disabled={dis || !st.processes.enabled} onChange={(v) => save({ processes: { kill: v } })} />
        </SettingRow>
        <ListEditor title="Accounts the process monitor skips" desc="Processes running under these users will not be monitored or terminated" items={st.processes.whitelist_users} options={users} disabled={dis} onChange={(v) => void save({ processes: { whitelist_users: v } })} />
        <ListEditor title="Whitelist Strings" desc="Skip processes whose path or command line contains these strings" items={st.processes.whitelist_strings} disabled={dis} onChange={(v) => void save({ processes: { whitelist_strings: v } })} />
      </div>
      <div className="my-3 rounded-xl border border-slate-200 p-4">
        <SettingRow title="Cron monitor" desc="Monitor cron jobs and alert on suspicious cron activities">
          <Toggle on={st.cron.enabled} disabled={dis} onChange={(v) => save({ cron: { enabled: v } })} />
        </SettingRow>
        <SettingRow title="Disable malicious cron jobs" desc="Comment out malicious lines in the user's crontab (the rest is kept): downloaded and run scripts, miners, backdoors, programs in temporary folders, files the scanner found. Lines that only start a program from a hidden folder are alerted, not switched off, and developer tools (PM2 or Node.js from nvm at boot) are not flagged. Re-enable a line from Process & Cron Monitor. Off: alert only">
          <Toggle on={st.cron.disable ?? true} disabled={dis || !st.cron.enabled} onChange={(v) => save({ cron: { disable: v } })} />
        </SettingRow>
        <ListEditor title="Accounts whose cron jobs are not checked" desc="Cron jobs from these users will not be monitored" items={st.cron.whitelist_users} options={users} disabled={dis} onChange={(v) => void save({ cron: { whitelist_users: v } })} />
      </div>
      <SettingRow title="Keep logs for" desc="How long to keep xPGuard logs and quarantined files on the server">
        <select className="input w-40" value={st.scanner.keep_days} disabled={dis} onChange={(e) => save({ scanner: { keep_days: Number(e.target.value) } })}>
          {[[7, '1 Week'], [30, '1 Month'], [60, '2 Months'], [90, '3 Months'], [180, '6 Months'], [365, '1 Year']].map(([d, l]) => (
            <option key={d} value={d}>{l}</option>
          ))}
        </select>
      </SettingRow>
    </div>
  );
}

/** ClamAV-format signature databases matched inside the agent. */
function ClamAVSection({ serverId, s, admin, busy, onSave }: { serverId: string; s: ScannerS; admin: boolean; busy: boolean; onSave: (p: Partial<ScannerS>) => void }) {
  const st = useAgent<{ enabled: boolean; loaded_at: number; stats: { hashes: number; body: number; logical: number; skipped: number; databases: string[] }; errors: Record<string, string> }>(serverId, 'clamav.status');
  const { run } = useAction();
  const [urls, setUrls] = useState(s.clamav_urls ?? '');
  useEffect(() => setUrls(s.clamav_urls ?? ''), [s.clamav_urls]);
  const dis = !admin || busy;
  const total = st.data ? st.data.stats.hashes + st.data.stats.body + st.data.stats.logical : 0;
  return (
    <div className="mt-6 border-t border-slate-200 pt-4">
      <SettingRow
        title="ClamAV-format signatures"
        desc="Match ClamAV signature databases inside the xPGuard agent: no clamscan or clamd process is started, scans stay one xPGuard process. The databases of an installed ClamAV (cPanel's ClamAV plugin, kept current by freshclam) are used automatically, filtered to web and script signatures."
        recommended
      >
        <Toggle on={s.clamav !== false} disabled={dis} onChange={(v) => onSave({ clamav: v })} />
      </SettingRow>
      <div className="border-b border-slate-100 py-4">
        <div className="font-medium text-navy-900">Signature subscriptions</div>
        <div className="mb-2 text-sm text-slate-500">
          One database URL per line (.ndb, .hdb, .hsb, .ldb, .cvd or .cld), for example a commercial PHP malware signature subscription with your own
          license key. Downloaded by the agent every 6 hours; the URL is stored on the server and shown masked here.
        </div>
        <textarea className="input h-20 font-mono text-xs" placeholder="https://example.com/signatures/php.ndb?key=YOUR-LICENSE" value={urls} disabled={dis || s.clamav === false} onChange={(e) => setUrls(e.target.value)} />
        <div className="mt-2 flex justify-end gap-2">
          <button className="btn-outline" disabled={dis || s.clamav === false} onClick={() => run(() => agentCall(serverId, 'clamav.reload').then(st.reload), 'Signature databases reloaded')}>
            Reload now
          </button>
          <button className="btn-primary" disabled={dis || urls === (s.clamav_urls ?? '')} onClick={() => onSave({ clamav_urls: urls.trim() })}>
            Save
          </button>
        </div>
      </div>
      {st.data?.enabled && (
        <div className="py-3 text-sm text-slate-600">
          {total > 0 ? (
            <>
              <b>{total.toLocaleString()}</b> signatures loaded ({st.data.stats.hashes.toLocaleString()} hashes, {st.data.stats.body.toLocaleString()} body,{' '}
              {st.data.stats.logical.toLocaleString()} logical{st.data.stats.skipped ? `, ${st.data.stats.skipped.toLocaleString()} executable-only skipped` : ''})
              {st.data.loaded_at > 0 && <> · {new Date(st.data.loaded_at * 1000).toLocaleString()}</>}
              <div className="mt-1 text-xs text-slate-500">{st.data.stats.databases.join(' · ')}</div>
            </>
          ) : (
            <span className="text-slate-500">No ClamAV databases on this server yet. Install ClamAV (WHM » Manage Plugins » ClamAV for cPanel) or add a subscription URL.</span>
          )}
          {Object.entries(st.data.errors ?? {}).map(([u, e]) => (
            <div key={u} className="mt-1 text-xs text-red-600">
              {u}: {e}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

interface EximGuard {
  supported: boolean;
  rbls: { name: string; zone: string; enabled: boolean; by?: string; problem?: string }[];
  phishing: 'off' | 'active' | 'added';
  rebuilt: boolean;
  error?: string;
  at: number;
}

/** Incoming mail protection in cPanel's Exim: blocklists that answer
 *  correctly from this server, and the phishing filter. */
function EximRBLs({ serverId, s, admin, busy, onSave }: { serverId: string; s: ReputationS; admin: boolean; busy: boolean; onSave: (p: Partial<ReputationS>) => void }) {
  const r = useAgent<{ rbls: { name: string; zone: string; defined: boolean; enabled: boolean }[] | null; guard: EximGuard | null }>(serverId, 'exim.rbls');
  const { run, busy: running } = useAction();
  const [dqs, setDqs] = useState(s.spamhaus_dqs_key ?? '');
  useEffect(() => setDqs(s.spamhaus_dqs_key ?? ''), [s.spamhaus_dqs_key]);
  if (!r.data?.rbls?.length) return null;
  const g = r.data.guard;
  const dis = !admin || busy;
  const rows = g?.rbls?.length ? g.rbls : r.data.rbls.map((x) => ({ name: x.name, zone: x.zone, enabled: x.enabled, by: undefined, problem: undefined }));
  return (
    <div className="mt-6 border-t border-slate-200 pt-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 className="text-lg font-semibold text-navy-900">Incoming mail protection (cPanel Exim)</h2>
          <p className="text-sm text-slate-500">Applied by xPGuard in WHM » Exim Configuration Manager; checked again every 6 hours.</p>
        </div>
        <button
          className="btn-outline"
          disabled={!admin || running}
          onClick={async () => {
            await run(() => agentCall(serverId, 'exim.guard', {}), 'Exim checked');
            r.reload();
          }}
        >
          Check now
        </button>
      </div>
      <SettingRow
        title="Turn on mail blocklists automatically"
        desc="Spamhaus ZEN, SpamCop, PSBL, Mailspike and Barracuda are switched on when they answer correctly from this server's DNS resolver; a list that refuses the resolver (Spamhaus with Google or Cloudflare DNS) stays off, so no mail is refused by mistake. Lists you switched on yourself are left alone."
        recommended
      >
        <Toggle on={s.exim_rbls ?? true} disabled={dis} onChange={(v) => onSave({ exim_rbls: v })} />
      </SettingRow>
      <SettingRow
        title="Phishing filter"
        desc='Mail from outside whose sender name claims to be cPanel, Webmail or the mail administrator and asks to verify, log in, or warns of deletion or a full mailbox gets "[PHISHING WARNING]" in its subject. It is still delivered.'
        recommended
      >
        {g && g.phishing !== 'off' && (
          <span className={`rounded-full px-2 py-0.5 text-xs ${g.phishing === 'active' ? 'bg-emerald-50 text-emerald-700' : 'bg-amber-50 text-amber-700'}`}>
            {g.phishing === 'active' ? 'active in Exim' : 'added; switch it on in WHM » Exim » Filters'}
          </span>
        )}
        <Toggle on={s.phishing_filter ?? true} disabled={dis} onChange={(v) => onSave({ phishing_filter: v })} />
      </SettingRow>
      <SettingRow
        title="Spamhaus DQS key"
        desc="Spamhaus does not answer public DNS resolvers (8.8.8.8, 1.1.1.1), so zen.spamhaus.org stays off on servers that use them. A free key from Spamhaus (spamhaus.com » Data Query Service, free for low volume and non-commercial use; check their terms) works through any resolver, without changing the server's DNS."
      >
        <input className="input w-72" placeholder="DQS key" value={dqs} disabled={dis} onChange={(e) => setDqs(e.target.value.trim())} />
        <button className="btn-outline" disabled={dis || dqs === (s.spamhaus_dqs_key ?? '') || (dqs !== '' && !/^[A-Za-z0-9]{20,40}$/.test(dqs))} onClick={() => onSave({ spamhaus_dqs_key: dqs })}>
          Save
        </button>
      </SettingRow>
      {g?.error && <p className="mt-2 text-sm text-red-600">{g.error}</p>}
      <div className="mt-2 overflow-x-auto">
        <table className="w-full min-w-[520px] text-sm">
          <tbody className="divide-y divide-slate-100">
            {rows.map((x) => (
              <tr key={x.name}>
                <td className="py-2 pr-3 font-medium">{x.name}</td>
                <td className="py-2 pr-3 font-mono text-xs text-slate-500">{x.zone}</td>
                <td className="py-2 text-right text-xs">
                  {x.enabled ? (
                    <span className="text-green-600">on{x.by === 'admin' ? ' (by you)' : x.by === 'xpguard' ? ' (by xPGuard)' : ''}</span>
                  ) : x.problem ? (
                    <span className="text-amber-700" title={x.problem}>off: {x.problem}</span>
                  ) : (
                    <span className="text-slate-500">off</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {g?.at ? <p className="mt-1 text-xs text-slate-400">Last check {fmtTime(g.at)}</p> : null}
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
  hits_24h?: number;
  hits_7d?: number;
}

interface WafPackage {
  id: string;
  title: string;
  desc: string;
  categories: string[];
  on: string[];
  enabled: boolean;
  rules: number;
  active: number;
  hits_24h: number;
  hits_7d: number;
}

/** xPGuard's rule packages as cards (like a vendor's packages): each can be
 *  switched on or off and shows how often its rules blocked something here. */
function PackageCards({ packages, meExtras, disabled, onSave }: { packages: WafPackage[]; meExtras: string[]; disabled: boolean; onSave: (p: Partial<WAFS>) => void }) {
  // Malware.Expert extra modules covering the same attacks.
  const me: Record<string, string> = { generic: 'generic', scanner: 'scanner', webshell: 'webshell', crawler: 'crawler', proxy: 'proxy' };
  return (
    <div className="my-4">
      <h3 className="text-base font-semibold text-navy-900">Rule packages</h3>
      <p className="mb-3 text-sm text-slate-500">xPGuard's own ModSecurity rules, grouped by the attacks they stop. Blocks are counted from this server's WAF log.</p>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {packages.map((p) => (
          <div key={p.id} className={`flex flex-col rounded-xl border p-3 ${p.enabled ? 'border-emerald-200 bg-emerald-50/40' : 'border-slate-200 bg-white'}`}>
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2 font-medium text-navy-900">
                <Shield className={`h-4 w-4 ${p.enabled ? 'text-emerald-600' : 'text-slate-400'}`} />
                {p.title}
              </div>
              <Toggle
                on={p.enabled}
                disabled={disabled}
                onChange={(v) =>
                  // Tor has a choice of actions, not a switch.
                  onSave(Object.fromEntries((v ? p.on : p.categories).map((c) => (c === 'tor' ? ['tor_action', v ? 'post' : 'off'] : [c, v]))) as Partial<WAFS>)
                }
              />
            </div>
            <p className="mt-1 flex-1 text-xs text-slate-500">{p.desc}</p>
            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
              <span className="text-slate-500">
                {p.active}/{p.rules} rules on
              </span>
              <span className={p.hits_24h ? 'font-medium text-red-600' : 'text-slate-400'}>{p.hits_24h.toLocaleString()} blocked 24h</span>
              <span className="text-slate-400">{p.hits_7d.toLocaleString()} in 7 days</span>
              {me[p.id] && meExtras.includes(me[p.id]) && (
                <span className="rounded-full bg-sky-50 px-2 py-0.5 text-sky-700" title="The Malware.Expert rules on this server cover this too; both can stay on.">
                  + Malware.Expert
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function WAFSection({ serverId, s, all, admin, busy, onSave, saveAll, onReload }: { serverId: string; s: WAFS; all: AllSettings; admin: boolean; busy: boolean; onSave: (p: Partial<WAFS>) => void; saveAll: (p: Partial<Record<keyof AllSettings, any>>, msg?: string) => Promise<unknown>; onReload: () => void }) {
  const { run } = useAction();
  const info = useAgent<{
    status: { available: boolean; web_server: string; error: string; warning: string; enabled_since: number; replaced_by?: string };
    rules: WafRule[];
    packages?: WafPackage[];
    tor?: { addresses: number; updated: number; error: string };
    ipdb_addresses?: number;
    auto_exclusions?: LearnedExclusion[];
    cpanel_off?: string[];
  }>(serverId, 'waf.status');
  const doms = useAgent<{ domains: { domain: string; user: string }[] }>(serverId, 'domains.list');
  const [bf, setBf] = useState({ t: s.bf_threshold, w: s.bf_window_minutes });
  useEffect(() => setBf({ t: s.bf_threshold, w: s.bf_window_minutes }), [s.bf_threshold, s.bf_window_minutes]);
  const dis = !admin || busy;
  const st = info.data?.status;
  // Malware.Expert replaces xPGuard's own rules on this server: only its
  // list is shown, not ours.
  const replaced = st?.replaced_by;
  const captchaOn = Boolean(all.firewall?.captcha);
  // Malware.Expert feed from WAF Rule Sets linked to this server, if any.
  const rs = useApi<{ config: { remote: { url: string; enabled: boolean; servers?: string[] }[] } }>('/api/waf/rulesets');
  const meFeed = rs.data?.config.remote.find((r) => r.enabled && /^https:\/\/rules\.malware\.expert\//.test(r.url) && (!r.servers?.length || r.servers.includes(serverId)));
  const meExtras = (() => {
    try {
      return meFeed ? (new URL(meFeed.url).searchParams.get('extra') ?? '').split(',').filter(Boolean) : [];
    } catch {
      return [];
    }
  })();
  // xPGuard rows that a Malware.Expert extra module also covers.
  const meCovers: Partial<Record<keyof WAFS, string>> = { bad_bots: 'scanner', webshell: 'webshell', ai_bots: 'crawler', proxy_ip_check: 'proxy' };
  const row = (key: keyof WAFS, title: string, desc: string, rec?: boolean) => (
    <SettingRow title={title} desc={desc} recommended={rec}>
      {meCovers[key] && meExtras.includes(meCovers[key]!) && (
        <span className="rounded-full bg-sky-50 px-2 py-0.5 text-xs text-sky-700" title="The Malware.Expert extra rules on this server cover this too; both can stay on.">
          + Malware.Expert
        </span>
      )}
      <Toggle on={Boolean(s[key])} disabled={dis || !s.enabled} onChange={(v) => onSave({ [key]: v } as Partial<WAFS>)} />
    </SettingRow>
  );
  return (
    <div>
      <div className="mb-2 flex items-start justify-between">
        <div>
          <h2 className="text-lg font-semibold text-navy-900">WAF Integration</h2>
          {st?.available && s.enabled && st.enabled_since > 0 ? (
            <p className="mt-2 flex items-center gap-2 text-sm text-slate-600">
              <CheckCircle2 className="h-5 w-5 text-green-600" /> WAF is enabled in Web Server configuration since {new Date(st.enabled_since * 1000).toLocaleString()}.
            </p>
          ) : (
            <p className="text-sm text-slate-500">
              xPGuard ModSecurity rules for {st?.web_server ?? 'the web server'}.{' '}
              {st && !st.available && <span className="text-amber-600">ModSecurity is not installed (cPanel: EasyApache 4 » ea-apache24-mod_security2).</span>}
            </p>
          )}
          {st?.error && <p className="mt-1 text-sm text-red-600">{st.error}</p>}
          {st?.warning && <p className="mt-1 text-sm text-amber-700">{st.warning}</p>}
        </div>
        <Toggle on={s.enabled} disabled={dis} onChange={(v) => onSave({ enabled: v })} />
      </div>
      {!replaced && <WafLevel level={s.level ?? 'normal'} disabled={dis || !s.enabled} onChange={(level) => onSave({ level })} />}
      {!replaced && info.data?.packages && <PackageCards packages={info.data.packages} meExtras={meExtras} disabled={dis || !s.enabled} onSave={(p) => { onSave(p); setTimeout(info.reload, 1500); }} />}
      {meFeed && (
        <SettingRow
          title="Malware.Expert on this server"
          desc={`This server uses your Malware.Expert key (WAF Rule Sets). Extra rules: ${meExtras.length ? meExtras.join(', ') : 'none'}.${
            meExtras.includes('recaptcha') ? ' Captcha by Malware.Expert: bots on WordPress and Joomla logins get the Malware.Expert reCaptcha; xPGuard\'s CAPTCHA above keeps working for firewall bans.' : ''
          } The OWASP Core Rule Set is off on this server.`}
        >
          <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${meExtras.includes('recaptcha') ? 'bg-emerald-50 text-emerald-700' : 'bg-slate-100 text-slate-600'}`}>
            {meExtras.includes('recaptcha') ? 'Captcha by Malware.Expert: on' : 'Captcha by Malware.Expert: off'}
          </span>
          <Link to="/waf-rulesets" className="text-sm text-blue-700 hover:underline">
            Change
          </Link>
        </SettingRow>
      )}
      {replaced && <VendorRulesCard serverId={serverId} name={replaced} admin={admin} onChanged={onReload} />}
      {!replaced && (
        <>
          <h3 className="mt-4 text-base font-semibold text-navy-900">Package options</h3>
          {row('ai_bots', 'AI Crawler protection', 'Stops AI crawlers (GPTBot, CCBot, Bytespider, ClaudeBot…) from sending requests to your websites')}
        </>
      )}
      <div className="mt-2 border-t border-slate-200" />
      {row('bruteforce', 'Bruteforce & Bot protection', 'Ban IPs that repeatedly fail logins on the protected URLs below (WordPress, Joomla, OpenCart and your own)', true)}
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
      <ListEditor
        title="Protected login URLs"
        desc={meExtras.includes('recaptcha')
          ? 'Login pages protected by the WAF brute-force module. On this server Malware.Expert protects them with its own CAPTCHA: visitors whose address is on its blacklist (blacklist.recaptcha.cloud) are sent to recaptcha.cloud; other visitors log in normally. xPGuard\'s login-page CAPTCHA is off here. Banned addresses still get xPGuard\'s CAPTCHA on the whole site (Firewall » CAPTCHA).'
          : 'Login pages whose failed logins count towards the brute-force bans above. Whether they ask for a CAPTCHA (suspicious visitors only or every visitor) is set in Firewall » CAPTCHA, with the other CAPTCHA options.'}
        header={
          replaced && !meExtras.includes('recaptcha') ? (
            <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600" title={`xPGuard's login-page CAPTCHA is one of its own rules, which are off on this server. Add the recaptcha extra to the ${replaced} feed for a login CAPTCHA.`}>
              Off ({replaced} rules only)
            </span>
          ) : meExtras.includes('recaptcha') ? (
            <span className="rounded-full bg-sky-50 px-2.5 py-1 text-xs font-medium text-sky-700" title="Malware.Expert's recaptcha extra is linked to this server, so its CAPTCHA replaces xPGuard's on the login pages.">
              Captcha by Malware.Expert
            </span>
          ) : (
            <Link to={`/servers/${serverId}/firewall`} className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600 hover:bg-slate-200" title="Whether these pages ask for a CAPTCHA is set with the other CAPTCHA options">
              CAPTCHA: {all.captcha?.login_gate ? 'every visitor' : all.captcha?.central ? 'suspicious visitors' : 'off'} · Firewall » CAPTCHA
            </Link>
          )
        }
        items={s.login_urls ?? []}
        disabled={dis}
        placeholder="Type here"
        validate={(v) => (v.startsWith('/') ? null : 'Enter a path starting with /')}
        onChange={(v) => onSave({ login_urls: v })}
      />
      {!replaced && <ListEditor
        title="Bad Bot blocker"
        desc="Block web requests from the bad bots listed below with ModSecurity (the User-Agent contains the entry, any case)"
        header={<Toggle on={s.bot_blocker} disabled={dis || !s.enabled} onChange={(v) => onSave({ bot_blocker: v })} />}
        items={s.bot_list ?? []}
        scroll
        disabled={dis}
        placeholder="UserAgent"
        validate={(v) => (v.length >= 2 && !/["'\\]/.test(v) ? null : 'Enter at least 2 characters, without quotes')}
        onChange={(v) => onSave({ bot_list: v })}
      />}
      <ListEditor
        title="Whitelisted rules"
        desc={replaced ? `Switch off ${replaced} rules by id (for a false positive). The list above has a switch for every ${replaced} rule that triggered here.` : "Disable certain WAF rules by adding specific rule ID (ours or any vendor's). WAF Logs also has a button to disable a rule causing false positives."}
        items={s.disabled_rules.map(String)}
        disabled={dis}
        placeholder="Type here"
        empty="No whitelisted rules"
        validate={(v) => (/^\d{1,8}$/.test(v) ? null : 'Enter a numeric rule id')}
        onChange={(v) => onSave({ disabled_rules: v.map(Number) })}
      />
      <ListEditor
        title="Whitelisted domains"
        desc={replaced ? `Domains ${replaced}'s rules never inspect` : 'Choose domains that should always be allowed by the WAF and CAPTCHA rules'}
        items={s.whitelist_domains ?? []}
        options={doms.data?.domains?.length ? doms.data.domains.map((d) => d.domain) : undefined}
        placeholder="example.com"
        empty="No whitelisted domains"
        disabled={dis}
        onChange={(v) => onSave({ whitelist_domains: v.map((x) => x.toLowerCase()) })}
      />

      <ListEditor title="WAF whitelist" desc={`These IPs are never inspected by ${replaced ? `${replaced}'s` : 'xPGuard'} rules`} items={s.whitelist_ips} disabled={dis} placeholder="IP or CIDR" validate={isIPorCIDR} onChange={(v) => onSave({ whitelist_ips: v })} />
      <Advanced>
        {!replaced && (
          <SettingRow
            title="Tor exit nodes"
            desc={`Visitors from the Tor network (list published by the Tor Project${info.data?.tor?.addresses ? `: ${info.data.tor.addresses.toLocaleString()} addresses, updated ${new Date(info.data.tor.updated * 1000).toLocaleString()}` : ', downloaded every 6 hours while this is on'}${info.data?.tor?.error ? `; last download failed: ${info.data.tor.error}` : ''}). Behind Cloudflare its Tor marker is used too. CAPTCHA sends them to the CAPTCHA page on the login pages (needs Overview » CAPTCHA Page; otherwise POST is blocked).`}
          >
            <select className="input w-56" value={s.tor_action ?? 'post'} disabled={dis || !s.enabled} onChange={(e) => onSave({ tor_action: e.target.value as WAFS['tor_action'] })}>
              <option value="off">Allow</option>
              <option value="captcha">CAPTCHA on login pages</option>
              <option value="post">Block POST (read only)</option>
              <option value="block">Block every request</option>
            </select>
          </SettingRow>
        )}
        <LearnedExclusions
          mode={s.auto_exclusions ?? 'auto'}
          items={info.data?.auto_exclusions ?? []}
          cpanelOff={info.data?.cpanel_off ?? []}
          disabled={dis}
          onMode={(m) => onSave({ auto_exclusions: m as WAFS['auto_exclusions'] })}
          onAction={async (key, action) => {
            const res = await run(() => agentCall<{ warning?: string }>(serverId, 'waf.auto_exclusion', { key, action }), 'Saved');
            if (res?.warning) alert(res.warning);
            info.reload();
          }}
        />
        <RuleExclusionsEditor
          items={s.rule_exclusions ?? []}
          domains={doms.data?.domains?.map((d) => d.domain)}
          disabled={dis}
          vendor={replaced}
          onChange={(v) => onSave({ rule_exclusions: v })}
        />
        {!replaced && (
          <>
        {s.seo_bots && row('seo_bots', 'Block SEO crawlers (older option)', 'Now part of the Bad Bot blocker list above: turn the Bad Bot blocker on and this switch is merged into it.')}
        {row('block_php_upload', 'Block PHP file uploads', 'Refuse any uploaded file with a PHP extension')}
        {info.data && (
          <div className="py-4">
            <div className="mb-1 font-medium text-navy-900">xPGuard rules</div>
            {meFeed && (
              <p className="mb-2 rounded-lg bg-sky-50 px-3 py-2 text-sm text-sky-800">
                This list shows xPGuard's own rules only. The Malware.Expert rules on this server are downloaded by the web server straight from Malware.Expert
                when it starts, so they are not stored here; whether they loaded shows under WAF Rule Sets » Rollout, and their blocks appear in WAF Logs with
                Malware.Expert's rule ids.
              </p>
            )}
            <p className="mb-2 text-sm text-slate-500">Switch single rules on or off. Switching on a rule of a group that is off turns on only that rule. The numbers are blocks in the last 24 hours / 7 days.</p>
            <table className="w-full text-sm">
              <tbody className="divide-y divide-slate-100">
                {info.data.rules.map((r) => (
                  <tr key={r.id}>
                    <td className="w-20 py-2 pr-3 font-mono text-xs text-slate-500">{r.id}</td>
                    <td className="py-2 pr-3">{r.title}</td>
                    <td className="py-2 pr-3 text-xs text-slate-500">{r.action}</td>
                    <td className="whitespace-nowrap py-2 pr-3 text-right text-xs" title="Blocked in the last 24 hours / 7 days">
                      <span className={r.hits_24h ? 'font-medium text-red-600' : 'text-slate-400'}>{r.hits_24h ?? 0}</span>
                      <span className="text-slate-400"> / {r.hits_7d ?? 0}</span>
                    </td>
                    <td className="py-2 pr-3 text-right text-xs">{r.enabled ? <span className="text-green-600">active</span> : <span className="text-slate-400">off</span>}</td>
                    <td className="w-20 py-2 text-right">
                      <Toggle
                        on={r.enabled}
                        disabled={dis || !s.enabled}
                        onChange={async (v) => {
                          const res = await run(() => agentCall<{ warning?: string }>(serverId, 'waf.rule', { id: r.id, enabled: v }), `Rule ${r.id} ${v ? 'on' : 'off'}`);
                          if (res?.warning) alert(res.warning);
                          info.reload();
                          onReload();
                        }}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
          </>
        )}
      </Advanced>
    </div>
  );
}

const LEVELS: { v: 'low' | 'normal' | 'strict'; title: string; desc: string }[] = [
  { v: 'low', title: 'Low', desc: 'Only clear attacks are blocked (OWASP CRS score 20). No blocks by IP reputation (IPDB, Tor). Logged-in WordPress users are never blocked while editing.' },
  { v: 'normal', title: 'Normal', desc: 'Like most hosting companies: one weak signal never blocks (CRS score 10). Logged-in WordPress users are never blocked while editing; visitors with attacks are.' },
  { v: 'strict', title: 'Strict', desc: 'Most protection: one CRS rule blocks (score from WAF Rule Sets, usually 5). More false positives on forms and page builders.' },
];

/** How strict the WAF is: low, normal (default) or strict. */
function WafLevel({ level, disabled, onChange }: { level: 'low' | 'normal' | 'strict'; disabled: boolean; onChange: (l: 'low' | 'normal' | 'strict') => void }) {
  return (
    <div className="border-b border-slate-100 py-4">
      <div className="font-medium text-navy-900">Protection level</div>
      <div className="mb-3 text-sm text-slate-500">How much ModSecurity may block on this server. Normal is recommended for shared hosting.</div>
      <div className="grid gap-2 sm:grid-cols-3">
        {LEVELS.map((l) => (
          <button
            key={l.v}
            type="button"
            disabled={disabled}
            onClick={() => l.v !== level && onChange(l.v)}
            className={`rounded-xl border p-3 text-left transition ${l.v === level ? 'border-[var(--xg-primary,#2563eb)] bg-blue-50 ring-1 ring-[var(--xg-primary,#2563eb)]' : 'border-slate-200 hover:bg-slate-50'} disabled:opacity-60`}
          >
            <div className="flex items-center justify-between font-medium text-navy-900">
              {l.title}
              {l.v === 'normal' && <span className="text-xs font-normal text-amber-600">recommended</span>}
            </div>
            <div className="mt-1 text-xs text-slate-500">{l.desc}</div>
          </button>
        ))}
      </div>
    </div>
  );
}

/** Less used WAF options, closed until opened (remembered per browser). */
function Advanced({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(() => {
    try {
      return localStorage.getItem('xg-waf-advanced') === '1';
    } catch {
      return false;
    }
  });
  const toggle = () => {
    setOpen(!open);
    try {
      localStorage.setItem('xg-waf-advanced', open ? '0' : '1');
    } catch {
      /* private window */
    }
  };
  return (
    <div className="mt-4 rounded-xl border border-slate-200">
      <button type="button" className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left" onClick={toggle} aria-expanded={open}>
        <span>
          <span className="font-medium text-navy-900">Advanced options</span>
          <span className="block text-sm text-slate-500">Tor, false-positive protection, per-site rule exclusions, PHP uploads and single xPGuard rules</span>
        </span>
        <ChevronDown className={`h-5 w-5 shrink-0 text-slate-400 transition ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && <div className="border-t border-slate-200 px-4">{children}</div>}
    </div>
  );
}

interface VendorRule {
  id: number;
  msg: string;
  hits: number;
  hits_24h: number;
  last: number;
  enabled: boolean;
}

/** Where Malware.Expert replaces xPGuard's rules: its packages and its rules
 *  that triggered on this server (from the web server log; the rules are
 *  loaded by the web server straight from Malware.Expert). */
function VendorRulesCard({ serverId, name, admin, onChanged }: { serverId: string; name: string; admin: boolean; onChanged: () => void }) {
  const v = useAgent<{ name: string; packages: { id: string; title: string; desc: string }[]; rules: VendorRule[] }>(serverId, 'waf.vendor_rules', {}, 60_000);
  const { run, busy } = useAction();
  const [q, setQ] = useState('');
  const rules = (v.data?.rules ?? []).filter((r) => !q || String(r.id).includes(q) || r.msg.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="my-4 rounded-xl border border-sky-200 bg-sky-50/40 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h3 className="text-base font-semibold text-navy-900">{name} rules on this server</h3>
          <p className="text-sm text-slate-600">
            Only {name}'s rules protect this server; xPGuard's own WAF rules and the OWASP Core Rule Set are off here, so no request is handled twice. The web
            server downloads the rules straight from {name} with your key when it starts; below are the packages you linked and every {name} rule that has
            blocked something here.
          </p>
        </div>
        <Link to="/waf-rulesets" className="text-sm text-blue-700 hover:underline">
          Change packages
        </Link>
      </div>
      {v.error && !v.data && <p className="mt-2 text-sm text-red-600">{v.error}</p>}
      {v.data && (
        <>
          <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {v.data.packages.map((p) => (
              <div key={p.id} className="rounded-lg border border-slate-200 bg-white p-3">
                <div className="flex items-center gap-2 text-sm font-medium text-navy-900">
                  <CheckCircle2 className="h-4 w-4 text-emerald-600" /> {p.title}
                  <span className="font-mono text-xs text-slate-400">{p.id}</span>
                </div>
                {p.desc && <div className="mt-0.5 text-xs text-slate-500">{p.desc}</div>}
              </div>
            ))}
          </div>
          <div className="mt-4 flex flex-wrap items-center justify-between gap-2">
            <div className="text-sm font-medium text-navy-900">
              Rules that triggered here <span className="font-normal text-slate-500">({v.data.rules.length})</span>
            </div>
            <input className="input w-56" placeholder="Search id or message" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          {v.data.rules.length === 0 ? (
            <p className="mt-2 rounded-lg bg-white p-3 text-sm text-slate-500">
              No {name} rule has blocked anything on this server yet. When one does it appears here with its hits, and you can switch it off if it blocks a
              real visitor.
            </p>
          ) : (
            <div className="mt-2 max-h-[420px] overflow-auto rounded-lg border border-slate-200 bg-white">
              <table className="w-full min-w-[560px] text-sm">
                <thead className="sticky top-0 bg-slate-50 text-left text-xs uppercase text-slate-500">
                  <tr>
                    <th className="px-3 py-2">Rule</th>
                    <th className="py-2 pr-3">Message</th>
                    <th className="py-2 pr-3 text-right">Hits (24 h)</th>
                    <th className="py-2 pr-3">Last</th>
                    <th className="py-2 pr-3 text-right">Active</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {rules.map((r) => (
                    <tr key={r.id}>
                      <td className="px-3 py-2 font-mono text-xs text-slate-600">{r.id}</td>
                      <td className="py-2 pr-3">{r.msg ? r.msg.replace(/^Malware\.Expert\s*-\s*/i, '') : <span className="text-slate-400">—</span>}</td>
                      <td className="py-2 pr-3 text-right tabular-nums">
                        {r.hits.toLocaleString()} <span className="text-xs text-slate-400">({r.hits_24h.toLocaleString()})</span>
                      </td>
                      <td className="py-2 pr-3 text-xs text-slate-500">{r.last ? fmtTime(r.last) : '—'}</td>
                      <td className="py-2 pr-3 text-right">
                        <Toggle
                          on={r.enabled}
                          disabled={!admin || busy}
                          onChange={async (on) => {
                            const res = await run(() => agentCall<{ warning?: string }>(serverId, 'waf.vendor_rule', { id: r.id, enabled: on }), `${name} rule ${r.id} ${on ? 'on' : 'off'}`);
                            if (res?.warning) alert(res.warning);
                            v.reload();
                            onChanged();
                          }}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
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
      <SettingRow
        title="Override wordpress wp-cron.php"
        desc="Performance setting, not a malware action: WordPress normally runs its scheduled tasks (wp-cron.php) on visitors' page loads. This adds DISABLE_WP_CRON to wp-config.php and runs wp-cron.php from the site owner's cron instead, at the interval below. Turning it off puts both back."
      >
        <Toggle on={s.wp_cron} disabled={dis || !s.enabled} onChange={(v) => onSave({ wp_cron: v })} />
      </SettingRow>
      <SettingRow
        title="Interval for running wp-cron.php"
        desc={
          s.wp_cron_hours > 1
            ? `WordPress runs scheduled posts, WooCommerce orders and emails, backups and plugin tasks only this often: every ${s.wp_cron_hours} hours can delay them up to ${s.wp_cron_hours} hours. Every hour is recommended.`
            : 'How often wp-cron.php runs (scheduled posts, WooCommerce tasks, emails, backups). Every hour is recommended.'
        }
      >
        <select className="input w-40" value={s.wp_cron_hours} disabled={dis || !s.wp_cron} onChange={(e) => onSave({ wp_cron_hours: Number(e.target.value) })}>
          {[1, 2, 6, 12, 24].map((h) => (
            <option key={h} value={h}>
              Every {h} Hour{h > 1 ? 's' : ''}
              {h === 1 ? ' (recommended)' : ''}
            </option>
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

function NotificationsSection({ serverId, s, meta, admin, busy, onSave }: { serverId: string; s: NotificationsS; meta: Meta; admin: boolean; busy: boolean; onSave: (p: Partial<NotificationsS>) => void }) {
  const [f, setF] = useState(s);
  const [tab, setTab] = useState<'email' | 'slack' | 'telegram'>('email');
  useEffect(() => setF(s), [s]);
  const dis = !admin || busy;
  const changed = (keys: (keyof NotificationsS)[]) => keys.some((k) => f[k] !== s[k]);
  const pick = (keys: (keyof NotificationsS)[]) => Object.fromEntries(keys.map((k) => [k, f[k]])) as Partial<NotificationsS>;
  const emailKeys: (keyof NotificationsS)[] = ['email', 'extra_email', 'from', 'mail_method', 'smtp_host', 'smtp_port', 'smtp_security', 'smtp_user', 'smtp_password'];
  const method = f.mail_method ?? 'local';
  const sec = f.smtp_security ?? 'starttls';
  const defPort = sec === 'ssl' ? 465 : sec === 'none' ? 25 : 587;
  const test = useAction();
  const [results, setResults] = useState<Record<string, string> | null>(null);
  const sendTest = () =>
    test.run(() => agentCall<Record<string, string>>(serverId, 'notify.test')).then((r) => r && setResults(r));
  const unsaved = changed([...emailKeys, 'slack_webhook', 'telegram_token', 'telegram_chat']);
  return (
    <div>
      <h2 className="text-lg font-semibold text-navy-900">Notifications</h2>
      <p className="mb-4 text-sm text-slate-500">Settings to manage all notifications from xPGuard. Email is sent through the server's local mail relay or your SMTP server; bursts are combined every 2 minutes.</p>
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
              <input className="input" type="email" placeholder={method === 'smtp' && f.smtp_user?.includes('@') ? `${f.smtp_user} (default)` : 'xpguard@hostname (default)'} value={f.from ?? ''} disabled={dis} onChange={(e) => setF({ ...f, from: e.target.value })} />
            </label>
            <div className="sm:col-span-2">
              <div className="label mb-1">Send email through</div>
              <div className="grid gap-2 sm:grid-cols-2">
                {([
                  ['local', 'Local mail relay', "The server's own mail system (Exim / Postfix via sendmail). No setup needed."],
                  ['smtp', 'SMTP server', 'Gmail, Microsoft 365, Amazon SES, Mailgun, your mail server… Better delivery to the inbox.'],
                ] as const).map(([v, l, d]) => (
                  <label key={v} className={`flex cursor-pointer gap-3 rounded-xl border p-3 text-sm ${method === v ? 'border-navy-600 bg-navy-50/60 ring-1 ring-navy-600' : 'border-slate-200 hover:border-slate-300'}`}>
                    <input type="radio" name="mail_method" className="mt-1" checked={method === v} disabled={dis} onChange={() => setF({ ...f, mail_method: v })} />
                    <span>
                      <span className="block font-medium text-navy-900">{l}</span>
                      <span className="block text-xs text-slate-500">{d}</span>
                    </span>
                  </label>
                ))}
              </div>
            </div>
            {method === 'smtp' && (
              <div className="grid gap-3 rounded-xl border border-slate-200 bg-slate-50/60 p-3 sm:col-span-2 sm:grid-cols-6">
                <label className="text-sm sm:col-span-3">
                  <div className="label">SMTP server</div>
                  <input className="input" placeholder="smtp.gmail.com" value={f.smtp_host ?? ''} disabled={dis} onChange={(e) => setF({ ...f, smtp_host: e.target.value })} />
                </label>
                <label className="text-sm sm:col-span-2">
                  <div className="label">Encryption</div>
                  <select className="input" value={sec} disabled={dis} onChange={(e) => setF({ ...f, smtp_security: e.target.value as NotificationsS['smtp_security'], smtp_port: 0 })}>
                    <option value="starttls">STARTTLS (587)</option>
                    <option value="ssl">SSL/TLS (465)</option>
                    <option value="none">None (25)</option>
                  </select>
                </label>
                <label className="text-sm sm:col-span-1">
                  <div className="label">Port</div>
                  <input className="input" type="number" min={1} max={65535} placeholder={String(defPort)} value={f.smtp_port || ''} disabled={dis} onChange={(e) => setF({ ...f, smtp_port: Number(e.target.value) || 0 })} />
                </label>
                <label className="text-sm sm:col-span-3">
                  <div className="label">Username</div>
                  <input className="input" placeholder="alerts@example.com (empty: no login)" value={f.smtp_user ?? ''} disabled={dis} onChange={(e) => setF({ ...f, smtp_user: e.target.value })} />
                </label>
                <label className="text-sm sm:col-span-3">
                  <div className="label">Password</div>
                  <input className="input" type="password" placeholder="password or app password" value={f.smtp_password ?? ''} disabled={dis} onChange={(e) => setF({ ...f, smtp_password: e.target.value })} />
                </label>
                <p className="text-xs text-slate-500 sm:col-span-6">
                  Gmail / Google Workspace: <code>smtp.gmail.com</code>, STARTTLS 587, and an App Password. Microsoft 365: <code>smtp.office365.com</code>, STARTTLS 587. The password is stored on the server only and never shown again. Leave "From address" empty to send as the SMTP username.
                </p>
              </div>
            )}
            <div className="flex items-end justify-end sm:col-span-2">
              <button className="btn-primary" disabled={dis || !changed(emailKeys) || (method === 'smtp' && !f.smtp_host?.trim())} onClick={() => onSave(pick(emailKeys))}>Save</button>
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
            <p className="text-xs text-slate-500 sm:col-span-3">
              Create a bot with @BotFather and paste its token. Send <code>/start</code> to the bot (or add it to your group/channel), then use your chat id: open{' '}
              <code>https://api.telegram.org/bot&lt;token&gt;/getUpdates</code> and copy <code>chat.id</code> (groups and channels start with <code>-100</code>).
            </p>
          </div>
        )}
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button className="btn-outline" disabled={!admin || test.busy || unsaved} onClick={sendTest}>
            {test.busy ? 'Sending…' : 'Send test notification'}
          </button>
          <span className="text-xs text-slate-500">{unsaved ? 'Save your changes first.' : 'Sends a test message to every configured channel now and shows the result.'}</span>
        </div>
        {results && (
          <ul className="mt-3 space-y-1 text-sm">
            {Object.entries(results).map(([k, v]) => {
              const ok = v === 'sent' || v.startsWith('sent to');
              return (
                <li key={k} className={ok ? 'text-emerald-700' : 'text-red-700'}>
                  <b className="capitalize">{k.replace('_', ' ')}:</b> {v.replace(new RegExp(`^${k}: `, 'i'), '')}
                </li>
              );
            })}
          </ul>
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
      <h2 className="mb-4 text-lg font-semibold text-navy-900">About xPGuard</h2>
      <div className="rounded-xl bg-slate-50 p-5 text-sm">
        <div className="grid grid-cols-[110px_minmax(0,1fr)] gap-x-2 gap-y-2 sm:grid-cols-[160px_1fr]">
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
      <p className="mt-6 text-xs text-slate-400">
        Third-party data and software:{' '}
        <Link to="/kb#attributions" className="text-blue-700 hover:underline">licenses and attributions</Link>.
      </p>
    </div>
  );
}
