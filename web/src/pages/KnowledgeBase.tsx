import { useState } from 'react';
import { BookOpen, ChevronDown, ExternalLink } from 'lucide-react';

interface Article {
  id: string;
  title: string;
  body: React.ReactNode;
}

const Code = ({ children }: { children: string }) => (
  <pre className="my-2 overflow-x-auto rounded-lg bg-navy-900 p-3 text-xs leading-relaxed text-slate-100">{children}</pre>
);

const Steps = ({ items }: { items: React.ReactNode[] }) => (
  <ol className="my-2 list-decimal space-y-1 pl-5">
    {items.map((x, i) => (
      <li key={i}>{x}</li>
    ))}
  </ol>
);

const guides: Article[] = [
  {
    id: 'realtime',
    title: 'Realtime scanner: how uploads are checked',
    body: (
      <>
        <p>
          The agent watches every hosting account's home directory with inotify (mail, logs, caches and the quarantine are skipped). Each new or changed
          file is scanned by the built-in rules, hash and YARA signatures as soon as it is fully written, usually within a second. Folders created by
          extracting an archive are picked up together with the files already inside them.
        </p>
        <p className="mt-2">
          The AI scanner runs afterwards in the background: the file is already marked (quarantined or notified) by the rules, and the AI verdict only
          confirms it or restores a false positive.
        </p>
        <p className="mt-2">If the dashboard shows <b>Realtime scanner · Not running</b>, check on the server:</p>
        <Code>{`xgcli status                        # protection overview
xgcli watch --list                  # directories the realtime scanner watches
sysctl fs.inotify.max_user_watches  # the agent raises this to 500000
journalctl -u xmartguard-agent -n 50`}</Code>
        <p>To find which files of a folder are not detected (for reporting detection gaps):</p>
        <Code>{`xmartguard-agent check /home/user/public_html/folder --misses`}</Code>
      </>
    ),
  },
  {
    id: 'actions',
    title: 'Virus action: quarantine or notify',
    body: (
      <>
        <p>
          New installs quarantine malware automatically. Servers whose settings were saved before 0.7.1 keep their previous choice (often “notify”); switch them all at once from{' '}
          <b>Mass Operations » Quarantine viruses automatically</b>, or per server in <b>Settings » Scanner</b>. Quarantined files can be viewed,
          restored or deleted from <b>Scanner Logs</b>.
        </p>
      </>
    ),
  },
  {
    id: 'waf-cpanel',
    title: 'WAF on cPanel (Apache)',
    body: (
      <Steps
        items={[
          <>Install ModSecurity from <b>WHM » EasyApache 4</b> (package <code>mod_security2</code>) if it is missing.</>,
          <>In <b>WHM » Security Center » ModSecurity® Configuration</b> set <code>SecRuleEngine</code> to <b>On</b> and <code>SecAuditEngine</code> to <b>RelevantOnly</b>, so only blocked requests are logged.</>,
          <>Keep other vendor rule sets disabled in <b>ModSecurity® Vendors</b>; two rule sets on the same requests cause false positives and slow pages.</>,
          <>Turn the WAF on in <b>Settings » WAF</b>. The agent writes its rules, tests the Apache configuration, reloads Apache and rolls back automatically if the test fails.</>,
        ]}
      />
    ),
  },
  {
    id: 'waf-litespeed',
    title: 'WAF on LiteSpeed',
    body: (
      <>
        <p>
          <b>LiteSpeed on cPanel:</b> nothing extra to do. LiteSpeed reads the ModSecurity rules from the Apache configuration; the agent restarts
          LiteSpeed after installing rules and reads the blocked requests from <code>/usr/local/lsws/logs/error.log</code>. Upload scanning works with
          LiteSpeed's <code>@inspectFile</code> exit-code convention.
        </p>
        <p className="mt-3">
          <b>Standalone LiteSpeed (Enhance, CyberPanel, no control panel):</b> the agent writes <code>/usr/local/lsws/conf/xmartguard-waf.conf</code>;
          add it once in LiteSpeed WebAdmin (port 7080):
        </p>
        <Steps
          items={[
            <><b>Configuration » Server » Security</b>: Enable WAF = Yes, Scan Request Body = Yes.</>,
            <>Add a <b>WAF Rule Set</b>: Name <code>XMartGuard</code>, Action <code>deny,log,status:403</code>, Enabled Yes, Rules Definition:</>,
          ]}
        />
        <Code>{`Include /usr/local/lsws/conf/xmartguard-waf.conf`}</Code>
        <p>Save and do a graceful restart. The WAF Logs page shows a hint until the Include is present.</p>
      </>
    ),
  },
  {
    id: 'waf-others',
    title: 'WAF on plain Apache, DirectAdmin, Plesk, CWP',
    body: (
      <>
        <p>
          On plain Apache the agent hooks in automatically: <code>/etc/httpd/conf.d/xmartguard-waf.conf</code> (AlmaLinux, Rocky, CentOS) or{' '}
          <code>/etc/apache2/conf-available/xmartguard-waf.conf</code> (Debian, Ubuntu). ModSecurity (<code>mod_security2</code>) must be installed and
          no other vendor rule set should be active.
        </p>
        <p className="mt-2">
          DirectAdmin, Plesk and CWP are not hooked in automatically yet: there the WAF page shows the web server as unsupported, while malware
          scanning, the firewall and the IPDB work normally. Support for their ModSecurity layouts is planned.
        </p>
      </>
    ),
  },
  {
    id: 'cli',
    title: 'Command line (xgcli)',
    body: (
      <Code>{`xgcli help
xgcli status
xgcli scan --path /home/user/public_html     # scan a folder now
xgcli scan --list                            # scans and their progress
xgcli logs --status quarantined
xgcli view LOG_ID                            # show a detected file
xgcli ip --deny 203.0.113.9 --reason "abuse"
xgcli ip --allow 198.51.100.4
xgcli fw --status`}</Code>
    ),
  },
];

interface Credit {
  name: string;
  use: string;
  license: string;
  url: string;
}

const credits: Credit[] = [
  { name: 'DB-IP IP to Country Lite', use: 'Country of an IP address (IPDB map, firewall country rules)', license: 'CC BY 4.0', url: 'https://db-ip.com' },
  { name: 'Spamhaus DROP / EDROP', use: 'Hijacked network ranges in the IPDB', license: 'Free for use, Spamhaus terms', url: 'https://www.spamhaus.org/blocklists/do-not-route-or-peer/' },
  { name: 'Linux Malware Detect signatures', use: 'Optional MD5 / HEX malware signature feed', license: 'GPL v2', url: 'https://www.rfxn.com/projects/linux-malware-detect/' },
  { name: 'signature-base (Neo23x0)', use: 'Optional webshell YARA rules', license: 'Detection Rule License 1.1', url: 'https://github.com/Neo23x0/signature-base' },
  { name: 'WordPress.org checksums API', use: 'Known-good WordPress core and plugin files, core file repair', license: 'GPL v2+ (WordPress)', url: 'https://wordpress.org' },
  { name: 'WPVulnerability', use: 'Vulnerable plugin and theme database', license: 'Public API', url: 'https://www.wpvulnerability.net' },
  { name: 'OWASP ModSecurity / ModSecurity', use: 'WAF engine the rules run in', license: 'Apache 2.0', url: 'https://github.com/owasp-modsecurity/ModSecurity' },
  { name: 'ClamAV, YARA, rkhunter, Lynis', use: 'Optional engines used when installed on the server', license: 'GPL v2 / BSD-3', url: 'https://www.clamav.net' },
  { name: 'Spamhaus DBL, SURBL, URIBL', use: 'Domain and IP reputation lookups', license: 'Free for low-volume use, provider terms', url: 'https://www.spamhaus.org' },
  { name: 'Natural Earth / world-atlas', use: 'World map', license: 'Public domain / ISC', url: 'https://github.com/topojson/world-atlas' },
  { name: 'React, Recharts, Lucide, D3, Fastify, PostgreSQL, SQLite (modernc), golang.org/x/sys', use: 'Portal and agent software', license: 'MIT / ISC / BSD / PostgreSQL', url: 'https://github.com/xmarthost/xmartguard' },
];

function Item({ a, open, onToggle }: { a: Article; open: boolean; onToggle: () => void }) {
  return (
    <div className="card overflow-hidden p-0" id={a.id}>
      <button className="flex w-full items-center justify-between px-5 py-4 text-left font-medium text-navy-900 hover:bg-slate-50" onClick={onToggle}>
        {a.title}
        <ChevronDown className={`h-4 w-4 shrink-0 transition ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && <div className="border-t border-slate-100 px-5 py-4 text-sm leading-relaxed text-slate-700">{a.body}</div>}
    </div>
  );
}

export default function KnowledgeBase() {
  const [open, setOpen] = useState<string | null>(location.hash.slice(1) || 'realtime');
  return (
    <div className="mx-auto max-w-4xl space-y-5">
      <h1 className="h-title flex items-center gap-2">
        <BookOpen className="h-6 w-6" /> Knowledge Base
      </h1>
      <div className="space-y-3">
        {guides.map((a) => (
          <Item key={a.id} a={a} open={open === a.id} onToggle={() => setOpen(open === a.id ? null : a.id)} />
        ))}
      </div>

      <div className="card p-6" id="attributions">
        <h2 className="mb-1 text-lg font-semibold text-navy-900">Third-party data and software</h2>
        <p className="mb-4 text-sm text-slate-500">XMart Guard uses the following projects. Their licenses and terms apply to their parts.</p>
        <div className="divide-y divide-slate-100">
          {credits.map((c) => (
            <div key={c.name} className="grid gap-1 py-3 text-sm sm:grid-cols-[minmax(0,1.2fr)_minmax(0,1.6fr)_150px]">
              <a href={c.url} target="_blank" rel="noreferrer" className="flex items-center gap-1 font-medium text-blue-700 hover:underline">
                {c.name} <ExternalLink className="h-3 w-3 shrink-0" />
              </a>
              <span className="text-slate-600">{c.use}</span>
              <span className="text-slate-500 sm:text-right">{c.license}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
