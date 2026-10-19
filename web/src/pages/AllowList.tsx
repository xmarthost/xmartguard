import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { CheckCircle2, Plus, Trash2 } from 'lucide-react';
import { can, useAuth } from '../auth';
import { Breadcrumb, Empty, ErrorBox, SectionLoader } from '../components/ui';
import { Card, agentCall, isIPorCIDR, useAction, useAgent, useApplyWatch } from '../components/controls';
import { exclusionError, type RuleExclusion } from '../components/RuleExclusions';
import { useServerName } from './Scanner';

/** What can be allowed, and where the system puts it. */
const KINDS = [
  { v: 'ip', l: 'IP address (everything)', hint: '203.0.113.7 or 203.0.113.0/24', where: 'Firewall allow list: no firewall, WAF or IPDB rule ever blocks it.' },
  { v: 'waf_ip', l: 'IP address (WAF only)', hint: '203.0.113.7', where: 'WAF: no web rule checks it; the firewall still applies.' },
  { v: 'site', l: 'Website (WAF off)', hint: 'example.com or *.example.com', where: 'WAF: xPGuard rules skip this website. Prefer a single rule below.' },
  { v: 'rule', l: 'A rule on a website', hint: 'rule id, e.g. 941100', where: 'WAF: one rule switched off for one website (and path), every other site stays protected.' },
  { v: 'sender', l: 'Mail sender', hint: 'user@example.com', where: 'Outgoing Spam Monitor: never held or counted.' },
  { v: 'mail_ip', l: 'Mail IP', hint: '203.0.113.7', where: 'Outgoing Spam Monitor: never held or counted.' },
  { v: 'rep_domain', l: 'Blacklisted website (no suspension)', hint: 'example.com', where: 'Automatic suspension: a blocklisted domain does not suspend the account.' },
] as const;
type Kind = (typeof KINDS)[number]['v'];

interface Settings {
  waf: { whitelist_ips: string[]; whitelist_domains: string[]; rule_exclusions?: RuleExclusion[] };
  osm: { whitelist_senders: string[]; whitelist_ips: string[] };
  auto_suspend: { whitelist_domains: string[] };
}

interface Entry {
  kind: Kind;
  value: string;
  detail?: string;
  remove: () => Promise<unknown>;
}

const reDomain = /^(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+$/;

/** Allow list: every "allow" of this server in one place. */
export default function AllowList() {
  const { id } = useParams();
  const host = useServerName(id);
  const canAct = can(useAuth().user, 'operator');
  const st = useAgent<{ settings: Settings }>(id, 'settings.get');
  const fw = useAgent<{ rules: { cidr: string; comment: string }[] | null }>(id, 'fw.list', { kind: 'allow' });
  const { run, busy } = useAction();
  const [kind, setKind] = useState<Kind>('ip');
  const [value, setValue] = useState('');
  const [site, setSite] = useState('');
  const [path, setPath] = useState('');
  const [comment, setComment] = useState('');
  const [err, setErr] = useState('');
  const [q, setQ] = useState('');

  const s = st.data?.settings;
  const reload = () => (st.reload(), fw.reload());
  const watch = useApplyWatch();
  const setList = (section: keyof Settings, field: string, list: unknown) =>
    agentCall(id!, 'settings.set', { [section]: { [field]: list } }).then((r) => (watch(id!, r), r));

  const entries: Entry[] = !s
    ? []
    : [
        ...(fw.data?.rules ?? []).map((r) => ({ kind: 'ip' as Kind, value: r.cidr, detail: r.comment, remove: () => agentCall(id!, 'fw.remove', { kind: 'allow', addr: r.cidr }) })),
        ...s.waf.whitelist_ips.map((v) => ({ kind: 'waf_ip' as Kind, value: v, remove: () => setList('waf', 'whitelist_ips', s.waf.whitelist_ips.filter((x) => x !== v)) })),
        ...s.waf.whitelist_domains.map((v) => ({ kind: 'site' as Kind, value: v, remove: () => setList('waf', 'whitelist_domains', s.waf.whitelist_domains.filter((x) => x !== v)) })),
        ...(s.waf.rule_exclusions ?? []).map((r, i) => ({
          kind: 'rule' as Kind,
          value: `#${r.rule} on ${r.domain || 'every website'}${r.path ? r.path : ''}`,
          detail: r.note,
          remove: () => setList('waf', 'rule_exclusions', (s.waf.rule_exclusions ?? []).filter((_, j) => j !== i)),
        })),
        ...s.osm.whitelist_senders.map((v) => ({ kind: 'sender' as Kind, value: v, remove: () => setList('osm', 'whitelist_senders', s.osm.whitelist_senders.filter((x) => x !== v)) })),
        ...s.osm.whitelist_ips.map((v) => ({ kind: 'mail_ip' as Kind, value: v, remove: () => setList('osm', 'whitelist_ips', s.osm.whitelist_ips.filter((x) => x !== v)) })),
        ...s.auto_suspend.whitelist_domains.map((v) => ({ kind: 'rep_domain' as Kind, value: v, remove: () => setList('auto_suspend', 'whitelist_domains', s.auto_suspend.whitelist_domains.filter((x) => x !== v)) })),
      ];
  const shown = entries.filter((e) => !q || e.value.toLowerCase().includes(q.toLowerCase()) || e.detail?.toLowerCase().includes(q.toLowerCase()));

  const add = async () => {
    if (!s) return;
    const v = value.trim().toLowerCase();
    setErr('');
    let job: () => Promise<unknown>;
    switch (kind) {
      case 'ip':
      case 'waf_ip':
      case 'mail_ip': {
        const bad = isIPorCIDR(v);
        if (bad) return setErr(bad);
        job =
          kind === 'ip'
            ? () => agentCall(id!, 'fw.add', { kind: 'allow', addr: v, comment: comment || 'Allow list' })
            : kind === 'waf_ip'
              ? () => setList('waf', 'whitelist_ips', [...s.waf.whitelist_ips, v])
              : () => setList('osm', 'whitelist_ips', [...s.osm.whitelist_ips, v]);
        break;
      }
      case 'site':
      case 'rep_domain':
        if (!reDomain.test(v)) return setErr('Enter a website like example.com');
        job = kind === 'site' ? () => setList('waf', 'whitelist_domains', [...s.waf.whitelist_domains, v]) : () => setList('auto_suspend', 'whitelist_domains', [...s.auto_suspend.whitelist_domains, v]);
        break;
      case 'sender':
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v) && !reDomain.test(v)) return setErr('Enter an email address or a domain');
        job = () => setList('osm', 'whitelist_senders', [...s.osm.whitelist_senders, v]);
        break;
      case 'rule': {
        const ex: RuleExclusion = { rule: Number(v), domain: site.trim().toLowerCase() || undefined, path: path.trim() || undefined, note: comment || 'Allow list' };
        const bad = exclusionError(ex);
        if (bad) return setErr(bad);
        job = () => setList('waf', 'rule_exclusions', [...(s.waf.rule_exclusions ?? []), ex]);
        break;
      }
    }
    const r = await run(job, 'Allowed');
    if (r !== undefined) {
      setValue('');
      setSite('');
      setPath('');
      setComment('');
      reload();
    }
  };

  const k = KINDS.find((x) => x.v === kind)!;
  return (
    <div className="space-y-5">
      <Breadcrumb items={[host, 'Allow list']} />
      <div className="max-w-3xl">
        <h1 className="h-title">Allow list</h1>
        <p className="text-sm text-slate-500">
          Everything allowed on this server, in one list. Choose what to allow; xPGuard puts it in the right place (firewall, WAF or mail).
        </p>
      </div>
      {canAct && (
        <Card title="Allow">
          <div className="grid gap-3 md:grid-cols-[16rem_1fr]">
            <select className="input" value={kind} onChange={(e) => (setKind(e.target.value as Kind), setErr(''))}>
              {KINDS.map((x) => (
                <option key={x.v} value={x.v}>
                  {x.l}
                </option>
              ))}
            </select>
            <div className="flex flex-wrap gap-2">
              <input className="input min-w-0 flex-1" placeholder={k.hint} value={value} onChange={(e) => setValue(e.target.value)} />
              {kind === 'rule' && (
                <>
                  <input className="input w-48" placeholder="website (empty = all)" value={site} onChange={(e) => setSite(e.target.value)} />
                  <input className="input w-40" placeholder="path (optional)" value={path} onChange={(e) => setPath(e.target.value)} />
                </>
              )}
              {(kind === 'ip' || kind === 'rule') && <input className="input w-48" placeholder="note (optional)" value={comment} onChange={(e) => setComment(e.target.value)} />}
              <button className="btn-primary" disabled={busy || !value.trim() || !s} onClick={add}>
                <Plus className="h-4 w-4" /> Allow
              </button>
            </div>
          </div>
          <p className="mt-2 text-xs text-slate-500">
            <CheckCircle2 className="mr-1 inline h-3.5 w-3.5 text-emerald-600" />
            {k.where}
          </p>
          {err && <p className="mt-2 text-sm text-red-600">{err}</p>}
        </Card>
      )}
      <Card title={`Allowed (${entries.length})`} right={<input className="input w-56" placeholder="Filter" value={q} onChange={(e) => setQ(e.target.value)} />}>
        {(st.error || fw.error) && <ErrorBox message={st.error || fw.error || ''} />}
        {!st.data ? (
          <SectionLoader />
        ) : shown.length === 0 ? (
          <Empty text="Nothing allowed yet." />
        ) : (
          <div className="divide-y divide-slate-100">
            {shown.map((e, i) => (
              <div key={`${e.kind}-${e.value}-${i}`} className="flex flex-wrap items-center gap-3 py-2 text-sm">
                <span className="w-56 shrink-0 text-xs text-slate-500">{KINDS.find((x) => x.v === e.kind)!.l}</span>
                <span className="min-w-0 flex-1 font-mono break-all">{e.value}</span>
                {e.detail && <span className="text-xs text-slate-400">{e.detail}</span>}
                {canAct && (
                  <button
                    className="text-slate-400 hover:text-red-600"
                    title="Remove"
                    disabled={busy}
                    onClick={() => confirm(`Remove ${e.value} from the allow list?`) && run(e.remove, 'Removed').then(reload)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
