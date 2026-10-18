import { lazy, Suspense, useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { Search } from 'lucide-react';
import { SectionLoader } from '../components/ui';
import { Modal, Tabs, agentCall, fmtTime } from '../components/controls';
import type { WafEvent } from './WAF';

const FirewallLogs = lazy(() => import('./Firewall').then((m) => ({ default: m.FirewallLogs })));
const WafLogs = lazy(() => import('./WAF').then((m) => ({ default: m.WafLogs })));
const BotAttacks = lazy(() => import('./WAF').then((m) => ({ default: m.BotAttacks })));
const ServerIPDB = lazy(() => import('./ServerIPDB'));

type Tab = 'waf' | 'firewall' | 'bots' | 'ipdb';

const TABS: { v: Tab; l: string }[] = [
  { v: 'waf', l: 'WAF' },
  { v: 'firewall', l: 'Firewall' },
  { v: 'bots', l: 'Bots' },
  { v: 'ipdb', l: 'IPDB' },
];

/** Security Events: the server's four logs behind one menu entry, and one
 *  address's whole story across them. */
export default function SecurityEvents({ initial }: { initial?: Tab }) {
  const { id } = useParams();
  const [sp, setSp] = useSearchParams();
  const tab = (TABS.find((t) => t.v === sp.get('tab'))?.v ?? initial ?? 'waf') as Tab;
  const [ip, setIp] = useState('');
  const [story, setStory] = useState('');
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Tabs tabs={TABS} value={tab} onChange={(v) => setSp({ tab: v }, { replace: true })} />
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (ip.trim()) setStory(ip.trim());
          }}
        >
          <input className="input w-56" placeholder="An IP's whole story" value={ip} onChange={(e) => setIp(e.target.value)} />
          <button className="btn-outline" disabled={!ip.trim()}>
            <Search className="h-4 w-4" />
          </button>
        </form>
      </div>
      <Suspense fallback={<SectionLoader />}>
        {tab === 'waf' && <WafLogs />}
        {tab === 'firewall' && <FirewallLogs />}
        {tab === 'bots' && <BotAttacks />}
        {tab === 'ipdb' && <ServerIPDB />}
      </Suspense>
      {story && id && <IPStory serverId={id} ip={story} onClose={() => setStory('')} />}
    </div>
  );
}

interface Check {
  status: string;
  found?: string[] | null;
  country?: string;
  trusted?: string;
  events?: { created_at: number; status: string; reason: string; source?: string }[] | null;
}

/** Everything this server knows about one address, newest first. */
function IPStory({ serverId, ip, onClose }: { serverId: string; ip: string; onClose: () => void }) {
  const [data, setData] = useState<{ fw: Check | null; waf: WafEvent[]; err: string } | null>(null);
  if (!data) {
    void Promise.all([
      agentCall<Check>(serverId, 'fw.check', { ip }).catch(() => null),
      agentCall<{ events: WafEvent[] | null }>(serverId, 'waf.events', { ip, limit: 100 }).catch(() => ({ events: [] })),
    ])
      .then(([fw, w]) => setData({ fw, waf: w.events ?? [], err: '' }))
      .catch((e) => setData({ fw: null, waf: [], err: String(e.message ?? e) }));
  }
  type Line = { at: number; source: string; text: string };
  const lines: Line[] = [
    ...(data?.waf ?? []).map((e) => ({ at: e.at, source: e.category === 'bot' ? 'Bot' : 'WAF', text: `${e.action.startsWith('Access denied') ? 'Blocked' : 'Logged'} ${e.method} ${e.host}${e.uri} — #${e.rule_id} ${e.msg}` })),
    ...(data?.fw?.events ?? []).map((e) => ({ at: e.created_at, source: e.source === 'ipdb' ? 'IPDB' : 'Firewall', text: `${e.status}: ${e.reason ?? ''}` })),
  ].sort((a, b) => b.at - a.at);
  return (
    <Modal title={`Story of ${ip}`} onClose={onClose} wide>
      {!data ? (
        <SectionLoader />
      ) : (
        <>
          {data.fw && (
            <p className="mb-3 text-sm text-slate-600">
              Now: <b>{data.fw.status}</b>
              {data.fw.found?.length ? ` (${data.fw.found.join(', ')})` : ''}
              {data.fw.trusted && ` · trusted service: ${data.fw.trusted}`}
              {data.fw.country && ` · country list: ${data.fw.country}`}
            </p>
          )}
          {lines.length === 0 ? (
            <p className="text-sm text-slate-500">Nothing recorded for this address on this server.</p>
          ) : (
            <ol className="max-h-[60vh] space-y-1 overflow-auto text-sm">
              {lines.map((l, i) => (
                <li key={i} className="flex gap-3 border-b border-slate-100 py-1.5">
                  <span className="w-40 shrink-0 text-xs text-slate-500">{fmtTime(l.at)}</span>
                  <span className="w-16 shrink-0 text-xs font-medium text-navy-800">{l.source}</span>
                  <span className="min-w-0 font-mono text-xs break-all">{l.text}</span>
                </li>
              ))}
            </ol>
          )}
        </>
      )}
    </Modal>
  );
}
