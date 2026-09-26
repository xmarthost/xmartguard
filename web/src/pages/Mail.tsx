import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { Ban, FileText, Globe, RefreshCw, Search, ShieldCheck, Trash2, Unlock } from 'lucide-react';
import { can, useAuth } from '../auth';
import { Breadcrumb, Empty, ErrorBox, PageLoader, StatCard } from '../components/ui';
import { Modal, Pager, agentCall, fmtTime, useAction, useAgent } from '../components/controls';
import { useServerName } from './Scanner';

interface OSMEvent {
  id: number;
  at: number;
  msg_id: string;
  sender: string;
  source: string;
  remarks: string;
  interval: string;
  count: number;
  action: string;
  user: string;
}

function SearchBox({ onSearch }: { onSearch: (q: string) => void }) {
  const [q, setQ] = useState('');
  return (
    <form
      className="flex gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        onSearch(q.trim());
      }}
    >
      <input className="input w-60" placeholder="Type to filter" value={q} onChange={(e) => setQ(e.target.value)} />
      <button className="btn-outline">
        <Search className="h-4 w-4" />
      </button>
    </form>
  );
}

export function OutgoingSpam() {
  const { id } = useParams();
  const host = useServerName(id);
  const { user } = useAuth();
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const [sel, setSel] = useState<number[]>([]);
  const [tx, setTx] = useState<OSMEvent | null>(null);
  const limit = 25;
  const list = useAgent<{ events: OSMEvent[]; total: number }>(id, 'osm.events', { q: query, limit, offset }, 15_000);
  const { run, busy } = useAction();

  return (
    <div className="space-y-5">
      <Breadcrumb items={[host, 'Outgoing Spam Monitor']} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="h-title">Outgoing Spam Monitor</h1>
          <p className="text-sm text-slate-500">Senders that exceeded the outgoing mail limits (Settings » Outgoing Spam Monitor).</p>
        </div>
        <div className="flex gap-2">
          <SearchBox onSearch={(q) => (setOffset(0), setQuery(q))} />
          {can(user, 'operator') && (
            <button
              className="btn-outline"
              disabled={busy || sel.length === 0}
              onClick={() =>
                run(() => agentCall(id!, 'osm.delete', { ids: sel }), `${sel.length} deleted`).then(() => {
                  setSel([]);
                  list.reload();
                })
              }
            >
              <Trash2 className="h-4 w-4" /> Delete
            </button>
          )}
        </div>
      </div>
      <div className="card overflow-x-auto p-0">
        {!list.data ? (
          list.error ? <ErrorBox message={list.error} /> : <PageLoader />
        ) : list.data.events.length === 0 ? (
          <Empty text="No outgoing spam detected" />
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs text-slate-500 uppercase">
              <tr>
                <th className="px-4 py-3">
                  <input type="checkbox" checked={sel.length === list.data.events.length} onChange={(e) => setSel(e.target.checked ? list.data!.events.map((x) => x.id) : [])} />
                </th>
                <th className="px-2">Reference ID</th>
                <th className="px-2">Sender</th>
                <th className="px-2">Source</th>
                <th className="px-2">Remarks</th>
                <th className="px-2">Time interval</th>
                <th className="px-2">Action</th>
                <th className="px-2">Date</th>
                <th className="px-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {list.data.events.map((e) => (
                <tr key={e.id} className="align-top">
                  <td className="px-4 py-3">
                    <input type="checkbox" checked={sel.includes(e.id)} onChange={(ev) => setSel(ev.target.checked ? [...sel, e.id] : sel.filter((x) => x !== e.id))} />
                  </td>
                  <td className="px-2 py-3 font-mono text-xs">{e.msg_id}</td>
                  <td className="px-2 py-3 break-all">
                    {e.sender}
                    {e.user && <div className="text-xs text-slate-500">account {e.user}</div>}
                  </td>
                  <td className="px-2 py-3 text-xs break-all">{e.source}</td>
                  <td className="max-w-xs px-2 py-3 text-xs break-all">{e.remarks}</td>
                  <td className="px-2 py-3">
                    <span className="rounded-full bg-navy-600 px-2.5 py-0.5 text-xs text-white">{e.interval}</span>
                    <div className="text-xs text-slate-500">{e.count} msgs</div>
                  </td>
                  <td className="px-2 py-3 text-xs">{e.action}</td>
                  <td className="px-2 py-3 text-xs whitespace-nowrap text-slate-500">{fmtTime(e.at)}</td>
                  <td className="px-2 py-3 whitespace-nowrap">
                    <button className="mr-2 text-slate-500 hover:text-navy-900" title="Show mail log for this message" onClick={() => setTx(e)}>
                      <FileText className="h-4 w-4" />
                    </button>
                    {can(user, 'admin') && e.user && (
                      <button
                        className="text-green-700 hover:text-green-900"
                        title={`Release outgoing mail for ${e.user}`}
                        disabled={busy}
                        onClick={() => confirm(`Release outgoing mail for ${e.user}?`) && run(() => agentCall(id!, 'osm.release', { user: e.user }), `Outgoing mail released for ${e.user}`)}
                      >
                        <Unlock className="h-4 w-4" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {list.data && <Pager total={list.data.total} limit={limit} offset={offset} onChange={setOffset} />}
      {tx && <TransactionModal serverId={id!} ev={tx} onClose={() => setTx(null)} />}
    </div>
  );
}

function TransactionModal({ serverId, ev, onClose }: { serverId: string; ev: OSMEvent; onClose: () => void }) {
  const r = useAgent<{ lines: string[] }>(serverId, 'osm.transaction', { msg_id: ev.msg_id });
  return (
    <Modal title={`Mail log ${ev.msg_id}`} onClose={onClose} wide>
      {r.error ? (
        <ErrorBox message={r.error} />
      ) : !r.data ? (
        <PageLoader />
      ) : r.data.lines.length === 0 ? (
        <Empty text="The message is no longer in the current Exim log" />
      ) : (
        <pre className="max-h-96 overflow-auto rounded bg-slate-900 p-3 text-xs whitespace-pre-wrap text-slate-100">{r.data.lines.join('\n')}</pre>
      )}
    </Modal>
  );
}

interface DomainRow {
  domain: string;
  user: string;
  status: 'clean' | 'listed' | 'error';
  reasons: string[];
  checked_at: number;
}

export function DomainReputation() {
  const { id } = useParams();
  const host = useServerName(id);
  const { user } = useAuth();
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const limit = 25;
  const res = useAgent<{ summary: { total: number; flagged: number; checked_at: number; errors: number }; domains: DomainRow[]; total: number }>(id, 'domainrep.get', { q: query, limit, offset });
  const { run, busy } = useAction();
  if (res.loading && !res.data) return <PageLoader />;
  if (res.error && !res.data) return <ErrorBox message={res.error} />;
  const s = res.data!.summary;

  return (
    <div className="space-y-5">
      <Breadcrumb items={[host, 'Domain Reputation']} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="h-title">Domain Reputation</h1>
        <div className="flex items-center gap-3 text-sm text-slate-600">
          {s.checked_at > 0 && <span>Last checked {fmtTime(s.checked_at)}</span>}
          {can(user, 'operator') && (
            <button className="btn-primary" disabled={busy} onClick={() => run(() => agentCall(id!, 'domainrep.check'), 'Domains checked').then(() => res.reload())}>
              <RefreshCw className={`h-4 w-4 ${busy ? 'animate-spin' : ''}`} /> Check now
            </button>
          )}
        </div>
      </div>
      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard icon={<ShieldCheck />} value={s.flagged ? 'bad' : 'good'} label={s.flagged ? `${s.flagged} domain${s.flagged > 1 ? 's are' : ' is'} bad` : 'No domain is blacklisted'} accent={s.flagged ? 'text-red-600' : 'text-green-600'} />
        <StatCard icon={<Globe />} value={s.total} label="Total Domains" />
        <StatCard icon={<Ban />} value={s.flagged} label="Flagged Domains" accent={s.flagged ? 'text-red-600' : 'text-navy-900'} />
      </div>
      <div className="flex justify-end">
        <SearchBox onSearch={(q) => (setOffset(0), setQuery(q))} />
      </div>
      <div className="card overflow-x-auto p-0">
        {res.data!.domains.length === 0 ? (
          <Empty text={s.total === 0 ? 'No domains checked yet (cPanel domains are checked automatically)' : 'No matching domains'} />
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs text-slate-500 uppercase">
              <tr>
                <th className="px-4 py-3">Domain</th>
                <th className="px-2">User</th>
                <th className="px-2">Reason</th>
                <th className="px-2">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {res.data!.domains.map((d) => (
                <tr key={d.domain}>
                  <td className="px-4 py-3">{d.domain}</td>
                  <td className="px-2">{d.user}</td>
                  <td className="px-2 text-xs">{d.reasons.join(', ') || (d.status === 'error' ? 'blocklists did not answer' : '–')}</td>
                  <td className="px-2">
                    <span className={`rounded-full px-3 py-1 text-xs ${d.status === 'listed' ? 'bg-red-100 text-red-700' : d.status === 'error' ? 'bg-slate-100 text-slate-500' : 'bg-green-100 text-green-700'}`}>
                      {d.status === 'listed' ? 'Blacklisted' : d.status === 'error' ? 'Unknown' : 'Clean'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <Pager total={res.data!.total} limit={limit} offset={offset} onChange={setOffset} />
      <p className="text-xs text-slate-400">Checked against Spamhaus DBL, SURBL and URIBL, plus Google Safe Browsing when an API key is set in Settings » RBL &amp; IP Reputation.</p>
    </div>
  );
}
