import { useState } from 'react';
import { Check, ChevronDown, ChevronRight, Eye, ShieldCheck } from 'lucide-react';
import { api } from '../api';
import { can, useAuth } from '../auth';
import { Empty, ErrorBox, SectionLoader } from '../components/ui';
import { Card, fmtTime, useAction } from '../components/controls';
import { useApi } from '../hooks';
import { ago } from '../format';

interface Example {
  at: number;
  ip: string;
  method: string;
  host: string;
  uri: string;
  action: string;
  detail: string;
  server: string;
}

interface Rule {
  id: number;
  title: string;
  since: string;
  servers: number;
  watching: number;
  hits: number;
  ips: number;
  sites: number;
  hit_servers: number;
  examples: Example[];
  decision: 'enforce' | 'watch' | null;
  decided_at: string | null;
}

interface Resp {
  hours: number;
  servers: number;
  asked: number;
  answered: number;
  rules: Rule[];
}

/** Learning Center » Rule approvals: new rules only log what they would
 *  block until an administrator approves them here. */
export default function RuleApprovals() {
  const { user } = useAuth();
  const admin = can(user, 'admin');
  const [hours, setHours] = useState(48);
  const res = useApi<Resp>(`/api/waf/approvals?hours=${hours}`);
  const { run, busy } = useAction();
  const [open, setOpen] = useState<number | null>(null);

  const decide = (id: number, status: 'enforce' | 'watch') =>
    run(
      () => api<{ pushed: number }>('POST', '/api/waf/approvals', { rule_id: id, status }).then((r) => (res.reload(), r)),
      (r) => `${status === 'enforce' ? 'Blocking' : 'Watching'} on ${r.pushed} online server${r.pushed === 1 ? '' : 's'}; the others follow when they connect`,
    );

  return (
    <div className="space-y-5">
      <Card
        title="Rule approvals"
        desc="A new WAF rule or virtual patch first only watches: it logs the requests it would block and lets them through, and nothing counts toward a ban. Check what it matched on all servers, then approve it to start blocking."
        right={
          <select className="input w-32" value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            {[24, 48, 72, 168].map((h) => (
              <option key={h} value={h}>
                Last {h >= 72 ? `${h / 24} days` : `${h} h`}
              </option>
            ))}
          </select>
        }
      >
        {res.error && !res.data && <ErrorBox message={res.error} />}
        {!res.data ? (
          <SectionLoader />
        ) : res.data.rules.length === 0 ? (
          <Empty text="No new rules are waiting for approval." />
        ) : (
          <>
            <p className="mb-3 text-xs text-slate-400">
              {res.data.answered} of {res.data.servers} servers answered (offline servers and older agents are not counted).
            </p>
            <div className="divide-y divide-slate-100">
              {res.data.rules.map((r) => {
                const blocking = r.decision === 'enforce';
                const shown = open === r.id;
                return (
                  <div key={r.id} className="py-3">
                    <div className="flex flex-wrap items-center gap-3">
                      <button className="flex min-w-0 flex-1 items-start gap-2 text-left" onClick={() => setOpen(shown ? null : r.id)}>
                        {shown ? <ChevronDown className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" /> : <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />}
                        <span className="min-w-0">
                          <span className="block font-medium text-navy-900">
                            {r.title || `Rule ${r.id}`} <span className="font-normal text-slate-400">#{r.id}</span>
                          </span>
                          <span className="block text-xs text-slate-500">
                            {r.since === 'portal' ? 'Portal virtual patch' : `New in ${r.since}`} · {r.hits.toLocaleString()} matches from {r.ips} addresses on {r.sites} sites
                            ({r.hit_servers} of {r.servers} servers)
                            {r.decided_at && ` · decided ${ago(r.decided_at)}`}
                          </span>
                        </span>
                      </button>
                      <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${blocking ? 'bg-red-50 text-red-700' : 'bg-amber-50 text-amber-700'}`}>
                        {blocking ? 'Blocking' : 'Watching'}
                      </span>
                      {admin &&
                        (blocking ? (
                          <button className="btn-outline px-3 py-1.5 text-sm" disabled={busy} onClick={() => decide(r.id, 'watch')}>
                            <Eye className="h-4 w-4" /> Watch again
                          </button>
                        ) : (
                          <button className="btn-primary px-3 py-1.5 text-sm" disabled={busy} onClick={() => decide(r.id, 'enforce')}>
                            <Check className="h-4 w-4" /> Approve: block
                          </button>
                        ))}
                    </div>
                    {shown && (
                      <div className="mt-3 overflow-x-auto rounded-lg border border-slate-200">
                        {r.examples.length === 0 ? (
                          <p className="p-3 text-sm text-slate-500">
                            <ShieldCheck className="mr-1 inline h-4 w-4 text-emerald-600" /> No request matched in this time window.
                          </p>
                        ) : (
                          <table className="w-full text-left text-xs">
                            <thead className="bg-slate-50 text-slate-500">
                              <tr>
                                <th className="px-3 py-2">Time</th>
                                <th className="px-3 py-2">Server</th>
                                <th className="px-3 py-2">Site</th>
                                <th className="px-3 py-2">Request</th>
                                <th className="px-3 py-2">Address</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                              {r.examples.map((e, i) => (
                                <tr key={i}>
                                  <td className="px-3 py-1.5 whitespace-nowrap">{fmtTime(e.at)}</td>
                                  <td className="px-3 py-1.5">{e.server}</td>
                                  <td className="px-3 py-1.5">{e.host}</td>
                                  <td className="max-w-md truncate px-3 py-1.5 font-mono" title={e.uri}>
                                    {e.method} {e.uri}
                                  </td>
                                  <td className="px-3 py-1.5 font-mono">{e.ip}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        )}
      </Card>
    </div>
  );
}
