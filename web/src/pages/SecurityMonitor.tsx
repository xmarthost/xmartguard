import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { Activity, Clock, ShieldAlert } from 'lucide-react';
import { can, useAuth } from '../auth';
import { Breadcrumb, Empty, ErrorBox, PageLoader } from '../components/ui';
import { Pager, Tabs, agentCall, fmtTime, useAction, useAgent } from '../components/controls';
import { useServerName } from './Scanner';

interface MonEvent {
  id: number;
  at: number;
  kind: 'process' | 'cron' | 'rootkit';
  user: string;
  subject: string;
  reason: string;
  action: string;
}

const ICON = { process: <Activity className="h-4 w-4" />, cron: <Clock className="h-4 w-4" />, rootkit: <ShieldAlert className="h-4 w-4" /> };

/** Alerts from the process monitor, cron monitor and rootkit scanner. */
export default function SecurityMonitor() {
  const { id } = useParams();
  const host = useServerName(id);
  const { user } = useAuth();
  const [kind, setKind] = useState<'' | 'process' | 'cron' | 'rootkit'>('');
  const [offset, setOffset] = useState(0);
  const limit = 25;
  const ev = useAgent<{ events: MonEvent[]; total: number; status: { rkhunter: boolean; rkhunter_last: number; rkhunter_warnings: number } }>(
    id, 'monitor.events', { kind, limit, offset }, 30_000);
  const { run, busy } = useAction();
  const st = ev.data?.status;
  return (
    <div className="space-y-5">
      <Breadcrumb items={[host, 'Process & Cron Monitor']} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="h-title">Process &amp; Cron Monitor</h1>
          <p className="text-sm text-slate-500">
            Malicious processes and cron jobs of hosting users, and rootkit checks.{' '}
            {st && (st.rkhunter ? (st.rkhunter_last ? `Last rootkit check ${fmtTime(st.rkhunter_last)} (${st.rkhunter_warnings} warnings).` : 'Rootkit check not run yet.') : 'rkhunter is not installed.')}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Tabs value={kind} onChange={(v) => (setOffset(0), setKind(v))} tabs={[{ v: '', l: 'All' }, { v: 'process', l: 'Processes' }, { v: 'cron', l: 'Cron' }, { v: 'rootkit', l: 'Rootkit' }]} />
          {can(user, 'admin') && st?.rkhunter && (
            <button className="btn-primary" disabled={busy} onClick={() => run(() => agentCall(id!, 'monitor.rootkit').then(ev.reload), (r: any) => `Rootkit check done: ${r?.warnings ?? 0} warning(s)`)}>
              {busy ? 'Checking…' : 'Run rootkit check'}
            </button>
          )}
        </div>
      </div>
      <div className="card overflow-x-auto p-0">
        {ev.error && !ev.data ? (
          <div className="p-4"><ErrorBox message={ev.error} /></div>
        ) : !ev.data ? (
          <PageLoader />
        ) : ev.data.events.length === 0 ? (
          <Empty text="No alerts. Suspicious processes and cron jobs appear here." />
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-slate-600">
              <tr>
                <th className="px-5 py-3 font-medium">Type</th>
                <th className="py-3 font-medium">User</th>
                <th className="py-3 font-medium">Reason</th>
                <th className="py-3 font-medium">Details</th>
                <th className="py-3 font-medium">Action</th>
                <th className="px-4 py-3 font-medium">Time</th>
              </tr>
            </thead>
            <tbody>
              {ev.data.events.map((e) => (
                <tr key={e.id} className="border-b border-slate-100 align-top last:border-0">
                  <td className="px-5 py-3"><span className="flex items-center gap-2 capitalize">{ICON[e.kind]} {e.kind}</span></td>
                  <td className="py-3">{e.user}</td>
                  <td className="py-3">{e.reason}</td>
                  <td className="max-w-md py-3 font-mono text-xs break-all text-slate-600">{e.subject}</td>
                  <td className="py-3">
                    <span className={`rounded-full px-2 py-0.5 text-xs ${e.action === 'killed' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-800'}`}>{e.action}</span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-slate-500">{fmtTime(e.at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {ev.data && <Pager total={ev.data.total} limit={limit} offset={offset} onChange={setOffset} />}
    </div>
  );
}
