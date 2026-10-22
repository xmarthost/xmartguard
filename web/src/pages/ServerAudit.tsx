import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { can, useAuth } from '../auth';
import { Breadcrumb, Empty, ErrorBox, SectionLoader } from '../components/ui';
import { Tabs, agentCall, fmtTime, useAction, useAgent } from '../components/controls';
import { useServerName } from './Scanner';

interface AuditItem {
  check: string;
  severity: 'high' | 'medium' | 'low';
  title: string;
  detail?: string;
  path?: string;
  owner?: string;
}

interface AuditReport {
  at: number;
  seconds: number;
  items: AuditItem[] | null;
  counts: Record<string, number>;
  skipped?: string[];
  websites: number;
}

const CHECKS: Record<string, string> = {
  mysql_hosts: 'Database users',
  leaked_secret: 'Keys in websites',
  public_backup: 'Public backups',
  wp_core: 'WordPress core',
  wp_debug: 'WordPress debug',
  php: 'PHP settings',
  php_eol: 'Old PHP',
  php_cve: 'PHP security update',
  stuck_php: 'Stuck PHP',
  cron: 'Cron jobs',
};

const SEV = {
  high: 'bg-red-100 text-red-700',
  medium: 'bg-amber-100 text-amber-800',
  low: 'bg-slate-100 text-slate-700',
};

/** Risky settings and leftovers the nightly server audit found (report only). */
export default function ServerAudit() {
  const { id } = useParams();
  const host = useServerName(id);
  const { user } = useAuth();
  const [sev, setSev] = useState<'' | 'high' | 'medium' | 'low'>('');
  const res = useAgent<{ running: boolean; report?: AuditReport }>(id, 'audit.get', {}, 15_000);
  const { run, busy } = useAction();
  const rep = res.data?.report;
  const items = (rep?.items ?? []).filter((i) => !sev || i.severity === sev);
  const running = res.data?.running;
  return (
    <div className="space-y-5">
      <Breadcrumb items={[host, 'Server Audit']} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="max-w-3xl">
          <h1 className="h-title">Server Audit</h1>
          <p className="text-sm text-slate-500">
            Risky settings that are not malware: database users reachable from other hosts, API keys and backups inside websites, unsafe PHP settings, broken
            WordPress installs, stuck PHP processes and cron jobs. Runs every night; nothing is changed.{' '}
            {rep && `Last run ${fmtTime(rep.at)} (${Math.max(1, Math.round(rep.seconds))} s, ${rep.websites} WordPress sites).`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Tabs
            value={sev}
            onChange={setSev}
            tabs={[
              { v: '', l: `All${rep ? ` (${rep.items?.length ?? 0})` : ''}` },
              { v: 'high', l: `High${rep ? ` (${rep.counts?.high ?? 0})` : ''}` },
              { v: 'medium', l: `Medium${rep ? ` (${rep.counts?.medium ?? 0})` : ''}` },
              { v: 'low', l: `Low${rep ? ` (${rep.counts?.low ?? 0})` : ''}` },
            ]}
          />
          {can(user, 'operator') && (
            <button className="btn-primary" disabled={busy || running} onClick={() => run(() => agentCall(id!, 'audit.run').then(res.reload), 'Audit started')}>
              {running ? 'Running…' : 'Run now'}
            </button>
          )}
        </div>
      </div>
      {rep?.skipped && rep.skipped.length > 0 && <p className="text-xs text-slate-500">Not checked: {rep.skipped.join('; ')}</p>}
      <div className="card overflow-x-auto p-0">
        {res.error && !res.data ? (
          <div className="p-4"><ErrorBox message={res.error} /></div>
        ) : !res.data ? (
          <SectionLoader />
        ) : !rep ? (
          <Empty text={running ? 'The first audit is running…' : 'No audit yet. It runs every night, or press Run now.'} />
        ) : items.length === 0 ? (
          <Empty text="Nothing found." />
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-slate-600">
              <tr>
                <th className="px-5 py-3 font-medium">Severity</th>
                <th className="py-3 font-medium">Check</th>
                <th className="py-3 font-medium">Finding</th>
                <th className="px-4 py-3 font-medium">User</th>
              </tr>
            </thead>
            <tbody>
              {items.map((it, i) => (
                <tr key={i} className="border-b border-slate-100 align-top last:border-0">
                  <td className="px-5 py-3">
                    <span className={`rounded-full px-2 py-0.5 text-xs capitalize ${SEV[it.severity]}`}>{it.severity}</span>
                  </td>
                  <td className="py-3 whitespace-nowrap">{CHECKS[it.check] ?? it.check}</td>
                  <td className="max-w-2xl py-3">
                    <div className="font-medium text-navy-900">{it.title}</div>
                    {it.path && <div className="font-mono text-xs break-all text-slate-600">{it.path}</div>}
                    {it.detail && <div className="mt-1 text-xs whitespace-pre-wrap text-slate-500">{it.detail}</div>}
                  </td>
                  <td className="px-4 py-3">{it.owner || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
