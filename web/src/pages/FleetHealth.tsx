import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, AlertTriangle, ArrowUpCircle, CheckCircle2, RotateCcw, WifiOff } from 'lucide-react';
import { api } from '../api';
import { can, useAuth } from '../auth';
import { Breadcrumb, ErrorBox, PageLoader } from '../components/ui';
import { Card, useAction } from '../components/controls';
import { useApi } from '../hooks';
import { ago } from '../format';
import { TIME_ZONE_LABEL, fromPortalInput } from '../timezone';

interface Problem {
  level: 'danger' | 'warning';
  text: string;
  fix: 'update' | 'waf' | 'dashboard' | 'install' | 'monitoring';
}

interface Row {
  id: string;
  hostname: string;
  online: boolean;
  last_seen_at: string | null;
  agent_version: string;
  cpu: number | null;
  mem: number | null;
  disk: number | null;
  alerts: number;
  problems: Problem[];
}

interface Resp {
  latest_agent_version: string | null;
  servers: Row[];
  summary: { total: number; offline: number; outdated: number; problems: number };
}

const pct = (v: number | null) => (v === null ? '–' : `${Math.round(v * 100)}%`);

/** Fleet health: every server on one page, what needs fixing first. */
export default function FleetHealth() {
  const { user } = useAuth();
  const admin = can(user, 'admin');
  const res = useApi<Resp>('/api/fleet/health', 60_000);
  const { run, busy } = useAction();
  const [only, setOnly] = useState(true);
  const [when, setWhen] = useState('');

  if (res.error && !res.data) return <ErrorBox message={res.error} />;
  if (!res.data) return <PageLoader />;
  const d = res.data;
  const rows = only ? d.servers.filter((s) => s.problems.length) : d.servers;

  const fixLink = (s: Row, p: Problem) => {
    switch (p.fix) {
      case 'update':
        return admin ? (
          <button
            className="text-xs text-navy-700 underline"
            disabled={busy}
            onClick={() => run(() => api('POST', `/api/servers/${s.id}/update-agent`), `${s.hostname}: updating the agent`).then(() => res.reload())}
          >
            Update now
          </button>
        ) : null;
      case 'waf':
        return <Link className="text-xs text-navy-700 underline" to={`/servers/${s.id}/settings?s=waf`}>WAF settings</Link>;
      case 'monitoring':
        return <Link className="text-xs text-navy-700 underline" to={`/servers/${s.id}/monitoring`}>Monitoring</Link>;
      case 'install':
        return <span className="text-xs text-slate-400">last seen {ago(s.last_seen_at)}</span>;
      default:
        return <Link className="text-xs text-navy-700 underline" to={`/servers/${s.id}`}>Dashboard</Link>;
    }
  };

  return (
    <div className="space-y-5">
      <Breadcrumb items={['Fleet health']} />
      <div className="max-w-3xl">
        <h1 className="h-title flex items-center gap-2">
          <Activity className="h-6 w-6" /> Fleet health
        </h1>
        <p className="text-sm text-slate-500">Every server at a glance: offline, old agent, WAF errors, full disks, high CPU and services that stopped, with the fix next to each.</p>
      </div>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {(
          [
            ['Servers', d.summary.total, 'text-navy-900', <CheckCircle2 key="a" className="h-5 w-5 text-emerald-500" />],
            ['Need attention', d.summary.problems, 'text-red-600', <AlertTriangle key="b" className="h-5 w-5 text-red-500" />],
            ['Offline', d.summary.offline, 'text-red-600', <WifiOff key="c" className="h-5 w-5 text-slate-400" />],
            ['Old agent', d.summary.outdated, 'text-amber-600', <ArrowUpCircle key="d" className="h-5 w-5 text-amber-500" />],
          ] as [string, number, string, React.ReactNode][]
        ).map(([l, v, c, icon]) => (
          <div key={l} className="card flex items-center justify-between p-4">
            <div>
              <div className="text-xs text-slate-500 uppercase">{l}</div>
              <div className={`mt-1 text-2xl font-bold ${c}`}>{v}</div>
            </div>
            {icon}
          </div>
        ))}
      </div>

      <Card
        title="Servers"
        desc={d.latest_agent_version ? `Latest agent: ${d.latest_agent_version}` : undefined}
        right={
          <label className="flex items-center gap-2 text-sm text-slate-500">
            <input type="checkbox" checked={only} onChange={(e) => setOnly(e.target.checked)} /> Only servers that need attention
          </label>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs text-slate-500">
              <tr>
                <th className="py-2 pr-3">Server</th>
                <th className="py-2 pr-3">Agent</th>
                <th className="py-2 pr-3">CPU</th>
                <th className="py-2 pr-3">Memory</th>
                <th className="py-2 pr-3">Disk</th>
                <th className="py-2">Needs attention</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-6 text-center text-slate-500">
                    <CheckCircle2 className="mr-1 inline h-4 w-4 text-emerald-600" /> Every server is healthy.
                  </td>
                </tr>
              )}
              {rows.map((s) => (
                <tr key={s.id} className="align-top">
                  <td className="py-2 pr-3">
                    <Link to={`/servers/${s.id}`} className="font-medium text-navy-900 hover:underline">
                      <span className={`mr-2 inline-block h-2 w-2 rounded-full ${s.online ? 'bg-emerald-500' : 'bg-red-500'}`} />
                      {s.hostname}
                    </Link>
                  </td>
                  <td className="py-2 pr-3 font-mono text-xs">{s.agent_version || '–'}</td>
                  <td className="py-2 pr-3">{s.cpu === null ? '–' : `${Math.round(s.cpu)}%`}</td>
                  <td className="py-2 pr-3">{pct(s.mem)}</td>
                  <td className="py-2 pr-3">{pct(s.disk)}</td>
                  <td className="py-2">
                    {s.problems.length === 0 ? (
                      <span className="text-xs text-emerald-700">OK</span>
                    ) : (
                      <ul className="space-y-1">
                        {s.problems.map((p, i) => (
                          <li key={i} className="flex flex-wrap items-center gap-2">
                            <span className={`text-xs ${p.level === 'danger' ? 'text-red-700' : 'text-amber-700'}`}>{p.text}</span>
                            {fixLink(s, p)}
                          </li>
                        ))}
                      </ul>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {admin && (
        <Card title="Roll back settings on every server" desc="Puts back each server's settings as they were at a time: every change made after it is undone (each server keeps its last 100 changes).">
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <input type="datetime-local" className="input w-60" value={when} onChange={(e) => setWhen(e.target.value)} title={`Time in ${TIME_ZONE_LABEL}`} />
            <span className="text-sm text-slate-500">{TIME_ZONE_LABEL}</span>
            <button
              className="btn-danger"
              disabled={busy || !when}
              onClick={async () => {
                const before = fromPortalInput(when);
                if (!before) return;
                if (!confirm(`Undo every settings change made after ${new Date(before * 1000).toLocaleString()} ${TIME_ZONE_LABEL} on all servers?`)) return;
                const r = await run(() =>
                  api<{ results: { server: string; ok: boolean; message: string }[] }>('POST', '/api/fleet/rollback', { before }),
                );
                if (r) alert(r.results.map((x) => `${x.ok ? '✓' : '✗'} ${x.server}: ${x.message}`).join('\n') || 'No servers');
              }}
            >
              <RotateCcw className="h-4 w-4" /> Roll back all servers
            </button>
          </div>
        </Card>
      )}
    </div>
  );
}
