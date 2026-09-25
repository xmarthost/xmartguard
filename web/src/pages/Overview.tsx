import { Link } from 'react-router-dom';
import { CircleCheck, CircleX, Server as ServerIcon } from 'lucide-react';
import { useApi } from '../hooks';
import { panelName } from '../format';
import { ErrorBox, PageLoader, StatCard, StatusDot } from '../components/ui';

interface OverviewData {
  servers_total: number;
  servers_online: number;
  servers_offline: number;
  quick_access: { id: string; hostname: string; primary_ip: string; os_name: string; control_panel: string; online: boolean }[];
}

export default function Overview() {
  const { data, error, loading } = useApi<OverviewData>('/api/overview', 30_000);
  if (loading && !data) return <PageLoader />;
  if (error && !data) return <ErrorBox message={error} />;
  const d = data!;
  return (
    <div className="space-y-6">
      <section>
        <h2 className="h-title mb-4">Quick Access</h2>
        {d.quick_access.length === 0 ? (
          <div className="card flex flex-col items-center gap-3 p-10 text-center">
            <p className="text-slate-500">No servers yet. Add your first server to start protecting it.</p>
            <Link to="/servers/add" className="btn-primary">Add Server</Link>
          </div>
        ) : (
          <div className="flex gap-4 overflow-x-auto pb-2">
            {d.quick_access.map((s) => (
              <Link key={s.id} to={`/servers/${s.id}`} className="card min-w-72 p-5 transition hover:shadow-md">
                <div className="mb-1 flex items-center justify-between">
                  <span className="text-xs font-medium text-orange-500">{panelName(s.control_panel)}</span>
                  <StatusDot online={s.online} />
                </div>
                <div className="truncate text-lg font-semibold text-navy-900">{s.hostname}</div>
                <div className="text-sm text-slate-500">
                  {s.primary_ip} · {s.os_name}
                </div>
              </Link>
            ))}
          </div>
        )}
      </section>
      <section className="grid gap-4 md:grid-cols-3">
        <StatCard icon={<ServerIcon />} value={d.servers_total} label="Servers" />
        <StatCard icon={<CircleCheck />} value={d.servers_online} label="Online" accent="text-green-600" />
        <StatCard icon={<CircleX />} value={d.servers_offline} label="Offline" accent={d.servers_offline ? 'text-red-600' : 'text-navy-900'} />
      </section>
      <p className="text-sm text-slate-400">
        Threat, web-attack and firewall statistics appear here once the scanner and firewall modules are enabled on your servers.
      </p>
    </div>
  );
}
