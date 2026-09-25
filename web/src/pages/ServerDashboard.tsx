import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Activity, Cpu, HardDrive, MemoryStick, Network, RefreshCw, ScanSearch } from 'lucide-react';
import { api, type Server } from '../api';
import { can, useAuth } from '../auth';
import { useApi } from '../hooks';
import { ago, bytes, duration, panelName, pct } from '../format';
import { Bar, ErrorBox, PageLoader, StatusDot } from '../components/ui';
import SecurityPanel from '../components/SecurityPanel';

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4 border-b border-slate-100 py-2 text-sm last:border-0">
      <span className="text-slate-500">{k}</span>
      <span className="text-right font-medium text-navy-900">{v || '–'}</span>
    </div>
  );
}

function Meter({ icon, label, value, detail }: { icon: React.ReactNode; label: string; value: number; detail: string }) {
  return (
    <div className="card p-5">
      <div className="mb-3 flex items-center gap-2 text-navy-800">
        {icon}
        <span className="font-medium">{label}</span>
        <span className="ml-auto text-2xl font-semibold text-navy-900">{value}%</span>
      </div>
      <Bar value={value} className={value > 90 ? 'bg-red-500' : value > 75 ? 'bg-amber-500' : 'bg-green-500'} />
      <div className="mt-2 text-xs text-slate-500">{detail}</div>
    </div>
  );
}

export default function ServerDashboard() {
  const { id } = useParams();
  const { user } = useAuth();
  const { data, error, loading } = useApi<{ server: Server; latest_agent_version: string | null }>(`/api/servers/${id}`, 15_000);
  const [ping, setPing] = useState<string>('');
  if (loading && !data) return <PageLoader />;
  if (error && !data) return <ErrorBox message={error} />;
  const s = data!.server;
  const m = s.last_metrics;
  const inv = s.inventory;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="h-title">{s.hostname}</h1>
          <div className="mt-1 flex items-center gap-3 text-sm text-slate-500">
            <span>{s.primary_ip}</span>
            <StatusDot online={s.online} />
            {!s.online && <span>last seen {ago(s.last_seen_at)}</span>}
          </div>
        </div>
        <div className="flex items-center gap-2">
          {ping && <span className="text-sm text-slate-500">{ping}</span>}
          {can(user, 'operator') && (
            <button
              className="btn-outline"
              disabled={!s.online}
              onClick={async () => {
                setPing('…');
                try {
                  const r = await api<{ rtt_ms: number }>('POST', `/api/servers/${s.id}/ping`, {});
                  setPing(`agent replied in ${r.rtt_ms} ms`);
                } catch (e: any) {
                  setPing(e.message);
                }
              }}
            >
              <RefreshCw className="h-4 w-4" /> Test connection
            </button>
          )}
          <Link to="monitoring" className="btn-outline"><Activity className="h-4 w-4" /> System Monitoring</Link>
          <Link to="scanner" className="btn-primary"><ScanSearch className="h-4 w-4" /> Quick Scan</Link>
        </div>
      </div>

      <SecurityPanel serverId={s.id} online={s.online} agentVersion={s.agent_version} latestVersion={data!.latest_agent_version} />

      {m ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <Meter icon={<Cpu className="h-5 w-5" />} label="CPU" value={m.cpu_percent} detail={`${inv.cpu_cores} cores · load ${m.load1.toFixed(2)}`} />
          <Meter icon={<MemoryStick className="h-5 w-5" />} label="Memory" value={pct(m.mem_used, m.mem_total)} detail={`${bytes(m.mem_used)} of ${bytes(m.mem_total)}`} />
          <Meter icon={<HardDrive className="h-5 w-5" />} label="Disk (/)" value={pct(m.disk_used, m.disk_total)} detail={`${bytes(m.disk_used)} of ${bytes(m.disk_total)}`} />
          <div className="card p-5">
            <div className="mb-3 flex items-center gap-2 text-navy-800">
              <Network className="h-5 w-5" />
              <span className="font-medium">Connections</span>
            </div>
            <div className="text-3xl font-semibold text-navy-900">{m.connections}</div>
            <div className="mt-2 text-xs text-slate-500">established TCP · up {duration(m.uptime_seconds)}</div>
          </div>
        </div>
      ) : (
        <div className="card p-6 text-sm text-slate-500">Waiting for the first metrics from the agent…</div>
      )}

      <div className="grid gap-5 lg:grid-cols-2">
        <div className="card p-6">
          <h2 className="mb-3 text-lg font-semibold text-navy-900">Server information</h2>
          <Row k="Hostname" v={inv.hostname} />
          <Row k="Primary IP" v={inv.primary_ip} />
          <Row k="All IPs" v={inv.ips?.join(', ')} />
          <Row k="Control panel" v={panelName(inv.control_panel)} />
          <Row k="Web server" v={inv.web_server} />
          <Row k="Operating system" v={`${inv.os_name ?? ''} ${inv.os_version ?? ''}`} />
          <Row k="Kernel" v={inv.kernel} />
          <Row k="Architecture" v={inv.arch} />
          <Row k="Virtualization" v={inv.virtualization} />
        </div>
        <div className="card p-6">
          <h2 className="mb-3 text-lg font-semibold text-navy-900">Agent</h2>
          <Row k="Status" v={<StatusDot online={s.online} />} />
          <Row k="Agent version" v={s.agent_version} />
          <Row k="Added" v={new Date(s.created_at).toLocaleString()} />
          <Row k="Last seen" v={ago(s.last_seen_at)} />
          <Row k="CPU" v={`${inv.cpu_model} (${inv.cpu_cores} cores)`} />
          <Row k="Memory" v={bytes(inv.mem_total_bytes)} />
          <Row k="Tags" v={s.tags.join(', ')} />
          <p className="mt-4 text-xs text-slate-400">
            WAF, CMS and outgoing-spam panels will appear here as those modules are released.
          </p>
        </div>
      </div>
    </div>
  );
}
