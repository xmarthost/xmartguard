import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Activity, ChevronLeft, Cpu, HardDrive, Info, MemoryStick, Network, RefreshCw, Search } from 'lucide-react';
import { api, type Server } from '../api';
import { can, useAuth } from '../auth';
import { useApi } from '../hooks';
import { ago, bytes, duration, panelName, pct } from '../format';
import { Bar, ErrorBox, PageLoader, StatusDot } from '../components/ui';
import { Modal, agentCall, useAction } from '../components/controls';
import AttackOverview from '../components/AttackOverview';

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
    <div className="rounded-xl border border-slate-100 p-4">
      <div className="mb-2 flex items-center gap-2 text-navy-800">
        {icon}
        <span className="text-sm font-medium">{label}</span>
        <span className="ml-auto text-lg font-semibold text-navy-900">{value}%</span>
      </div>
      <Bar value={value} className={value > 90 ? 'bg-red-500' : value > 75 ? 'bg-amber-500' : 'bg-green-500'} />
      <div className="mt-1.5 text-xs text-slate-500">{detail}</div>
    </div>
  );
}

/** Server details (the (i) button): health, inventory and agent. */
function ServerInfo({ s, onClose }: { s: Server; onClose: () => void }) {
  const { user } = useAuth();
  const [ping, setPing] = useState('');
  const m = s.last_metrics;
  const inv = s.inventory;
  return (
    <Modal title={s.hostname} onClose={onClose} wide>
      {m && (
        <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Meter icon={<Cpu className="h-4 w-4" />} label="CPU" value={m.cpu_percent} detail={`${inv.cpu_cores} cores · load ${m.load1.toFixed(2)}`} />
          <Meter icon={<MemoryStick className="h-4 w-4" />} label="Memory" value={pct(m.mem_used, m.mem_total)} detail={`${bytes(m.mem_used)} of ${bytes(m.mem_total)}`} />
          <Meter icon={<HardDrive className="h-4 w-4" />} label="Disk (/)" value={pct(m.disk_used, m.disk_total)} detail={`${bytes(m.disk_used)} of ${bytes(m.disk_total)}`} />
          <div className="rounded-xl border border-slate-100 p-4">
            <div className="mb-1 flex items-center gap-2 text-sm font-medium text-navy-800">
              <Network className="h-4 w-4" /> Connections
            </div>
            <div className="text-2xl font-semibold text-navy-900">{m.connections}</div>
            <div className="text-xs text-slate-500">established TCP · up {duration(m.uptime_seconds)}</div>
          </div>
        </div>
      )}
      <div className="grid gap-6 md:grid-cols-2">
        <div>
          <h3 className="mb-2 font-semibold text-navy-900">Server information</h3>
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
        <div>
          <h3 className="mb-2 font-semibold text-navy-900">Agent</h3>
          <Row k="Status" v={<StatusDot online={s.online} />} />
          <Row k="Agent version" v={s.agent_version} />
          <Row k="Added" v={new Date(s.created_at).toLocaleString()} />
          <Row k="Last seen" v={ago(s.last_seen_at)} />
          <Row k="CPU" v={`${inv.cpu_model} (${inv.cpu_cores} cores)`} />
          <Row k="Memory" v={bytes(inv.mem_total_bytes)} />
          <Row k="Tags" v={s.tags.join(', ')} />
        </div>
      </div>
      <div className="mt-5 flex flex-wrap items-center justify-end gap-2">
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
        <Link to="monitoring" className="btn-primary" onClick={onClose}>
          <Activity className="h-4 w-4" /> System Monitoring
        </Link>
      </div>
    </Modal>
  );
}

export default function ServerDashboard() {
  const { id } = useParams();
  const { user } = useAuth();
  const nav = useNavigate();
  const { data, error, loading } = useApi<{ server: Server; latest_agent_version: string | null }>(`/api/servers/${id}`, 15_000);
  const [days, setDays] = useState(30);
  const [info, setInfo] = useState(false);
  const { run, busy } = useAction();
  if (loading && !data) return <PageLoader />;
  if (error && !data) return <ErrorBox message={error} />;
  const s = data!.server;

  const quickScan = async () => {
    const r = await run(() => agentCall<{ id: number }>(s.id, 'scan.start', { kind: 'quick' }), 'Quick scan started');
    if (r) nav('scanner');
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Link to="/servers" className="text-navy-900 hover:text-blue-700" aria-label="All servers">
              <ChevronLeft className="h-6 w-6" />
            </Link>
            <h1 className="h-title">{s.hostname}</h1>
            <button className="text-navy-800 hover:text-blue-700" title="Server information" onClick={() => setInfo(true)}>
              <Info className="h-5 w-5" />
            </button>
          </div>
          <div className="mt-1 ml-8 flex items-center gap-3 text-sm text-slate-500">
            <span>{s.primary_ip}</span>
            {!s.online && (
              <>
                <StatusDot online={false} /> <span>last seen {ago(s.last_seen_at)}</span>
              </>
            )}
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-slate-500">View</span>
          <select className="input w-36" value={days} onChange={(e) => setDays(Number(e.target.value))}>
            <option value={7}>7 Days</option>
            <option value={30}>30 Days</option>
            <option value={90}>90 Days</option>
          </select>
          {can(user, 'operator') && (
            <button className="btn-primary" disabled={!s.online || busy} onClick={quickScan}>
              <Search className="h-4 w-4" /> Quick Scan
            </button>
          )}
        </div>
      </div>

      {data!.latest_agent_version && s.agent_version !== data!.latest_agent_version && (
        <Link to="settings?s=about" className="block rounded-lg bg-amber-50 p-3 text-sm text-amber-800 hover:bg-amber-100">
          This server runs agent {s.agent_version}; version {data!.latest_agent_version} is available (it installs automatically when the agent reconnects, or update it from Settings » About).
        </Link>
      )}

      <AttackOverview serverId={s.id} online={s.online} days={days} />
      {info && <ServerInfo s={s} onClose={() => setInfo(false)} />}
    </div>
  );
}
