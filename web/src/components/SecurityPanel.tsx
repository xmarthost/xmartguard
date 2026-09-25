import { Link } from 'react-router-dom';
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { AlertTriangle, Ban, Bug, CheckCircle2, Lock, ShieldX } from 'lucide-react';
import { useAgent } from './controls';

interface Stats {
  summary: {
    scanner: { threats_30d: number; threats_total: number; quarantined: number; open_findings: number; last_scan_at: number; realtime_watches: number };
    firewall: { active_blocks: number; blocks_30d: number; blocks_total: number; dropped_packets?: Record<string, number> };
    blacklisted_ips: number;
  };
  daily: { day: string; virus: number; suspicious: number; binary: number }[];
  firewall: { enabled: boolean; healthy: boolean; provider: string; error: string };
  version: string;
}

function Tile({ icon, value, label, sub, tone = 'text-navy-900' }: { icon: React.ReactNode; value: number | string; label: string; sub?: string; tone?: string }) {
  return (
    <div className="card flex items-center gap-4 p-5">
      <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-navy-100 text-navy-800">{icon}</div>
      <div>
        <div className={`text-3xl font-semibold ${tone}`}>{value}</div>
        <div className="text-sm text-slate-500">{label}</div>
        {sub && <div className="text-xs text-slate-400">{sub}</div>}
      </div>
    </div>
  );
}

export default function SecurityPanel({ serverId, online, agentVersion, latestVersion }: { serverId: string; online: boolean; agentVersion: string; latestVersion?: string | null }) {
  const { data, error } = useAgent<Stats>(online ? serverId : undefined, 'stats.get', {}, 30_000);
  if (!online) return null;
  if (error) {
    return (
      <div className="card flex items-center gap-3 p-5 text-sm text-amber-800">
        <AlertTriangle className="h-5 w-5" />
        {error.includes('older agent') || error.includes('unsupported')
          ? `This server runs agent ${agentVersion}. Update it (Settings → About) to enable the scanner, firewall and reputation features.`
          : error}
      </div>
    );
  }
  if (!data) return null;
  const s = data.summary;
  const dropped = Object.values(s.firewall.dropped_packets ?? {}).reduce((a, b) => a + b, 0);
  const alerts: { tone: string; text: string; to: string }[] = [];
  if (s.scanner.open_findings) alerts.push({ tone: 'red', text: `${s.scanner.open_findings} infected file(s) need attention`, to: 'scanner-logs' });
  if (s.blacklisted_ips) alerts.push({ tone: 'red', text: `${s.blacklisted_ips} server IP(s) blacklisted`, to: 'ip-reputation' });
  if (data.firewall.enabled && !data.firewall.healthy) alerts.push({ tone: 'amber', text: `Firewall rules are not loaded (${data.firewall.provider})`, to: 'firewall' });
  if (!data.firewall.enabled) alerts.push({ tone: 'amber', text: 'Firewall is disabled', to: 'firewall' });
  if (latestVersion && agentVersion !== latestVersion) alerts.push({ tone: 'amber', text: `Agent ${agentVersion} → ${latestVersion} update available`, to: 'settings?s=about' });

  return (
    <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Tile icon={<Bug />} value={s.scanner.threats_30d} label="Threats detected (30 days)" sub={`${s.scanner.threats_total} all time`} tone={s.scanner.threats_30d ? 'text-red-600' : 'text-green-600'} />
        <Tile icon={<Lock />} value={s.scanner.quarantined} label="Files in quarantine" sub={`realtime: ${s.scanner.realtime_watches.toLocaleString()} folders watched`} />
        <Tile icon={<Ban />} value={s.firewall.blocks_30d} label="IPs blocked (30 days)" sub={`${s.firewall.active_blocks} active · ${dropped.toLocaleString()} packets dropped`} />
        <Tile icon={<ShieldX />} value={s.blacklisted_ips} label="Blacklisted server IPs" tone={s.blacklisted_ips ? 'text-red-600' : 'text-green-600'} />
      </div>
      <div className="grid gap-5 lg:grid-cols-[2fr_1fr]">
        <div className="card p-5">
          <h3 className="mb-3 font-semibold text-navy-900">Virus Infections — 30 days</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.daily} margin={{ left: -20, right: 10 }}>
                <CartesianGrid stroke="#eef0f5" vertical={false} />
                <XAxis dataKey="day" tickFormatter={(d: string) => d.slice(8)} tick={{ fontSize: 11, fill: '#64748b' }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#64748b' }} />
                <Tooltip />
                <Legend />
                <Bar dataKey="virus" stackId="a" fill="#1d2b64" name="Virus" />
                <Bar dataKey="suspicious" stackId="a" fill="#64748b" name="Suspicious" />
                <Bar dataKey="binary" stackId="a" fill="#a5b4fc" name="Binary" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="card p-5">
          <h3 className="mb-3 font-semibold text-navy-900">Alerts</h3>
          {alerts.length === 0 ? (
            <div className="flex items-center gap-2 text-sm text-green-700">
              <CheckCircle2 className="h-5 w-5" /> No alerts. This server looks healthy.
            </div>
          ) : (
            <div className="space-y-2">
              {alerts.map((a) => (
                <Link key={a.text} to={`/servers/${serverId}/${a.to}`} className={`flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm ${a.tone === 'red' ? 'bg-red-50 text-red-700' : 'bg-amber-50 text-amber-800'}`}>
                  <AlertTriangle className="h-4 w-4 shrink-0" /> {a.text}
                </Link>
              ))}
            </div>
          )}
          <div className="mt-4 text-xs text-slate-400">
            Last completed scan: {s.scanner.last_scan_at ? new Date(s.scanner.last_scan_at * 1000).toLocaleString() : 'never'}
          </div>
        </div>
      </div>
    </div>
  );
}
