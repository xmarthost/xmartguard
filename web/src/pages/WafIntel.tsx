import { useEffect, useState } from 'react';
import { Brain, Check, EyeOff, Plus, RotateCcw, Save, Search } from 'lucide-react';
import { api } from '../api';
import { can, useAuth } from '../auth';
import { Breadcrumb, ErrorBox, PageLoader } from '../components/ui';
import { Card, SettingRow, Toggle, useAction } from '../components/controls';
import { useApi } from '../hooks';

interface LearnedName {
  name: string;
  servers: number;
  reports: number;
  clean_servers: number;
  tails: string[];
  signatures: string[];
  first_seen: string;
  last_seen: string;
  override: 'approved' | 'ignored' | 'added' | null;
  status: 'active' | 'pending' | 'ignored' | 'not_allowed' | 'false_positive';
  reason: string;
}

interface Patch {
  id: number;
  title: string;
  cve?: string;
  plugin: string;
  enabled: boolean;
}

interface Resp {
  config: { enabled: boolean; min_servers: number; disabled_patches: number[] };
  names: LearnedName[];
  patches: Patch[];
  active: { names: number; patches: number };
}

const STATUS: Record<LearnedName['status'], [string, string]> = {
  active: ['Blocked', 'bg-red-50 text-red-700'],
  pending: ['Waiting', 'bg-amber-50 text-amber-700'],
  false_positive: ['Restored as clean', 'bg-sky-50 text-sky-700'],
  ignored: ['Ignored', 'bg-slate-100 text-slate-600'],
  not_allowed: ['Too common', 'bg-slate-100 text-slate-500'],
};

/** Overview » WAF Intelligence: web shell names learned from the scanners of
 *  all servers, and the portal's virtual patches. */
export default function WafIntel() {
  const { user } = useAuth();
  const admin = can(user, 'admin');
  const res = useApi<Resp>('/api/waf/intel');
  const { run, busy } = useAction();
  const [enabled, setEnabled] = useState(true);
  const [minServers, setMinServers] = useState(2);
  const [off, setOff] = useState<number[]>([]);
  const [add, setAdd] = useState('');
  const [q, setQ] = useState('');

  useEffect(() => {
    if (!res.data) return;
    setEnabled(res.data.config.enabled);
    setMinServers(res.data.config.min_servers);
    setOff(res.data.config.disabled_patches);
  }, [res.data]);

  if (res.error && !res.data) return <ErrorBox message={res.error} />;
  if (!res.data) return <PageLoader />;
  const d = res.data;
  const dirty = enabled !== d.config.enabled || minServers !== d.config.min_servers || [...off].sort().join() !== [...d.config.disabled_patches].sort().join();
  const done = (r: { pushed: number; names: number; patches: number }) => `Sent to ${r.pushed} online server${r.pushed === 1 ? '' : 's'}: ${r.names} names, ${r.patches} patches`;
  const save = () => run(() => api<{ pushed: number; names: number; patches: number }>('PUT', '/api/waf/intel/config', { enabled, min_servers: minServers, disabled_patches: off }).then((r) => (res.reload(), r)), done);
  const setName = (name: string, status: string) =>
    run(() => api<{ pushed: number; names: number; patches: number }>('POST', '/api/waf/intel/names', { name, status }).then((r) => (res.reload(), r)), done);
  const names = d.names.filter((n) => !q || n.name.includes(q.toLowerCase()) || n.tails.some((t) => t.includes(q.toLowerCase())));

  return (
    <div className="space-y-5">
      <Breadcrumb items={['Overview', 'WAF Intelligence']} />
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="h-title flex items-center gap-2">
            <Brain className="h-6 w-6 text-orange-500" /> WAF Intelligence
          </h1>
          <p className="max-w-3xl text-sm text-slate-500">
            When the virus scanner of any server finds a web shell, its file name comes here. A name found on enough servers is blocked by the WAF of every server,
            so attackers looking for the same backdoor elsewhere get nothing. Common names (index.php, config.php …), files in wp-admin and wp-includes and names
            of files restored as clean are never blocked automatically. Virtual patches for plugin vulnerabilities are sent the same way; servers apply them
            without an agent update.
          </p>
        </div>
        {admin && (
          <button className="btn-primary" disabled={busy || !dirty} onClick={save}>
            <Save className="h-4 w-4" /> {dirty ? 'Save & apply to all servers' : 'Saved'}
          </button>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {(
          [
            ['Names blocked', d.active.names, 'text-red-600'],
            ['Names waiting', d.names.filter((n) => n.status === 'pending').length, 'text-amber-600'],
            ['Names reported', d.names.length, 'text-navy-900'],
            ['Virtual patches on', d.active.patches, 'text-emerald-600'],
          ] as [string, number, string][]
        ).map(([l, v, c]) => (
          <div key={l} className="card p-4">
            <div className="text-xs uppercase text-slate-500">{l}</div>
            <div className={`mt-1 text-2xl font-bold ${c}`}>{v}</div>
          </div>
        ))}
      </div>

      <Card title="Settings">
        <SettingRow title="Share and apply fleet intelligence" desc="Learned web shell names and the portal's virtual patches on every server (WAF » Web shells and Virtual patches packages).">
          <Toggle on={enabled} disabled={!admin || busy} onChange={setEnabled} />
        </SettingRow>
        <SettingRow title="Block a name automatically once found on" desc="Fewer servers blocks new backdoors sooner; more servers is safer against a wrong detection. You can always approve a name by hand.">
          <select className="input w-40" value={minServers} disabled={!admin || busy} onChange={(e) => setMinServers(Number(e.target.value))}>
            {[1, 2, 3, 5, 10].map((n) => (
              <option key={n} value={n}>
                {n} server{n === 1 ? '' : 's'}
              </option>
            ))}
          </select>
        </SettingRow>
      </Card>

      <Card title="Learned web shell names" desc="Names the scanners reported, with where they were found (the part under the web root) and the detection.">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <div className="relative min-w-[200px] flex-1">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
            <input className="input w-full pl-9" placeholder="Search names" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          {admin && (
            <form
              className="flex gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                if (add.trim()) setName(add.trim().toLowerCase(), 'added').then(() => setAdd(''));
              }}
            >
              <input className="input w-56 font-mono" placeholder="backdoor-name.php" value={add} disabled={busy} onChange={(e) => setAdd(e.target.value)} />
              <button className="btn-outline" disabled={busy || !add.trim()}>
                <Plus className="h-4 w-4" /> Add name
              </button>
            </form>
          )}
        </div>
        {names.length === 0 ? (
          <p className="py-6 text-center text-sm text-slate-500">No web shell names yet. They appear here when a scanner finds one.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase text-slate-500">
                <tr>
                  <th className="py-2 pr-3">Name</th>
                  <th className="py-2 pr-3">Found on</th>
                  <th className="py-2 pr-3">Where</th>
                  <th className="py-2 pr-3">Last seen</th>
                  <th className="py-2 pr-3">State</th>
                  {admin && <th className="py-2 text-right">Action</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {names.map((n) => (
                  <tr key={n.name} className="align-top">
                    <td className="py-2 pr-3 font-mono text-navy-900">
                      {n.name}
                      {n.signatures[0] && <div className="font-sans text-xs text-slate-400">{n.signatures.join(', ')}</div>}
                    </td>
                    <td className="whitespace-nowrap py-2 pr-3">
                      {n.servers} server{n.servers === 1 ? '' : 's'}
                      {n.clean_servers > 0 && <div className="text-xs text-sky-700">clean on {n.clean_servers}</div>}
                    </td>
                    <td className="max-w-xs py-2 pr-3 font-mono text-xs text-slate-500">{n.tails.join(' · ') || '—'}</td>
                    <td className="whitespace-nowrap py-2 pr-3 text-xs text-slate-500">{new Date(n.last_seen).toLocaleString()}</td>
                    <td className="py-2 pr-3">
                      <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${STATUS[n.status][1]}`} title={n.reason}>
                        {STATUS[n.status][0]}
                      </span>
                      <div className="mt-1 max-w-[240px] text-xs text-slate-400">{n.reason}</div>
                    </td>
                    {admin && (
                      <td className="whitespace-nowrap py-2 text-right">
                        {n.status !== 'not_allowed' && n.status !== 'active' && n.override !== 'ignored' && (
                          <button className="btn-outline px-2 py-1 text-xs" disabled={busy} onClick={() => setName(n.name, 'approved')}>
                            <Check className="h-3.5 w-3.5" /> Block
                          </button>
                        )}
                        {n.status === 'active' && (
                          <button className="btn-outline px-2 py-1 text-xs" disabled={busy} onClick={() => setName(n.name, 'ignored')}>
                            <EyeOff className="h-3.5 w-3.5" /> Ignore
                          </button>
                        )}
                        {n.override && (
                          <button className="ml-1 btn-outline px-2 py-1 text-xs" disabled={busy} title="Remove your decision" onClick={() => setName(n.name, '')}>
                            <RotateCcw className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card
        title="Virtual patches from the portal"
        desc="Known vulnerabilities of WordPress plugins, blocked at the WAF before they reach the plugin. They come with portal updates; servers apply them without an agent update (agent 0.14.0 or newer). The agent's own patches are listed under WAF » Virtual patches."
      >
        <table className="w-full text-sm">
          <tbody className="divide-y divide-slate-100">
            {d.patches.map((p) => {
              const on = enabled && !off.includes(p.id);
              return (
                <tr key={p.id}>
                  <td className="w-20 py-2 pr-3 font-mono text-xs text-slate-500">{p.id}</td>
                  <td className="py-2 pr-3">
                    <div className="text-navy-900">{p.title}</div>
                    <div className="text-xs text-slate-500">{p.plugin}</div>
                  </td>
                  <td className="whitespace-nowrap py-2 pr-3 font-mono text-xs">
                    {p.cve && (
                      <a className="text-blue-700 hover:underline" href={`https://www.cve.org/CVERecord?id=${p.cve}`} target="_blank" rel="noreferrer">
                        {p.cve}
                      </a>
                    )}
                  </td>
                  <td className="w-20 py-2 text-right">
                    <Toggle on={on} disabled={!admin || busy || !enabled} onChange={(v) => setOff(v ? off.filter((x) => x !== p.id) : [...off, p.id])} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
