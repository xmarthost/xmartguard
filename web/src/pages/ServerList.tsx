import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, Gauge, Plus, Tag, Trash2 } from 'lucide-react';
import { api, type Server } from '../api';
import { can, useAuth } from '../auth';
import { useApi } from '../hooks';
import { ago, panelName, pct } from '../format';
import { Bar, Empty, ErrorBox, PageLoader, StatusDot } from '../components/ui';

function TagEditor({ server, onSaved }: { server: Server; onSaved: () => void }) {
  const [value, setValue] = useState(server.tags.join(', '));
  const [open, setOpen] = useState(false);
  if (!open) {
    return (
      <button className="flex items-center gap-1 text-xs text-slate-400 hover:text-navy-700" onClick={() => setOpen(true)}>
        <Tag className="h-3.5 w-3.5" /> {server.tags.length ? 'Edit tags' : 'Assign tag'}
      </button>
    );
  }
  return (
    <form
      className="flex gap-1"
      onSubmit={async (e) => {
        e.preventDefault();
        const tags = value.split(',').map((t) => t.trim()).filter(Boolean);
        await api('PATCH', `/api/servers/${server.id}`, { tags });
        setOpen(false);
        onSaved();
      }}
    >
      <input className="input py-1 text-xs" value={value} onChange={(e) => setValue(e.target.value)} placeholder="tag1, tag2" autoFocus />
      <button className="btn-primary px-2 py-1 text-xs">Save</button>
    </form>
  );
}

function ServerCard({ s, onChange }: { s: Server; onChange: () => void }) {
  const { user } = useAuth();
  const m = s.last_metrics;
  const mem = pct(m?.mem_used, m?.mem_total);
  const disk = pct(m?.disk_used, m?.disk_total);
  return (
    <div className="card flex flex-col p-5">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-xs font-medium text-orange-500">{panelName(s.control_panel)}</div>
          <Link to={`/servers/${s.id}`} className="block truncate text-lg font-semibold text-navy-900 hover:underline">
            {s.hostname || '(unknown host)'}
          </Link>
          <div className="text-sm text-slate-500">
            {s.primary_ip} · {s.os_name}
          </div>
        </div>
        <StatusDot online={s.online} />
      </div>
      <div className="mt-4 grid grid-cols-3 gap-3 text-center">
        <div>
          <div className="text-xl font-semibold text-green-600">{m ? `${m.cpu_percent}%` : '–'}</div>
          <div className="text-xs text-slate-500">CPU</div>
        </div>
        <div>
          <div className="text-xl font-semibold text-green-600">{m ? `${mem}%` : '–'}</div>
          <div className="text-xs text-slate-500">Memory</div>
        </div>
        <div>
          <div className="text-xl font-semibold text-navy-800">{m ? m.load1.toFixed(2) : '–'}</div>
          <div className="text-xs text-slate-500">Load</div>
        </div>
      </div>
      <div className="mt-4">
        <div className="mb-1 flex justify-between text-xs text-slate-500">
          <span>Disk</span>
          <span>{disk}%</span>
        </div>
        <Bar value={disk} className={disk > 90 ? 'bg-red-500' : disk > 75 ? 'bg-amber-500' : 'bg-green-500'} />
      </div>
      {s.tags.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1">
          {s.tags.map((t) => (
            <span key={t} className="rounded-full bg-navy-100 px-2 py-0.5 text-xs text-navy-800">{t}</span>
          ))}
        </div>
      )}
      <div className="mt-auto flex items-center justify-between border-t pt-3 text-slate-400">
        <div className="flex items-center gap-3">
          <Link to={`/servers/${s.id}`} title="Dashboard" className="hover:text-navy-700"><Gauge className="h-4 w-4" /></Link>
          <Link to={`/servers/${s.id}/monitoring`} title="System Monitoring" className="hover:text-navy-700"><Activity className="h-4 w-4" /></Link>
          {can(user, 'admin') && (
            <button
              title="Remove server"
              className="hover:text-red-600"
              onClick={async () => {
                if (!confirm(`Remove ${s.hostname} from XMart Guard? The agent on the server will stop.`)) return;
                await api('DELETE', `/api/servers/${s.id}`);
                onChange();
              }}
            >
              <Trash2 className="h-4 w-4" />
            </button>
          )}
        </div>
        {can(user, 'operator') ? <TagEditor server={s} onSaved={onChange} /> : <span className="text-xs">seen {ago(s.last_seen_at)}</span>}
      </div>
      {!s.online && <div className="mt-2 text-xs text-slate-400">Last seen {ago(s.last_seen_at)}</div>}
    </div>
  );
}

export default function ServerList() {
  const [q, setQ] = useState('');
  const { user } = useAuth();
  const { data, error, loading, reload } = useApi<{ servers: Server[] }>(`/api/servers?q=${encodeURIComponent(q)}`, 30_000);
  return (
    <div>
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <h1 className="h-title">All Servers</h1>
        <input className="input max-w-xs" placeholder="filter by hostname, IP or tag" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {error && <ErrorBox message={error} />}
      {loading && !data ? (
        <PageLoader />
      ) : (
        <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
          {data?.servers.map((s) => <ServerCard key={s.id} s={s} onChange={reload} />)}
          {can(user, 'admin') && (
            <Link to="/servers/add" className="card flex min-h-60 flex-col items-center justify-center gap-2 text-slate-500 transition hover:text-navy-800 hover:shadow-md">
              <Plus className="h-10 w-10" />
              Add Server
            </Link>
          )}
          {data?.servers.length === 0 && !can(user, 'admin') && <Empty text="No servers found" />}
        </div>
      )}
    </div>
  );
}
