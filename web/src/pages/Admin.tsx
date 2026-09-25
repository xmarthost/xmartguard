import { useState } from 'react';
import { Trash2 } from 'lucide-react';
import { api } from '../api';
import { useAuth } from '../auth';
import { useApi } from '../hooks';
import { ago } from '../format';
import { Empty, ErrorBox, PageLoader } from '../components/ui';

interface UserRow {
  id: string;
  email: string;
  name: string;
  role: string;
  created_at: string;
  last_login_at: string | null;
}

export function UsersPage() {
  const { user } = useAuth();
  const { data, error, loading, reload } = useApi<{ users: UserRow[] }>('/api/users');
  const [form, setForm] = useState({ email: '', name: '', password: '', role: 'operator' });
  const [msg, setMsg] = useState('');
  if (loading && !data) return <PageLoader />;
  return (
    <div className="mx-auto max-w-4xl space-y-5">
      <h1 className="h-title">Users</h1>
      {error && <ErrorBox message={error} />}
      <div className="card overflow-x-auto p-5">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-slate-500">
              <th className="py-2 font-medium">Email</th>
              <th className="py-2 font-medium">Name</th>
              <th className="py-2 font-medium">Role</th>
              <th className="py-2 font-medium">Last login</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {data?.users.map((u) => (
              <tr key={u.id} className="border-b border-slate-100 last:border-0">
                <td className="py-2 font-medium text-navy-900">{u.email}</td>
                <td className="py-2">{u.name}</td>
                <td className="py-2 capitalize">{u.role}</td>
                <td className="py-2 text-slate-500">{ago(u.last_login_at)}</td>
                <td className="py-2 text-right">
                  {u.role !== 'owner' && u.id !== user?.id && (
                    <button
                      className="text-slate-400 hover:text-red-600"
                      title="Delete user"
                      onClick={async () => {
                        if (!confirm(`Delete ${u.email}?`)) return;
                        await api('DELETE', `/api/users/${u.id}`);
                        reload();
                      }}
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <form
        className="card grid gap-4 p-5 md:grid-cols-2"
        onSubmit={async (e) => {
          e.preventDefault();
          setMsg('');
          try {
            await api('POST', '/api/users', form);
            setForm({ email: '', name: '', password: '', role: 'operator' });
            setMsg('User added.');
            reload();
          } catch (err: any) {
            setMsg(err.message);
          }
        }}
      >
        <h2 className="text-lg font-semibold text-navy-900 md:col-span-2">Add user</h2>
        <div>
          <label className="label">Email</label>
          <input className="input" type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        </div>
        <div>
          <label className="label">Name</label>
          <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </div>
        <div>
          <label className="label">Password (10+ characters)</label>
          <input className="input" type="password" minLength={10} required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        </div>
        <div>
          <label className="label">Role</label>
          <select className="input" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option value="admin">Admin — manage servers and settings</option>
            <option value="operator">Operator — scans, tags, day-to-day actions</option>
            <option value="viewer">Viewer — read only</option>
          </select>
        </div>
        <div className="flex items-center gap-3 md:col-span-2">
          <button className="btn-primary">Add user</button>
          {msg && <span className="text-sm text-slate-600">{msg}</span>}
        </div>
      </form>
    </div>
  );
}

export function AccountPage() {
  const { user } = useAuth();
  const [cur, setCur] = useState('');
  const [next, setNext] = useState('');
  const [msg, setMsg] = useState('');
  return (
    <div className="mx-auto max-w-lg space-y-5">
      <h1 className="h-title">Account</h1>
      <div className="card p-5 text-sm">
        <div><span className="text-slate-500">Email:</span> {user?.email}</div>
        <div className="capitalize"><span className="text-slate-500">Role:</span> {user?.role}</div>
      </div>
      <form
        className="card space-y-4 p-5"
        onSubmit={async (e) => {
          e.preventDefault();
          try {
            await api('POST', '/api/auth/password', { current_password: cur, new_password: next });
            setCur('');
            setNext('');
            setMsg('Password changed. Other sessions were signed out.');
          } catch (err: any) {
            setMsg(err.message);
          }
        }}
      >
        <h2 className="text-lg font-semibold text-navy-900">Change password</h2>
        <div>
          <label className="label">Current password</label>
          <input className="input" type="password" required value={cur} onChange={(e) => setCur(e.target.value)} />
        </div>
        <div>
          <label className="label">New password (10+ characters)</label>
          <input className="input" type="password" minLength={10} required value={next} onChange={(e) => setNext(e.target.value)} />
        </div>
        <button className="btn-primary">Save</button>
        {msg && <p className="text-sm text-slate-600">{msg}</p>}
      </form>
    </div>
  );
}

interface AuditRow {
  id: number;
  action: string;
  detail: Record<string, unknown>;
  ip: string | null;
  created_at: string;
  user_email: string | null;
  server_hostname: string | null;
}

export function SecurityLogPage() {
  const { data, error, loading } = useApi<{ events: AuditRow[] }>('/api/audit', 30_000);
  if (loading && !data) return <PageLoader />;
  return (
    <div className="space-y-5">
      <h1 className="h-title">Security Log</h1>
      {error && <ErrorBox message={error} />}
      <div className="card overflow-x-auto p-5">
        {data?.events.length ? (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left text-slate-500">
                <th className="py-2 font-medium">Time</th>
                <th className="py-2 font-medium">Action</th>
                <th className="py-2 font-medium">User</th>
                <th className="py-2 font-medium">Server</th>
                <th className="py-2 font-medium">IP</th>
              </tr>
            </thead>
            <tbody>
              {data.events.map((e) => (
                <tr key={e.id} className="border-b border-slate-100 last:border-0">
                  <td className="py-2 whitespace-nowrap text-slate-500">{new Date(e.created_at).toLocaleString()}</td>
                  <td className="py-2 font-medium text-navy-900">{e.action}</td>
                  <td className="py-2">{e.user_email ?? '–'}</td>
                  <td className="py-2">{e.server_hostname ?? '–'}</td>
                  <td className="py-2 text-slate-500">{e.ip ?? '–'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty />
        )}
      </div>
    </div>
  );
}

export function SupportPage() {
  return (
    <div className="card mx-auto mt-6 max-w-2xl space-y-3 p-8">
      <h1 className="h-title">Support</h1>
      <p className="text-slate-600">
        Need help with XMart Guard? Email <a className="text-navy-700 underline" href="mailto:support@xmarthost.com">support@xmarthost.com</a> with your server hostname and a description of the problem.
      </p>
      <p className="text-sm text-slate-500">
        Useful commands on the server: <code className="rounded bg-slate-100 px-1">systemctl status xmartguard-agent</code>,{' '}
        <code className="rounded bg-slate-100 px-1">tail -n 100 /var/log/xmartguard/agent.log</code>
      </p>
    </div>
  );
}
