import { useEffect, useState } from 'react';
import { Navigate, useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api';
import { useAuth } from '../auth';
import { ErrorBox, Logo } from '../components/ui';

export default function Login() {
  const { user, refresh } = useAuth();
  const nav = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [q] = useSearchParams();
  const [error, setError] = useState(q.get('sso') === 'expired' ? 'That sign-in link has expired or was already used. Sign in with your password, or open the panel again from the website.' : '');
  const [busy, setBusy] = useState(false);
  const [client, setClient] = useState<{ login: string; area: string } | null>(null);
  // Customers sign in through the website's client area (its "App Portal"
  // button opens the panel without a password). A browser that came from
  // there goes back there; this page stays the operator's sign-in
  // (/login?admin shows it in any browser).
  useEffect(() => {
    api<{ client_login_url: string; client_area_url: string }>('GET', '/api/auth/options')
      .then((o) => {
        if (!o.client_login_url) return;
        setClient({ login: o.client_login_url, area: o.client_area_url });
        const isClient = /(?:^|;\s*)xg_client=1/.test(document.cookie);
        if (isClient && !q.has('admin') && !user) window.location.replace(q.has('out') ? o.client_area_url : o.client_login_url);
      })
      .catch(() => {});
  }, [q, user]);
  if (user) return <Navigate to="/" replace />;

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-navy-950 via-navy-900 to-navy-700 p-4">
      <form
        className="card w-full max-w-sm p-8"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError('');
          try {
            await api('POST', '/api/auth/login', { email, password });
            await refresh();
            nav('/');
          } catch (err: any) {
            setError(err.message);
          } finally {
            setBusy(false);
          }
        }}
      >
        <div className="mb-6 flex justify-center">
          <Logo full />
        </div>
        <h1 className="mb-6 text-center text-lg font-medium text-navy-900">Sign in to your account</h1>
        {error && (
          <div className="mb-4">
            <ErrorBox message={error} />
          </div>
        )}
        <label className="label" htmlFor="email">Email</label>
        <input id="email" className="input mb-4" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required />
        <label className="label" htmlFor="password">Password</label>
        <input id="password" className="input mb-6" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        <button className="btn-primary w-full" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
        {client && (
          <div className="mt-6 border-t border-slate-200 pt-5 text-center">
            <p className="mb-3 text-sm text-slate-500">Customer? Open the panel from your client area: no password needed.</p>
            <a className="inline-flex w-full items-center justify-center rounded-lg bg-red-600 px-4 py-2.5 font-semibold text-white hover:bg-red-700" href={client.login}>
              Sign in to the client area
            </a>
          </div>
        )}
      </form>
    </div>
  );
}
