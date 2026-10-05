import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api';
import { useAuth } from '../auth';
import { ErrorBox, Logo } from '../components/ui';

/** New customers choose their password from the link the website gave them. */
export default function SetPassword() {
  const [q] = useSearchParams();
  const token = q.get('token') ?? '';
  const { refresh } = useAuth();
  const nav = useNavigate();
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    api<{ email: string }>('GET', `/api/auth/set-password?token=${encodeURIComponent(token)}`)
      .then((r) => setEmail(r.email))
      .catch((e) => setError(e.message));
  }, [token]);
  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-navy-950 via-navy-900 to-navy-700 p-4">
      <form
        className="card w-full max-w-sm p-8"
        onSubmit={async (e) => {
          e.preventDefault();
          if (pw !== pw2) return setError('The two passwords are not the same.');
          setBusy(true);
          setError('');
          try {
            await api('POST', '/api/auth/set-password', { token, password: pw });
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
        <h1 className="mb-1 text-center text-lg font-medium text-navy-900">Choose your password</h1>
        {email && <p className="mb-5 text-center text-sm text-slate-500">for {email}</p>}
        {error && (
          <div className="mb-4">
            <ErrorBox message={error} />
          </div>
        )}
        {email && (
          <>
            <label className="label" htmlFor="pw">New password (10+ characters)</label>
            <input id="pw" className="input mb-4" type="password" autoComplete="new-password" minLength={10} required value={pw} onChange={(e) => setPw(e.target.value)} />
            <label className="label" htmlFor="pw2">Repeat it</label>
            <input id="pw2" className="input mb-6" type="password" autoComplete="new-password" minLength={10} required value={pw2} onChange={(e) => setPw2(e.target.value)} />
            <button className="btn-primary w-full" disabled={busy}>
              {busy ? 'Saving…' : 'Save and open the panel'}
            </button>
          </>
        )}
      </form>
    </div>
  );
}
