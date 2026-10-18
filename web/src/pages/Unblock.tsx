import { useEffect, useState } from 'react';
import { CheckCircle2 } from 'lucide-react';
import { api } from '../api';
import { ErrorBox, Logo } from '../components/ui';

/** Public: a visitor who cannot open a website asks to be unblocked. */
export default function Unblock() {
  const [ip, setIp] = useState('');
  const [site, setSite] = useState('');
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [trap, setTrap] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  useEffect(() => {
    api<{ ip: string }>('GET', '/api/unblock/whoami').then((r) => setIp(r.ip)).catch(() => {});
  }, []);
  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-navy-950 via-navy-900 to-navy-700 p-4">
      <div className="card w-full max-w-md p-8">
        <div className="mb-5 flex justify-center">
          <Logo />
        </div>
        {sent ? (
          <div className="text-center">
            <CheckCircle2 className="mx-auto h-10 w-10 text-emerald-600" />
            <h1 className="mt-3 text-lg font-semibold text-navy-900">Request sent</h1>
            <p className="mt-1 text-sm text-slate-500">We will check why {ip || 'your address'} was blocked on {site} and unblock it if it was a mistake.</p>
          </div>
        ) : (
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              setError('');
              try {
                await api('POST', '/api/unblock', { site: site.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, ''), email, message, ...(trap ? { website: trap } : {}) });
                setSent(true);
              } catch (err: any) {
                setError(err.message);
              } finally {
                setBusy(false);
              }
            }}
          >
            <h1 className="text-lg font-semibold text-navy-900">Blocked from a website?</h1>
            <p className="mt-1 mb-4 text-sm text-slate-500">
              Tell us which website you could not open. Your address {ip ? <b className="font-mono">{ip}</b> : 'is'} sent with the request.
            </p>
            {error && <ErrorBox message={error} />}
            <label className="mt-3 block text-sm">
              <span className="label">Website</span>
              <input className="input" required value={site} onChange={(e) => setSite(e.target.value)} placeholder="example.com" />
            </label>
            <label className="mt-3 block text-sm">
              <span className="label">Your email (optional)</span>
              <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
            </label>
            <label className="mt-3 block text-sm">
              <span className="label">What were you doing? (optional)</span>
              <textarea className="input min-h-20" maxLength={1000} value={message} onChange={(e) => setMessage(e.target.value)} placeholder="e.g. saving a post in WordPress" />
            </label>
            <input className="hidden" tabIndex={-1} autoComplete="off" value={trap} onChange={(e) => setTrap(e.target.value)} aria-hidden="true" />
            <button className="btn-primary mt-5 w-full justify-center" disabled={busy}>
              Send unblock request
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
