import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { CircleCheck, KeyRound, Terminal, X } from 'lucide-react';
import { api, type Server } from '../api';
import { CopyBox, ErrorBox, Spinner } from '../components/ui';

interface TokenResponse {
  token: string;
  expires_at: string;
  install_command: string;
  uninstall_command: string;
}

const PANELS = ['cPanel/WHM', 'DirectAdmin', 'Plesk', 'CyberPanel', 'CWP', 'Webuzo', 'InterWorx', 'Enhance', 'Standalone'];
const OSES = ['AlmaLinux', 'CloudLinux', 'Rocky Linux', 'CentOS', 'RHEL', 'Ubuntu', 'Debian', 'Amazon Linux'];

export default function AddServer() {
  const nav = useNavigate();
  const [label, setLabel] = useState('');
  const [tok, setTok] = useState<TokenResponse | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [joined, setJoined] = useState<Server | null>(null);
  const known = useRef<Set<string> | null>(null);

  // After a token is issued, poll for the new server to appear.
  useEffect(() => {
    if (!tok || joined) return;
    const t = setInterval(async () => {
      const { servers } = await api<{ servers: Server[] }>('GET', '/api/servers');
      if (!known.current) {
        known.current = new Set(servers.map((s) => s.id));
        return;
      }
      const fresh = servers.find((s) => !known.current!.has(s.id));
      if (fresh) setJoined(fresh);
    }, 4000);
    return () => clearInterval(t);
  }, [tok, joined]);

  async function issue() {
    setBusy(true);
    setError('');
    try {
      const { servers } = await api<{ servers: Server[] }>('GET', '/api/servers');
      known.current = new Set(servers.map((s) => s.id));
      setTok(await api<TokenResponse>('POST', '/api/enrollment-tokens', { label }));
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-3xl">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="h-title">Add Server</h1>
        <button onClick={() => nav('/servers')} className="text-slate-400 hover:text-navy-800" aria-label="close">
          <X />
        </button>
      </div>

      <div className="space-y-5">
        <div className="card flex gap-5 p-6">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-blue-50 text-blue-600"><KeyRound /></div>
          <div className="flex-1">
            <h2 className="text-lg font-semibold text-navy-900">1&nbsp; Create an install token</h2>
            <p className="mb-3 text-sm text-slate-500">
              Each token works once and expires after 24 hours. Nothing secret stays in your shell history after it is used.
            </p>
            {error && <ErrorBox message={error} />}
            {!tok ? (
              <div className="flex flex-wrap gap-2">
                <input className="input max-w-xs" placeholder="Label (optional), e.g. server5" value={label} onChange={(e) => setLabel(e.target.value)} />
                <button className="btn-primary" onClick={issue} disabled={busy}>
                  {busy ? 'Creating…' : 'Create token'}
                </button>
              </div>
            ) : (
              <p className="text-sm text-green-700">Token created. Expires {new Date(tok.expires_at).toLocaleString()}.</p>
            )}
          </div>
        </div>

        <div className={`card flex gap-5 p-6 ${tok ? '' : 'opacity-50'}`}>
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-green-50 text-green-600"><Terminal /></div>
          <div className="min-w-0 flex-1">
            <h2 className="text-lg font-semibold text-navy-900">2&nbsp; Run this command on your server as root</h2>
            <p className="mb-3 text-sm text-slate-500">It detects your OS and control panel, verifies the download and starts the agent.</p>
            {tok ? <CopyBox text={tok.install_command} /> : <div className="rounded-lg bg-slate-100 px-4 py-3 text-sm text-slate-400">Create a token first</div>}
            {tok && (
              <p className="mt-3 text-xs text-slate-500">
                To remove it later: <code className="rounded bg-slate-100 px-1">{tok.uninstall_command}</code>
              </p>
            )}
          </div>
        </div>

        <div className={`card flex gap-5 p-6 ${tok ? '' : 'opacity-50'}`}>
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-amber-50 text-amber-600"><CircleCheck /></div>
          <div className="flex-1">
            <h2 className="text-lg font-semibold text-navy-900">3&nbsp; That's it</h2>
            {joined ? (
              <div className="mt-2 rounded-lg border border-green-200 bg-green-50 p-4 text-sm text-green-800">
                <strong>{joined.hostname}</strong> ({joined.primary_ip}) is connected.{' '}
                <Link className="font-medium underline" to={`/servers/${joined.id}`}>Open dashboard →</Link>
              </div>
            ) : tok ? (
              <div className="mt-2 flex items-center gap-2 text-sm text-slate-500">
                <Spinner /> Waiting for the server to connect…
              </div>
            ) : (
              <p className="text-sm text-slate-500">Your server appears here automatically once the agent connects.</p>
            )}
            <div className="mt-4 rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
              The agent connects <strong>out</strong> to this portal over HTTPS (port 443). You do not need to open any inbound port or whitelist our IPs.
            </div>
          </div>
        </div>
      </div>

      <div className="mt-10 text-center">
        <h3 className="mb-3 font-semibold text-navy-900">Supported control panels</h3>
        <div className="flex flex-wrap justify-center gap-2">
          {PANELS.map((p) => <span key={p} className="rounded-full bg-white px-3 py-1 text-sm text-slate-600 shadow-sm">{p}</span>)}
        </div>
        <h3 className="mt-6 mb-3 font-semibold text-navy-900">Supported operating systems</h3>
        <div className="flex flex-wrap justify-center gap-2">
          {OSES.map((p) => <span key={p} className="rounded-full bg-white px-3 py-1 text-sm text-slate-600 shadow-sm">{p}</span>)}
        </div>
      </div>
    </div>
  );
}
