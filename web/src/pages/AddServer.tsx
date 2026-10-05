import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { CircleCheck, KeyRound, Terminal, X } from 'lucide-react';
import { api, type Server } from '../api';
import { CopyBox, ErrorBox, Spinner } from '../components/ui';

interface TokenResponse {
  id?: string;
  label?: string;
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

  const [buyUrl, setBuyUrl] = useState('');
  // Tokens not used yet stay visible (after a reload too) until a server uses them.
  const [pending, setPending] = useState<TokenResponse[]>([]);
  async function loadPending(pick: boolean) {
    try {
      const r = await api<{ tokens: TokenResponse[] }>('GET', '/api/enrollment-tokens/pending');
      setPending(r.tokens);
      if (pick && r.tokens[0]) setTok((t) => t ?? r.tokens[0]);
    } catch {
      /* viewers cannot list tokens */
    }
  }
  useEffect(() => {
    loadPending(true);
  }, []);
  useEffect(() => {
    if (joined) loadPending(false);
  }, [joined]);

  async function issue() {
    setBusy(true);
    setError('');
    try {
      const { servers } = await api<{ servers: Server[] }>('GET', '/api/servers');
      known.current = new Set(servers.map((s) => s.id));
      setTok(await api<TokenResponse>('POST', '/api/enrollment-tokens', { label }));
      setJoined(null);
      loadPending(false);
    } catch (e: any) {
      setError(e.message);
      setBuyUrl(e?.status === 402 ? String(e.data?.buy_url ?? '') || 'subscription' : '');
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
            {error && !buyUrl && <ErrorBox message={error} />}
            {buyUrl && (
              <div className="mb-3 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
                <p className="font-semibold">No free server licence</p>
                <p className="mt-1">{error}</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {buyUrl !== 'subscription' && (
                    <a className="btn-primary" href={buyUrl} target="_blank" rel="noreferrer">
                      Buy another server licence
                    </a>
                  )}
                  <button type="button" className="btn-outline" onClick={() => nav('/subscription')}>
                    View my plan
                  </button>
                </div>
              </div>
            )}
            {!tok ? (
              <div className="flex flex-wrap gap-2">
                <input className="input max-w-xs" placeholder="Label (optional), e.g. server5" value={label} onChange={(e) => setLabel(e.target.value)} />
                <button className="btn-primary" onClick={issue} disabled={busy}>
                  {busy ? 'Creating…' : 'Create token'}
                </button>
              </div>
            ) : (
              <div className="flex flex-wrap items-center gap-3">
                <p className="text-sm text-green-700">
                  Token {tok.label ? <strong>{tok.label}</strong> : null} ready. It stays here until a server uses it; expires {new Date(tok.expires_at).toLocaleString()}.
                </p>
                <button className="btn-outline" onClick={() => { setTok(null); setLabel(''); }}>
                  Create another token
                </button>
              </div>
            )}
            {pending.length > 1 && (
              <div className="mt-4 rounded-lg border border-slate-200 p-3 text-sm">
                <p className="mb-2 font-medium text-navy-900">Tokens not used yet</p>
                <ul className="space-y-1">
                  {pending.map((p) => (
                    <li key={p.id} className="flex flex-wrap items-center gap-2">
                      <button className={`text-left underline-offset-2 hover:underline ${tok?.id === p.id ? 'font-semibold text-blue-700' : 'text-slate-700'}`} onClick={() => setTok(p)}>
                        {p.label || 'Unnamed token'}
                      </button>
                      <span className="text-xs text-slate-400">expires {new Date(p.expires_at).toLocaleString()}</span>
                      <button
                        className="ml-auto text-xs text-red-600 hover:underline"
                        onClick={async () => {
                          await api('DELETE', `/api/enrollment-tokens/${p.id}`).catch(() => {});
                          if (tok?.id === p.id) setTok(null);
                          loadPending(false);
                        }}
                      >
                        Delete
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
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
