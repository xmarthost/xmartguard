import { useState } from 'react';
import { CheckCircle2, KeyRound, Mail, RefreshCw, XCircle } from 'lucide-react';
import { api } from '../api';
import { can, useAuth } from '../auth';
import { Breadcrumb, ErrorBox, PageLoader } from '../components/ui';
import { Card, fmtTime, useAction } from '../components/controls';
import { useApi } from '../hooks';

interface RBLState {
  name: string;
  zone: string;
  enabled: boolean;
  by?: string;
  problem?: string;
}
interface Guard {
  supported: boolean;
  rbls: RBLState[] | null;
  phishing: 'off' | 'active' | 'added';
  error?: string;
  at: number;
  dqs_source?: string;
}
interface ServerState {
  id: string;
  hostname: string;
  online: boolean;
  agent_version: string;
  state: Guard | null;
  cpanel?: boolean;
  error: string;
}
interface Resp {
  dqs_key_set: boolean;
  dqs_key_hint: string;
  servers: ServerState[];
}

/** What a server says about Spamhaus DQS. */
function dqsState(s: ServerState, keySet: boolean): { ok: boolean | null; text: string } {
  if (s.error) return { ok: null, text: s.error };
  if (s.cpanel === false || (s.state && !s.state.supported)) return { ok: null, text: 'not a cPanel server (no Exim)' };
  if (!s.state?.at) return { ok: null, text: 'not checked yet: press Check all servers' };
  const d = s.state.rbls?.find((r) => r.name === 'spamhausdqs');
  if (!keySet && !d) return { ok: null, text: 'no key' };
  if (d?.enabled) return { ok: true, text: `connected${s.state.dqs_source === 'server' ? ' (this server’s own key)' : ''}` };
  if (d?.problem) return { ok: false, text: /no answer/.test(d.problem) ? 'Spamhaus did not accept this key: check it in portal.spamhaus.com » DQS' : d.problem };
  return { ok: null, text: 'waiting for the agent' };
}

/** Mail protection for all servers: one Spamhaus DQS key, every server's state. */
export default function MailProtection() {
  const { user } = useAuth();
  const admin = can(user, 'admin');
  const res = useApi<Resp>('/api/mail-protection');
  const { run, busy } = useAction();
  const [key, setKey] = useState('');
  const [checked, setChecked] = useState<ServerState[] | null>(null);
  if (res.error && !res.data) return <ErrorBox message={res.error} />;
  if (!res.data) return <PageLoader />;
  const d = res.data;
  const servers = checked ?? d.servers;
  const valid = /^[A-Za-z0-9]{20,40}$/.test(key.trim());
  const save = (k: string) =>
    run(
      () => api<{ pushed: number }>('PUT', '/api/mail-protection', { dqs_key: k }),
      (r) => (k ? `Key saved and sent to ${r.pushed} online server(s); they test it within a minute` : 'Key removed from all servers'),
    ).then(() => {
      setKey('');
      setChecked(null);
      setTimeout(res.reload, 8000);
      res.reload();
    });
  return (
    <div className="space-y-6">
      <div>
        <Breadcrumb items={['Overview', 'Mail Protection']} />
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-navy-900">
          <Mail className="h-6 w-6" /> Mail Protection
        </h1>
        <p className="text-sm text-slate-500">Incoming mail protection in Exim on every cPanel server: blocklists (RBLs), Spamhaus and the phishing filter.</p>
      </div>

      <Card
        title="Spamhaus DQS key (all servers)"
        desc="Spamhaus does not answer public DNS resolvers (8.8.8.8, 1.1.1.1). With a Data Query Service key every server uses Spamhaus ZEN through any resolver. Saved once here, it is sent to every server, also to servers added later. A key set on a server itself (Settings » RBL & IP Reputation) wins there."
      >
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${d.dqs_key_set ? 'bg-emerald-50 text-emerald-700' : 'bg-slate-100 text-slate-600'}`}>
            <KeyRound className="h-3.5 w-3.5" /> {d.dqs_key_set ? `Key saved: ${d.dqs_key_hint}` : 'No key'}
          </span>
          {d.dqs_key_set && admin && (
            <button className="text-sm text-red-600 hover:underline" disabled={busy} onClick={() => confirm('Remove the Spamhaus DQS key from all servers?') && save('')}>
              Remove
            </button>
          )}
        </div>
        {admin && (
          <div className="mt-3 flex flex-wrap gap-2">
            <input className="input w-full max-w-md" placeholder={d.dqs_key_set ? 'New key (replaces the saved one)' : 'Paste the Query Key from portal.spamhaus.com » DQS'} value={key} onChange={(e) => setKey(e.target.value.trim())} autoComplete="off" />
            <button className="btn-primary" disabled={busy || !valid} onClick={() => save(key.trim())}>
              Save for all servers
            </button>
          </div>
        )}
        {key && !valid && <p className="mt-1 text-xs text-red-600">A DQS key is 20-40 letters and digits.</p>}
      </Card>

      <Card
        title="Servers"
        desc="Whether each server's Exim uses the key, the other blocklists and the phishing filter."
        right={
          admin && (
            <button
              className="btn-outline"
              disabled={busy}
              onClick={() => run(() => api<{ servers: ServerState[] }>('POST', '/api/mail-protection/check').then((r) => setChecked(r.servers)), 'All servers checked')}
            >
              <RefreshCw className={`h-4 w-4 ${busy ? 'animate-spin' : ''}`} /> Check all servers
            </button>
          )
        }
      >
        <div className="mt-3 overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
            <thead className="text-left text-xs text-slate-500 uppercase">
              <tr>
                <th className="py-2 pr-3">Server</th>
                <th className="py-2 pr-3">Spamhaus DQS</th>
                <th className="py-2 pr-3">Other blocklists</th>
                <th className="py-2 pr-3">Phishing filter</th>
                <th className="py-2">Checked</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {servers.map((s) => {
                const q = dqsState(s, d.dqs_key_set);
                const on = (s.state?.rbls ?? []).filter((r) => r.enabled && r.name !== 'spamhausdqs').map((r) => r.name);
                return (
                  <tr key={s.id} className="align-top">
                    <td className="py-2 pr-3 font-medium text-navy-900">{s.hostname}</td>
                    <td className="py-2 pr-3">
                      <span className={`inline-flex items-start gap-1.5 ${q.ok === true ? 'text-emerald-700' : q.ok === false ? 'text-red-600' : 'text-slate-500'}`}>
                        {q.ok === true ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" /> : q.ok === false ? <XCircle className="mt-0.5 h-4 w-4 shrink-0" /> : null}
                        {q.text}
                      </span>
                    </td>
                    <td className="py-2 pr-3 text-xs text-slate-600">{s.state?.supported ? on.join(', ') || 'none on' : '—'}</td>
                    <td className="py-2 pr-3 text-xs">
                      {!s.state?.supported ? '—' : s.state.phishing === 'active' ? <span className="text-emerald-700">active</span> : s.state.phishing === 'added' ? <span className="text-amber-700">added, not in Exim yet</span> : <span className="text-slate-500">off</span>}
                    </td>
                    <td className="py-2 text-xs text-slate-500">{s.state?.at ? fmtTime(s.state.at) : '—'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {servers.some((s) => s.state?.error) && <p className="mt-2 text-sm text-red-600">{servers.filter((s) => s.state?.error).map((s) => `${s.hostname}: ${s.state!.error}`).join(' · ')}</p>}
      </Card>
    </div>
  );
}
