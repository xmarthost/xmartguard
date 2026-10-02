import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Globe2, KeyRound } from 'lucide-react';
import { api } from '../api';
import { can, useAuth } from '../auth';
import { Breadcrumb, ErrorBox, PageLoader } from '../components/ui';
import { Card, fmtTime, useAction } from '../components/controls';
import { useApi } from '../hooks';

interface ServerState {
  id: string;
  hostname: string;
  online: boolean;
  agent_version: string;
  enabled?: boolean | null;
  key_source?: '' | 'server' | 'portal' | null;
  summary?: { total?: number; flagged?: number; checked_at?: number } | null;
  last_check?: number;
  old?: boolean;
  error: string;
}

interface Resp {
  key_set: boolean;
  key_hint: string;
  min_agent: string;
  servers: ServerState[];
}

/** Domain reputation for all servers: one Google Safe Browsing key, every server's state. */
export default function DomainReputation() {
  const { user } = useAuth();
  const admin = can(user, 'admin');
  const res = useApi<Resp>('/api/domain-reputation');
  const { run, busy } = useAction();
  const [key, setKey] = useState('');
  if (res.error && !res.data) return <ErrorBox message={res.error} />;
  if (!res.data) return <PageLoader />;
  const d = res.data;
  const valid = /^[A-Za-z0-9_-]{20,200}$/.test(key.trim());
  const save = (k: string) =>
    run(
      () => api<{ pushed: number }>('PUT', '/api/domain-reputation', { safe_browsing_key: k }),
      (r) => (k ? `Key saved and sent to ${r.pushed} online server(s)` : 'Key removed from all servers'),
    ).then(() => {
      setKey('');
      setTimeout(res.reload, 4000);
      res.reload();
    });
  return (
    <div className="space-y-6">
      <div>
        <Breadcrumb items={['Overview', 'Domain Reputation']} />
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-navy-900">
          <Globe2 className="h-6 w-6" /> Domain Reputation
        </h1>
        <p className="text-sm text-slate-500">
          Every server checks its hosted domains each night against domain blocklists (Spamhaus DBL, SURBL, URIBL) and, with a key, Google Safe Browsing. A
          listed domain sends an alert and can suspend the account.
        </p>
      </div>

      <Card
        title="Google Safe Browsing API key (all servers)"
        desc="Adds Google's malware and phishing list: the warning browsers show for a hacked or phishing site. Saved once here, it is sent to every server, also to servers added later; on each server you only switch domain reputation on or off (Settings » RBL & IP Reputation). A key still saved on a server itself wins there."
      >
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${d.key_set ? 'bg-emerald-50 text-emerald-700' : 'bg-slate-100 text-slate-600'}`}>
            <KeyRound className="h-3.5 w-3.5" /> {d.key_set ? `Key saved: ${d.key_hint}` : 'No key'}
          </span>
          {d.key_set && admin && (
            <button className="text-sm text-red-600 hover:underline" disabled={busy} onClick={() => confirm('Remove the Google Safe Browsing key from all servers?') && save('')}>
              Remove
            </button>
          )}
        </div>
        {admin && (
          <div className="mt-3 flex flex-wrap gap-2">
            <input
              className="input w-full max-w-md"
              type="password"
              placeholder={d.key_set ? 'New key (replaces the saved one)' : 'AIza… (Google Cloud » APIs & Services » Credentials)'}
              value={key}
              onChange={(e) => setKey(e.target.value.trim())}
              autoComplete="off"
            />
            <button className="btn-primary" disabled={busy || !valid} onClick={() => save(key.trim())}>
              Save for all servers
            </button>
          </div>
        )}
        {key && !valid && <p className="mt-1 text-xs text-red-600">A Google API key is letters, digits, - and _ (usually 39 characters, starting with AIza).</p>}
        <p className="mt-3 text-xs text-slate-500">
          Getting a key: in Google Cloud Console create a project, enable the <b>Safe Browsing API</b>, then create an API key under APIs &amp; Services » Credentials.
          It is free for non-commercial use.
        </p>
      </Card>

      <Card title="Servers" desc="Whether each server checks its domains, which key it uses, and what it found.">
        <div className="mt-3 overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
            <thead className="text-left text-xs text-slate-500 uppercase">
              <tr>
                <th className="py-2 pr-3">Server</th>
                <th className="py-2 pr-3">Domain reputation</th>
                <th className="py-2 pr-3">Safe Browsing key</th>
                <th className="py-2 pr-3">Domains</th>
                <th className="py-2 pr-3">Last check</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {d.servers.map((s) => (
                <tr key={s.id}>
                  <td className="py-2 pr-3">
                    <Link to={`/servers/${s.id}/settings?s=rbl`} className="font-medium text-navy-900 hover:underline">
                      {s.hostname}
                    </Link>
                  </td>
                  {s.error ? (
                    <td colSpan={4} className="py-2 pr-3 text-xs text-slate-500">
                      {s.error}
                    </td>
                  ) : (
                    <>
                      <td className="py-2 pr-3">{s.enabled ? <span className="text-emerald-700">On</span> : <span className="text-slate-500">Off</span>}</td>
                      <td className="py-2 pr-3 text-xs">
                        {s.old
                          ? `update the agent to ${d.min_agent}`
                          : s.key_source === 'server'
                            ? 'this server’s own key'
                            : s.key_source === 'portal'
                              ? 'from the portal'
                              : 'none (blocklists only)'}
                      </td>
                      <td className="py-2 pr-3 text-xs">
                        {s.summary?.total ? (
                          <>
                            {s.summary.total.toLocaleString()} checked
                            {s.summary.flagged ? <span className="ml-1 font-medium text-red-600">· {s.summary.flagged} listed</span> : <span className="ml-1 text-emerald-700">· none listed</span>}
                          </>
                        ) : (
                          <span className="text-slate-400">not checked yet</span>
                        )}
                      </td>
                      <td className="py-2 pr-3 text-xs whitespace-nowrap">{s.last_check || s.summary?.checked_at ? fmtTime(s.last_check || s.summary!.checked_at!) : '–'}</td>
                    </>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
