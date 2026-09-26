import { useState } from 'react';
import { Cable, KeyRound, Plus, ShieldAlert, Trash2 } from 'lucide-react';
import { api } from '../api';
import { useApi } from '../hooks';
import { ago } from '../format';
import { Breadcrumb, CopyBox, Empty, ErrorBox, PageLoader } from '../components/ui';
import { Card, useAction } from '../components/controls';

interface Token {
  id: string;
  label: string;
  prefix: string;
  scope: 'read' | 'write';
  last_used_at: string | null;
  calls: number;
  created_at: string;
  created_by: string | null;
}

const READ_TOOLS = ['list_servers', 'fleet_overview', 'server_dashboard', 'list_findings', 'get_finding_content', 'list_scans', 'get_settings', 'firewall_events', 'waf_events', 'ipdb_status', 'ai_knowledge', 'agent_command (read actions)'];
const WRITE_TOOLS = ['start_scan', 'finding_action', 'update_settings', 'mark_file', 'agent_command (all actions)'];

export default function AIConnector() {
  const { data, error, loading, reload } = useApi<{ tokens: Token[]; endpoint: string }>('/api/mcp/tokens');
  const [label, setLabel] = useState('Claude');
  const [scope, setScope] = useState<'read' | 'write'>('read');
  const [created, setCreated] = useState<{ url: string; token: string; scope: string } | null>(null);
  const { run, busy } = useAction();

  if (loading && !data) return <PageLoader />;
  if (error && !data) return <ErrorBox message={error} />;

  const create = async () => {
    const r = await run(() => api<{ url: string; token: string }>('POST', '/api/mcp/tokens', { label, scope }), 'Connector created');
    if (r) {
      setCreated({ ...r, scope });
      reload();
    }
  };
  const revoke = async (t: Token) => {
    if (!confirm(`Revoke "${t.label}"? Any AI using it loses access immediately.`)) return;
    if (await run(() => api('DELETE', `/api/mcp/tokens/${t.id}`), 'Connector revoked')) reload();
  };

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <Breadcrumb items={['AI Connector (MCP)']} />
      <div>
        <h1 className="h-title flex items-center gap-2">
          <Cable className="h-6 w-6" /> AI Connector (MCP)
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-slate-500">
          Connect Claude or any AI assistant that supports the Model Context Protocol. It can then read live data from every server (dashboards,
          scanner findings and file contents, firewall, WAF and IPDB logs, settings, the AI knowledge base) and, with a read &amp; write connector, run
          scans and act on findings.
        </p>
      </div>

      <Card title="New connector" desc="The connector URL contains a secret token. It is shown once; store it like a password.">
        <div className="mt-3 flex flex-wrap items-end gap-3">
          <label className="text-sm">
            <span className="mb-1 block text-slate-600">Name</span>
            <input className="input w-56" value={label} maxLength={80} onChange={(e) => setLabel(e.target.value)} />
          </label>
          <div className="text-sm">
            <span className="mb-1 block text-slate-600">Access</span>
            <div className="inline-flex overflow-hidden rounded-lg border border-slate-200">
              {(['read', 'write'] as const).map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => setScope(s)}
                  className={`px-4 py-2 ${scope === s ? 'bg-navy-900 text-white' : 'bg-white text-slate-600 hover:bg-slate-50'}`}
                >
                  {s === 'read' ? 'Read only' : 'Read & write'}
                </button>
              ))}
            </div>
          </div>
          <button className="btn-primary" disabled={busy || !label.trim()} onClick={create}>
            <Plus className="h-4 w-4" /> Create connector
          </button>
        </div>
        {scope === 'write' && (
          <p className="mt-3 flex items-start gap-2 rounded-lg bg-amber-50 p-3 text-sm text-amber-800">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
            A read &amp; write connector lets the AI quarantine, restore or delete files and change settings on your servers. Every action is written to the
            Security Log. Ask the AI to confirm with you before it acts.
          </p>
        )}
        {created && (
          <div className="mt-4 space-y-2 rounded-xl border border-emerald-200 bg-emerald-50/60 p-4">
            <div className="text-sm font-medium text-emerald-900">Connector URL ({created.scope === 'write' ? 'read & write' : 'read only'}) — copy it now, it will not be shown again:</div>
            <CopyBox text={created.url} />
            <div className="text-xs text-slate-500">
              For clients that take a header instead: URL <code>{data?.endpoint}</code> with <code>Authorization: Bearer {created.token.slice(0, 10)}…</code>
            </div>
          </div>
        )}
      </Card>

      <Card title="Connectors">
        {data?.tokens.length ? (
          <div className="mt-2 divide-y divide-slate-100">
            {data.tokens.map((t) => (
              <div key={t.id} className="flex flex-wrap items-center gap-3 py-3 text-sm">
                <KeyRound className="h-4 w-4 text-slate-400" />
                <div className="min-w-[180px] flex-1">
                  <div className="font-medium text-navy-900">{t.label}</div>
                  <div className="text-xs text-slate-500">
                    <code>{t.prefix}…</code> · created {ago(t.created_at)}
                    {t.created_by ? ` by ${t.created_by}` : ''}
                  </div>
                </div>
                <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${t.scope === 'write' ? 'bg-amber-100 text-amber-800' : 'bg-sky-100 text-sky-800'}`}>
                  {t.scope === 'write' ? 'Read & write' : 'Read only'}
                </span>
                <div className="w-44 text-xs text-slate-500">{t.last_used_at ? `Used ${ago(t.last_used_at)} · ${t.calls} calls` : 'Never used'}</div>
                <button className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 text-red-600 hover:bg-red-50" title="Revoke" onClick={() => revoke(t)}>
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <Empty text="No connectors yet" />
        )}
      </Card>

      <Card title="Connect Claude">
        <ol className="mt-2 list-decimal space-y-1.5 pl-5 text-sm text-slate-700">
          <li>Create a connector above and copy its URL.</li>
          <li>
            In Claude open <b>Settings » Connectors » Add custom connector</b>.
          </li>
          <li>
            Name it <b>XMart Guard</b>, paste the URL and click <b>Continue</b>. Under <b>Authentication</b> choose <b>No sign-in</b> (the token is already in the URL), then <b>Add</b> and <b>Connect</b>.
          </li>
          <li>In a chat, enable the XMart Guard connector from the tools menu and ask, for example: “Review the quarantined files on all servers and list likely false positives.”</li>
        </ol>
        <p className="mt-3 text-sm text-slate-500">
          The portal must be reachable over HTTPS from the internet for Claude's servers to connect. Other MCP clients (Claude Code, Cursor, …) use the same URL:
        </p>
        <pre className="mt-2 overflow-x-auto rounded-lg bg-navy-900 p-3 text-xs text-slate-100">{`claude mcp add --transport http xmartguard ${data?.endpoint ?? ''}/<token>`}</pre>
        <div className="mt-4 grid gap-4 text-sm sm:grid-cols-2">
          <div>
            <div className="mb-1 font-medium text-navy-900">Read tools</div>
            <div className="flex flex-wrap gap-1.5">
              {READ_TOOLS.map((t) => (
                <code key={t} className="rounded bg-slate-100 px-1.5 py-0.5 text-xs">{t}</code>
              ))}
            </div>
          </div>
          <div>
            <div className="mb-1 font-medium text-navy-900">Write tools (read &amp; write connectors)</div>
            <div className="flex flex-wrap gap-1.5">
              {WRITE_TOOLS.map((t) => (
                <code key={t} className="rounded bg-amber-50 px-1.5 py-0.5 text-xs text-amber-900">{t}</code>
              ))}
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
}
