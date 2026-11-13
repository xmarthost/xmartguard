import { useState, type CSSProperties } from 'react';
import { CheckCircle2, KeyRound, RefreshCw, ShieldAlert, Webhook, XCircle } from 'lucide-react';
import { api } from '../api';
import { useApi } from '../hooks';
import { Breadcrumb, CopyBox, PageLoader } from '../components/ui';
import { Card, useAction } from '../components/controls';

interface FeedState {
  key_set: boolean;
  key_hint: string;
  secret_set: boolean;
  webhook_url: string;
  every_hours: number;
  items: number;
  sent: number;
  last_sync_at: string | null;
  last_changed: number;
  last_error: string;
  last_webhook_at: string | null;
  last_webhook_ok: boolean | null;
}
type TestResult = { ok: boolean; error?: string; note?: string };

const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : 'never');
const masked = (v: string) => ({ WebkitTextSecurity: v ? 'disc' : 'none' }) as CSSProperties;
const noFill = { spellCheck: false, autoComplete: 'off', 'data-lpignore': 'true', 'data-1p-ignore': 'true' } as const;

function newSecret(): string {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function Result({ r, okText }: { r: TestResult | null; okText: string }) {
  if (!r) return null;
  return <p className={`rounded-lg px-3 py-2 text-sm ${r.ok ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-700'}`}>{r.ok ? okText : `Not working: ${r.error}`}</p>;
}

/** Master: Wordfence Intelligence key and webhook for fast plugin vulnerability response. */
export default function VulnFeed() {
  const st = useApi<FeedState>('/api/vuln-feed', 30_000);
  const { run, busy } = useAction();
  const [key, setKey] = useState('');
  const [secret, setSecret] = useState('');
  const [keyTest, setKeyTest] = useState<TestResult | null>(null);
  const [hookTest, setHookTest] = useState<TestResult | null>(null);
  const [since, setSince] = useState('2026-11-01');
  const d = st.data;
  const save = (body: Record<string, string>, ok: string) =>
    run(() => api<FeedState>('PUT', '/api/vuln-feed', body), ok).then((r) => {
      if (r) {
        setKey('');
        setSecret('');
        st.reload();
        setTimeout(() => st.reload(), 15000);
      }
    });
  if (!d) return <PageLoader />;
  return (
    <div className="space-y-5">
      <Breadcrumb items={['Web Protection', 'Plugin Vulnerabilities']} />
      <Card
        title="Fast response to new plugin vulnerabilities"
        desc="The full WordPress scan runs every 3 days. A newly disclosed hole in a plugin, theme or WordPress core is acted on within hours instead: the servers check their last scan's plugin list (no new scan) and update the affected sites; when the vulnerable version stays, the plugin's PHP files are shielded and a critical one is deactivated. The data comes from Wordfence Intelligence (free)."
        right={
          d.key_set || d.secret_set ? (
            d.last_error ? (
              <span className="flex items-center gap-1 whitespace-nowrap text-xs font-semibold text-red-600"><XCircle className="h-4 w-4" /> Error</span>
            ) : (
              <span className="flex items-center gap-1 whitespace-nowrap text-xs font-semibold text-green-600"><CheckCircle2 className="h-4 w-4" /> On</span>
            )
          ) : (
            <span className="whitespace-nowrap text-xs font-semibold text-slate-400">Not set up</span>
          )
        }
      >
        <div className="grid gap-3 text-sm sm:grid-cols-3">
          <div className="rounded-lg bg-slate-50 px-3 py-2">
            <div className="text-xs text-slate-500">Vulnerabilities known</div>
            <b>{d.items.toLocaleString()}</b> <span className="text-slate-500">({d.sent.toLocaleString()} sent to servers as new)</span>
          </div>
          <div className="rounded-lg bg-slate-50 px-3 py-2">
            <div className="text-xs text-slate-500">Last feed download (every {d.every_hours} h)</div>
            {when(d.last_sync_at)}
            {d.last_sync_at && <span className="text-slate-500"> · {d.last_changed} new</span>}
          </div>
          <div className="rounded-lg bg-slate-50 px-3 py-2">
            <div className="text-xs text-slate-500">Last webhook delivery</div>
            {when(d.last_webhook_at)}
            {d.last_webhook_at && <span className={d.last_webhook_ok ? 'text-green-700' : 'text-red-600'}> · {d.last_webhook_ok ? 'signature OK' : 'bad signature'}</span>}
          </div>
        </div>
        {d.last_error && <p className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">Last error: {d.last_error}</p>}
      </Card>

      <Card
        title="1. Wordfence Intelligence API key"
        desc="On wordfence.com: Account » Integrations » Wordfence Intelligence API Key » Create API Key, then paste it here. The portal downloads the vulnerability feed with it every few hours (and as soon as it is saved). Wordfence allows only a few downloads per hour: a test is a download, so when the feed was downloaded recently the test only reports that. The key stays on the portal and is shown only as a hint."
        right={<KeyRound className="h-5 w-5 text-slate-400" />}
      >
        <div className="space-y-3 text-sm">
          <div className="flex flex-wrap items-end gap-2">
            <label className="min-w-[260px] flex-1">
              <span className="mb-1 block text-xs font-medium text-slate-500">API key {d.key_set && <span className="font-mono">(saved: {d.key_hint})</span>}</span>
              <input
                className="input font-mono"
                type="text"
                name="wordfence-api-key"
                style={masked(key)}
                {...noFill}
                placeholder={d.key_set ? 'Enter a new key to replace it' : 'Paste your Wordfence Intelligence API key'}
                value={key}
                onChange={(e) => {
                  setKey(e.target.value.trim());
                  setKeyTest(null);
                }}
              />
            </label>
            <button className="btn-outline" disabled={busy || (!key && !d.key_set)} onClick={() => void run(() => api<TestResult>('POST', '/api/vuln-feed/test', { api_key: key })).then((r) => r && setKeyTest(r))}>
              Test API key
            </button>
            <button className="btn-primary" disabled={busy || !key} onClick={() => void save({ api_key: key }, 'API key saved; downloading the feed')}>
              Save key
            </button>
            {d.key_set && (
              <button className="btn-outline text-red-600" disabled={busy} onClick={() => confirm('Remove the Wordfence API key? The feed is no longer downloaded.') && void save({ api_key: '' }, 'API key removed')}>
                Remove
              </button>
            )}
            {d.key_set && (
              <button
                className="btn-outline"
                disabled={busy}
                onClick={() =>
                  void run(() => api<{ ok: boolean; changed?: number; error?: string }>('POST', '/api/vuln-feed/sync'), (r) => (r.ok ? `Feed downloaded: ${r.changed ?? 0} new` : `Feed: ${r.error}`)).then(() => st.reload())
                }
              >
                <RefreshCw className="h-4 w-4" /> Download now
              </button>
            )}
          </div>
          <Result r={keyTest} okText={`Working: Wordfence accepted the key${keyTest?.note ? ` (${keyTest.note})` : ' and the feed was downloaded'}.`} />
        </div>
      </Card>

      <Card
        title="2. Webhook (instant)"
        desc="Wordfence sends every new, changed or removed vulnerability to this address the moment it is published, signed with your secret, and the servers act on it at once. It works with or without the API key; with both, a missed delivery is caught by the next download."
        right={<Webhook className="h-5 w-5 text-slate-400" />}
      >
        <div className="space-y-3 text-sm">
          <div>
            <span className="mb-1 block text-xs font-medium text-slate-500">Webhook URL (paste in Wordfence » Integrations » Add Webhook » URL)</span>
            <CopyBox text={d.webhook_url} />
          </div>
          <div className="flex flex-wrap items-end gap-2">
            <label className="min-w-[260px] flex-1">
              <span className="mb-1 block text-xs font-medium text-slate-500">Secret {d.secret_set && <span>(saved)</span>}</span>
              <input
                className="input font-mono"
                type="text"
                name="wordfence-webhook-secret"
                {...noFill}
                placeholder={d.secret_set ? 'Enter or generate a new secret to replace it' : 'Generate, or paste the secret you gave Wordfence'}
                value={secret}
                onChange={(e) => {
                  setSecret(e.target.value.trim());
                  setHookTest(null);
                }}
              />
            </label>
            <button className="btn-outline" disabled={busy} onClick={() => setSecret(newSecret())}>
              Generate
            </button>
            <button className="btn-primary" disabled={busy || secret.length < 32} onClick={() => void save({ webhook_secret: secret }, 'Webhook secret saved: paste the same secret in Wordfence')}>
              Save secret
            </button>
            <button className="btn-outline" disabled={busy || !d.secret_set} onClick={() => void run(() => api<TestResult>('POST', '/api/vuln-feed/webhook-test')).then((r) => (r && setHookTest(r), st.reload()))}>
              Test webhook
            </button>
            {d.secret_set && (
              <button className="btn-outline text-red-600" disabled={busy} onClick={() => confirm('Remove the webhook secret? Wordfence deliveries are refused until a new one is saved.') && void save({ webhook_secret: '' }, 'Webhook secret removed')}>
                Remove
              </button>
            )}
          </div>
          {secret && <p className="text-xs text-amber-700">Copy this secret now: after saving it is not shown again. Paste the same value in Wordfence's Secret field.</p>}
          <Result r={hookTest} okText="Working: a signed test delivery reached the webhook address and its signature was verified." />
          <ol className="list-decimal space-y-1 pl-5 text-slate-600">
            <li>Click Generate, copy the secret, then Save secret.</li>
            <li>In Wordfence » Account » Integrations » Add Webhook: paste the URL above and the same secret; leave "Format for Slack/Discord" off; keep Create, Replace and Delete ticked.</li>
            <li>Click Create and Test Webhook in Wordfence: "Last webhook delivery" above shows it with "signature OK".</li>
          </ol>
        </div>
      </Card>
      <Card
        title="3. Act on earlier vulnerabilities"
        desc="The first download is kept as history: the servers only act on what is published after it. To have them act on the holes of the last weeks too, choose a date: every vulnerability Wordfence published since then is sent to the servers as new. Each site is updated (or shielded) once per vulnerability, so sending again does nothing twice."
      >
        <div className="flex flex-wrap items-end gap-2 text-sm">
          <label>
            <span className="mb-1 block text-xs font-medium text-slate-500">Published since</span>
            <input className="input" type="date" value={since} onChange={(e) => setSince(e.target.value)} />
          </label>
          <button
            className="btn-primary"
            disabled={busy || !since}
            onClick={() =>
              confirm(`Send every vulnerability published since ${since} to the servers? Affected sites are updated now; where the update does not apply, the plugin is shielded or (critical, if enabled) deactivated.`) &&
              void run(() => api<{ ok: boolean; sent?: number; error?: string }>('POST', '/api/vuln-feed/replay', { since }), (r) => (r.ok ? `${r.sent ?? 0} vulnerabilities sent to the servers` : `Not sent: ${r.error}`))
            }
          >
            Send to servers
          </button>
        </div>
      </Card>
      <p className="flex items-center gap-2 text-xs text-slate-500">
        <ShieldAlert className="h-4 w-4" /> What each server does is set in its Settings » WordPress and CMS (fast response, minimum score, deactivation of critical plugins).
      </p>
    </div>
  );
}
