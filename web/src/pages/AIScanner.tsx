import { useMemo, useState } from 'react';
import {
  BrainCircuit, CheckCircle2, CircleAlert, Database, ExternalLink, FlaskConical, KeyRound, Pencil, Plus, RefreshCw, Search, Sparkles, Trash2, Zap,
} from 'lucide-react';
import { api } from '../api';
import { useApi } from '../hooks';
import { useAuth, can } from '../auth';
import { Breadcrumb, Empty, ErrorBox, PageLoader, StatCard } from '../components/ui';
import { Card, Modal, Pager, Toggle, useAction } from '../components/controls';
import { ago, bytes } from '../format';

interface Preset {
  kind: string;
  label: string;
  baseUrl: string;
  model: string;
  keyUrl: string;
  free: string;
}

interface Provider {
  id: string;
  kind: string;
  name: string;
  base_url: string;
  api_key: string;
  model: string;
  priority: number;
  enabled: boolean;
  cooldown_until: string | null;
  last_error: string;
  last_error_at: string | null;
  last_ok_at: string | null;
  requests: string;
  failures: string;
  files: string;
  tokens_in: string;
  tokens_out: string;
  requests_today: number;
}

interface Status {
  providers: { total: number; enabled: number; ready: number; requests_today: number; files: number; tokens: number };
  kb: { total: number; malicious: number; suspicious: number; clean: number; reused: number };
  samples: number;
  samples_malicious: number;
  samples_clean: number;
  train_min_per_class: number;
  models: { base_version: string; version: string; samples: number; accuracy: number; trained_at: string; weights: number }[];
}

interface KBEntry {
  sha256: string;
  size: number;
  verdict: string;
  confidence: number;
  reason: string;
  injected: boolean;
  cut: { from: number; to: number; text?: string }[];
  model: string;
  name: string;
  match: string;
  hits: number;
  overridden: boolean;
  updated_at: string;
  server: string | null;
}

interface ModelInfo {
  id: string;
  name: string;
  free: boolean;
  context: number;
}

const num = (v: string | number) => Number(v).toLocaleString();

const VERDICT: Record<string, string> = {
  malicious: 'bg-red-100 text-red-700',
  suspicious: 'bg-amber-100 text-amber-800',
  clean: 'bg-green-100 text-green-700',
};

/**
 * Global AI settings: the free AI API keys every linked server's AI scanner
 * uses through the portal, their failover state, and the fleet's shared
 * knowledge (verdicts + trained model).
 */
export default function AIScanner() {
  const { user } = useAuth();
  const admin = can(user, 'admin');
  const status = useApi<Status>('/api/ai/status', 15_000);
  const providers = useApi<{ providers: Provider[] }>('/api/ai/providers', 15_000);
  const presets = useApi<{ presets: Preset[] }>('/api/ai/presets');
  const [edit, setEdit] = useState<Provider | 'new' | null>(null);
  const { run, busy } = useAction();

  if (status.error) return <ErrorBox message={status.error} />;
  if (!status.data || !providers.data || !presets.data) return <PageLoader />;
  const st = status.data;
  const list = providers.data.providers;
  const model = st.models[0];
  const label = (kind: string) => presets.data!.presets.find((p) => p.kind === kind)?.label ?? kind;
  const reload = () => {
    providers.reload();
    status.reload();
  };

  return (
    <div className="space-y-5">
      <Breadcrumb items={['AI Scanner']} />
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="h-title">AI Scanner</h1>
          <p className="max-w-3xl text-sm text-slate-500">
            Free AI APIs check files for all your servers. Add several keys (for example 5 Gemini keys, then Groq and OpenRouter): when one key reaches its
            limit or fails, the next one is used automatically. Every verdict is shared, so a file judged on one server is recognised on all others at once.
          </p>
        </div>
        {admin && (
          <button className="btn-primary" onClick={() => setEdit('new')}>
            <Plus className="h-4 w-4" /> Add API key
          </button>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={<KeyRound />}
          value={`${st.providers.ready} / ${st.providers.enabled}`}
          label="API keys ready now"
          accent={st.providers.enabled && st.providers.ready === 0 ? 'text-red-600' : 'text-navy-900'}
        />
        <StatCard icon={<Zap />} value={num(st.providers.requests_today)} label={`AI requests today · ${num(st.providers.tokens)} tokens in total`} />
        <StatCard icon={<Database />} value={num(st.kb.total)} label={`files known (${num(st.kb.malicious)} malicious) · ${num(st.kb.reused)} answered without AI`} />
        <StatCard
          icon={<BrainCircuit />}
          value={model ? `${Math.round(model.accuracy * 100)}%` : '—'}
          label={
            model
              ? `fleet model: ${num(model.samples)} examples, trained ${ago(model.trained_at)}`
              : `fleet model: collecting examples (${num(st.samples_malicious)} malicious, ${num(st.samples_clean)} clean; ${st.train_min_per_class} of each needed)`
          }
        />
      </div>

      <Card
        title="AI API keys"
        desc="Tried in priority order (1 first). Keys with the same priority share the load. A key that hits its limit rests and comes back by itself."
        right={
          admin && st.samples > 0 ? (
            <button
              className="btn-outline"
              disabled={busy}
              onClick={() =>
                run(
                  () => api<{ trained: { result: { waiting?: string; samples?: number } | null }[] }>('POST', '/api/ai/train').finally(reload),
                  (r) => r.trained.map((t) => t.result?.waiting ?? `Fleet model trained on ${t.result?.samples ?? 0} examples`).join('; ') || 'Nothing to train yet',
                )
              }
            >
              <RefreshCw className="h-4 w-4" /> Train fleet model now
            </button>
          ) : undefined
        }
      >
        {list.length === 0 ? (
          <Empty text="No AI API keys yet. Until you add one, servers use their built-in model.">
            {admin && (
              <button className="btn-primary mt-3" onClick={() => setEdit('new')}>
                <Plus className="h-4 w-4" /> Add a free API key
              </button>
            )}
          </Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-sm [&_td]:px-2 [&_td]:py-3 [&_th]:px-2 [&_th]:py-3 [&_th]:text-left [&_th]:font-medium [&_th]:text-slate-500 [&_thead_tr]:border-b [&_tbody_tr]:border-b [&_tbody_tr]:border-slate-100">
              <thead>
                <tr>
                  <th className="w-16">Priority</th>
                  <th>Name</th>
                  <th>Model</th>
                  <th>Status</th>
                  <th className="text-right">Today</th>
                  <th className="text-right">Files</th>
                  <th className="text-right">Tokens</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {list.map((p) => (
                  <ProviderRow key={p.id} p={p} label={label(p.kind)} admin={admin} onEdit={() => setEdit(p)} onChange={reload} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="How requests stay small" desc="The AI only sees what it needs, and never the same file twice.">
        <ul className="grid gap-3 text-sm text-slate-600 md:grid-cols-2">
          <li className="flex gap-2">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-green-600" />
            A file any server already had judged is answered from the shared knowledge base: no request, no tokens.
          </li>
          <li className="flex gap-2">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-green-600" />
            Up to 6 files go in one request with one copy of the instructions (free tiers count requests per day).
          </li>
          <li className="flex gap-2">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-green-600" />
            Big files are cut to their start, end and the lines around risky calls; long encoded strings are shortened; indentation is removed.
          </li>
          <li className="flex gap-2">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-green-600" />
            The instructions come first and never change, so providers that cache repeated prompts (Gemini, Groq, OpenRouter) can reuse them.
          </li>
          <li className="flex gap-2">
            <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
            <span>
              The AI marks injected lines, so the scanner can <b>trim</b> just the hacker's code and keep the site running (Settings » Virus Scanner » Trim).
            </span>
          </li>
          <li className="flex gap-2">
            <BrainCircuit className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
            Verdicts train the built-in model of every server (fleet model), so detection improves even without the AI.
          </li>
        </ul>
      </Card>

      <KnowledgeBase admin={admin} onChange={() => status.reload()} />

      {edit && presets.data && (
        <ProviderModal
          presets={presets.data.presets}
          current={edit === 'new' ? null : edit}
          nextPriority={Math.max(0, ...list.map((p) => p.priority)) + 1}
          onClose={() => setEdit(null)}
          onSaved={() => {
            setEdit(null);
            reload();
          }}
        />
      )}
    </div>
  );
}

function ProviderRow({ p, label, admin, onEdit, onChange }: { p: Provider; label: string; admin: boolean; onEdit: () => void; onChange: () => void }) {
  const { run, busy } = useAction();
  const resting = p.cooldown_until && new Date(p.cooldown_until).getTime() > Date.now();
  let state = <span className="font-medium text-green-700">Ready</span>;
  if (!p.enabled) state = <span className="text-slate-400">Off</span>;
  else if (resting)
    state = (
      <span className="text-amber-700" title={p.last_error}>
        Resting until {new Date(p.cooldown_until!).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
      </span>
    );
  else if (p.last_error && (!p.last_ok_at || (p.last_error_at && p.last_error_at > p.last_ok_at)))
    state = (
      <span className="text-red-600" title={p.last_error}>
        Error
      </span>
    );
  return (
    <tr>
      <td className="font-semibold text-navy-900">{p.priority}</td>
      <td>
        <div className="font-medium text-navy-900">{p.name}</div>
        <div className="text-xs text-slate-500">
          {label} · {p.api_key || 'no key'}
        </div>
      </td>
      <td className="font-mono text-xs">{p.model}</td>
      <td className="max-w-[260px]">
        {state}
        {p.last_error && <div className="truncate text-xs text-slate-400" title={p.last_error}>{p.last_error}</div>}
      </td>
      <td className="text-right tabular-nums">{num(p.requests_today)}</td>
      <td className="text-right tabular-nums">{num(p.files)}</td>
      <td className="text-right tabular-nums">{num(Number(p.tokens_in) + Number(p.tokens_out))}</td>
      <td>
        {admin && (
          <div className="flex items-center justify-end gap-2">
            <Toggle on={p.enabled} disabled={busy} onChange={(v) => run(() => api('PATCH', `/api/ai/providers/${p.id}`, { enabled: v }).then(onChange))} />
            <button
              className="btn-outline !px-2 !py-1 text-xs"
              disabled={busy}
              title="Send a tiny test request"
              onClick={() =>
                run(
                  () => api<{ ms: number; tokens_in: number; tokens_out: number }>('POST', `/api/ai/providers/${p.id}/test`).finally(onChange),
                  (r) => `Works: answered in ${(r.ms / 1000).toFixed(1)} s (${r.tokens_in + r.tokens_out} tokens)`,
                )
              }
            >
              <FlaskConical className="h-3.5 w-3.5" /> Test
            </button>
            <button className="rounded p-1 text-slate-500 hover:bg-slate-100" title="Edit" onClick={onEdit}>
              <Pencil className="h-4 w-4" />
            </button>
            <button
              className="rounded p-1 text-red-500 hover:bg-red-50"
              title="Delete"
              onClick={() => confirm(`Delete ${p.name}?`) && run(() => api('DELETE', `/api/ai/providers/${p.id}`).then(onChange), 'Key deleted')}
            >
              <Trash2 className="h-4 w-4" />
            </button>
          </div>
        )}
      </td>
    </tr>
  );
}

function ProviderModal({
  presets, current, nextPriority, onClose, onSaved,
}: { presets: Preset[]; current: Provider | null; nextPriority: number; onClose: () => void; onSaved: () => void }) {
  const [kind, setKind] = useState(current?.kind ?? 'gemini');
  const pre = presets.find((p) => p.kind === kind)!;
  const [name, setName] = useState(current?.name ?? pre.label);
  const [key, setKey] = useState(current?.api_key ?? '');
  const [baseUrl, setBaseUrl] = useState(current?.base_url ?? pre.baseUrl);
  const [model, setModel] = useState(current?.model ?? pre.model);
  const [priority, setPriority] = useState(current?.priority ?? nextPriority);
  const [models, setModels] = useState<ModelInfo[] | null>(null);
  const [onlyFree, setOnlyFree] = useState(true);
  const [filter, setFilter] = useState('');
  const { run, busy } = useAction();
  const advanced = kind === 'custom' || kind === 'cloudflare';

  const pick = (k: string) => {
    const p = presets.find((x) => x.kind === k)!;
    setKind(k);
    if (!current) setName(p.label);
    setBaseUrl(p.baseUrl);
    setModel(p.model);
    setModels(null);
  };
  const shown = useMemo(
    () =>
      (models ?? []).filter(
        (m) => (kind !== 'openrouter' || !onlyFree || m.free) && (!filter || m.id.toLowerCase().includes(filter.toLowerCase())),
      ),
    [models, onlyFree, filter, kind],
  );

  return (
    <Modal title={current ? `Edit ${current.name}` : 'Add a free AI API key'} onClose={onClose} wide>
      <div className="grid gap-4 md:grid-cols-2">
        <label className="block">
          <span className="label">Provider</span>
          <select className="input" value={kind} disabled={Boolean(current)} onChange={(e) => pick(e.target.value)}>
            {presets.map((p) => (
              <option key={p.kind} value={p.kind}>
                {p.label}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          <span className="label">Name (shown in the list)</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Gemini key 1" />
        </label>
      </div>
      <div className="mt-3 rounded-lg bg-blue-50 p-3 text-sm text-blue-900">
        <b>{pre.label}:</b> {pre.free}{' '}
        {pre.keyUrl && (
          <a className="inline-flex items-center gap-1 font-medium underline" href={pre.keyUrl} target="_blank" rel="noreferrer">
            Get a free key <ExternalLink className="h-3.5 w-3.5" />
          </a>
        )}
      </div>
      <div className="mt-4 grid gap-4 md:grid-cols-[1fr_140px]">
        <label className="block">
          <span className="label">API key</span>
          <input className="input font-mono" value={key} onChange={(e) => setKey(e.target.value)} placeholder="paste the key" autoComplete="off" />
        </label>
        <label className="block">
          <span className="label">Priority</span>
          <input className="input" type="number" min={1} max={1000} value={priority} onChange={(e) => setPriority(Number(e.target.value))} />
        </label>
      </div>
      {advanced && (
        <label className="mt-4 block">
          <span className="label">API address (OpenAI-compatible)</span>
          <input className="input font-mono" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
        </label>
      )}
      <div className="mt-4">
        <span className="label">Model</span>
        <div className="flex gap-2">
          <input className="input flex-1 font-mono" value={model} onChange={(e) => setModel(e.target.value)} placeholder="model id" />
          <button
            className="btn-outline"
            disabled={busy || (!key && !current)}
            onClick={async () => {
              const r = await run(() => api<{ models: ModelInfo[] }>('POST', '/api/ai/models', { kind, base_url: baseUrl, api_key: key, provider_id: current?.id }));
              if (r) setModels(r.models);
            }}
          >
            <RefreshCw className={`h-4 w-4 ${busy ? 'animate-spin' : ''}`} /> Fetch models
          </button>
        </div>
        {models && (
          <div className="mt-2 rounded-lg border border-slate-200">
            <div className="flex items-center gap-3 border-b border-slate-100 p-2">
              <div className="relative flex-1">
                <Search className="absolute top-2.5 left-2 h-4 w-4 text-slate-400" />
                <input className="input !pl-8" placeholder="filter models" value={filter} onChange={(e) => setFilter(e.target.value)} />
              </div>
              {kind === 'openrouter' && (
                <label className="flex items-center gap-2 text-sm text-slate-600">
                  <input type="checkbox" checked={onlyFree} onChange={(e) => setOnlyFree(e.target.checked)} /> only free
                </label>
              )}
            </div>
            <div className="max-h-56 overflow-y-auto">
              {shown.length === 0 ? (
                <div className="p-3 text-sm text-slate-500">No models match.</div>
              ) : (
                shown.map((m) => (
                  <button
                    key={m.id}
                    className={`flex w-full items-center justify-between px-3 py-1.5 text-left text-sm hover:bg-slate-50 ${m.id === model ? 'bg-blue-50' : ''}`}
                    onClick={() => setModel(m.id)}
                  >
                    <span className="font-mono">{m.id}</span>
                    <span className="flex gap-2 text-xs text-slate-500">
                      {m.context > 0 && <span>{Math.round(m.context / 1000)}k ctx</span>}
                      {kind === 'openrouter' && m.free && <span className="rounded bg-green-100 px-1.5 text-green-700">free</span>}
                    </span>
                  </button>
                ))
              )}
            </div>
          </div>
        )}
        <p className="mt-1 text-xs text-slate-500">Tip: fast "flash"/"lite" or gpt-oss models are plenty for this job and have the highest free limits.</p>
      </div>
      <div className="mt-6 flex justify-end gap-2">
        <button className="btn-outline" onClick={onClose}>
          Cancel
        </button>
        <button
          className="btn-primary"
          disabled={busy || !model.trim() || (!current && !key.trim())}
          onClick={() =>
            run(async () => {
              const body = { kind, name, base_url: baseUrl, api_key: key, model, priority };
              if (current) await api('PATCH', `/api/ai/providers/${current.id}`, body);
              else await api('POST', '/api/ai/providers', body);
              onSaved();
            }, 'Saved')
          }
        >
          Save
        </button>
      </div>
    </Modal>
  );
}

function KnowledgeBase({ admin, onChange }: { admin: boolean; onChange: () => void }) {
  const [verdict, setVerdict] = useState('');
  const [q, setQ] = useState('');
  const [offset, setOffset] = useState(0);
  const limit = 25;
  const kb = useApi<{ entries: KBEntry[]; total: number }>(`/api/ai/kb?verdict=${verdict}&q=${encodeURIComponent(q)}&limit=${limit}&offset=${offset}`, 30_000);
  const { run, busy } = useAction();
  const mark = (e: KBEntry, v: 'clean' | 'malicious') => {
    const reason = prompt(`Mark ${e.name || e.sha256.slice(0, 12)} as ${v} on all servers. Reason (optional):`);
    if (reason === null) return;
    run(() => api('PUT', `/api/ai/kb/${e.sha256}`, { verdict: v, reason: reason || undefined }).then(() => (kb.reload(), onChange())), 'Saved; servers update within 10 minutes');
  };
  return (
    <Card title="Shared knowledge" desc="Every file the AI judged, on any server. Correct a verdict and all servers follow (and the fleet model learns from it).">
      <div className="mb-3 flex flex-wrap gap-2">
        {['', 'malicious', 'suspicious', 'clean'].map((v) => (
          <button
            key={v || 'all'}
            className={`rounded-full px-3 py-1 text-sm ${verdict === v ? 'bg-navy-800 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'}`}
            onClick={() => {
              setVerdict(v);
              setOffset(0);
            }}
          >
            {v || 'all'}
          </button>
        ))}
        <div className="relative ml-auto w-72">
          <Search className="absolute top-2.5 left-2 h-4 w-4 text-slate-400" />
          <input
            className="input !pl-8"
            placeholder="file name, reason, hash"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setOffset(0);
            }}
          />
        </div>
      </div>
      {kb.error && <ErrorBox message={kb.error} />}
      {!kb.data ? (
        <PageLoader />
      ) : kb.data.entries.length === 0 ? (
        <Empty text="Nothing yet. Verdicts appear here as servers send files to the AI." />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[980px] text-sm [&_td]:px-2 [&_td]:py-3 [&_th]:px-2 [&_th]:py-3 [&_th]:text-left [&_th]:font-medium [&_th]:text-slate-500 [&_thead_tr]:border-b [&_tbody_tr]:border-b [&_tbody_tr]:border-slate-100">
            <thead>
              <tr>
                <th>File</th>
                <th>Verdict</th>
                <th>Reason</th>
                <th>First seen on</th>
                <th className="text-right">Seen</th>
                <th>Updated</th>
                {admin && <th />}
              </tr>
            </thead>
            <tbody>
              {kb.data.entries.map((e) => (
                <tr key={e.sha256}>
                  <td className="max-w-[220px]">
                    <div className="truncate font-medium text-navy-900" title={e.name}>
                      {e.name || '—'}
                    </div>
                    <div className="truncate font-mono text-[11px] text-slate-400" title={e.sha256}>
                      {e.sha256.slice(0, 16)}… · {bytes(e.size)}
                    </div>
                  </td>
                  <td>
                    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${VERDICT[e.verdict] ?? ''}`}>
                      {e.verdict} {e.confidence}%
                    </span>
                    {e.injected && <div className="mt-1 text-xs text-blue-700">injected · {e.cut.length} cut(s)</div>}
                    {e.overridden && <div className="mt-1 text-xs text-slate-500">set by admin</div>}
                  </td>
                  <td className="max-w-[380px] text-sm text-slate-600">
                    {e.reason}
                    <div className="text-xs text-slate-400">
                      {e.match && <>engine: {e.match} · </>}
                      {e.model}
                    </div>
                  </td>
                  <td className="text-sm">{e.server ?? '—'}</td>
                  <td className="text-right tabular-nums">{e.hits}</td>
                  <td className="text-sm whitespace-nowrap text-slate-500">{ago(e.updated_at)}</td>
                  {admin && (
                    <td className="whitespace-nowrap">
                      {e.verdict !== 'clean' && (
                        <button className="btn-outline !px-2 !py-1 text-xs" disabled={busy} onClick={() => mark(e, 'clean')}>
                          <CheckCircle2 className="h-3.5 w-3.5" /> False positive
                        </button>
                      )}
                      {e.verdict !== 'malicious' && (
                        <button className="btn-outline !px-2 !py-1 text-xs" disabled={busy} onClick={() => mark(e, 'malicious')}>
                          <CircleAlert className="h-3.5 w-3.5" /> Malicious
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
          <Pager total={kb.data.total} limit={limit} offset={offset} onChange={setOffset} />
        </div>
      )}
    </Card>
  );
}
