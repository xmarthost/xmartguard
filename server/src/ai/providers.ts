/**
 * AI API providers the AI scanner can use. All of them speak the OpenAI
 * "chat completions" format, so one client covers them; the presets only
 * fill in the address, a sensible default model and where to get a key.
 */

export interface Preset {
  kind: string;
  label: string;
  baseUrl: string;
  model: string;
  keyUrl: string;
  free: string;
  /** Extra request fields that lower cost (e.g. less "thinking"). */
  extra?: Record<string, unknown>;
  /** Model list endpoint when it is not <baseUrl>/models. */
  modelsUrl?: string;
}

export const PRESETS: Preset[] = [
  {
    kind: 'gemini',
    label: 'Google Gemini',
    baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai',
    model: 'gemini-flash-latest',
    keyUrl: 'https://aistudio.google.com/app/apikey',
    free: 'Free tier, no card: about 10–15 requests/minute and a daily cap per model (Flash-Lite allows the most).',
    extra: { reasoning_effort: 'low' },
  },
  {
    kind: 'groq',
    label: 'Groq',
    baseUrl: 'https://api.groq.com/openai/v1',
    model: 'openai/gpt-oss-120b',
    keyUrl: 'https://console.groq.com/keys',
    free: 'Free tier, no card: about 30 requests/minute and 1,000 requests/day per model. Very fast.',
    extra: { reasoning_effort: 'low' },
  },
  {
    kind: 'openrouter',
    label: 'OpenRouter',
    baseUrl: 'https://openrouter.ai/api/v1',
    model: 'openai/gpt-oss-120b:free',
    keyUrl: 'https://openrouter.ai/keys',
    free: 'Models ending in ":free" cost nothing: about 20 requests/minute and 50 requests/day (1,000/day after a one-time $10 top-up).',
  },
  {
    kind: 'cerebras',
    label: 'Cerebras',
    baseUrl: 'https://api.cerebras.ai/v1',
    model: 'gpt-oss-120b',
    keyUrl: 'https://cloud.cerebras.ai',
    free: 'Free/trial tier with a daily token allowance. Very fast.',
  },
  {
    kind: 'mistral',
    label: 'Mistral AI',
    baseUrl: 'https://api.mistral.ai/v1',
    model: 'mistral-small-latest',
    keyUrl: 'https://console.mistral.ai/api-keys',
    free: 'Free "Experiment" plan (phone verification), low rate limits.',
  },
  {
    kind: 'github',
    label: 'GitHub Models',
    baseUrl: 'https://models.github.ai/inference',
    model: 'openai/gpt-4.1-mini',
    keyUrl: 'https://github.com/settings/tokens',
    free: 'Free with any GitHub account (a token with the "models" permission); small daily limits.',
    modelsUrl: 'https://models.github.ai/catalog/models',
  },
  {
    kind: 'nvidia',
    label: 'NVIDIA NIM',
    baseUrl: 'https://integrate.api.nvidia.com/v1',
    model: 'openai/gpt-oss-120b',
    keyUrl: 'https://build.nvidia.com',
    free: 'Free developer access (about 40 requests/minute).',
  },
  {
    kind: 'huggingface',
    label: 'Hugging Face',
    baseUrl: 'https://router.huggingface.co/v1',
    model: 'openai/gpt-oss-120b',
    keyUrl: 'https://huggingface.co/settings/tokens',
    free: 'Small monthly free credit.',
  },
  {
    kind: 'cloudflare',
    label: 'Cloudflare Workers AI',
    baseUrl: 'https://api.cloudflare.com/client/v4/accounts/ACCOUNT_ID/ai/v1',
    model: '@cf/openai/gpt-oss-120b',
    keyUrl: 'https://dash.cloudflare.com/profile/api-tokens',
    free: '10,000 free "neurons" per day. Put your Cloudflare account ID in the address.',
  },
  {
    kind: 'custom',
    label: 'Other (OpenAI-compatible)',
    baseUrl: 'https://',
    model: '',
    keyUrl: '',
    free: 'Any service with an OpenAI-compatible /chat/completions endpoint.',
  },
];

export function preset(kind: string): Preset | undefined {
  return PRESETS.find((p) => p.kind === kind);
}

export interface ProviderRow {
  id: string;
  kind: string;
  name: string;
  base_url: string;
  api_key: string;
  model: string;
}

export class ProviderError extends Error {
  constructor(
    message: string,
    /** How long to rest this key (0 = try it again for the next request). */
    public cooldownMs: number,
    /** The request itself was the problem (too big, format): other keys may still work. */
    public badRequest = false,
  ) {
    super(message);
  }
}

export interface Completion {
  text: string;
  tokensIn: number;
  tokensOut: number;
}

const MINUTE = 60_000;

/** How long to rest a key after a failed call. */
export function cooldownFor(status: number, body: string, retryAfter: string | null): number {
  const ra = Number(retryAfter);
  if (Number.isFinite(ra) && ra > 0) return Math.min(ra * 1000, 24 * 60 * MINUTE);
  if (status === 401 || status === 403) return 12 * 60 * MINUTE; // wrong or revoked key
  if (status === 402) return 6 * 60 * MINUTE; // credits exhausted
  if (status === 429) return /day|daily|quota|per.?d\b|RPD|exhausted/i.test(body) ? 60 * MINUTE : 2 * MINUTE;
  if (status >= 500 || status === 0) return 2 * MINUTE;
  return 0;
}

function authHeaders(p: ProviderRow): Record<string, string> {
  const h: Record<string, string> = { 'content-type': 'application/json' };
  if (p.api_key) h.authorization = `Bearer ${p.api_key}`;
  if (p.kind === 'openrouter') {
    h['http-referer'] = 'https://xmartguard.com';
    h['x-title'] = 'XMart Guard';
  }
  return h;
}

/** One chat completion that must return a JSON object. */
export async function complete(p: ProviderRow, system: string, user: string, maxTokens: number, timeoutMs: number): Promise<Completion> {
  const base: Record<string, unknown> = {
    model: p.model,
    temperature: 0,
    max_tokens: maxTokens,
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: user },
    ],
  };
  const tries = [
    { ...base, ...preset(p.kind)?.extra, response_format: { type: 'json_object' } },
    base, // some models reject response_format or reasoning options
  ];
  let last: ProviderError | null = null;
  for (const body of tries) {
    let res: Response;
    try {
      res = await fetch(p.base_url.replace(/\/+$/, '') + '/chat/completions', {
        method: 'POST',
        headers: authHeaders(p),
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      throw new ProviderError(`unreachable: ${(err as Error).message}`, 2 * MINUTE);
    }
    const text = await res.text();
    if (!res.ok) {
      const msg = errorText(text) || `HTTP ${res.status}`;
      if (res.status === 400 && body !== base) {
        last = new ProviderError(msg, 0, true);
        continue;
      }
      throw new ProviderError(`HTTP ${res.status}: ${msg}`, cooldownFor(res.status, text, res.headers.get('retry-after')), res.status === 400 || res.status === 413);
    }
    let data: any;
    try {
      data = JSON.parse(text);
    } catch {
      throw new ProviderError('the answer was not JSON', MINUTE);
    }
    const content = data?.choices?.[0]?.message?.content;
    if (typeof content !== 'string' || !content.trim()) {
      const reason = data?.choices?.[0]?.finish_reason ?? 'empty';
      throw new ProviderError(`no answer (${reason})`, 0, reason === 'length' || reason === 'content_filter');
    }
    return { text: content, tokensIn: Number(data?.usage?.prompt_tokens) || 0, tokensOut: Number(data?.usage?.completion_tokens) || 0 };
  }
  throw last ?? new ProviderError('request rejected', 0, true);
}

function errorText(body: string): string {
  try {
    const j = JSON.parse(body);
    const e = Array.isArray(j) ? j[0]?.error : j?.error;
    return String(e?.message ?? e ?? j?.message ?? '').slice(0, 300);
  } catch {
    return body.slice(0, 200);
  }
}

export interface ModelInfo {
  id: string;
  name: string;
  free: boolean;
  context: number;
}

/** Lists the models a key can use (for the model picker). */
export async function listModels(p: Omit<ProviderRow, 'id' | 'name'>): Promise<ModelInfo[]> {
  const pre = preset(p.kind);
  const url = pre?.modelsUrl ?? p.base_url.replace(/\/+$/, '') + '/models';
  const res = await fetch(url, { headers: authHeaders({ ...p, id: '', name: '' }), signal: AbortSignal.timeout(20_000) });
  const text = await res.text();
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${errorText(text) || 'model list unavailable'}`);
  const data = JSON.parse(text);
  const list: any[] = Array.isArray(data) ? data : (data?.data ?? data?.models ?? []);
  const out: ModelInfo[] = [];
  for (const m of list) {
    let id = String(m?.id ?? m?.name ?? '');
    if (!id) continue;
    if (p.kind === 'gemini') {
      id = id.replace(/^models\//, '');
      if (!/gemini|gemma/i.test(id) || /embedding|imagen|veo|tts|image|audio|live/i.test(id)) continue;
    }
    if (/embed|whisper|tts|guard|moderation|rerank|dall-e|image/i.test(id) && p.kind !== 'gemini') continue;
    const price = m?.pricing;
    const free =
      p.kind === 'openrouter'
        ? id.endsWith(':free') || (price && Number(price.prompt) === 0 && Number(price.completion) === 0)
        : p.kind !== 'custom';
    out.push({
      id,
      name: String(m?.name ?? m?.display_name ?? id),
      free: Boolean(free),
      context: Number(m?.context_length ?? m?.context_window ?? m?.inputTokenLimit ?? m?.limits?.max_input_tokens ?? 0) || 0,
    });
  }
  out.sort((a, b) => Number(b.free) - Number(a.free) || a.id.localeCompare(b.id));
  return out;
}
