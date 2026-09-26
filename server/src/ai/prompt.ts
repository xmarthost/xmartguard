/**
 * What the AI APIs are asked, kept short on purpose: the instructions are
 * sent once per request (not once per file) and come first, so providers
 * that cache repeated prompt prefixes (Gemini, Groq, OpenRouter) can reuse
 * them; the answer is a compact JSON object.
 */

export interface FileIn {
  id: string;
  sha256: string;
  size: number;
  name: string;
  match?: string;
  excerpt: string;
  lines: number;
  truncated: boolean;
  base?: string;
  z?: number;
  features?: number[];
}

export interface Cut {
  from: number;
  to: number;
  text?: string;
}

export interface Judgement {
  id: string;
  verdict: 'malicious' | 'suspicious' | 'clean';
  confidence: number;
  reason: string;
  injected: boolean;
  cut: Cut[];
}

export const SYSTEM = `You are the malware analyst of a web hosting security product. You get files from customers' websites
(PHP, JavaScript, HTML, .htaccess, scripts). Each line starts with its line number and "|". "… N lines …"
marks parts left out; "…[N chars]" marks a shortened long string.

For each file decide what the code DOES:
- malicious: web shells, backdoors, eval/assert of decoded or request data, remote code download+run,
  hidden admin users, credential/card skimmers, SEO spam or redirect injection, spam mailers,
  cryptominers, defacements, droppers.
- suspicious: risky but could be legitimate (unclear obfuscation, file managers, raw uploads).
- clean: ordinary application, plugin, theme or library code. Minified or encoded code is often legitimate.
A signature "match" from the local engine is a hint, not proof.

If malicious code was ADDED to an otherwise legitimate file (e.g. a backdoor on line 1 of a real
plugin file), set "injected": true and list in "cut" exactly the lines to delete as {"from":N,"to":M}.
If the bad code shares a line with legitimate code (including the file's own "<?php" tag), use
{"from":N,"to":N,"text":"<exact bad code>"} so the legitimate part stays.
If the whole file is malicious, "injected": false and "cut": [].

Reply with JSON only:
{"results":[{"id":"<id>","verdict":"malicious|suspicious|clean","confidence":0-100,"reason":"<=25 words naming the behaviour","injected":false,"cut":[]}]}`;

export function userMessage(files: FileIn[]): string {
  return files
    .map((f) => {
      const head = [`id=${f.id}`, `name=${f.name}`, `lines=${f.lines}`];
      if (f.match) head.push(`match=${f.match}`);
      if (f.truncated) head.push('excerpt');
      return `<file ${head.join(' ')}>\n${f.excerpt.trimEnd()}\n</file>`;
    })
    .join('\n');
}

/** Output tokens to allow: a short JSON entry per file, more when cuts are listed. */
export function maxTokens(n: number): number {
  return 400 + 220 * n;
}

/** Parses the model's answer; tolerates code fences and surrounding text. */
export function parseAnswer(text: string, ids: string[]): Map<string, Judgement> {
  const out = new Map<string, Judgement>();
  let data: any = null;
  const cleaned = text.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');
  try {
    data = JSON.parse(cleaned);
  } catch {
    const a = cleaned.indexOf('{');
    const b = cleaned.lastIndexOf('}');
    if (a >= 0 && b > a) {
      try {
        data = JSON.parse(cleaned.slice(a, b + 1));
      } catch {
        data = null;
      }
    }
  }
  if (!data) return out;
  let list: any[] = Array.isArray(data) ? data : Array.isArray(data.results) ? data.results : [data];
  // A single-file answer without an id belongs to that file.
  if (ids.length === 1 && list.length === 1 && !list[0]?.id) list = [{ ...list[0], id: ids[0] }];
  for (const r of list) {
    const id = String(r?.id ?? '');
    const verdict = String(r?.verdict ?? '').toLowerCase();
    if (!ids.includes(id) || !['malicious', 'suspicious', 'clean'].includes(verdict)) continue;
    const cut: Cut[] = [];
    if (Array.isArray(r.cut)) {
      for (const c of r.cut.slice(0, 50)) {
        const from = Math.trunc(Number(c?.from));
        const to = Math.trunc(Number(c?.to ?? c?.from));
        if (!(from >= 1 && to >= from)) continue;
        const t = typeof c?.text === 'string' && c.text && from === to ? c.text.slice(0, 2000) : undefined;
        cut.push(t ? { from, to, text: t } : { from, to });
      }
    }
    const injected = verdict === 'malicious' && Boolean(r.injected) && cut.length > 0;
    out.set(id, {
      id,
      verdict: verdict as Judgement['verdict'],
      confidence: Math.max(0, Math.min(100, Math.round(Number(r.confidence) || 0))),
      reason: String(r.reason ?? '').slice(0, 600),
      injected,
      cut: injected ? cut : [],
    });
  }
  return out;
}
