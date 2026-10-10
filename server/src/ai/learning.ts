import crypto from 'node:crypto';
import type { Pool } from '../db.js';
import type { AgentHub } from '../agents/hub.js';
import type { Result } from './gateway.js';

/**
 * AI Learning: the scanner's false positives. When a file a signature
 * flagged is judged clean by the AI, the portal keeps what is needed to fix
 * the signature (where, which signature, the code it matched, why the AI
 * restored it), and a signature that keeps flagging clean files is moved
 * to "review": on every server its matches wait for the AI instead of being
 * quarantined and restored over and over.
 */

/** How sure the AI must be that a file is clean to count it (the agent restores at 90). */
export const FP_MIN_CONFIDENCE = 90;
/** Different clean files before a signature is moved to review automatically. */
export const AUTO_REVIEW_FILES = 5;

/** Detections no signature decision applies to (the AI's own, a file name the admin blacklisted). */
export function overridable(sig: string): boolean {
  return !!sig && !/^XG\.AI\./.test(sig) && !/^XG-BLACKLIST\./.test(sig) && !/EICAR/i.test(sig);
}

export interface FlaggedFile {
  sha256: string;
  size: number;
  name: string;
  match?: string;
  path?: string;
  line?: number;
  snippet?: string;
}

/** Signatures of malware families where a wrong "clean" is costly. */
const RISKY_SIG = /backdoor|dropper|webshell|web_shell|uploader|ai\.learned|globalsdispatch/i;
/** Where real plugins and themes never put code: PHP or archives here are droppers. */
const RISKY_PATH = /(?:^|\/)wp-content\/(?:mu-plugins\/[^/]+\.php$|uploads\/.*\.(?:php\d?|phtml|phar|pht|inc|zip)$)/i;
/** A family with this many malicious verdicts, and four times more than clean ones, is not cleared by one "clean". */
export const FAMILY_MIN_MALICIOUS = 20;

/**
 * Guard against the AI clearing real malware. A "clean" verdict does not
 * restore a file (and is kept as "suspicious" for an administrator) when the
 * file sits where only malware puts code (mu-plugins, PHP or archives in
 * uploads) under a backdoor-type signature, or when the signature's family
 * is overwhelmingly malicious across the fleet. Returns the reason, or "".
 */
export async function distrustClean(pool: Pool, f: { match?: string; path?: string; name: string }): Promise<string> {
  const sig = (f.match ?? '').trim();
  if (!sig) return '';
  const where = f.path || f.name;
  if (RISKY_SIG.test(sig) && RISKY_PATH.test(where)) {
    return 'a backdoor-type signature in a folder where plugins never keep code';
  }
  if (!RISKY_SIG.test(sig)) return '';
  const { rows } = await pool.query(
    `SELECT count(*) FILTER (WHERE verdict = 'malicious')::int AS mal, count(*) FILTER (WHERE verdict = 'clean')::int AS clean
       FROM ai_kb WHERE match = $1`,
    [sig],
  );
  const { mal, clean } = rows[0];
  if (mal >= FAMILY_MIN_MALICIOUS && clean * 4 <= mal) {
    return `the fleet found ${mal} files of this signature malicious`;
  }
  return '';
}

/** Keeps the false positives from one judge request; returns the signatures it moved to review. */
export async function recordFalsePositives(pool: Pool, serverId: string, files: (FlaggedFile & { id: string })[], results: Result[]): Promise<string[]> {
  const byId = new Map(results.map((r) => [r.id, r]));
  const sigs = new Set<string>();
  for (const f of files) {
    const r = byId.get(f.id);
    const sig = (f.match ?? '').trim().slice(0, 200);
    if (!sig || !r || r.verdict !== 'clean' || (r.confidence ?? 0) < FP_MIN_CONFIDENCE) continue;
    await pool.query(
      `INSERT INTO ai_fp (sha256, server_id, signature, path, name, size, line, snippet, reason, confidence, model, source)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       ON CONFLICT (sha256, coalesce(server_id, '00000000-0000-0000-0000-000000000000'::uuid), path) DO UPDATE SET
         count = ai_fp.count + 1, last_at = now(), signature = excluded.signature, reason = excluded.reason,
         confidence = excluded.confidence, model = excluded.model, source = excluded.source,
         line = CASE WHEN excluded.snippet <> '' THEN excluded.line ELSE ai_fp.line END,
         snippet = CASE WHEN excluded.snippet <> '' THEN excluded.snippet ELSE ai_fp.snippet END`,
      [
        f.sha256.toLowerCase(),
        serverId,
        sig,
        (f.path ?? '').slice(0, 500),
        f.name.slice(0, 200),
        f.size,
        Math.max(0, Math.min(f.line ?? 0, 10_000_000)),
        (f.snippet ?? '').slice(0, 2000),
        (r.reason ?? '').slice(0, 1000),
        r.confidence ?? 0,
        (r.model ?? '').slice(0, 120),
        r.source === 'fleet' ? 'fleet' : 'ai',
      ],
    );
    sigs.add(sig);
  }
  const moved: string[] = [];
  for (const sig of sigs) if (await autoReview(pool, sig)) moved.push(sig);
  return moved;
}

/**
 * Moves a signature to review once it flagged enough different clean files
 * and never a file the AI found malicious. Never touches a signature an
 * administrator already decided on.
 */
export async function autoReview(pool: Pool, sig: string): Promise<boolean> {
  if (!overridable(sig)) return false;
  const { rows } = await pool.query(
    `SELECT (SELECT count(DISTINCT sha256)::int FROM ai_fp WHERE signature = $1 AND confidence >= $2) AS clean,
            (SELECT count(*)::int FROM ai_kb WHERE match = $1 AND verdict = 'malicious') AS malicious,
            (SELECT count(*)::int FROM sig_overrides WHERE signature = $1) AS decided`,
    [sig, FP_MIN_CONFIDENCE],
  );
  const s = rows[0];
  if (s.decided || s.malicious > 0 || s.clean < AUTO_REVIEW_FILES) return false;
  const { rowCount } = await pool.query(
    `INSERT INTO sig_overrides (signature, action, note, auto, created_by)
     VALUES ($1, 'review', $2, true, 'AI Learning') ON CONFLICT DO NOTHING`,
    [sig, `Flagged ${s.clean} different files the AI found clean and none it found malicious.`],
  );
  return !!rowCount;
}

/** What agents apply: signature -> 'review' | 'off' ('keep' changes nothing on a server). */
export async function overridesBundle(pool: Pool): Promise<{ etag: string; overrides: Record<string, string> }> {
  const { rows } = await pool.query("SELECT signature, action FROM sig_overrides WHERE action <> 'keep' ORDER BY signature");
  const overrides: Record<string, string> = {};
  for (const r of rows) overrides[r.signature] = r.action;
  const etag = crypto.createHash('sha256').update(JSON.stringify(overrides)).digest('hex').slice(0, 16);
  return { etag, overrides };
}

/** Sends the current signature decisions to every connected server. */
export async function pushOverrides(pool: Pool, hub: AgentHub): Promise<number> {
  const b = await overridesBundle(pool);
  let n = 0;
  for (const c of hub.connections()) {
    n++;
    void hub.command(c.serverId, 'scanner.overrides', b, 30_000).catch(() => undefined);
  }
  return n;
}
