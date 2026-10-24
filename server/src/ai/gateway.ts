import type { FastifyBaseLogger } from 'fastify';
import type { Pool } from '../db.js';
import { isPlatform, masterAccount } from '../tenancy.js';
import { distrustClean } from './learning.js';
import type { Config } from '../config.js';
import { complete, ProviderError, type ProviderRow } from './providers.js';
import { SYSTEM, maxTokens, parseAnswer, userMessage, type FileIn, type Judgement } from './prompt.js';

export interface Result {
  id: string;
  verdict?: string;
  confidence?: number;
  reason?: string;
  injected?: boolean;
  cut?: unknown[];
  model?: string;
  source?: 'ai' | 'fleet';
  error?: string;
}

interface Pending {
  file: FileIn;
  serverId: string;
  resolve: (r: Result) => void;
}

/** Characters of file excerpts per request (keeps requests inside free-tier token limits). */
const BATCH_CHARS = 60_000;
/**
 * The AI scanner gateway. Agents send files; the gateway answers from the
 * fleet's knowledge base when any server already had the same file judged,
 * otherwise batches files into as few AI API requests as possible and tries
 * the account's keys in priority order, resting a key that hit its limit,
 * failed or was rejected, and moving on to the next one (another key of the
 * same provider, then other providers).
 */
export class AIGateway {
  private queues = new Map<string, { items: Pending[]; chars: number; timer: NodeJS.Timeout | null }>();

  constructor(
    private pool: Pool,
    private cfg: Config,
    private log: FastifyBaseLogger,
  ) {}

  /**
   * Nothing runs in the background: there is no fleet model any more (the
   * agents have no offline model since 0.23.8; the AI only comments and an
   * administrator decides).
   */
  start(): void {}

  stop(): void {
    for (const q of this.queues.values()) if (q.timer) clearTimeout(q.timer);
  }

  // ------------------------------------------------------------------ judging

  async judge(accountId: string, serverId: string, files: FileIn[]): Promise<Result[]> {
    const shas = files.map((f) => f.sha256.toLowerCase());
    const fleet = await isPlatform(this.pool, accountId);
    const { rows } = await this.pool.query(
      `UPDATE ai_kb SET hits = hits + 1 WHERE sha256 = ANY($1)
       RETURNING sha256, verdict, confidence, reason, injected, cut, model`,
      [shas],
    );
    const known = new Map(rows.map((r) => [r.sha256, r]));
    if (!fleet && known.size < shas.length) {
      // The account's own earlier verdicts (customer servers never write the fleet's).
      const own = await this.pool.query(
        'SELECT sha256, verdict, confidence, reason, injected, cut, model FROM ai_kb_account WHERE account_id = $1 AND sha256 = ANY($2)',
        [accountId, shas.filter((s) => !known.has(s))],
      );
      for (const r of own.rows) known.set(r.sha256, r);
    }
    const out: Promise<Result>[] = [];
    for (const f of files) {
      const k = known.get(f.sha256.toLowerCase());
      if (k) {
        // Another server already had this exact file judged: no tokens spent.
        out.push(
          Promise.resolve({ id: f.id, verdict: k.verdict, confidence: k.confidence, reason: k.reason, injected: k.injected, cut: k.cut, model: k.model, source: 'fleet' }),
        );
        continue;
      }
      out.push(new Promise<Result>((resolve) => this.enqueue(accountId, { file: f, serverId, resolve })));
    }
    return Promise.all(out);
  }

  private enqueue(accountId: string, p: Pending): void {
    let q = this.queues.get(accountId);
    if (!q) {
      q = { items: [], chars: 0, timer: null };
      this.queues.set(accountId, q);
    }
    q.items.push(p);
    q.chars += p.file.excerpt.length;
    if (q.items.length >= this.cfg.aiBatchFiles || q.chars >= BATCH_CHARS) {
      this.flush(accountId);
    } else if (!q.timer) {
      q.timer = setTimeout(() => this.flush(accountId), this.cfg.aiBatchWaitMs);
    }
  }

  private flush(accountId: string): void {
    const q = this.queues.get(accountId);
    if (!q || q.items.length === 0) return;
    if (q.timer) clearTimeout(q.timer);
    this.queues.delete(accountId);
    // Split oversize batches by characters.
    let batch: Pending[] = [];
    let chars = 0;
    for (const it of q.items) {
      if (batch.length && (chars + it.file.excerpt.length > BATCH_CHARS || batch.length >= this.cfg.aiBatchFiles)) {
        this.launch(accountId, batch);
        batch = [];
        chars = 0;
      }
      batch.push(it);
      chars += it.file.excerpt.length;
    }
    if (batch.length) this.launch(accountId, batch);
  }

  /**
   * Runs a batch from a timer. Nothing may escape as an unhandled
   * rejection (Node ends the process on one, taking the whole portal down):
   * a failure answers every file of the batch that is still waiting.
   */
  private launch(accountId: string, batch: Pending[]): void {
    this.run(accountId, batch).catch((err) => {
      this.log.error({ err: (err as Error).message }, 'AI batch failed');
      for (const p of batch) p.resolve({ id: p.file.id, error: 'the portal could not judge this file; it is tried again later' });
    });
  }

  private async run(accountId: string, batch: Pending[], attempt = 0): Promise<void> {
    // Batch ids are positions, so agents' ids never collide across servers.
    const files = batch.map((p, i) => ({ ...p.file, id: String(i + 1) }));
    let answers: Map<string, Judgement>;
    let model = '';
    try {
      const r = await this.ask(accountId, SYSTEM, userMessage(files), maxTokens(files.length), files.length);
      answers = parseAnswer(r.text, files.map((f) => f.id));
      model = r.model;
    } catch (err) {
      const e = err as Error & { badRequest?: boolean };
      if (e.badRequest && batch.length > 1) {
        // Too big for the models: judge the files one by one.
        await Promise.all(batch.map((p) => this.run(accountId, [p], attempt + 1)));
        return;
      }
      for (const p of batch) p.resolve({ id: p.file.id, error: e.message });
      return;
    }
    const missing: Pending[] = [];
    for (let i = 0; i < batch.length; i++) {
      const p = batch[i];
      const a = answers.get(String(i + 1));
      if (!a) {
        missing.push(p);
        continue;
      }
      if (a.verdict === 'clean') {
        const why = await distrustClean(this.pool, p.file);
        if (why) {
          a.verdict = 'suspicious';
          a.reason = `Not restored: the AI found it clean, but ${why}; an administrator decides. AI: ${a.reason}`.slice(0, 600);
          a.confidence = Math.min(a.confidence, 60);
        }
      }
      await this.store(accountId, p, a, model);
      p.resolve({ id: p.file.id, verdict: a.verdict, confidence: a.confidence, reason: a.reason, injected: a.injected, cut: a.cut, model, source: 'ai' });
    }
    if (missing.length) {
      if (attempt < 1 && batch.length > 1) {
        await Promise.all(missing.map((p) => this.run(accountId, [p], attempt + 1)));
      } else {
        for (const p of missing) p.resolve({ id: p.file.id, error: 'the AI gave no usable answer for this file' });
      }
    }
  }

  /** Calls the account's AI keys in order until one answers. */
  async ask(accountId: string, system: string, user: string, tokens: number, files = 1): Promise<{ text: string; model: string }> {
    // Customers' servers use the platform's AI keys.
    accountId = await masterAccount(this.pool, accountId);
    const { rows } = await this.pool.query<ProviderRow & { cooldown_until: Date | null; priority: number }>(
      `SELECT id, kind, name, base_url, api_key, model, priority, cooldown_until FROM ai_providers
       WHERE account_id = $1 AND enabled ORDER BY priority, (CASE WHEN day = current_date THEN requests_today ELSE 0 END), created_at`,
      [accountId],
    );
    if (rows.length === 0) throw Object.assign(new Error('no AI API keys are configured on the portal (AI Settings)'), { noKeys: true });
    const now = Date.now();
    const ready = rows.filter((r) => !r.cooldown_until || r.cooldown_until.getTime() <= now);
    if (ready.length === 0) {
      const next = Math.min(...rows.map((r) => r.cooldown_until!.getTime()));
      throw new Error(`all AI API keys are resting after hitting limits; next one is available at ${new Date(next).toISOString()}`);
    }
    const errors: string[] = [];
    let allBadRequest = true;
    for (const p of ready) {
      try {
        const r = await complete(p, system, user, tokens, this.cfg.aiTimeoutSeconds * 1000);
        await this.pool.query(
          `UPDATE ai_providers SET requests = requests + 1, files = files + $2, tokens_in = tokens_in + $3, tokens_out = tokens_out + $4,
             requests_today = CASE WHEN day = current_date THEN requests_today + 1 ELSE 1 END, day = current_date,
             last_ok_at = now(), last_error = '', cooldown_until = NULL WHERE id = $1`,
          [p.id, files, r.tokensIn, r.tokensOut],
        );
        return { text: r.text, model: `${p.kind}/${p.model}` };
      } catch (err) {
        const e = err instanceof ProviderError ? err : new ProviderError((err as Error).message, 60_000);
        if (!e.badRequest) allBadRequest = false;
        errors.push(`${p.name || p.kind}: ${e.message}`);
        this.log.warn({ provider: p.name || p.kind, err: e.message }, 'AI provider failed; trying the next one');
        await this.pool.query(
          `UPDATE ai_providers SET failures = failures + 1, last_error = $2, last_error_at = now(),
             requests_today = CASE WHEN day = current_date THEN requests_today + 1 ELSE 1 END, day = current_date,
             cooldown_until = CASE WHEN $3::int > 0 THEN now() + ($3::int * interval '1 millisecond') ELSE cooldown_until END
           WHERE id = $1`,
          [p.id, e.message.slice(0, 500), Math.round(e.cooldownMs)],
        );
      }
    }
    throw Object.assign(new Error('all AI API keys failed: ' + errors.join('; ').slice(0, 600)), { badRequest: allBadRequest });
  }

  /**
   * Keeps a verdict. Only the platform's own servers write the fleet
   * knowledge base (and the training samples) that every server receives:
   * the portal cannot check that an agent's excerpt belongs to the hash it
   * names, so a customer's server could otherwise mark any file clean on
   * every other account's servers. Customers' verdicts serve their account.
   */
  private async store(accountId: string, p: Pending, a: Judgement, model: string): Promise<void> {
    const f = p.file;
    if (!(await isPlatform(this.pool, accountId))) {
      await this.pool.query(
        `INSERT INTO ai_kb_account (account_id, sha256, verdict, confidence, reason, injected, cut, model)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (account_id, sha256) DO UPDATE SET verdict = excluded.verdict, confidence = excluded.confidence,
           reason = excluded.reason, injected = excluded.injected, cut = excluded.cut, model = excluded.model, updated_at = now()`,
        [accountId, f.sha256.toLowerCase(), a.verdict, a.confidence, a.reason, a.injected, JSON.stringify(a.cut), model],
      );
      return;
    }
    await this.pool.query(
      `INSERT INTO ai_kb (sha256, size, verdict, confidence, reason, injected, cut, model, name, match, server_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT (sha256) DO UPDATE SET verdict = excluded.verdict, confidence = excluded.confidence, reason = excluded.reason,
         injected = excluded.injected, cut = excluded.cut, model = excluded.model, updated_at = now(),
         seq = nextval(pg_get_serial_sequence('ai_kb', 'seq'))
       WHERE NOT ai_kb.overridden`,
      [f.sha256.toLowerCase(), f.size, a.verdict, a.confidence, a.reason, a.injected, JSON.stringify(a.cut), model, f.name.slice(0, 200), (f.match ?? '').slice(0, 200), p.serverId],
    );
  }

  /**
   * What an agent downloads: new verdicts since its cursor. delta is always
   * null (agents before 0.23.8 asked for a fleet model update; there is none).
   */
  async sync(_base: string, cursor: number, _modelVersion: number) {
    const limit = 2000;
    const { rows } = await this.pool.query(
      `SELECT seq, sha256, size, verdict, confidence, reason, model, injected FROM ai_kb WHERE seq > $1 ORDER BY seq LIMIT $2`,
      [cursor, limit],
    );
    return {
      kb: rows.map(({ seq: _s, size, ...r }) => ({ ...r, size: Number(size) })),
      cursor: rows.length ? Number(rows[rows.length - 1].seq) : cursor,
      more: rows.length === limit,
      delta: null,
    };
  }
}
