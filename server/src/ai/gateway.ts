import type { FastifyBaseLogger } from 'fastify';
import type { Pool } from '../db.js';
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
/** Samples the fleet model learns from: AI verdicts at least this confident. */
const TRAIN_MIN_CONFIDENCE = 80;
/**
 * Examples of each class needed before training: learning from malicious
 * files alone would push up features every PHP file has and cause false
 * positives, so clean verdicts must balance them.
 */
export const TRAIN_MIN_PER_CLASS = 5;
const BUCKETS = 1 << 17;

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
  private dirty = new Set<string>();
  private trainTimer: NodeJS.Timeout | null = null;
  private training = false;

  constructor(
    private pool: Pool,
    private cfg: Config,
    private log: FastifyBaseLogger,
  ) {}

  start(): void {
    if (!this.cfg.aiTraining) return;
    this.trainTimer = setInterval(() => void this.trainDirty(), 5 * 60_000);
    this.trainTimer.unref();
  }

  stop(): void {
    if (this.trainTimer) clearInterval(this.trainTimer);
    for (const q of this.queues.values()) if (q.timer) clearTimeout(q.timer);
  }

  // ------------------------------------------------------------------ judging

  async judge(accountId: string, serverId: string, files: FileIn[]): Promise<Result[]> {
    const shas = files.map((f) => f.sha256.toLowerCase());
    const { rows } = await this.pool.query(
      `UPDATE ai_kb SET hits = hits + 1 WHERE sha256 = ANY($1)
       RETURNING sha256, verdict, confidence, reason, injected, cut, model`,
      [shas],
    );
    const known = new Map(rows.map((r) => [r.sha256, r]));
    const out: Promise<Result>[] = [];
    for (const f of files) {
      const k = known.get(f.sha256.toLowerCase());
      if (k) {
        // Another server already had this exact file judged: no tokens spent.
        await this.saveSample(f, k.verdict, k.confidence);
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
        void this.run(accountId, batch);
        batch = [];
        chars = 0;
      }
      batch.push(it);
      chars += it.file.excerpt.length;
    }
    if (batch.length) void this.run(accountId, batch);
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
      await this.store(p, a, model);
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

  private async store(p: Pending, a: Judgement, model: string): Promise<void> {
    const f = p.file;
    await this.pool.query(
      `INSERT INTO ai_kb (sha256, size, verdict, confidence, reason, injected, cut, model, name, match, server_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT (sha256) DO UPDATE SET verdict = excluded.verdict, confidence = excluded.confidence, reason = excluded.reason,
         injected = excluded.injected, cut = excluded.cut, model = excluded.model, updated_at = now(),
         seq = nextval(pg_get_serial_sequence('ai_kb', 'seq'))
       WHERE NOT ai_kb.overridden`,
      [f.sha256.toLowerCase(), f.size, a.verdict, a.confidence, a.reason, a.injected, JSON.stringify(a.cut), model, f.name.slice(0, 200), (f.match ?? '').slice(0, 200), p.serverId],
    );
    await this.saveSample(f, a.verdict, a.confidence);
  }

  private async saveSample(f: FileIn, verdict: string, confidence: number): Promise<void> {
    if (!f.base || !f.features?.length || typeof f.z !== 'number' || verdict === 'suspicious' || confidence < TRAIN_MIN_CONFIDENCE) return;
    const features = f.features.filter((x) => Number.isInteger(x) && x >= 0 && x < BUCKETS).slice(0, 20_000);
    const { rowCount } = await this.pool.query(
      `INSERT INTO ai_samples (sha256, base_version, z, features, label) VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (sha256, base_version) DO NOTHING`,
      [f.sha256.toLowerCase(), f.base.slice(0, 80), f.z, features, verdict === 'malicious' ? 1 : 0],
    );
    if (rowCount) this.dirty.add(f.base);
  }

  // ------------------------------------------------------------------ fleet model

  private async trainDirty(): Promise<void> {
    if (this.training) return;
    const bases = [...this.dirty];
    this.dirty.clear();
    for (const b of bases) {
      try {
        await this.train(b);
      } catch (err) {
        this.log.warn({ err: (err as Error).message }, 'AI fleet model training failed');
      }
    }
  }

  /**
   * Trains the update every agent adds to its built-in model: logistic
   * regression on top of the base model's logit (z), from the verdicts the
   * AI APIs gave on all servers. It only adjusts what the base model got
   * wrong or was unsure about; weights are kept small (L2 + clamp) so one
   * mistaken verdict cannot swing the model.
   */
  async train(base: string, minPerClass = TRAIN_MIN_PER_CLASS): Promise<{ version: number; samples: number; accuracy: number } | { waiting: string } | null> {
    this.training = true;
    try {
      const { rows } = await this.pool.query<{ z: number; features: number[]; label: number; weight: number }>(
        `SELECT s.z, s.features, CASE WHEN k.overridden THEN (k.verdict = 'malicious')::int ELSE s.label END AS label, s.weight
         FROM ai_samples s LEFT JOIN ai_kb k ON k.sha256 = s.sha256
         WHERE s.base_version = $1 AND (k.verdict IS NULL OR k.verdict <> 'suspicious')
         ORDER BY s.created_at DESC LIMIT 50000`,
        [base],
      );
      const pos = rows.filter((r) => r.label === 1).length;
      const neg = rows.length - pos;
      if (pos < minPerClass || neg < minPerClass) {
        return { waiting: `collecting examples: ${pos} malicious and ${neg} clean (needs ${minPerClass} of each)` };
      }
      const wPos = pos ? Math.min(5, Math.max(0.2, rows.length / (2 * pos))) : 1;
      const wNeg = neg ? Math.min(5, Math.max(0.2, rows.length / (2 * neg))) : 1;
      const delta = new Float32Array(BUCKETS);
      let bias = 0;
      const epochs = 40;
      for (let ep = 0; ep < epochs; ep++) {
        const lr = 0.5 / (1 + ep * 0.1);
        for (let i = rows.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          [rows[i], rows[j]] = [rows[j], rows[i]];
        }
        for (const r of rows) {
          let z = r.z + bias;
          for (const f of r.features) z += delta[f];
          const p = 1 / (1 + Math.exp(-Math.max(-30, Math.min(30, z))));
          const g = (p - r.label) * (r.label ? wPos : wNeg) * r.weight;
          if (Math.abs(g) < 1e-4) continue;
          // Spread the step over the file's features, so a file with many
          // features does not move the model more than a small one.
          const step = (lr * g) / Math.sqrt(Math.max(1, r.features.length));
          for (const f of r.features) delta[f] = Math.max(-3, Math.min(3, delta[f] - step));
          bias = Math.max(-1, Math.min(1, bias - lr * g * 0.01));
        }
        for (let i = 0; i < BUCKETS; i++) if (delta[i] !== 0) delta[i] *= 0.995; // L2 decay
      }
      let correct = 0;
      for (const r of rows) {
        let z = r.z + bias;
        for (const f of r.features) z += delta[f];
        if ((z >= 0 ? 1 : 0) === r.label) correct++;
      }
      const entries: [number, number][] = [];
      for (let i = 0; i < BUCKETS; i++) if (Math.abs(delta[i]) >= 0.002) entries.push([i, Math.round(delta[i] * 10000) / 10000]);
      const version = Date.now();
      const accuracy = correct / rows.length;
      await this.pool.query(
        `INSERT INTO ai_models (base_version, version, bias, entries, samples, accuracy, trained_at) VALUES ($1,$2,$3,$4,$5,$6, now())
         ON CONFLICT (base_version) DO UPDATE SET version = excluded.version, bias = excluded.bias, entries = excluded.entries,
           samples = excluded.samples, accuracy = excluded.accuracy, trained_at = now()`,
        [base, version, Math.round(bias * 10000) / 10000, JSON.stringify(entries), rows.length, accuracy],
      );
      this.log.info({ base, samples: rows.length, accuracy, weights: entries.length }, 'AI fleet model trained');
      return { version, samples: rows.length, accuracy };
    } finally {
      this.training = false;
    }
  }

  /** What an agent downloads: new verdicts since its cursor and the current model update. */
  async sync(base: string, cursor: number, modelVersion: number) {
    const limit = 2000;
    const { rows } = await this.pool.query(
      `SELECT seq, sha256, size, verdict, confidence, reason, model, injected FROM ai_kb WHERE seq > $1 ORDER BY seq LIMIT $2`,
      [cursor, limit],
    );
    let delta = null;
    const m = await this.pool.query('SELECT version, bias, entries, samples FROM ai_models WHERE base_version = $1', [base]);
    if (m.rows[0] && Number(m.rows[0].version) !== modelVersion) {
      delta = { base_version: base, version: Number(m.rows[0].version), bias: m.rows[0].bias, entries: m.rows[0].entries, samples: m.rows[0].samples };
    }
    return {
      kb: rows.map(({ seq: _s, size, ...r }) => ({ ...r, size: Number(size) })),
      cursor: rows.length ? Number(rows[rows.length - 1].seq) : cursor,
      more: rows.length === limit,
      delta,
    };
  }

  markDirty(base: string): void {
    this.dirty.add(base);
  }
}
