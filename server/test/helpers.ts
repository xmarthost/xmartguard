import type { AddressInfo } from 'node:net';
import pg from 'pg';
import { loadConfig, type Config } from '../src/config.js';
import { migrate } from '../src/db.js';
import { buildApp, type App } from '../src/app.js';
import { createOwner } from '../src/routes/users.js';

export const TEST_DB = process.env.TEST_DATABASE_URL || 'postgres://xg:xg@localhost:5432/xmartguard_test';

export interface Harness extends App {
  pool: pg.Pool;
  cfg: Config;
  url: string;
  close: () => Promise<void>;
}

export const OWNER = { email: 'owner@example.com', password: 'correct-horse-battery' };

/** Fresh schema + running app on a random port. */
export async function startHarness(overrides: Partial<Config> = {}): Promise<Harness> {
  const pool = new pg.Pool({ connectionString: TEST_DB, max: 5 });
  await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
  await migrate(pool);
  await createOwner(pool, OWNER.email, OWNER.password);
  const cfg: Config = { ...loadConfig({}), databaseUrl: TEST_DB, webDir: '', autoUpdateAgents: false, ipdbSync: false, ipdbFeeds: [], geoUrl: '', ...overrides };
  const built = await buildApp(cfg, pool, { logger: false });
  await built.app.listen({ host: '127.0.0.1', port: 0 });
  const port = (built.app.server.address() as AddressInfo).port;
  const url = `http://127.0.0.1:${port}`;
  cfg.publicUrl = url;
  return {
    ...built,
    pool,
    cfg,
    url,
    close: async () => {
      await built.app.close();
      await pool.end();
    },
  };
}

/** Minimal cookie-keeping JSON client. */
export class Client {
  cookie = '';
  constructor(private base: string) {}

  async req(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
    const h: Record<string, string> = { ...headers };
    if (this.cookie) h.cookie = this.cookie;
    if (body !== undefined) h['content-type'] ??= 'application/json';
    const res = await fetch(this.base + path, {
      method,
      headers: h,
      body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
    });
    const set = res.headers.get('set-cookie');
    if (set) this.cookie = set.split(';')[0];
    const text = await res.text();
    let json: any = null;
    try {
      json = JSON.parse(text);
    } catch {
      json = text;
    }
    return { status: res.status, body: json };
  }

  async login(email = OWNER.email, password = OWNER.password) {
    const r = await this.req('POST', '/api/auth/login', { email, password });
    if (r.status !== 200) throw new Error('login failed: ' + JSON.stringify(r.body));
    return r;
  }
}

export async function waitFor<T>(fn: () => Promise<T | undefined | null | false>, timeoutMs = 10_000): Promise<T> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('waitFor timed out');
    await new Promise((r) => setTimeout(r, 100));
  }
}
