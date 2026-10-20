import { loadConfig } from './config.js';
import { createPool, migrate } from './db.js';
import { buildApp } from './app.js';
import { createOwner } from './routes/users.js';

const cfg = loadConfig();
const pool = createPool(cfg.databaseUrl);

const applied = await migrate(pool);
const { app } = await buildApp(cfg, pool);

// A promise nobody waited for that fails must not end the portal (Node exits
// on an unhandled rejection): every agent, CAPTCHA page and user would go
// with it. Logged; the code that let it escape is the bug to fix.
process.on('unhandledRejection', (err) => app.log.error({ err }, 'unhandled promise rejection'));
if (applied.length) app.log.info({ applied }, 'database migrated');

// Nobody is connected right after a restart.
await pool.query('UPDATE servers SET connected = false WHERE connected');

// First-run bootstrap of the owner account from ADMIN_EMAIL / ADMIN_PASSWORD.
const { rows } = await pool.query('SELECT count(*)::int AS n FROM users');
if (rows[0].n === 0) {
  if (cfg.adminEmail && cfg.adminPassword) {
    await createOwner(pool, cfg.adminEmail, cfg.adminPassword);
    app.log.info({ email: cfg.adminEmail }, 'created owner account');
  } else {
    app.log.warn('no users exist: set ADMIN_EMAIL and ADMIN_PASSWORD or run `npm run create-admin`');
  }
}

const prune = setInterval(() => {
  pool
    .query("DELETE FROM server_metrics WHERE ts < now() - make_interval(days => $1)", [cfg.metricsRetentionDays])
    .then(() => pool.query('DELETE FROM sessions WHERE expires_at < now()'))
    .catch((err) => app.log.error({ err }, 'prune failed'));
}, 3600_000);

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.once(sig, async () => {
    clearInterval(prune);
    await app.close();
    await pool.end();
    process.exit(0);
  });
}

await app.listen({ host: cfg.host, port: cfg.port });
