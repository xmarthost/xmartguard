// Usage:
//   node dist/cli.js migrate
//   node dist/cli.js create-admin <email> <password>
//   node dist/cli.js list-users
//   node dist/cli.js set-password <email> <password>
import { loadConfig } from './config.js';
import { createPool, migrate } from './db.js';
import { createOwner } from './routes/users.js';
import { hashPassword } from './security.js';

const [cmd, ...args] = process.argv.slice(2);
const pool = createPool(loadConfig().databaseUrl);

try {
  switch (cmd) {
    case 'migrate': {
      const applied = await migrate(pool);
      console.log(applied.length ? `applied: ${applied.join(', ')}` : 'database is up to date');
      break;
    }
    case 'create-admin': {
      const [email, password] = args;
      if (!email || !password || password.length < 10) {
        console.error('usage: create-admin <email> <password (10+ chars)>');
        process.exitCode = 2;
        break;
      }
      await migrate(pool);
      await createOwner(pool, email, password);
      console.log(`owner ${email} created`);
      break;
    }
    case 'list-users': {
      const { rows } = await pool.query(
        `SELECT u.email, u.role, a.name AS account, a.platform, u.last_login_at
           FROM users u JOIN accounts a ON a.id = u.account_id ORDER BY a.platform DESC, u.created_at`,
      );
      for (const r of rows) console.log(`${r.platform ? 'OPERATOR' : 'customer'}\t${r.role}\t${r.email}\t${r.account}\tlast login: ${r.last_login_at ? new Date(r.last_login_at).toISOString() : 'never'}`);
      break;
    }
    case 'set-password': {
      // Resets a user's password (a forgotten operator password) and ends
      // their sessions.
      const [email, password] = args;
      if (!email || !password || password.length < 10) {
        console.error('usage: set-password <email> <password (10+ chars)>');
        process.exitCode = 2;
        break;
      }
      const { rows } = await pool.query('UPDATE users SET password_hash = $2 WHERE lower(email) = lower($1) RETURNING id', [email, await hashPassword(password)]);
      if (!rows[0]) {
        console.error(`no user with the email ${email} (list them with: list-users)`);
        process.exitCode = 1;
        break;
      }
      await pool.query('DELETE FROM sessions WHERE user_id = $1', [rows[0].id]);
      console.log(`password of ${email} changed`);
      break;
    }
    default:
      console.error('commands: migrate | create-admin <email> <password> | list-users | set-password <email> <password>');
      process.exitCode = 2;
  }
} finally {
  await pool.end();
}
