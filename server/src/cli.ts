// Usage:
//   node dist/cli.js migrate
//   node dist/cli.js create-admin <email> <password>
import { loadConfig } from './config.js';
import { createPool, migrate } from './db.js';
import { createOwner } from './routes/users.js';

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
    default:
      console.error('commands: migrate | create-admin <email> <password>');
      process.exitCode = 2;
  }
} finally {
  await pool.end();
}
