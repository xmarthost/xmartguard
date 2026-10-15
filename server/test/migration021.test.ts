import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startHarness, type Harness } from './helpers.js';
import { migrations } from '../src/migrations.js';

let h: Harness;
beforeAll(async () => {
  h = await startHarness();
});
afterAll(async () => h.close());

const sha = (n: number) => n.toString(16).padStart(64, '0');

// From the AI Learning export of 2026-10-15.
describe('migration 021: clean verdicts where malware hides', () => {
  it('distrusts hidden folders, drop-ins and files WordPress does not ship in wp-admin/user', async () => {
    const q = (sql: string, a: unknown[] = []) => h.pool.query(sql, a);
    const add = async (n: number, sig: string, path: string) => {
      await q("INSERT INTO ai_kb (sha256, verdict, confidence, match, reason) VALUES ($1,'clean',100,$2,'Legitimate')", [sha(n), sig]);
      await q('INSERT INTO ai_fp (sha256, signature, path, confidence) VALUES ($1,$2,$3,100)', [sha(n), sig, path]);
    };
    await add(1, 'PHP.Backdoor.FileDropper', '~/olxpharma.com/wp-admin/user/cgi.php');
    await add(2, 'PHP.Backdoor.SomeFamily', '~/Manahil.example.com/wp-content/.sc_1d91536f/4cf27233.php');
    await add(3, 'PHP.Obfuscated.CompressedPayload', '~/Manahil.example.com/wp-content/db.php');
    // Real false positives stay.
    await add(4, 'PHP.WebShell.ExecAlternatives', '~/public_html/erp.example.pk/core/lib/functions.lib.php');
    await add(5, 'PHP.Suspicious.EncodedPayload', '~/public_html/.well-known/x/CaBundle.php');
    await add(6, 'PHP.Backdoor.FileDropper', '~/public_html/wp-admin/user/profile.php');

    await q(migrations.find((m) => m.version === '021_distrust_hidden_and_families')!.sql);
    const v = async (n: number) => (await q('SELECT verdict FROM ai_kb WHERE sha256 = $1', [sha(n)])).rows[0].verdict;
    expect([await v(1), await v(2), await v(3)]).toEqual(['suspicious', 'suspicious', 'suspicious']);
    expect([await v(4), await v(5), await v(6)]).toEqual(['clean', 'clean', 'clean']);
  });
});
