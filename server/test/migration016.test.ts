import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startHarness, type Harness } from './helpers.js';
import { migrations } from '../src/migrations.js';

let h: Harness;
beforeAll(async () => {
  h = await startHarness();
});
afterAll(async () => h.close());

const sha = (n: number) => n.toString(16).padStart(64, '0');

describe('migration 016: clean verdicts of malware families', () => {
  it('turns risky "clean" verdicts into "suspicious" and drops them from AI Learning', async () => {
    const q = (sql: string, a: unknown[] = []) => h.pool.query(sql, a);
    for (let i = 1; i <= 25; i++) await q("INSERT INTO ai_kb (sha256, verdict, confidence, match) VALUES ($1,'malicious',95,'PHP.Backdoor.GlobalsDispatch')", [sha(i)]);
    // Family overwhelmingly malicious: cleared copy gets distrusted.
    await q("INSERT INTO ai_kb (sha256, verdict, confidence, match, reason) VALUES ($1,'clean',95,'PHP.Backdoor.GlobalsDispatch','Legitimate plugin')", [sha(100)]);
    await q("INSERT INTO ai_fp (sha256, signature, path, confidence) VALUES ($1,'PHP.Backdoor.GlobalsDispatch','~/public_html/wp-content/mu-plugins/helix-config-mod.php',95)", [sha(100)]);
    // Small family, but the file is an archive in uploads.
    await q("INSERT INTO ai_kb (sha256, verdict, confidence, match) VALUES ($1,'clean',100,'Archive.XG.AI.Learned')", [sha(101)]);
    await q("INSERT INTO ai_fp (sha256, signature, path, confidence) VALUES ($1,'Archive.XG.AI.Learned','~/public_html/wp-content/uploads/2026/10/87fdac7b.zip',100)", [sha(101)]);
    // A real false positive stays.
    await q("INSERT INTO ai_kb (sha256, verdict, confidence, match) VALUES ($1,'clean',100,'PHP.Backdoor.DynamicCall')", [sha(102)]);
    await q("INSERT INTO ai_fp (sha256, signature, path, confidence) VALUES ($1,'PHP.Backdoor.DynamicCall','~/public_html/wp-content/updraft/plugins-old/updraftplus/class-updraftplus.php',100)", [sha(102)]);
    // An administrator's decision stays.
    await q("INSERT INTO ai_kb (sha256, verdict, confidence, match, overridden) VALUES ($1,'clean',100,'PHP.Backdoor.GlobalsDispatch',true)", [sha(103)]);

    await q(migrations.find((m) => m.version === '016_distrust_risky_clean')!.sql);
    const v = async (n: number) => (await q('SELECT verdict, reason FROM ai_kb WHERE sha256 = $1', [sha(n)])).rows[0];
    expect((await v(100)).verdict).toBe('suspicious');
    expect((await v(100)).reason).toContain('Not restored');
    expect((await v(101)).verdict).toBe('suspicious');
    expect((await v(102)).verdict).toBe('clean');
    expect((await v(103)).verdict).toBe('clean');
    const fp = (await q('SELECT sha256 FROM ai_fp ORDER BY sha256')).rows.map((r) => r.sha256);
    expect(fp).toEqual([sha(102)]);
  });
});
