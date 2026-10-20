import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ACTIONS, summarize } from '../src/routes/agent-cmd.js';

/** Every file under dir (recursively) with one of the extensions. */
function files(dir: string, ext: RegExp): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...files(p, ext));
    else if (ext.test(e.name)) out.push(p);
  }
  return out;
}

describe('agent actions the web app sends', () => {
  it('are all allowed by the portal (else the button answers "unknown action")', () => {
    const web = path.resolve(import.meta.dirname, '..', '..', 'web', 'src');
    const used = new Set<string>();
    const call = /\b(?:agentCall|useAgent)(?:<[^>]*>)?\(\s*[^,()]+,\s*['"`]([a-z_]+\.[a-z_.]+)['"`]/g;
    for (const f of files(web, /\.tsx?$/)) {
      for (const m of fs.readFileSync(f, 'utf8').matchAll(call)) used.add(m[1]);
    }
    expect(used.size).toBeGreaterThan(30);
    expect([...used].filter((a) => !ACTIONS[a])).toEqual([]);
    expect(ACTIONS['waf.auto_exclusion']).toMatchObject({ role: 'admin', mutates: true });
  });
});

describe('audit entries of agent actions', () => {
  it('never keep secrets sent with settings', () => {
    const d = summarize({
      notify: { smtp_password: 'pw-value-1', telegram_token: 'tg-value-2', smtp_user: 'mailer' },
      domain_reputation: { safe_browsing_key: 'sb-value-3' },
      captcha: { secret_key: 'cs-value-4', site_key_list: ['a'] },
      waf: { whitelist_ips: ['192.0.2.1'] },
    });
    const text = JSON.stringify(d);
    for (const s of ['pw-value-1', 'tg-value-2', 'sb-value-3', 'cs-value-4']) expect(text).not.toContain(s);
    expect(text).toContain('mailer');
    expect(text).toContain('192.0.2.1');
    expect((d.notify as Record<string, unknown>).smtp_password).toBe('***');
  });
});
