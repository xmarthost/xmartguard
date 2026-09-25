// An old agent connects, the portal pushes the bundled release, the agent
// verifies it, replaces its own binary and exits so systemd restarts it.
import { execFile, execFileSync, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { Client, startHarness, waitFor, type Harness } from './helpers.js';

const repo = path.resolve(import.meta.dirname, '..', '..');
let h: Harness;
let tmp: string;

beforeAll(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xg-upd-'));
  // The "release" bundled with the portal.
  execFileSync('bash', ['scripts/build-agent.sh'], { cwd: repo, env: { ...process.env, VERSION: '9.9.9', OUT: path.join(tmp, 'downloads') }, stdio: 'inherit' });
  // The old agent installed on the server.
  execFileSync('go', ['build', '-ldflags', '-X github.com/xmarthost/xmartguard/agent/internal/version.Version=0.1.0', '-o', path.join(tmp, 'agent'), './cmd/xmartguard-agent'], { cwd: path.join(repo, 'agent'), stdio: 'inherit' });
  h = await startHarness({ autoUpdateAgents: true, downloadsDir: path.join(tmp, 'downloads') });
}, 300_000);

afterAll(async () => {
  await h.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

it('auto-updates an outdated agent', async () => {
  const c = new Client(h.url);
  await c.login();
  const { body } = await c.req('POST', '/api/enrollment-tokens', {});
  const env = { ...process.env, XG_CONFIG_DIR: path.join(tmp, 'conf'), XG_STATE_DIR: path.join(tmp, 'state') };
  const bin = path.join(tmp, 'agent');
  await promisify(execFile)(bin, ['enroll', '--server', h.url, '--token', body.token], { env });
  fs.writeFileSync(path.join(tmp, 'conf', 'settings.json'), JSON.stringify({ firewall: { enabled: false }, scanner: { realtime: false } }));
  expect((await promisify(execFile)(bin, ['version'])).stdout.trim()).toBe('0.1.0');

  const proc = spawn(bin, ['run'], { env, stdio: 'ignore' });
  const code = await new Promise<number | null>((r) => proc.once('exit', r));
  expect(code).toBe(3); // asks systemd to restart it
  expect((await promisify(execFile)(bin, ['version'])).stdout.trim()).toBe('9.9.9');

  // After the "restart" the new version reports in and is not updated again.
  const again = spawn(bin, ['run'], { env, stdio: 'ignore' });
  const srv = await waitFor(async () => {
    const r = await c.req('GET', '/api/servers');
    const s = r.body.servers[0];
    return s?.online && s.agent_version === '9.9.9' ? s : null;
  }, 15_000);
  expect(srv.agent_version).toBe('9.9.9');
  again.kill('SIGTERM');
}, 60_000);
