import crypto from 'node:crypto';
import http from 'node:http';
import zlib from 'node:zlib';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';
import { envelopeMessage } from '../src/agent-sign.js';
import { validateCustomRules } from '../src/waf/rulesets.js';

function makeTgz(files: Record<string, string>): Buffer {
  const parts: Buffer[] = [];
  for (const [name, text] of Object.entries(files)) {
    const body = Buffer.from(text);
    const h = Buffer.alloc(512);
    h.write(name, 0);
    h.write('0000644\0', 100);
    h.write(body.length.toString(8).padStart(11, '0') + '\0', 124);
    h.write('0', 156);
    h.write('        ', 148);
    let sum = 0;
    for (const b of h) sum += b;
    h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
    parts.push(h, body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  parts.push(Buffer.alloc(1024));
  return zlib.gzipSync(Buffer.concat(parts));
}

const tgz = makeTgz({
  'coreruleset-4.29.0/crs-setup.conf.example': 'SecDefaultAction "phase:1,log,auditlog,pass"\n',
  'coreruleset-4.29.0/rules/REQUEST-901-INITIALIZATION.conf': 'SecAction "id:901001,phase:1,pass,nolog"\n',
  'coreruleset-4.29.0/rules/scanners-user-agents.data': 'sqlmap\n',
  'coreruleset-4.29.0/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example': '# example\n',
  'coreruleset-4.29.0/tests/regression/x.yaml': 'not a rule',
});
const sha = crypto.createHash('sha256').update(tgz).digest('hex');

let gh: http.Server;
let base = '';
let h: Harness;
let admin: Client;
let serverId = '';
const keys = crypto.generateKeyPairSync('ed25519');
const pub = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');

beforeAll(async () => {
  gh = http.createServer((req, res) => {
    const u = req.url ?? '';
    if (u === '/repos/coreruleset/coreruleset/releases/latest') {
      res.setHeader('content-type', 'application/json');
      return res.end(
        JSON.stringify({
          tag_name: 'v4.29.0',
          published_at: '2026-08-17T10:00:00Z',
          assets: [
            { name: 'coreruleset-4.29.0-minimal.tar.gz', browser_download_url: `${base}/dl/min.tgz` },
            { name: 'coreruleset-4.29.0-minimal.tar.gz.sha256', browser_download_url: `${base}/dl/min.sha256` },
          ],
        }),
      );
    }
    if (u === '/dl/min.tgz') return res.end(tgz);
    if (u === '/dl/min.sha256') return res.end(`${sha}  coreruleset-4.29.0-minimal.tar.gz\n`);
    res.statusCode = 404;
    res.end('{}');
  });
  await new Promise<void>((r) => gh.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(gh.address() as AddressInfo).port}`;
  h = await startHarness({ crsApi: base });
  const { rows: acc } = await h.pool.query('SELECT id FROM accounts LIMIT 1');
  const { rows } = await h.pool.query("INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, 'web1', $2) RETURNING id", [acc[0].id, pub]);
  serverId = rows[0].id;
  admin = new Client(h.url);
  await admin.login();
});

afterAll(async () => {
  await h.close();
  gh.close();
});

async function agent(path: string, payload: unknown) {
  const raw = JSON.stringify(payload);
  const ts = String(Math.floor(Date.now() / 1000));
  const signature = crypto.sign(null, Buffer.from(envelopeMessage(serverId, ts, raw)), keys.privateKey).toString('base64');
  const r = await fetch(h.url + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ server_id: serverId, ts, signature, payload: raw }) });
  return { status: r.status, body: await r.json() };
}

const config = (over: Record<string, unknown> = {}) => ({
  xmartguard: { enabled: true },
  crs: { enabled: true, version: 'latest', paranoia: 1, inbound_threshold: 5, outbound_threshold: 4 },
  vendors: [{ id: 'malware_expert', name: 'Malware.Expert', url: 'https://malware.example/meta_licensed.yaml', enabled: true }],
  custom: { enabled: true, rules: 'SecRule REQUEST_URI "@beginsWith /old-admin" "id:1000001,phase:1,deny,status:403,log"' },
  ...over,
});

describe('WAF rule sets', () => {
  it('starts with defaults and leaves servers alone until saved', async () => {
    const r = await admin.req('GET', '/api/waf/rulesets');
    expect(r.body.version).toBe(0);
    expect(r.body.config.crs.enabled).toBe(false);
    expect(r.body.presets.map((p: any) => p.id)).toContain('malware_expert');
    const a = await agent('/api/agent/waf/config', { version: 0, crs_version: '' });
    expect(a.body.unchanged).toBe(true);
  });

  it('rejects dangerous custom rules', async () => {
    expect(validateCustomRules('CustomLog "|/bin/sh" common')).toMatch(/only SecRule/);
    expect(validateCustomRules('SecRule ARGS "@rx x" "id:1,phase:2,pass,exec:/tmp/x"')).toMatch(/exec/);
    const bad = await admin.req('PUT', '/api/waf/rulesets', config({ custom: { enabled: true, rules: 'LoadModule x /tmp/x.so' } }));
    expect(bad.status).toBe(400);
    const badUrl = await admin.req('PUT', '/api/waf/rulesets', config({ vendors: [{ id: 'x', name: 'x', url: 'http://plain.example/v.yaml', enabled: true }] }));
    expect(badUrl.status).toBe(400);
  });

  it('saves, downloads the latest CRS and gives agents the config and files', async () => {
    const r = await admin.req('PUT', '/api/waf/rulesets', config());
    expect(r.status).toBe(200);
    expect(r.body.version).toBe(1);
    const g = await admin.req('GET', '/api/waf/rulesets');
    expect(g.body.crs.resolved).toBe('4.29.0');
    expect(g.body.crs.releases[0].files).toBe(3);

    const a = await agent('/api/agent/waf/config', { version: 0, crs_version: '' });
    expect(a.body.config.version).toBe(1);
    expect(a.body.config.crs.version).toBe('4.29.0');
    expect(a.body.config.vendors[0].url).toContain('meta_licensed.yaml');
    expect(Object.keys(a.body.crs.files).sort()).toEqual(['crs-setup.conf.example', 'rules/REQUEST-901-INITIALIZATION.conf', 'rules/scanners-user-agents.data']);

    // Up to date: nothing to send.
    expect((await agent('/api/agent/waf/config', { version: 1, crs_version: '4.29.0' })).body.unchanged).toBe(true);
    // Config current but CRS missing on the server: files again.
    const again = await agent('/api/agent/waf/config', { version: 1, crs_version: '' });
    expect(again.body.crs.version).toBe('4.29.0');
  });

  it('stores what servers report', async () => {
    const st = { version: 1, rule_sets: [{ id: 'owasp_crs', name: 'OWASP Core Rule Set', state: 'active', version: '4.29.0' }], status: { logs: ['/etc/apache2/logs/error_log'] } };
    expect((await agent('/api/agent/waf/status', st)).status).toBe(200);
    const g = await admin.req('GET', '/api/waf/rulesets');
    expect(g.body.servers[0]).toMatchObject({ hostname: 'web1', version: 1 });
    expect(g.body.servers[0].status.rule_sets[0].state).toBe('active');
    const { rows } = await h.pool.query("SELECT detail FROM audit_events WHERE action = 'waf.rulesets_saved'");
    expect(rows[0].detail.crs).toBe('latest PL1');
  });

  it('lets only the owner add a custom vendor', async () => {
    await admin.req('POST', '/api/users', { email: 'ops@example.com', name: 'Ops', role: 'admin', password: 'correct-horse-battery-2' });
    const ops = new Client(h.url);
    await ops.login('ops@example.com', 'correct-horse-battery-2');
    const custom = config({ vendors: [...config().vendors, { id: 'other', name: 'Other', url: 'https://rules.example/meta_other.yaml', enabled: true }] });
    expect((await ops.req('PUT', '/api/waf/rulesets', custom)).status).toBe(403);
    expect((await admin.req('PUT', '/api/waf/rulesets', custom)).status).toBe(200);
    // Already added by the owner: an admin may keep it or switch it off.
    expect((await ops.req('PUT', '/api/waf/rulesets', custom)).status).toBe(200);
  });
});
