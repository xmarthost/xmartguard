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
  vendors: [{ id: 'comodo', name: 'Comodo WAF', url: 'https://waf.example/meta_licensed.yaml', enabled: true }],
  custom: { enabled: true, rules: 'SecRule REQUEST_URI "@beginsWith /old-admin" "id:1000001,phase:1,deny,status:403,log"' },
  ...over,
});

describe('WAF rule sets', () => {
  it('starts with defaults and leaves servers alone until saved', async () => {
    const r = await admin.req('GET', '/api/waf/rulesets');
    expect(r.body.version).toBe(0);
    expect(r.body.config.crs.enabled).toBe(true); // OWASP CRS is on by default
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

describe('remote rule feeds', () => {
  it('stores the license key, masks it in the portal and keeps it on save', async () => {
    const remote = [{ id: 'malware_expert', name: 'Malware.Expert', key: 'LICENSE-KEY-9876', url: 'https://rules.example/modsec.conf', enabled: true }];
    expect((await admin.req('PUT', '/api/waf/rulesets', config({ remote }))).status).toBe(200);
    const g = await admin.req('GET', '/api/waf/rulesets');
    expect(g.body.config.remote[0].key).toBe('********9876');
    // Saving the masked value keeps the real key.
    expect((await admin.req('PUT', '/api/waf/rulesets', { ...g.body.config })).status).toBe(200);
    const a = await agent('/api/agent/waf/config', { version: 0, crs_version: '' });
    expect(a.body.config.remote[0].key).toBe('LICENSE-KEY-9876');
    const bad = await admin.req('PUT', '/api/waf/rulesets', config({ remote: [{ ...remote[0], key: 'x" exec' }] }));
    expect(bad.status).toBe(400);
  });
});

describe('linking feeds to servers', () => {
  it('sends a licensed feed only to the servers it is linked to', async () => {
    const other = '00000000-0000-4000-8000-000000000001';
    const remote = [
      { id: 'me', name: 'Malware.Expert', key: 'SERIAL.12345', url: 'https://rules.example/generic', enabled: true, servers: [serverId], rbl: 'RBL.Example.net' },
      { id: 'all', name: 'Everyone', key: 'KEY-ALL', url: 'https://rules.example/all', enabled: true },
    ];
    expect((await admin.req('PUT', '/api/waf/rulesets', config({ remote }))).status).toBe(200);
    const a = await agent('/api/agent/waf/config', { version: 0, crs_version: '' });
    expect(a.body.config.remote.map((r: { id: string }) => r.id)).toEqual(['me', 'all']);
    expect(a.body.config.remote[0].rbl).toBe('rbl.example.net');
    expect(a.body.config.remote[0].servers).toBeUndefined();

    // Servers of another account (or unknown ids) are refused.
    const bad = await admin.req('PUT', '/api/waf/rulesets', config({ remote: [{ ...remote[0], servers: [other] }] }));
    expect(bad.status).toBe(400);
    const g = await admin.req('GET', '/api/waf/rulesets');
    expect(g.body.remote_presets[0].url).toContain('malware.expert');
    const cfg = g.body.config;
    cfg.remote[0].servers = [];
    cfg.remote = [cfg.remote[1], { ...cfg.remote[0], id: 'me2', key: 'KEY-TWO', servers: [serverId] }];
    expect((await admin.req('PUT', '/api/waf/rulesets', cfg)).status).toBe(200);
    const b = await agent('/api/agent/waf/config', { version: 0, crs_version: '' });
    expect(b.body.config.remote.map((r: { id: string }) => r.id)).toEqual(['all', 'me2']);
    const badRbl = await admin.req('PUT', '/api/waf/rulesets', config({ remote: [{ ...remote[1], rbl: 'x" exec' }] }));
    expect(badRbl.status).toBe(400);
  });
});

describe('Malware.Expert replaces the OWASP CRS', () => {
  it('turns CRS off only on the servers linked to Malware.Expert', async () => {
    const me = { id: 'malware_expert', name: 'Malware.Expert', key: 'SERIAL.1', url: 'https://rules.malware.expert/download.php?rules=generic', enabled: true };
    expect((await admin.req('PUT', '/api/waf/rulesets', config({ remote: [{ ...me, servers: [serverId] }] }))).status).toBe(200);
    const a = await agent('/api/agent/waf/config', { version: 0, crs_version: '' });
    expect(a.body.config.crs.enabled).toBe(false);
    expect(a.body.config.crs.replaced_by).toBe('Malware.Expert');
    expect(a.body.crs).toBeUndefined();
    // Switched off: CRS comes back.
    expect((await admin.req('PUT', '/api/waf/rulesets', config({ remote: [{ ...me, enabled: false }] }))).status).toBe(200);
    const b = await agent('/api/agent/waf/config', { version: 0, crs_version: '' });
    expect(b.body.config.crs.enabled).toBe(true);
    expect(b.body.crs.version).toBe('4.29.0');
  });
});

describe('CRS replacement reaches servers that are up to date', () => {
  it('resyncs a server still running CRS once Malware.Expert is linked', async () => {
    const me = { id: 'malware_expert', name: 'Malware.Expert', key: 'SERIAL.1', url: 'https://rules.malware.expert/download.php?rules=generic', enabled: true, servers: [serverId] };
    const put = await admin.req('PUT', '/api/waf/rulesets', config({ remote: [me] }));
    const v = put.body.version;
    // Same version, but the server still reports CRS 4.29.0: not "unchanged".
    const a = await agent('/api/agent/waf/config', { version: v, crs_version: '4.29.0' });
    expect(a.body.unchanged).toBeUndefined();
    expect(a.body.config.crs.enabled).toBe(false);
    const b = await agent('/api/agent/waf/config', { version: v, crs_version: '' });
    expect(b.body.unchanged).toBe(true);
    // CRS never downloaded, but still switched on in the server's config.
    const c = await agent('/api/agent/waf/config', { version: v, crs_version: '', crs_enabled: true });
    expect(c.body.config.crs.enabled).toBe(false);
    const d = await agent('/api/agent/waf/config', { version: v, crs_version: '', crs_enabled: false });
    expect(d.body.unchanged).toBe(true);
  });
});

describe('method override', () => {
  it('accepts PUT sent as POST with X-HTTP-Method-Override (firewalls block PUT)', async () => {
    const r = await admin.req('POST', '/api/waf/rulesets', config({ remote: [] }), { 'x-http-method-override': 'PUT' });
    expect(r.status).toBe(200);
    expect(typeof r.body.version).toBe('number');
    // Without the header a POST is not a save.
    expect((await admin.req('POST', '/api/waf/rulesets', config({ remote: [] }))).status).toBe(404);
    // Only PUT/PATCH/DELETE can be requested.
    expect((await admin.req('POST', '/api/waf/rulesets', config({ remote: [] }), { 'x-http-method-override': 'GET' })).status).toBe(404);
  });
});
