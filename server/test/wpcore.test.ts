import crypto from 'node:crypto';
import http from 'node:http';
import zlib from 'node:zlib';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';
import { envelopeMessage } from '../src/agent-sign.js';
import { compareVersions } from '../src/wpcore/service.js';
import { flattenYara, parseLMDHex, parseLMDMD5, readTar } from '../src/signatures/service.js';
import { readZip } from '../src/wpcore/zip.js';

const md5 = (b: string | Buffer) => crypto.createHash('md5').update(b).digest('hex');

/** Minimal zip writer (deflate) for the fake beta release. */
function makeZip(files: Record<string, string>): Buffer {
  const locals: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const [name, text] of Object.entries(files)) {
    const data = Buffer.from(text);
    const comp = zlib.deflateRawSync(data);
    const crc = zlib.crc32(data);
    const n = Buffer.from(name);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(8, 8);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(comp.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(n.length, 26);
    locals.push(lh, n, comp);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(8, 10);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(comp.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(n.length, 28);
    ch.writeUInt32LE(offset, 42);
    central.push(ch, n);
    offset += lh.length + n.length + comp.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Object.keys(files).length, 8);
  end.writeUInt16LE(Object.keys(files).length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

/** Minimal tar.gz writer for the fake LMD signature pack. */
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

// A fake release: 150 files so it passes the completeness check.
const release = (ver: string) => {
  const f: Record<string, string> = {};
  for (let i = 0; i < 150; i++) f[`wp-includes/f${i}.php`] = `<?php // ${ver} file ${i}\n`;
  f['wp-admin/includes/file.php'] = `<?php // official file.php ${ver}\n`;
  return f;
};

let h: Harness;
let site: http.Server;
let admin: Client;
let serverId = '';
const keys = crypto.generateKeyPairSync('ed25519');
const pub = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
const svnHits: string[] = [];

beforeAll(async () => {
  const rels: Record<string, Record<string, string>> = { '5.7': release('5.7'), '6.8': release('6.8'), '7.1.2': release('7.1.2') };
  const beta = release('7.2-beta1');
  site = http.createServer((req, res) => {
    const u = new URL(req.url!, 'http://x');
    const json = (o: unknown) => (res.setHeader('content-type', 'application/json'), res.end(JSON.stringify(o)));
    if (u.pathname === '/core/stable-check/1.0/') return json({ '5.7': 'insecure', '6.8': 'outdated', '7.1.2': 'latest' });
    if (u.pathname === '/download/releases/') return res.end('<a href="https://wordpress.org/wordpress-7.2-beta1.zip">7.2 Beta 1</a> <a href="/wordpress-5.0-RC1.zip">old</a>');
    if (u.pathname === '/core/checksums/1.0/') {
      const r = rels[u.searchParams.get('version') ?? ''];
      return json({ checksums: r ? Object.fromEntries(Object.entries(r).map(([k, v]) => [k, md5(v)])) : false });
    }
    if (u.pathname === '/wordpress-7.2-beta1.zip') return res.end(makeZip(Object.fromEntries(Object.entries(beta).map(([k, v]) => ['wordpress/' + k, v]))));
    const svn = /^\/tags\/([^/]+)\/(.+)$/.exec(u.pathname);
    if (svn) {
      svnHits.push(u.pathname);
      const body = rels[svn[1]]?.[svn[2]];
      if (!body) return (res.statusCode = 404), res.end();
      return res.end(body);
    }
    if (u.pathname === '/plugin-checksums/akismet/5.3.json') return json({ plugin: 'akismet', version: '5.3', files: { 'akismet.php': { md5: 'a'.repeat(32) } } });
    if (u.pathname === '/sigpack.tgz') {
      return res.end(
        makeTgz({
          'sigs/md5v2.dat': `${'a'.repeat(32)}:1234:{MD5}php.cmdshell.test.1\nbad line\n`,
          'sigs/hex.dat': `${Buffer.from('this is a very distinctive shell marker').toString('hex')}:{HEX}php.shell.marker.1\n6162:{HEX}too.short\n`,
          'sigs/rfxn.yara': 'rule lmd_test { strings: $a = "zzz_marker" condition: $a }',
        }),
      );
    }
    if (u.pathname === '/yara/main.yar') return res.end('import "math"\ninclude "parts/extra.yar"\nrule main_rule { condition: extra_rule }');
    if (u.pathname === '/yara/parts/extra.yar') return res.end('import "math"\nprivate rule extra_rule { strings: $a = "shell_marker" condition: $a }');
    res.statusCode = 404;
    res.end();
  });
  await new Promise<void>((r) => site.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(site.address() as AddressInfo).port}`;
  h = await startHarness({
    wpApi: base,
    wpSite: base,
    wpSvn: base + '/tags',
    wpMirror: base + '/mirror',
    wpDownloads: base,
    wpCoreMinVersion: '5.8',
    sigFeeds: [`lmd:${base}/sigpack.tgz`, `yara:${base}/yara/main.yar`],
  });
  const { rows: acc } = await h.pool.query('SELECT id FROM accounts LIMIT 1');
  const { rows } = await h.pool.query("INSERT INTO servers (account_id, hostname, public_key) VALUES ($1, 'web1', $2) RETURNING id", [acc[0].id, pub]);
  serverId = rows[0].id;
  admin = new Client(h.url);
  await admin.login();
});

afterAll(async () => {
  await h.close();
  site.close();
});

async function agent(path: string, payload: unknown) {
  const raw = JSON.stringify(payload);
  const ts = String(Math.floor(Date.now() / 1000));
  const signature = crypto.sign(null, Buffer.from(envelopeMessage(serverId, ts, raw)), keys.privateKey).toString('base64');
  const r = await fetch(h.url + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ server_id: serverId, ts, signature, payload: raw }) });
  return { status: r.status, body: await r.json() };
}

describe('WordPress core files', () => {
  it('collects every release and beta since the minimum version', async () => {
    const r = await admin.req('POST', '/api/wp-core/sync');
    expect(r.status).toBe(200);
    expect(r.body.added.sort(compareVersions)).toEqual(['6.8', '7.1.2', '7.2-beta1']);
    expect(r.body.status).toMatchObject({ versions: 3, stable: 2, prerelease: 1, latest: '7.1.2', newest_prerelease: '7.2-beta1' });
    // 151 files x 3 versions, all different.
    expect(r.body.status.files).toBe(453);
  });

  it('sends agents the known-good list only when it changed', async () => {
    const r = await agent('/api/agent/wp-core/set', { etag: '' });
    expect(r.status).toBe(200);
    const raw = zlib.gunzipSync(Buffer.from(r.body.data, 'base64'));
    expect(raw.length).toBe(453 * 16);
    expect(raw.includes(Buffer.from(md5('<?php // official file.php 7.2-beta1\n'), 'hex'))).toBe(true);
    const again = await agent('/api/agent/wp-core/set', { etag: r.body.etag });
    expect(again.body).toEqual({ etag: r.body.etag, unchanged: true });
  });

  it('serves verified official files for repairs', async () => {
    const f = await agent('/api/agent/wp-core/file', { version: '7.1.2', path: 'wp-admin/includes/file.php' });
    expect(Buffer.from(f.body.content, 'base64').toString()).toBe('<?php // official file.php 7.1.2\n');
    // Cached after the first download.
    const n = svnHits.length;
    await agent('/api/agent/wp-core/file', { version: '7.1.2', path: 'wp-admin/includes/file.php' });
    expect(svnHits.length).toBe(n);
    expect((await agent('/api/agent/wp-core/file', { version: '7.1.2', path: 'wp-content/evil.php' })).status).toBe(404);
    expect((await agent('/api/agent/wp-core/file', { version: '7.1.2', path: '../../etc/passwd' })).status).toBe(404);
    const c = await agent('/api/agent/wp-core/checksums', { version: '6.8' });
    expect(Object.keys(c.body.checksums)).toHaveLength(151);
  });
});

describe('WordPress.org plugin checksums', () => {
  it('proxies and caches official plugin checksums', async () => {
    const r = await agent('/api/agent/wp-plugin/checksums', { slug: 'akismet', version: '5.3' });
    expect(r.body.checksums.files['akismet.php'].md5).toBe('a'.repeat(32));
    expect((await agent('/api/agent/wp-plugin/checksums', { slug: 'premium-thing', version: '1.0' })).body).toEqual({ missing: true });
    expect((await agent('/api/agent/wp-plugin/checksums', { slug: '../etc', version: '1' })).body).toEqual({ missing: true });
  });
});

describe('malware signature feeds', () => {
  it('downloads LMD and YARA feeds and sends them to agents', async () => {
    const r = await admin.req('POST', '/api/signatures/sync');
    expect(r.body.results.every((x: any) => x.ok)).toBe(true);
    const s = await agent('/api/agent/signatures', { etag: '' });
    expect(s.body.md5).toEqual([['a'.repeat(32), 1234, 'php.cmdshell.test.1']]);
    expect(s.body.hex).toEqual([[Buffer.from('this is a very distinctive shell marker').toString('hex'), 'php.shell.marker.1']]);
    const names = s.body.yara.map((y: any) => y.name).sort();
    expect(names).toEqual(['lmd-rfxn-yara', 'main']);
    const main = s.body.yara.find((y: any) => y.name === 'main').text;
    expect(main.match(/import "math"/g)).toHaveLength(1);
    expect(main).toContain('private rule extra_rule');
    expect((await agent('/api/agent/signatures', { etag: s.body.etag })).body.unchanged).toBe(true);
    const st = await admin.req('GET', '/api/signatures/status');
    expect(st.body.feeds[0].counts).toEqual({ md5: 1, hex: 1, yara: 1 });
  });

  it('parses the formats', async () => {
    expect(parseLMDMD5('0123456789abcdef0123456789abcdef:10:{MD5}x.y.1\n')).toEqual([['0123456789abcdef0123456789abcdef', 10, 'x.y.1']]);
    expect(parseLMDHex('zz:{HEX}bad\n')).toEqual([]);
    expect(readTar(makeTgz({ 'a/b.txt': 'hi' })).get('a/b.txt')?.toString()).toBe('hi');
    expect(readZip(makeZip({ 'x.txt': 'hello' }))[0].data().toString()).toBe('hello');
    const flat = await flattenYara('http://h/r/a.yar', async (u) => (u.endsWith('a.yar') ? 'include "../b.yar"\nrule a { condition: b }' : 'private rule b { condition: true }'));
    expect(flat).toContain('private rule b');
    expect(compareVersions('7.2-beta1', '7.1.2')).toBeGreaterThan(0);
    expect(compareVersions('7.2-RC1', '7.2-beta3')).toBeGreaterThan(0);
    expect(compareVersions('7.2', '7.2-RC1')).toBeGreaterThan(0);
  });
});
