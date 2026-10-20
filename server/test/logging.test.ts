import { Writable } from 'node:stream';
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import { logOptions, redactUrl } from '../src/app.js';

describe('request log', () => {
  it('never writes MCP tokens or one-time link tokens', async () => {
    let out = '';
    const stream = new Writable({
      write(chunk, _enc, cb) {
        out += chunk.toString();
        cb();
      },
    });
    const app = Fastify({ logger: { ...logOptions('info'), stream } });
    app.post('/mcp/:token', async () => ({ ok: true }));
    app.get('/sso', async () => ({ ok: true }));
    await app.inject({ method: 'POST', url: '/mcp/xgm_secretvalue123', payload: {} });
    await app.inject({ method: 'GET', url: '/sso?token=linkvalue456&x=1' });
    await app.close();
    expect(out).toContain('incoming request');
    expect(out).not.toContain('xgm_secretvalue123');
    expect(out).not.toContain('linkvalue456');
    expect(out).toContain('/mcp/***');
    expect(redactUrl('/set-password?token=abc')).toBe('/set-password?token=***');
    expect(redactUrl('/api/auth/set-password?x=1&token=abc')).toBe('/api/auth/set-password?x=1&token=***');
    expect(redactUrl('/api/servers')).toBe('/api/servers');
  });
});
