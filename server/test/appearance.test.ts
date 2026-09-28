import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, type Harness } from './helpers.js';

let h: Harness;
let c: Client;
beforeAll(async () => {
  h = await startHarness();
  c = new Client(h.url);
});
afterAll(async () => h.close());

describe('appearance', () => {
  it('defaults to navy and is readable before sign-in', async () => {
    const r = await new Client(h.url).req('GET', '/api/appearance');
    expect(r.body.appearance).toEqual({ theme: 'navy', mode: 'light' });
  });

  it('lets an admin save a theme for everyone', async () => {
    expect((await c.req('PUT', '/api/appearance', { theme: 'midnight', mode: 'dark' })).status).toBe(401);
    await c.login();
    expect((await c.req('PUT', '/api/appearance', { theme: 'custom', mode: 'light' })).status).toBe(400);
    expect((await c.req('PUT', '/api/appearance', { theme: 'custom', mode: 'dark', sidebar: '#123456', accent: 'red' })).status).toBe(400);
    expect((await c.req('PUT', '/api/appearance', { theme: 'custom', mode: 'dark', sidebar: '#123456', accent: '#ff8800' })).status).toBe(200);
    const anon = await new Client(h.url).req('GET', '/api/appearance');
    expect(anon.body.appearance).toEqual({ theme: 'custom', mode: 'dark', sidebar: '#123456', accent: '#ff8800' });
  });
});
