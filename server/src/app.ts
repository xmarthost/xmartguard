import fs from 'node:fs';
import path from 'node:path';
import Fastify, { type FastifyInstance } from 'fastify';
import cookie from '@fastify/cookie';
import websocket from '@fastify/websocket';
import rateLimit from '@fastify/rate-limit';
import fastifyStatic from '@fastify/static';
import type { Config } from './config.js';
import type { Pool } from './db.js';
import { AgentHub } from './agents/hub.js';
import { registerAuth } from './auth.js';
import { authRoutes } from './routes/auth.js';
import { agentRoutes } from './routes/agent.js';
import { serverRoutes } from './routes/servers.js';
import { userRoutes } from './routes/users.js';
import { downloadRoutes } from './routes/downloads.js';

export interface App {
  app: FastifyInstance;
  hub: AgentHub;
}

export async function buildApp(cfg: Config, pool: Pool, opts: { logger?: boolean } = {}): Promise<App> {
  const app = Fastify({
    logger: opts.logger === false ? false : { level: cfg.logLevel },
    trustProxy: cfg.trustProxy,
    bodyLimit: 256 * 1024,
  });
  const hub = new AgentHub(pool, app.log);

  await app.register(cookie);
  await app.register(rateLimit, { global: false });
  await app.register(websocket, { options: { maxPayload: 4 * 1024 * 1024 } });

  app.addHook('onSend', async (_req, reply) => {
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('X-Frame-Options', 'DENY');
    reply.header('Referrer-Policy', 'same-origin');
  });

  registerAuth(app, pool);
  app.get('/api/health', async () => ({ ok: true }));
  authRoutes(app, pool, cfg);
  agentRoutes(app, pool, cfg, hub);
  serverRoutes(app, pool, cfg, hub);
  userRoutes(app, pool);
  downloadRoutes(app, cfg);

  if (cfg.webDir && fs.existsSync(path.join(cfg.webDir, 'index.html'))) {
    await app.register(fastifyStatic, { root: cfg.webDir, wildcard: false });
    // SPA fallback for client-side routes.
    app.setNotFoundHandler((req, reply) => {
      if (req.method === 'GET' && !req.url.startsWith('/api/') && !req.url.startsWith('/downloads/')) {
        return reply.type('text/html').sendFile('index.html');
      }
      return reply.code(404).send({ error: 'not found' });
    });
  }

  app.addHook('onClose', async () => hub.closeAll());
  return { app, hub };
}
