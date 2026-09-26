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
import { agentCommandRoutes } from './routes/agent-cmd.js';
import { ipdbRoutes } from './routes/ipdb.js';
import { massRoutes } from './routes/mass.js';
import { aiRoutes } from './routes/ai.js';
import { GeoDB, initGeo } from './ipdb/geo.js';
import { IPDBService } from './ipdb/service.js';
import { AIGateway } from './ai/gateway.js';
import { WPCoreService } from './wpcore/service.js';
import { SignatureService } from './signatures/service.js';
import { wpcoreRoutes } from './routes/wpcore.js';
import { mcpRoutes } from './routes/mcp.js';

export interface App {
  app: FastifyInstance;
  hub: AgentHub;
  ipdb: IPDBService;
  ai: AIGateway;
  wp: WPCoreService;
  sigs: SignatureService;
}

export async function buildApp(cfg: Config, pool: Pool, opts: { logger?: boolean } = {}): Promise<App> {
  const app = Fastify({
    logger: opts.logger === false ? false : { level: cfg.logLevel },
    trustProxy: cfg.trustProxy,
    bodyLimit: 256 * 1024,
  });
  const hub = new AgentHub(pool, app.log);
  const geo = new GeoDB();
  const ipdb = new IPDBService(pool, cfg, hub, geo, app.log);
  const ai = new AIGateway(pool, cfg, app.log);
  const wp = new WPCoreService(pool, cfg, app.log);
  const sigs = new SignatureService(pool, cfg, app.log);
  void initGeo(geo, cfg.dataDir, cfg.geoUrl, app.log).then(() => ipdb.markDirty());

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
  agentRoutes(app, pool, cfg, hub, ipdb);
  serverRoutes(app, pool, cfg, hub);
  userRoutes(app, pool);
  downloadRoutes(app, cfg);
  agentCommandRoutes(app, pool, cfg, hub);
  ipdbRoutes(app, pool, ipdb);
  massRoutes(app, pool, cfg, hub);
  aiRoutes(app, pool, ai);
  wpcoreRoutes(app, pool, wp, sigs);
  mcpRoutes(app, pool, cfg, hub);

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

  ipdb.start();
  ai.start();
  wp.start();
  sigs.start();
  app.addHook('onClose', async () => {
    ipdb.stop();
    ai.stop();
    wp.stop();
    sigs.stop();
    hub.closeAll();
  });
  return { app, hub, ipdb, ai, wp, sigs };
}
