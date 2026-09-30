import fs from 'node:fs';
import path from 'node:path';
import Fastify, { type FastifyInstance } from 'fastify';
import cookie from '@fastify/cookie';
import websocket from '@fastify/websocket';
import rateLimit from '@fastify/rate-limit';
import fastifyStatic from '@fastify/static';
import compress from '@fastify/compress';
import { constants as zlib } from 'node:zlib';
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
import { wafRulesetRoutes } from './routes/waf-rulesets.js';
import { appearanceRoutes } from './routes/appearance.js';
import { trustedRoutes } from './routes/trusted.js';
import { captchaRoutes } from './routes/captcha.js';
import { wafIntelRoutes } from './routes/waf-intel.js';
import { CRSService } from './waf/rulesets.js';

export interface App {
  app: FastifyInstance;
  hub: AgentHub;
  ipdb: IPDBService;
  ai: AIGateway;
  wp: WPCoreService;
  sigs: SignatureService;
  crs: CRSService;
}

export async function buildApp(cfg: Config, pool: Pool, opts: { logger?: boolean } = {}): Promise<App> {
  const app = Fastify({
    logger: opts.logger === false ? false : { level: cfg.logLevel },
    trustProxy: cfg.trustProxy,
    bodyLimit: 256 * 1024,
    // Firewalls in front of the portal often refuse PUT/PATCH/DELETE (OWASP
    // CRS allows only GET/HEAD/POST/OPTIONS by default), so the web app sends
    // them as POST with X-HTTP-Method-Override. A custom header cannot be set
    // cross-site without a CORS preflight, so this adds no CSRF risk.
    rewriteUrl: (req) => {
      const o = String(req.headers['x-http-method-override'] ?? '').toUpperCase();
      if (req.method === 'POST' && req.url?.startsWith('/api/') && (o === 'PUT' || o === 'PATCH' || o === 'DELETE')) req.method = o;
      return req.url ?? '/';
    },
  });
  const hub = new AgentHub(pool, app.log);
  const geo = new GeoDB();
  const ipdb = new IPDBService(pool, cfg, hub, geo, app.log);
  const ai = new AIGateway(pool, cfg, app.log);
  const wp = new WPCoreService(pool, cfg, app.log);
  const sigs = new SignatureService(pool, cfg, app.log);
  const crs = new CRSService(pool, cfg, app.log);
  void initGeo(geo, cfg.dataDir, cfg.geoUrl, app.log).then(() => ipdb.markDirty());

  await app.register(cookie);
  await app.register(rateLimit, { global: false });
  // API answers (agent data can be large) are compressed; quick settings,
  // since they are made for every request. Web files come precompressed.
  await app.register(compress, {
    global: true,
    threshold: 1024,
    encodings: ['br', 'gzip'],
    brotliOptions: { params: { [zlib.BROTLI_PARAM_QUALITY]: 4 } },
    zlibOptions: { level: 6 },
  });
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
  wafRulesetRoutes(app, pool, hub, crs);
  appearanceRoutes(app, pool);
  trustedRoutes(app, pool, hub);
  captchaRoutes(app, pool, cfg, hub);
  wafIntelRoutes(app, pool, hub);
  // API answers are live data: never stored by browsers or proxies/CDNs.
  app.addHook('onSend', async (req, reply, payload) => {
    if (req.url.startsWith('/api/') && !reply.hasHeader('Cache-Control')) reply.header('Cache-Control', 'no-store');
    return payload;
  });

  if (cfg.webDir && fs.existsSync(path.join(cfg.webDir, 'index.html'))) {
    // Hashed build assets never change; index.html must always be checked so
    // a portal update is picked up (an old cached page kept old code, e.g.
    // an old theme, after updating).
    await app.register(fastifyStatic, {
      root: cfg.webDir,
      wildcard: false,
      cacheControl: false,
      // Brotli/gzip copies made at build time (web/scripts/compress.mjs).
      preCompressed: true,
      setHeaders: (res, file) => {
        res.header('Cache-Control', file.includes(`${path.sep}assets${path.sep}`) ? 'public, max-age=31536000, immutable' : 'no-cache');
      },
    });
    // SPA fallback for client-side routes. Machine paths (API, downloads,
    // MCP, /.well-known OAuth discovery) get a real 404 so AI clients see
    // that no sign-in service exists instead of an HTML page.
    const machine = ['/api/', '/downloads/', '/mcp', '/.well-known/'];
    app.setNotFoundHandler((req, reply) => {
      // cPanel's error documents (/403.shtml …) fetched through the proxy
      // must stay errors, not turn into the home page with status 200.
      if (req.method === 'GET' && !machine.some((p) => req.url.startsWith(p)) && !/\.shtml(?:\?|$)/.test(req.url)) {
        return reply.type('text/html').header('Cache-Control', 'no-cache').sendFile('index.html');
      }
      return reply.code(404).send({ error: 'not found' });
    });
  }

  ipdb.start();
  ai.start();
  wp.start();
  sigs.start();
  crs.start();
  app.addHook('onClose', async () => {
    ipdb.stop();
    ai.stop();
    wp.stop();
    sigs.stop();
    crs.stop();
    hub.closeAll();
  });
  return { app, hub, ipdb, ai, wp, sigs, crs };
}
