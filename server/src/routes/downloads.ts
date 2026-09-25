import fs from 'node:fs/promises';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';
import type { Config } from '../config.js';

// Only these files are ever served from downloadsDir.
const ALLOWED = /^xmartguard-agent-linux-(amd64|arm64)(\.sha256)?$/;

/**
 * Serves the one-line installer scripts (with this portal's URL baked in) and
 * the agent binaries they download.
 */
export function downloadRoutes(app: FastifyInstance, cfg: Config): void {
  async function script(name: 'install.sh' | 'uninstall.sh' | 'selftest.sh') {
    const raw = await fs.readFile(path.join(cfg.installerDir, name), 'utf8');
    return raw.replaceAll('__XG_PORTAL_URL__', cfg.publicUrl);
  }

  for (const name of ['install.sh', 'uninstall.sh', 'selftest.sh'] as const) {
    app.get(`/${name}`, async (_req, reply) => {
      reply.header('Cache-Control', 'no-store').type('text/x-shellscript; charset=utf-8');
      return script(name);
    });
  }

  app.get('/downloads/:file', async (req, reply) => {
    const file = (req.params as { file: string }).file;
    if (!ALLOWED.test(file)) return reply.code(404).send({ error: 'not found' });
    const full = path.join(cfg.downloadsDir, file);
    let data: Buffer;
    try {
      data = await fs.readFile(full);
    } catch {
      return reply.code(404).send({ error: 'not found' });
    }
    reply.header('Cache-Control', 'no-cache');
    reply.type(file.endsWith('.sha256') ? 'text/plain; charset=utf-8' : 'application/octet-stream');
    return data;
  });
}
