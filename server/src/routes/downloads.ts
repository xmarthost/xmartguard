import { createReadStream } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';
import type { Config } from '../config.js';

// Only these files are ever served from downloadsDir. Agents before 0.11
// (and their installers) ask for the program by its old name.
const ALLOWED = /^(?:xpguard|xmartguard)-agent-linux-(amd64|arm64)(\.sha256)?$/;

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
    // Streamed, not read into memory: after a portal restart every agent
    // downloads the ~18 MB binary at once.
    let found: { file: string; size: number } | null = null;
    const names = [file.replace(/^xmartguard-/, 'xpguard-'), file];
    for (const name of names) {
      try {
        const p = path.join(cfg.downloadsDir, name);
        const st = await fs.stat(p);
        if (st.isFile()) {
          found = { file: p, size: st.size };
          break;
        }
      } catch {
        /* try the next name */
      }
    }
    if (!found) return reply.code(404).send({ error: 'not found' });
    reply.header('Cache-Control', 'no-cache');
    reply.header('Content-Length', found.size);
    reply.type(file.endsWith('.sha256') ? 'text/plain; charset=utf-8' : 'application/octet-stream');
    return reply.send(createReadStream(found.file));
  });
}
