import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import { audit, requireRole } from '../auth.js';

/**
 * Portal appearance: a ready-made theme or custom colours, chosen by an
 * administrator and applied for every user (and on the login page).
 */
const Hex = z.string().regex(/^#[0-9a-fA-F]{6}$/);
export const Appearance = z.object({
  theme: z.string().regex(/^[a-z0-9-]{2,30}$/),
  mode: z.enum(['light', 'dark']),
  // Only for theme "custom".
  sidebar: Hex.optional(),
  accent: Hex.optional(),
  // The page style: "classic" (dark sidebar, the default) or "modern"
  // (light sidebar with labels, white header, tinted icon cards).
  style: z.enum(['classic', 'modern']).optional(),
});
export type Appearance = z.infer<typeof Appearance>;

export const DEFAULT_APPEARANCE: Appearance = { theme: 'navy', mode: 'light' };

export function appearanceRoutes(app: FastifyInstance, pool: Pool): void {
  // Public: the login page is themed too. Before sign-in (or after the
  // session expired) the most recently saved choice applies.
  app.get('/api/appearance', async (req) => {
    const acc = req.user?.accountId;
    const { rows } = acc
      ? await pool.query('SELECT appearance FROM account_appearance WHERE account_id = $1', [acc])
      : await pool.query('SELECT appearance FROM account_appearance ORDER BY updated_at DESC LIMIT 1');
    const parsed = Appearance.safeParse(rows[0]?.appearance);
    return { appearance: parsed.success ? parsed.data : DEFAULT_APPEARANCE };
  });

  app.put('/api/appearance', { preHandler: requireRole('admin') }, async (req, reply) => {
    const b = Appearance.safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: 'invalid appearance' });
    if (b.data.theme === 'custom' && (!b.data.sidebar || !b.data.accent)) return reply.code(400).send({ error: 'custom themes need a sidebar and an accent colour' });
    await pool.query(
      `INSERT INTO account_appearance (account_id, appearance) VALUES ($1, $2)
       ON CONFLICT (account_id) DO UPDATE SET appearance = EXCLUDED.appearance, updated_at = now()`,
      [req.user!.accountId, JSON.stringify(b.data)],
    );
    await audit(pool, { accountId: req.user!.accountId, userId: req.user!.id, action: 'portal.appearance', detail: b.data, ip: req.ip });
    return { appearance: b.data };
  });
}
