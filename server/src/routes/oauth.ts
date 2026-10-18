import crypto from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { Pool } from '../db.js';
import type { Config } from '../config.js';
import { audit, hasRole } from '../auth.js';
import { randomToken, sha256 } from '../security.js';

/**
 * OAuth 2.1 sign-in for the MCP connector (the MCP authorization spec), for
 * clients that do not take a token in the URL: Claude Code in the cloud,
 * Claude's connector directory with "OAuth", and other MCP clients.
 *
 * - discovery: /.well-known/oauth-protected-resource[/mcp] and
 *   /.well-known/oauth-authorization-server (also as openid-configuration);
 * - dynamic client registration (public clients, PKCE S256 only);
 * - /oauth/authorize: an owner or admin signed in to the portal approves
 *   the connection (read & write by default);
 * - /oauth/token: authorization_code and refresh_token grants.
 *
 * The access token is an ordinary MCP token (mcp_tokens, linked to the
 * grant): it does not expire, so the connector keeps working until it is
 * revoked on the AI Connector page. The refresh token stays the same for the
 * life of the grant, so two client sessions refreshing at once never lock
 * each other out.
 */

const CODE_TTL_MINUTES = 10;
/** A replaced access token keeps working this long (another session may hold it). */
const OLD_TOKEN_GRACE = '1 day';

const RegisterBody = z.object({
  redirect_uris: z.array(z.string().max(2000)).min(1).max(10),
  client_name: z.string().max(200).optional(),
  token_endpoint_auth_method: z.string().optional(),
  grant_types: z.array(z.string()).optional(),
  response_types: z.array(z.string()).optional(),
});

const DecisionBody = z.object({
  client_id: z.string().min(1).max(200),
  redirect_uri: z.string().min(1).max(2000),
  code_challenge: z.string().min(43).max(128),
  state: z.string().max(2000).optional(),
  scope: z.enum(['read', 'write']),
  approve: z.boolean(),
});

/** https anywhere; plain http only back to this computer (desktop clients). */
export function validRedirect(uri: string): boolean {
  try {
    const u = new URL(uri);
    if (u.hash) return false;
    if (u.protocol === 'https:') return true;
    return u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  } catch {
    return false;
  }
}

const s256 = (verifier: string) => crypto.createHash('sha256').update(verifier).digest('base64url');

/** "read" only when asked for alone; otherwise read & write. */
const pickScope = (asked: unknown): 'read' | 'write' => {
  const parts = String(asked ?? '').split(/\s+/).filter(Boolean);
  return parts.length && parts.every((p) => p === 'read') ? 'read' : 'write';
};

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

function withParams(uri: string, params: Record<string, string | undefined>): string {
  const u = new URL(uri);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) u.searchParams.set(k, v);
  return u.toString();
}

export function oauthRoutes(app: FastifyInstance, pool: Pool, cfg: Config): void {
  // Read on every request: the public URL may be set after start-up.
  const baseUrl = () => cfg.publicUrl;
  const resourceUrl = () => `${cfg.publicUrl}/mcp`;

  const resourceMeta = () => ({ resource: resourceUrl(), authorization_servers: [baseUrl()], scopes_supported: ['read', 'write'], bearer_methods_supported: ['header'], resource_name: 'xPGuard' });
  const serverMeta = (base = baseUrl()) => ({
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/oauth/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    scopes_supported: ['read', 'write'],
  });
  const json = (reply: FastifyReply, body: unknown) => reply.header('Cache-Control', 'no-store').header('Access-Control-Allow-Origin', '*').send(body);
  for (const p of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
    app.get(p, async (_req, reply) => json(reply, resourceMeta()));
  }
  for (const p of ['/.well-known/oauth-authorization-server', '/.well-known/openid-configuration']) {
    app.get(p, async (_req, reply) => json(reply, serverMeta()));
  }

  const limit = (max: number) => ({ config: { rateLimit: { max, timeWindow: '1 minute' } } });

  // ------------------------------------------------------------ registration

  app.post('/oauth/register', limit(20), async (req, reply) => {
    const b = RegisterBody.safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: 'invalid_client_metadata', error_description: 'redirect_uris is required' });
    const uris = [...new Set(b.data.redirect_uris)];
    if (!uris.every(validRedirect)) return reply.code(400).send({ error: 'invalid_redirect_uri', error_description: 'redirect URIs must use https (or http to localhost)' });
    const clientId = 'xgc_' + randomToken(16);
    const name = (b.data.client_name ?? '').trim().slice(0, 200) || 'MCP client';
    await pool.query(`INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES ($1, $2, $3)`, [clientId, name, uris]);
    return reply.code(201).header('Cache-Control', 'no-store').send({
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_name: name,
      redirect_uris: uris,
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    });
  });

  async function client(id: unknown): Promise<{ client_id: string; client_name: string; redirect_uris: string[] } | null> {
    const { rows } = await pool.query(`SELECT client_id, client_name, redirect_uris FROM oauth_clients WHERE client_id = $1`, [String(id ?? '').slice(0, 200)]);
    return rows[0] ?? null;
  }

  // ------------------------------------------------------------ authorize

  function page(reply: FastifyReply, status: number, title: string, body: string) {
    return reply
      .code(status)
      .header('Cache-Control', 'no-store')
      .header('X-Frame-Options', 'DENY')
      .type('text/html; charset=utf-8')
      .send(
        `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>` +
          `<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0b1730;font:15px/1.5 system-ui,sans-serif;color:#0f172a;padding:16px}` +
          `.c{background:#fff;border-radius:14px;max-width:440px;width:100%;padding:28px;box-shadow:0 10px 40px #0005}h1{font-size:19px;margin:0 0 12px}` +
          `ul{padding-left:20px;color:#334155}.b{display:flex;gap:10px;margin-top:22px}button{flex:1;padding:11px;border-radius:9px;border:0;font-weight:600;cursor:pointer;font-size:15px}` +
          `.ok{background:#1d4ed8;color:#fff}.no{background:#e2e8f0;color:#0f172a}.m{color:#64748b;font-size:13px;margin-top:14px}.e{color:#b91c1c}</style></head>` +
          `<body><div class="c">${body}</div></body></html>`,
      );
  }

  app.get('/oauth/authorize', limit(60), async (req: FastifyRequest, reply) => {
    const q = req.query as Record<string, string | undefined>;
    const c = await client(q.client_id);
    // Without a known client and redirect URI nothing may be sent back.
    if (!c || !q.redirect_uri || !c.redirect_uris.includes(q.redirect_uri)) {
      return page(reply, 400, 'Connector sign-in', `<h1>Connector sign-in</h1><p class="e">This sign-in link is not valid (unknown client or redirect address). Add the connector again in your AI app.</p>`);
    }
    const back = (params: Record<string, string>) => reply.redirect(withParams(q.redirect_uri!, { ...params, state: q.state, iss: baseUrl() }));
    if (q.response_type !== 'code') return back({ error: 'unsupported_response_type' });
    if (q.code_challenge_method !== 'S256' || !q.code_challenge || !/^[A-Za-z0-9_-]{43,128}$/.test(q.code_challenge)) {
      return back({ error: 'invalid_request', error_description: 'PKCE with S256 is required' });
    }
    if (q.resource && q.resource.replace(/\/+$/, '') !== resourceUrl()) return back({ error: 'invalid_target' });
    if (!req.user) return reply.redirect(`/login?admin&next=${encodeURIComponent(req.url)}`);
    if (!hasRole(req.user, 'admin')) {
      return page(reply, 403, 'Connector sign-in', `<h1>Connector sign-in</h1><p class="e">Only an owner or admin of the account can connect an AI assistant.</p>`);
    }
    const scope = pickScope(q.scope);
    const params = { client_id: c.client_id, redirect_uri: q.redirect_uri, code_challenge: q.code_challenge, state: q.state ?? '', scope };
    const perms =
      scope === 'write'
        ? '<li>Read every server: dashboards, malware findings, WAF, firewall and IPDB logs, settings</li><li>Run actions: scans, quarantine and restore, settings, firewall, WAF rules</li>'
        : '<li>Read every server: dashboards, malware findings, WAF, firewall and IPDB logs, settings</li>';
    return page(
      reply,
      200,
      'Connect an AI assistant',
      `<h1>Connect “${esc(c.client_name)}” to xPGuard?</h1><p>Signed in as <b>${esc(req.user.email)}</b>. The assistant may:</p><ul>${perms}</ul>` +
        // Any app can call itself "Claude": the address the access goes to tells them apart.
        `<p class="m">Access goes to <b>${esc(new URL(q.redirect_uri).host)}</b>. Allow only if you started this from your AI app.</p>` +
        `<div class="b"><button class="no" id="no">Deny</button><button class="ok" id="ok">Allow</button></div>` +
        `<p class="m">It keeps this access until you revoke it on the AI Connector page. Every action it runs is in the audit log.</p>` +
        `<script>const p=${JSON.stringify(params).replace(/</g, '\\u003c')};` +
        `async function go(a){document.querySelectorAll('button').forEach(b=>b.disabled=true);` +
        `const r=await fetch('/oauth/authorize/decision',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({...p,approve:a})});` +
        `const j=await r.json().catch(()=>({}));if(j.redirect)location.replace(j.redirect);else{document.querySelector('.c').insertAdjacentHTML('beforeend','<p class="e">'+(j.error||'Something went wrong')+'</p>')}}` +
        `document.getElementById('ok').onclick=()=>go(true);document.getElementById('no').onclick=()=>go(false);</script>`,
    );
  });

  // The consent page's buttons (JSON and same-origin: the CSRF hook checks both).
  app.post('/oauth/authorize/decision', limit(30), async (req, reply) => {
    if (!req.user) return reply.code(401).send({ error: 'Your portal session ended; sign in again.' });
    if (!hasRole(req.user, 'admin')) return reply.code(403).send({ error: 'Only an owner or admin can connect an AI assistant.' });
    const b = DecisionBody.safeParse(req.body);
    if (!b.success) return reply.code(400).send({ error: 'invalid request' });
    const c = await client(b.data.client_id);
    if (!c || !c.redirect_uris.includes(b.data.redirect_uri)) return reply.code(400).send({ error: 'unknown client' });
    const state = b.data.state || undefined;
    if (!b.data.approve) return { redirect: withParams(b.data.redirect_uri, { error: 'access_denied', state, iss: baseUrl() }) };
    const code = randomToken(32);
    await pool.query(
      `INSERT INTO oauth_codes (code_hash, client_id, account_id, user_id, redirect_uri, code_challenge, scope, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(mins => $8))`,
      [sha256(code), c.client_id, req.user.accountId, req.user.id, b.data.redirect_uri, b.data.code_challenge, b.data.scope, CODE_TTL_MINUTES],
    );
    await audit(pool, { accountId: req.user.accountId, userId: req.user.id, action: 'mcp.oauth_approved', detail: { client: c.client_name, scope: b.data.scope }, ip: req.ip });
    return { redirect: withParams(b.data.redirect_uri, { code, state, iss: baseUrl() }) };
  });

  // ------------------------------------------------------------ token

  // OAuth clients post the token request as a form; only these routes parse it.
  app.register(async (sub) => {
    sub.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string', bodyLimit: 16_384 }, (_req, body, done) => {
      done(null, Object.fromEntries(new URLSearchParams(String(body))));
    });

    const err = (reply: FastifyReply, error: string, description: string, status = 400) =>
      reply.code(status).header('Cache-Control', 'no-store').send({ error, error_description: description });

    async function issue(grantId: string, accountId: string, userId: string, scope: string, label: string): Promise<string> {
      const token = 'xgm_' + randomToken(32);
      await pool.query(
        `INSERT INTO mcp_tokens (account_id, created_by, label, token_hash, prefix, scope, grant_id) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [accountId, userId, label, sha256(token), token.slice(0, 10), scope, grantId],
      );
      return token;
    }

    sub.post('/oauth/token', limit(60), async (req, reply) => {
      const b = (req.body ?? {}) as Record<string, string | undefined>;
      const clientId = String(b.client_id ?? '');
      if (b.grant_type === 'authorization_code') {
        if (!b.code || !b.code_verifier || !b.redirect_uri || !clientId) return err(reply, 'invalid_request', 'code, code_verifier, redirect_uri and client_id are required');
        // One use only, even when two requests race.
        const { rows } = await pool.query(
          `UPDATE oauth_codes SET used_at = now() WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now() RETURNING *`,
          [sha256(b.code)],
        );
        const code = rows[0];
        if (!code || code.client_id !== clientId || code.redirect_uri !== b.redirect_uri || s256(b.code_verifier) !== code.code_challenge) {
          return err(reply, 'invalid_grant', 'the code is invalid, expired or was already used');
        }
        const c = await client(clientId);
        const refresh = 'xgr_' + randomToken(32);
        const g = await pool.query(
          `INSERT INTO oauth_grants (client_id, account_id, user_id, scope, refresh_hash) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
          [clientId, code.account_id, code.user_id, code.scope, sha256(refresh)],
        );
        const access = await issue(g.rows[0].id, code.account_id, code.user_id, code.scope, `${c?.client_name ?? 'MCP client'} (sign-in)`);
        return reply.header('Cache-Control', 'no-store').send({ access_token: access, token_type: 'Bearer', refresh_token: refresh, scope: code.scope });
      }
      if (b.grant_type === 'refresh_token') {
        if (!b.refresh_token) return err(reply, 'invalid_request', 'refresh_token is required');
        const { rows } = await pool.query(
          `SELECT g.id, g.client_id, g.account_id, g.user_id, g.scope, c.client_name
             FROM oauth_grants g JOIN oauth_clients c ON c.client_id = g.client_id JOIN users u ON u.id = g.user_id
            WHERE g.refresh_hash = $1 AND g.revoked_at IS NULL AND u.role IN ('owner','admin')`,
          [sha256(b.refresh_token)],
        );
        const g = rows[0];
        if (!g || (clientId && clientId !== g.client_id)) return err(reply, 'invalid_grant', 'the connection was revoked; connect the assistant again');
        await pool.query(
          `UPDATE mcp_tokens SET revoked_at = now() + interval '${OLD_TOKEN_GRACE}' WHERE grant_id = $1 AND revoked_at IS NULL`,
          [g.id],
        );
        const access = await issue(g.id, g.account_id, g.user_id, g.scope, `${g.client_name} (sign-in)`);
        return reply.header('Cache-Control', 'no-store').send({ access_token: access, token_type: 'Bearer', refresh_token: b.refresh_token, scope: g.scope });
      }
      return err(reply, 'unsupported_grant_type', 'use authorization_code or refresh_token');
    });
  });
}
