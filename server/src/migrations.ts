/**
 * Ordered schema migrations. Never edit an applied migration; append a new one.
 */
export const migrations: { version: string; sql: string }[] = [
  {
    version: '001_init',
    sql: `
CREATE TABLE accounts (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id     uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  email          text NOT NULL,
  name           text NOT NULL DEFAULT '',
  password_hash  text NOT NULL,
  role           text NOT NULL CHECK (role IN ('owner','admin','operator','viewer')),
  created_at     timestamptz NOT NULL DEFAULT now(),
  last_login_at  timestamptz
);
CREATE UNIQUE INDEX users_email_uq ON users (lower(email));

CREATE TABLE sessions (
  id          text PRIMARY KEY,               -- sha256 of the cookie token
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  ip          text,
  user_agent  text
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

CREATE TABLE servers (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id     uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  hostname       text NOT NULL DEFAULT '',
  public_key     text NOT NULL UNIQUE,
  status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  agent_version  text NOT NULL DEFAULT '',
  inventory      jsonb NOT NULL DEFAULT '{}'::jsonb,
  primary_ip     text NOT NULL DEFAULT '',
  os_name        text NOT NULL DEFAULT '',
  control_panel  text NOT NULL DEFAULT '',
  web_server     text NOT NULL DEFAULT '',
  tags           text[] NOT NULL DEFAULT '{}',
  connected      boolean NOT NULL DEFAULT false,
  last_seen_at   timestamptz,
  last_metrics   jsonb,
  created_at     timestamptz NOT NULL DEFAULT now(),
  revoked_at     timestamptz
);
CREATE INDEX servers_account_idx ON servers (account_id) WHERE status = 'active';

CREATE TABLE enrollment_tokens (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id  uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  token_hash  text NOT NULL UNIQUE,
  label       text NOT NULL DEFAULT '',
  created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  server_id   uuid REFERENCES servers(id) ON DELETE SET NULL
);

CREATE TABLE server_metrics (
  server_id    uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  ts           timestamptz NOT NULL,
  cpu          real NOT NULL,
  load1        real NOT NULL,
  load5        real NOT NULL,
  load15       real NOT NULL,
  mem_used     bigint NOT NULL,
  mem_total    bigint NOT NULL,
  swap_used    bigint NOT NULL,
  swap_total   bigint NOT NULL,
  disk_used    bigint NOT NULL,
  disk_total   bigint NOT NULL,
  connections  integer NOT NULL,
  PRIMARY KEY (server_id, ts)
);

CREATE TABLE audit_events (
  id          bigserial PRIMARY KEY,
  account_id  uuid REFERENCES accounts(id) ON DELETE CASCADE,
  user_id     uuid REFERENCES users(id) ON DELETE SET NULL,
  server_id   uuid REFERENCES servers(id) ON DELETE SET NULL,
  action      text NOT NULL,
  detail      jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip          text,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_account_idx ON audit_events (account_id, created_at DESC);
`,
  },
  {
    version: '002_ipdb',
    sql: `
-- Automatic bans reported by agents (brute force, DoS, ...).
CREATE TABLE ipdb_reports (
  id          bigserial PRIMARY KEY,
  ip          inet NOT NULL,
  server_id   uuid REFERENCES servers(id) ON DELETE CASCADE,
  account_id  uuid REFERENCES accounts(id) ON DELETE CASCADE,
  source      text NOT NULL DEFAULT '',
  reason      text NOT NULL DEFAULT '',
  reported_at timestamptz NOT NULL DEFAULT now(),
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ipdb_reports_ip_idx ON ipdb_reports (ip, created_at);
CREATE INDEX ipdb_reports_created_idx ON ipdb_reports (created_at);

-- The distributed list every agent drops.
CREATE TABLE ipdb_entries (
  cidr        cidr PRIMARY KEY,
  source      text NOT NULL CHECK (source IN ('community','manual','feed')),
  country     text NOT NULL DEFAULT '',
  reporters   integer NOT NULL DEFAULT 0,
  reports     integer NOT NULL DEFAULT 0,
  reason      text NOT NULL DEFAULT '',
  note        text NOT NULL DEFAULT '',
  first_seen  timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz,
  created_by  uuid REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX ipdb_entries_source_idx ON ipdb_entries (source);

-- Never listed, whatever is reported.
CREATE TABLE ipdb_whitelist (
  cidr        cidr PRIMARY KEY,
  note        text NOT NULL DEFAULT '',
  created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Traffic dropped by IPDB entries, per server and day (live monitor + map).
CREATE TABLE ipdb_hits (
  server_id   uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  entry       text NOT NULL,
  day         date NOT NULL,
  country     text NOT NULL DEFAULT '',
  hits        bigint NOT NULL DEFAULT 0,
  last_seen   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (server_id, entry, day)
);
CREATE INDEX ipdb_hits_last_idx ON ipdb_hits (last_seen DESC);
CREATE INDEX ipdb_hits_day_idx ON ipdb_hits (day);

ALTER TABLE servers
  ADD COLUMN ipdb_cursor  bigint NOT NULL DEFAULT 0,
  ADD COLUMN ipdb_version text NOT NULL DEFAULT '',
  ADD COLUMN ipdb_synced_at timestamptz;
`,
  },
  {
    version: '003_ai',
    sql: `
-- Free AI API keys the AI scanner uses (Gemini, Groq, OpenRouter, ...).
-- Several keys per provider are allowed; the gateway fails over between them.
CREATE TABLE ai_providers (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id     uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  kind           text NOT NULL,
  name           text NOT NULL DEFAULT '',
  base_url       text NOT NULL,
  api_key        text NOT NULL DEFAULT '',
  model          text NOT NULL,
  priority       integer NOT NULL DEFAULT 100,
  enabled        boolean NOT NULL DEFAULT true,
  cooldown_until timestamptz,
  last_error     text NOT NULL DEFAULT '',
  last_error_at  timestamptz,
  last_ok_at     timestamptz,
  requests       bigint NOT NULL DEFAULT 0,
  failures       bigint NOT NULL DEFAULT 0,
  files          bigint NOT NULL DEFAULT 0,
  tokens_in      bigint NOT NULL DEFAULT 0,
  tokens_out     bigint NOT NULL DEFAULT 0,
  day            date NOT NULL DEFAULT current_date,
  requests_today integer NOT NULL DEFAULT 0,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ai_providers_account_idx ON ai_providers (account_id, priority);

-- The fleet's knowledge: one verdict per distinct file, shared by all servers.
CREATE TABLE ai_kb (
  seq         bigserial UNIQUE,
  sha256      text PRIMARY KEY,
  size        bigint NOT NULL DEFAULT 0,
  verdict     text NOT NULL CHECK (verdict IN ('malicious','suspicious','clean')),
  confidence  integer NOT NULL DEFAULT 0,
  reason      text NOT NULL DEFAULT '',
  injected    boolean NOT NULL DEFAULT false,
  cut         jsonb NOT NULL DEFAULT '[]'::jsonb,
  model       text NOT NULL DEFAULT '',
  name        text NOT NULL DEFAULT '',
  match       text NOT NULL DEFAULT '',
  server_id   uuid REFERENCES servers(id) ON DELETE SET NULL,
  hits        integer NOT NULL DEFAULT 1,
  overridden  boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ai_kb_created_idx ON ai_kb (created_at DESC);

-- Training samples for the fleet model: the built-in model's features and
-- logit for a file, labelled by the AI.
CREATE TABLE ai_samples (
  sha256        text NOT NULL,
  base_version  text NOT NULL,
  z             real NOT NULL,
  features      integer[] NOT NULL,
  label         smallint NOT NULL,
  weight        real NOT NULL DEFAULT 1,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (sha256, base_version)
);

-- The trained update each agent applies on top of its built-in model.
CREATE TABLE ai_models (
  base_version  text PRIMARY KEY,
  version       bigint NOT NULL,
  bias          real NOT NULL DEFAULT 0,
  entries       jsonb NOT NULL DEFAULT '[]'::jsonb,
  samples       integer NOT NULL DEFAULT 0,
  accuracy      real NOT NULL DEFAULT 0,
  trained_at    timestamptz NOT NULL DEFAULT now()
);
`,
  },
  {
    version: '004_wpcore_signatures',
    sql: `
-- Official WordPress core checksums per version (releases, betas, RCs).
CREATE TABLE wp_core_versions (
  version     text PRIMARY KEY,
  channel     text NOT NULL DEFAULT 'stable',
  files       integer NOT NULL DEFAULT 0,
  checksums   jsonb NOT NULL,
  source      text NOT NULL DEFAULT 'api',
  fetched_at  timestamptz NOT NULL DEFAULT now()
);

-- Downloaded malware signature feeds (latest good copy of each).
CREATE TABLE sig_feeds (
  url         text PRIMARY KEY,
  kind        text NOT NULL,
  etag        text NOT NULL DEFAULT '',
  bundle      jsonb NOT NULL DEFAULT '{}'::jsonb,
  counts      jsonb NOT NULL DEFAULT '{}'::jsonb,
  error       text NOT NULL DEFAULT '',
  fetched_at  timestamptz
);
`,
  },
  {
    version: '005_mcp_tokens',
    sql: `
-- Tokens for AI assistants connecting over MCP (Model Context Protocol).
CREATE TABLE mcp_tokens (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id    uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  created_by    uuid REFERENCES users(id) ON DELETE SET NULL,
  label         text NOT NULL DEFAULT '',
  token_hash    text NOT NULL UNIQUE,
  prefix        text NOT NULL,
  scope         text NOT NULL CHECK (scope IN ('read','write')),
  last_used_at  timestamptz,
  calls         bigint NOT NULL DEFAULT 0,
  revoked_at    timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mcp_tokens_account_idx ON mcp_tokens (account_id, created_at DESC);
`,
  },
  {
    version: '006_waf_rulesets',
    sql: `
-- WAF Rule Sets: one ModSecurity configuration per account, rolled out to
-- every server (XMart Guard rules, OWASP CRS, cPanel vendors, custom rules).
CREATE TABLE waf_rulesets (
  account_id  uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  config      jsonb NOT NULL DEFAULT '{}'::jsonb,
  version     bigint NOT NULL DEFAULT 1,
  updated_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- OWASP CRS releases downloaded from the official GitHub repository.
CREATE TABLE waf_crs (
  version     text PRIMARY KEY,
  files       jsonb NOT NULL,
  size        integer NOT NULL DEFAULT 0,
  source      text NOT NULL DEFAULT '',
  published   timestamptz,
  fetched_at  timestamptz NOT NULL DEFAULT now()
);

-- What each server reported after applying the rule sets.
CREATE TABLE waf_server_status (
  server_id   uuid PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
  version     bigint NOT NULL DEFAULT 0,
  status      jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at  timestamptz NOT NULL DEFAULT now()
);
`,
  },
];
