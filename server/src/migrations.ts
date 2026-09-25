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
];
