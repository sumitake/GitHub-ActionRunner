export const FLEET_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS fleet_state (
  fleet_id TEXT PRIMARY KEY,
  inventoried INTEGER NOT NULL,
  epoch INTEGER NOT NULL,
  session_id TEXT,
  sequence INTEGER NOT NULL,
  lease_generation INTEGER NOT NULL,
  last_issued_lease_expiry_max TEXT,
  lease_not_before TEXT,
  holder TEXT NOT NULL,
  fence_generation INTEGER NOT NULL,
  routing_state TEXT NOT NULL,
  hosted_hold INTEGER NOT NULL,
  config_revision INTEGER NOT NULL,
  policy_digest TEXT,
  max_capacity INTEGER NOT NULL,
  canary_scale_set TEXT,
  canary_passed INTEGER NOT NULL,
  canary_evidence TEXT,
  cron_inventory_revision TEXT,
  cron_inventory_digest TEXT,
  cron_tick_timestamp TEXT,
  cron_tick_nonce TEXT,
  cron_addressed_at TEXT,
  persistence_generation INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS request_nonces (
  digest TEXT PRIMARY KEY,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS repositories (
  alias TEXT PRIMARY KEY,
  expected_route TEXT NOT NULL,
  confirmed_route TEXT,
  archive_latched INTEGER NOT NULL,
  archive_policy_revision INTEGER,
  archive_observed_at TEXT,
  archived INTEGER NOT NULL,
  selector_evidence_at TEXT,
  expected_scale_set TEXT,
  confirmed_scale_set TEXT,
  expected_legacy_label TEXT,
  confirmed_legacy_label TEXT,
  open_queue_risk TEXT
);
CREATE TABLE IF NOT EXISTS transitions (
  epoch INTEGER PRIMARY KEY,
  from_state TEXT NOT NULL,
  to_state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS due_work (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  due_at TEXT NOT NULL,
  claim_id TEXT,
  claim_expires_at TEXT,
  attempts INTEGER NOT NULL,
  status TEXT NOT NULL,
  payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event TEXT NOT NULL
);
`;

export const ADD_PERSISTENCE_GENERATION_SQL =
  "ALTER TABLE fleet_state ADD COLUMN persistence_generation INTEGER NOT NULL DEFAULT 1";

export const FLEET_STATE_COLUMN_MIGRATIONS = [
  {
    name: "canary_evidence",
    sql: "ALTER TABLE fleet_state ADD COLUMN canary_evidence TEXT",
  },
  {
    name: "cron_inventory_revision",
    sql: "ALTER TABLE fleet_state ADD COLUMN cron_inventory_revision TEXT",
  },
  {
    name: "cron_inventory_digest",
    sql: "ALTER TABLE fleet_state ADD COLUMN cron_inventory_digest TEXT",
  },
  {
    name: "cron_tick_timestamp",
    sql: "ALTER TABLE fleet_state ADD COLUMN cron_tick_timestamp TEXT",
  },
  {
    name: "cron_tick_nonce",
    sql: "ALTER TABLE fleet_state ADD COLUMN cron_tick_nonce TEXT",
  },
  {
    name: "cron_addressed_at",
    sql: "ALTER TABLE fleet_state ADD COLUMN cron_addressed_at TEXT",
  },
  {
    name: "persistence_generation",
    sql: ADD_PERSISTENCE_GENERATION_SQL,
  },
] as const;

export const REPOSITORY_COLUMN_MIGRATIONS = [
  {
    name: "archive_policy_revision",
    sql: "ALTER TABLE repositories ADD COLUMN archive_policy_revision INTEGER",
  },
  {
    name: "expected_scale_set",
    sql: "ALTER TABLE repositories ADD COLUMN expected_scale_set TEXT",
  },
  {
    name: "confirmed_scale_set",
    sql: "ALTER TABLE repositories ADD COLUMN confirmed_scale_set TEXT",
  },
  {
    name: "expected_legacy_label",
    sql: "ALTER TABLE repositories ADD COLUMN expected_legacy_label TEXT",
  },
  {
    name: "confirmed_legacy_label",
    sql: "ALTER TABLE repositories ADD COLUMN confirmed_legacy_label TEXT",
  },
] as const;

export const TABLE_NAMES = [
  "fleet_state",
  "request_nonces",
  "repositories",
  "transitions",
  "due_work",
  "audit_events",
] as const;
