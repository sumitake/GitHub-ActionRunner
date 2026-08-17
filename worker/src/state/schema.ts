export const FLEET_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS fleet_state (
  fleet_id TEXT PRIMARY KEY,
  epoch INTEGER NOT NULL,
  session_id TEXT,
  sequence INTEGER NOT NULL,
  lease_generation INTEGER NOT NULL,
  last_issued_lease_expiry_max TEXT,
  lease_not_before TEXT,
  holder TEXT NOT NULL,
  routing_state TEXT NOT NULL,
  hosted_hold INTEGER NOT NULL,
  config_revision INTEGER NOT NULL,
  policy_digest TEXT
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
  archive_observed_at TEXT,
  archived INTEGER NOT NULL,
  selector_evidence_at TEXT,
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

export const TABLE_NAMES = [
  "fleet_state",
  "request_nonces",
  "repositories",
  "transitions",
  "due_work",
  "audit_events",
] as const;
