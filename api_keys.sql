CREATE TABLE IF NOT EXISTS api_keys (
  api_key TEXT PRIMARY KEY NOT NULL,
  max_per_day INTEGER DEFAULT 100000,
  created_at TEXT DEFAULT (datetime('now'))
);
