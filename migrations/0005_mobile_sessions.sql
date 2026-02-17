PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS api_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  refresh_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  refresh_expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used_at TEXT NOT NULL,
  client_type TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_sessions_token_hash ON api_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_api_sessions_refresh_hash ON api_sessions(refresh_hash);
CREATE INDEX IF NOT EXISTS idx_api_sessions_user_id ON api_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_api_sessions_expires_at ON api_sessions(expires_at);
