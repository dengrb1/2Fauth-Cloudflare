PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS login_risk_control (
  key TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  ip TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0,
  lock_until INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_risk_control_updated_at ON login_risk_control(updated_at);
CREATE INDEX IF NOT EXISTS idx_login_risk_control_lock_until ON login_risk_control(lock_until);
