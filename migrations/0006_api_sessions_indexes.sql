PRAGMA foreign_keys = ON;

CREATE INDEX IF NOT EXISTS idx_api_sessions_client_type ON api_sessions(client_type);
CREATE INDEX IF NOT EXISTS idx_api_sessions_refresh_expires_at ON api_sessions(refresh_expires_at);
