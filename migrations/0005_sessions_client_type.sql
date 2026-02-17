ALTER TABLE sessions ADD COLUMN client_type TEXT NOT NULL DEFAULT 'web' CHECK (client_type IN ('web', 'mobile'));

CREATE INDEX IF NOT EXISTS idx_sessions_client_type ON sessions(client_type);
