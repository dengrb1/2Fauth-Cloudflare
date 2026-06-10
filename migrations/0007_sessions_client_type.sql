-- Migration 0007: Add client_type index on sessions table (idempotent).
-- The client_type column may already exist from a prior ALTER TABLE or manual application;
-- this migration ensures the index exists without failing on a duplicate column.
CREATE INDEX IF NOT EXISTS idx_sessions_client_type ON sessions(client_type);
