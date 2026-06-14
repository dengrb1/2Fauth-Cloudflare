PRAGMA foreign_keys = ON;

ALTER TABLE totp_entries ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;

CREATE INDEX IF NOT EXISTS idx_totp_entries_enabled ON totp_entries(enabled);
