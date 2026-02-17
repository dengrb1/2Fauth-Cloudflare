PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  color TEXT NOT NULL DEFAULT '#0f766e',
  created_at TEXT NOT NULL,
  UNIQUE(user_id, name),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_groups_user_id ON groups(user_id);

ALTER TABLE totp_entries ADD COLUMN group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL;
ALTER TABLE totp_entries ADD COLUMN otp_type TEXT NOT NULL DEFAULT 'totp' CHECK (otp_type IN ('totp', 'hotp'));
ALTER TABLE totp_entries ADD COLUMN hotp_counter INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_totp_entries_group_id ON totp_entries(group_id);
