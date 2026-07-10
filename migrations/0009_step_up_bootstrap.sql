PRAGMA foreign_keys = ON;

ALTER TABLE sessions ADD COLUMN step_up_at TEXT;

INSERT INTO app_settings (key, value, updated_at)
SELECT 'bootstrap_completed', 'true', CAST(strftime('%s', 'now') AS INTEGER)
WHERE EXISTS (SELECT 1 FROM users)
ON CONFLICT(key) DO NOTHING;
