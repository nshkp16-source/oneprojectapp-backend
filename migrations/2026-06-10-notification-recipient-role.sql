-- 2026-06-10 - add role-aware recipient columns to notifications

ALTER TABLE notification_recipients
  ADD COLUMN IF NOT EXISTS recipient_role TEXT,
  ADD COLUMN IF NOT EXISTS recipient_role_id INTEGER,
  ADD COLUMN IF NOT EXISTS recipient_email TEXT;

CREATE INDEX IF NOT EXISTS idx_notif_recipients_role_id
  ON notification_recipients(recipient_role, recipient_role_id);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_notification_recipient_role
  ON notification_recipients(notification_id, recipient_role, recipient_role_id)
  WHERE recipient_role IS NOT NULL;
