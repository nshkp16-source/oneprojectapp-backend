-- ================================================================
-- NOTIFICATION SCHEMA MIGRATION
-- Run this on your Neon database to set up notifications
-- WARNING: this migration drops and recreates the notifications schema.
-- ================================================================

DROP FUNCTION IF EXISTS create_notification_for_project(INTEGER,TEXT,INTEGER,TEXT,INTEGER,TEXT) CASCADE;
DROP FUNCTION IF EXISTS mark_notification_read(INTEGER,TEXT,INTEGER) CASCADE;
DROP FUNCTION IF EXISTS mark_all_notifications_read_for_recipient(TEXT,INTEGER) CASCADE;
DROP TABLE IF EXISTS notification_recipients CASCADE;
DROP TABLE IF EXISTS notifications CASCADE;

-- Create notifications table
CREATE TABLE IF NOT EXISTS notifications (
  id             SERIAL PRIMARY KEY,
  project_id     INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  entity_type    TEXT NOT NULL,
  entity_id      INTEGER NOT NULL,
  message        TEXT NOT NULL,
  added_by_id    INTEGER,
  added_by_role  TEXT,
  created_at     TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notifications_project_entity_created
  ON notifications(project_id, entity_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_entity
  ON notifications(entity_id, entity_type);

-- Create notification_recipients table
CREATE TABLE IF NOT EXISTS notification_recipients (
  id                 SERIAL PRIMARY KEY,
  notification_id    INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
  recipient_role     TEXT NOT NULL,
  recipient_role_id  INTEGER NOT NULL,
  is_read            BOOLEAN DEFAULT false,
  read_at            TIMESTAMP,
  created_at         TIMESTAMP DEFAULT NOW(),
  CONSTRAINT uniq_notif_recipient_per_role
    UNIQUE (notification_id, recipient_role, recipient_role_id)
);

CREATE INDEX IF NOT EXISTS idx_notif_recipients_unread_by_role_id
  ON notification_recipients(recipient_role, recipient_role_id)
  WHERE is_read = false;
CREATE INDEX IF NOT EXISTS idx_notif_recipients_notification
  ON notification_recipients(notification_id);

-- Create helper functions
CREATE OR REPLACE FUNCTION create_notification_for_project(
  p_project_id       INTEGER,
  p_entity_type      TEXT,
  p_entity_id        INTEGER,
  p_message          TEXT,
  p_added_by_id      INTEGER,
  p_added_by_role    TEXT
) RETURNS INTEGER AS $$
DECLARE nid INTEGER;
BEGIN
  INSERT INTO notifications (
    project_id, entity_type, entity_id, message,
    added_by_id, added_by_role, created_at
  ) VALUES (
    p_project_id, p_entity_type, p_entity_id, p_message,
    p_added_by_id, p_added_by_role, NOW()
  ) RETURNING id INTO nid;

  INSERT INTO notification_recipients
    (notification_id, recipient_role, recipient_role_id, created_at)
  SELECT nid, av.role, av.role_id, NOW()
  FROM   assignments_view av
  WHERE  av.project_id = p_project_id
  ON CONFLICT ON CONSTRAINT uniq_notif_recipient_per_role DO NOTHING;

  RETURN nid;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION mark_notification_read(
  p_notification_id   INTEGER,
  p_recipient_role    TEXT,
  p_recipient_role_id INTEGER
) RETURNS VOID AS $$
BEGIN
  UPDATE notification_recipients
  SET    is_read = true, read_at = NOW()
  WHERE  notification_id   = p_notification_id
    AND  recipient_role    = p_recipient_role
    AND  recipient_role_id = p_recipient_role_id
    AND  is_read           = false;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION mark_all_notifications_read_for_recipient(
  p_recipient_role    TEXT,
  p_recipient_role_id INTEGER
) RETURNS VOID AS $$
BEGIN
  UPDATE notification_recipients
  SET    is_read = true, read_at = NOW()
  WHERE  recipient_role    = p_recipient_role
    AND  recipient_role_id = p_recipient_role_id
    AND  is_read           = false;
END;
$$ LANGUAGE plpgsql;
