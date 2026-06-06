-- Migration: Add attachments, delivery flag, and read receipts
-- Run this on your Postgres DB.

BEGIN;

-- Add columns for attachments and delivery status to messages
ALTER TABLE IF EXISTS project_chat_messages
  ADD COLUMN IF NOT EXISTS attachment_url TEXT,
  ADD COLUMN IF NOT EXISTS attachment_name TEXT,
  ADD COLUMN IF NOT EXISTS attachment_mime TEXT,
  ADD COLUMN IF NOT EXISTS attachment_size BIGINT,
  ADD COLUMN IF NOT EXISTS delivered BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMP NULL;

-- Create read receipts table
CREATE TABLE IF NOT EXISTS project_chat_read_receipts (
  id SERIAL PRIMARY KEY,
  message_id INTEGER NOT NULL REFERENCES project_chat_messages(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL,
  read_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(message_id, user_id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_chat_messages_project_id ON project_chat_messages(project_id);
CREATE INDEX IF NOT EXISTS idx_chat_messages_created_at ON project_chat_messages(created_at);
CREATE INDEX IF NOT EXISTS idx_chat_read_receipts_message_id ON project_chat_read_receipts(message_id);
CREATE INDEX IF NOT EXISTS idx_chat_read_receipts_user_id ON project_chat_read_receipts(user_id);

COMMIT;

-- Trigger: when a read receipt is inserted, mark the message as delivered and set delivered_at
BEGIN;
CREATE OR REPLACE FUNCTION fn_set_message_delivered_on_read() RETURNS trigger AS $$
BEGIN
  UPDATE project_chat_messages SET delivered = TRUE, delivered_at = NOW() WHERE id = NEW.message_id;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_set_delivered_on_read ON project_chat_read_receipts;
CREATE TRIGGER trg_set_delivered_on_read
AFTER INSERT ON project_chat_read_receipts
FOR EACH ROW
EXECUTE PROCEDURE fn_set_message_delivered_on_read();

COMMIT;
