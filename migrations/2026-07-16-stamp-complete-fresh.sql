-- ================================================================
-- STAMP COMPLETE MIGRATION - FRESH START
-- Drops old user_stamps table and recreates with project_id
-- Adds stamp positioning columns to all 5 record tables
-- Safe to run on live DB — user_stamps data will be cleared
-- ================================================================

BEGIN;

-- ── 1. DROP old user_stamps table (if exists) ────────────────────
DROP TABLE IF EXISTS user_stamps CASCADE;

-- ── 2. CREATE new user_stamps with project_id ────────────────────
CREATE TABLE user_stamps (
  id              SERIAL PRIMARY KEY,
  user_id         INTEGER NOT NULL,
  user_role       TEXT    NOT NULL,
  project_id      INTEGER NOT NULL,
  signer_name     TEXT,
  signature_image TEXT,
  stamp_image_url TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT fk_user_stamps_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
  CONSTRAINT uniq_user_stamp_project UNIQUE (user_id, user_role, project_id)
);

CREATE INDEX idx_user_stamps_lookup ON user_stamps(user_id, user_role, project_id);

-- ── 3. Add stamp positioning columns to all 5 record tables ───────

ALTER TABLE contractual_records
  ADD COLUMN IF NOT EXISTS stamp_page  INTEGER,
  ADD COLUMN IF NOT EXISTS stamp_x     NUMERIC,
  ADD COLUMN IF NOT EXISTS stamp_y     NUMERIC;

ALTER TABLE administrative_records
  ADD COLUMN IF NOT EXISTS stamp_page  INTEGER,
  ADD COLUMN IF NOT EXISTS stamp_x     NUMERIC,
  ADD COLUMN IF NOT EXISTS stamp_y     NUMERIC;

ALTER TABLE safety_records
  ADD COLUMN IF NOT EXISTS stamp_page  INTEGER,
  ADD COLUMN IF NOT EXISTS stamp_x     NUMERIC,
  ADD COLUMN IF NOT EXISTS stamp_y     NUMERIC;

ALTER TABLE operational_records
  ADD COLUMN IF NOT EXISTS stamp_page  INTEGER,
  ADD COLUMN IF NOT EXISTS stamp_x     NUMERIC,
  ADD COLUMN IF NOT EXISTS stamp_y     NUMERIC;

ALTER TABLE financial_records
  ADD COLUMN IF NOT EXISTS stamp_page  INTEGER,
  ADD COLUMN IF NOT EXISTS stamp_x     NUMERIC,
  ADD COLUMN IF NOT EXISTS stamp_y     NUMERIC;

COMMIT;
