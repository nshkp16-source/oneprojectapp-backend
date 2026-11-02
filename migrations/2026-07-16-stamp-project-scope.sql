-- ================================================================
-- STAMP PROJECT SCOPE MIGRATION
-- Adds project_id to user_stamps, making stamps per-project
-- Safe to run on live DB — existing stamps (with NULL project_id)
-- won't collide with new per-project stamps
-- ================================================================

BEGIN;

-- ── 1. Add project_id column to user_stamps ──────────────────────
ALTER TABLE user_stamps
  ADD COLUMN IF NOT EXISTS project_id INTEGER;

-- ── 2. Add FK to projects (optional, but good for referential integrity)
ALTER TABLE user_stamps
  ADD CONSTRAINT IF NOT EXISTS fk_user_stamps_project
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

-- ── 3. Drop old unique constraint, add new one with project_id ────
ALTER TABLE user_stamps
  DROP CONSTRAINT IF EXISTS uniq_user_stamp;

ALTER TABLE user_stamps
  ADD CONSTRAINT uniq_user_stamp_project UNIQUE (user_id, user_role, project_id);

-- Note: Old stamps with NULL project_id won't collide with new ones.
-- Users will need to set their stamp per-project after this migration.

COMMIT;
