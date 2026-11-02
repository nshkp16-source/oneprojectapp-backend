-- Apply after 2026-09-27-project-lifecycle.sql.
-- Stores completed deletion-pause time so the schedule clock resumes on cancellation.
BEGIN;

ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS lifecycle_paused_seconds BIGINT NOT NULL DEFAULT 0;

COMMIT;