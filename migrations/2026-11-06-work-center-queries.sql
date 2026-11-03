-- Questions from task leaders to assigned team members, with answers and resolution state.
-- Apply after 2026-11-05-standalone-work-center-tasks.sql.
-- Safe to run more than once.

BEGIN;

CREATE TABLE IF NOT EXISTS work_center_queries (
  id              BIGSERIAL PRIMARY KEY,
  task_id         INTEGER NOT NULL REFERENCES workspace_work_center(id) ON DELETE CASCADE,
  project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  asked_by_id     INTEGER NOT NULL,
  asked_by_role   TEXT NOT NULL,
  recipient_id    INTEGER NOT NULL,
  question        TEXT NOT NULL CHECK (BTRIM(question) <> ''),
  answer          TEXT,
  status          TEXT NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open', 'answered', 'resolved')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  answered_at     TIMESTAMPTZ,
  answered_by_id  INTEGER,
  resolved_at     TIMESTAMPTZ,
  resolved_by_id  INTEGER,
  resolved_by_role TEXT,
  CHECK ((status = 'open' AND answer IS NULL AND answered_at IS NULL
          AND answered_by_id IS NULL AND resolved_at IS NULL AND resolved_by_id IS NULL AND resolved_by_role IS NULL)
      OR (status = 'answered' AND answer IS NOT NULL AND answered_at IS NOT NULL
          AND answered_by_id IS NOT NULL AND resolved_at IS NULL AND resolved_by_id IS NULL AND resolved_by_role IS NULL)
      OR (status = 'resolved' AND answer IS NOT NULL AND answered_at IS NOT NULL
          AND answered_by_id IS NOT NULL AND resolved_at IS NOT NULL
          AND resolved_by_id IS NOT NULL AND resolved_by_role IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_work_center_queries_task_status
  ON work_center_queries (task_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_work_center_queries_recipient
  ON work_center_queries (recipient_id, status, created_at DESC);

COMMIT;

-- End of 2026-11-06-work-center-queries.sql
