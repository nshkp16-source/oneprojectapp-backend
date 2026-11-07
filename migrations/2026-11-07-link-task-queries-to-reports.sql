-- Tie leader questions to the progress report they concern.
-- Apply after 2026-11-06-work-center-queries.sql.
-- Safe to run more than once.

BEGIN;

ALTER TABLE work_center_queries
  ADD COLUMN IF NOT EXISTS report_id INTEGER
    REFERENCES workspace_work_center_progress(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_work_center_queries_report
  ON work_center_queries (report_id) WHERE report_id IS NOT NULL;

COMMIT;

-- End of 2026-11-07-link-task-queries-to-reports.sql
