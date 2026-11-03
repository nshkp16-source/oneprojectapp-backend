-- Standalone Work Center tasks.
-- Apply after 2026-11-04-verification-reminders.sql.
-- Safe to run more than once.

BEGIN;

ALTER TABLE workspace_work_center
  ALTER COLUMN activity_id DROP NOT NULL,
  ADD COLUMN IF NOT EXISTS activity_type TEXT,
  ADD COLUMN IF NOT EXISTS standalone_unit TEXT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'workspace_work_center_standalone_measure_check'
      AND conrelid = 'workspace_work_center'::regclass
  ) THEN
    ALTER TABLE workspace_work_center
      ADD CONSTRAINT workspace_work_center_standalone_measure_check
      CHECK (
        activity_id IS NOT NULL
        OR (
          activity_type IS NOT NULL
          AND activity_type IN ('quantity', 'count', 'stages', 'percentage')
          AND (
            activity_type NOT IN ('quantity', 'count')
            OR (
              target_quantity > 0
              AND standalone_unit IS NOT NULL
              AND BTRIM(standalone_unit) <> ''
              AND (activity_type <> 'count' OR target_quantity = TRUNC(target_quantity))
            )
          )
        )
      );
  END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_wc_standalone_project_side
  ON workspace_work_center (project_id, side, created_at DESC)
  WHERE activity_id IS NULL;

COMMIT;

-- End of 2026-11-05-standalone-work-center-tasks.sql
