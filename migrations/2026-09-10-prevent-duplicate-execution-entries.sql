-- Keep the newest entry when older duplicate same-day entries already exist.
WITH ranked AS (
  SELECT id, ROW_NUMBER() OVER (
    PARTITION BY activity_id, report_date ORDER BY created_at DESC, id DESC
  ) AS row_number
  FROM planning_execution_tracking
)
DELETE FROM planning_execution_tracking t
USING ranked r
WHERE t.id = r.id AND r.row_number > 1;

CREATE UNIQUE INDEX IF NOT EXISTS ux_planning_execution_tracking_activity_date
  ON planning_execution_tracking(activity_id, report_date);