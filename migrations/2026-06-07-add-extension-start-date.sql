-- Migration: Add explicit start date to extensions
-- Allows proper display of extension period ranges

BEGIN;

ALTER TABLE schedule_extensions
ADD COLUMN new_planned_start DATE NULL;

-- Backfill: compute start from previous record or baseline finish
UPDATE schedule_extensions se
SET new_planned_start = (
  SELECT COALESCE(
    (SELECT new_planned_finish FROM schedule_extensions se2
     WHERE se2.schedule_id = se.schedule_id 
       AND se2.created_at < se.created_at
     ORDER BY created_at DESC LIMIT 1),
    ps.planned_finish
  ) + INTERVAL '1 day'
  FROM project_schedules ps
  WHERE ps.id = se.schedule_id
)
WHERE se.new_planned_start IS NULL;

ALTER TABLE schedule_extensions
ALTER COLUMN new_planned_start SET NOT NULL;

CREATE INDEX idx_schedule_extensions_start_finish ON schedule_extensions(new_planned_start, new_planned_finish);

COMMIT;
