-- Migration: Migrate existing project data to new schedule schema (2026-06-09)
-- Purpose: Transfer milestone and progress data from old schema to new schedule-based structure
-- This migration populates project_schedules, milestones, and progress tracking tables

BEGIN;

-- Step 1: Populate project_schedules from existing projects
-- (using planning_execution baseline as project baseline)
INSERT INTO project_schedules (project_id, planned_start, planned_finish, total_duration, created_by_user_id, created_by_role, created_at, updated_at)
SELECT 
  CAST(p.id AS TEXT) AS project_id,
  COALESCE(MIN(pe.start_date), CURRENT_DATE) AS planned_start,
  COALESCE(MAX(pe.end_date), CURRENT_DATE + INTERVAL '30 days') AS planned_finish,
  COALESCE(
    EXTRACT(DAY FROM (MAX(pe.end_date) - MIN(pe.start_date)))::INTEGER,
    0
  ) AS total_duration,
  p.created_by_user_id,
  p.created_by_role,
  NOW(),
  NOW()
FROM projects p
LEFT JOIN planning_execution pe ON p.id = pe.project_id
WHERE NOT EXISTS (
  SELECT 1 FROM project_schedules ps WHERE ps.project_id = CAST(p.id AS TEXT)
)
GROUP BY p.id, p.created_by_user_id, p.created_by_role
ON CONFLICT (project_id) DO NOTHING;

-- Step 2: Populate milestones from planning_execution records
INSERT INTO milestones (
  schedule_id, project_id, title, description, sort_order,
  planned_start, planned_end, duration_days, float_days,
  is_critical, weight_pct, quantity, unit, depends_on,
  executed, progress_pct, activity_status, completed_at,
  created_by_user_id, created_by_role, updated_at
)
SELECT 
  ps.id,
  pe.project_id::TEXT,
  pe.title,
  pe.description,
  ROW_NUMBER() OVER (PARTITION BY ps.id ORDER BY pe.start_date) - 1,
  pe.start_date,
  pe.end_date,
  EXTRACT(DAY FROM (pe.end_date - pe.start_date))::INTEGER,
  0, -- float_days
  FALSE,
  (1.0 / (SELECT COUNT(*) FROM planning_execution WHERE project_id = pe.project_id))::NUMERIC(8,2) * 100,
  pe.planned_quantity,
  pe.unit,
  NULL, -- no dependency tracking in old schema
  COALESCE((
    SELECT MAX(actual_quantity) FROM planning_execution_tracking 
    WHERE activity_id = pe.id
  ), 0),
  COALESCE((
    SELECT MAX(progress_pct) FROM planning_execution_tracking 
    WHERE activity_id = pe.id
  ), 0),
  CASE 
    WHEN pe.status = 'completed' THEN 'completed'
    WHEN pe.status = 'closed' THEN 'completed'
    WHEN (SELECT MAX(progress_pct) FROM planning_execution_tracking WHERE activity_id = pe.id) > 0 THEN 'in_progress'
    ELSE 'planned'
  END,
  CASE WHEN pe.status IN ('completed', 'closed') THEN NOW() ELSE NULL END,
  p.created_by_user_id,
  p.created_by_role,
  COALESCE(pe.updated_at, NOW())
FROM planning_execution pe
JOIN projects p ON p.id = pe.project_id
JOIN project_schedules ps ON ps.project_id = CAST(p.id AS TEXT)
WHERE NOT EXISTS (
  SELECT 1 FROM milestones m 
  WHERE m.project_id = pe.project_id::TEXT 
    AND m.title = pe.title
    AND m.planned_start = pe.start_date
);

-- Step 3: Populate milestone_progress_entries from planning_execution_tracking
INSERT INTO milestone_progress_entries (
  milestone_id, project_id, report_date,
  qty_executed, cumulative_after_entry, progress_pct_after_entry,
  remarks, reported_by_user_id, reported_by_role, created_at
)
SELECT 
  m.id,
  m.project_id,
  pet.report_date,
  pet.actual_quantity,
  pet.actual_quantity, -- cumulative
  pet.progress_pct,
  COALESCE(pet.remark, '') || CASE 
    WHEN pet.issues IS NOT NULL THEN ' [Issues: ' || pet.issues || ']'
    ELSE ''
  END,
  pet.logged_by,
  pet.logged_by_role,
  pet.created_at
FROM planning_execution_tracking pet
JOIN planning_execution pe ON pe.id = pet.activity_id
JOIN milestones m ON m.project_id = CAST(pe.project_id AS TEXT)
  AND m.title = pe.title
  AND m.planned_start = pe.start_date
WHERE NOT EXISTS (
  SELECT 1 FROM milestone_progress_entries mpe
  WHERE mpe.milestone_id = m.id AND mpe.report_date = pet.report_date
);

-- Step 4: Update milestone executed quantities with latest cumulative
UPDATE milestones m
SET executed = (
  SELECT COALESCE(MAX(cumulative_after_entry), 0)
  FROM milestone_progress_entries mpe
  WHERE mpe.milestone_id = m.id
)
WHERE EXISTS (
  SELECT 1 FROM milestone_progress_entries mpe WHERE mpe.milestone_id = m.id
);

-- Verify migration
DO $$
DECLARE
  sched_count INT;
  ms_count INT;
  entry_count INT;
BEGIN
  SELECT COUNT(*) INTO sched_count FROM project_schedules;
  SELECT COUNT(*) INTO ms_count FROM milestones;
  SELECT COUNT(*) INTO entry_count FROM milestone_progress_entries;
  
  RAISE NOTICE 'Migration complete: % schedules, % milestones, % progress entries',
    sched_count, ms_count, entry_count;
END $$;

COMMIT;
