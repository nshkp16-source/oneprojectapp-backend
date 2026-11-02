-- Activity > Task progress model.
-- Apply after 2026-10-30-document-folders.sql.
-- Safe to run more than once: columns and tables use IF NOT EXISTS, constraints are checked
-- before they are added, and the one-time data conversion (section 3) runs only on the first run.
--
-- What this adds
--   * Activity type (quantity, count, stages, percentage), "done when", and a link to a schedule
--     milestone (baseline or additional). A typed milestone name stays valid as a standalone milestone.
--   * Task weight (% of the activity), optional target, cached progress, actual dates, close details.
--   * Member reports carry a quantity or a stage, and record the role of the leader who validated them.
--   * Daily execution entries remember where they came from and which reports they were built from.
--   * Weight changes are kept as history, so a rebalance after work has started can be traced.
--   * Approved reports cannot be deleted or have their figures edited (they stay until the project is purged).
--
-- Rules that stay in the API (a plain CHECK cannot enforce them):
--   * the task weights of one activity add up to exactly 100
--   * the stage weights of one task add up to exactly 100
--   * the activity weights inside one milestone add up to exactly 100

BEGIN;

-- Project-deletion guard: a project waiting for deletion is read-only, and the one-off conversion in
-- section 3 would hit that guard and fail the whole migration. This is the same switch the purge
-- job uses, and it applies to this transaction only.
SELECT set_config('app.project_deletion_purge', 'on', true);

-- 1) Activities ---------------------------------------------------------------------------------
ALTER TABLE planning_execution
  ADD COLUMN IF NOT EXISTS activity_type           TEXT NOT NULL DEFAULT 'quantity',
  ADD COLUMN IF NOT EXISTS done_when               TEXT,
  ADD COLUMN IF NOT EXISTS baseline_milestone_id   INTEGER REFERENCES milestones(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS additional_milestone_id INTEGER REFERENCES additional_milestones(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS milestone_weight_pct    NUMERIC(6,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS progress_pct            NUMERIC(5,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS actual_start            DATE,
  ADD COLUMN IF NOT EXISTS actual_end              DATE,
  ADD COLUMN IF NOT EXISTS closed_at               TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS closed_by_id            INTEGER,
  ADD COLUMN IF NOT EXISTS closed_by_role          TEXT,
  ADD COLUMN IF NOT EXISTS close_summary           TEXT;

-- Quantity and unit are only needed by the quantity and count types.
ALTER TABLE planning_execution ALTER COLUMN planned_quantity DROP NOT NULL;
ALTER TABLE planning_execution ALTER COLUMN unit DROP NOT NULL;

CREATE INDEX IF NOT EXISTS idx_pe_milestone_group
  ON planning_execution (project_id, side, baseline_milestone_id, additional_milestone_id);

-- 2) Work Center tasks and reports --------------------------------------------------------------
-- (columns are added in section 3 so that the one-time conversion knows whether this is the first run)

-- 3) One-time conversion of existing data (first run only) --------------------------------------
DO $$
DECLARE
  first_run     BOOLEAN;
  n_orphans     INTEGER;
  n_converted   INTEGER;
BEGIN
  first_run := NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'workspace_work_center' AND column_name = 'weight_pct'
  );

  ALTER TABLE workspace_work_center
    ADD COLUMN IF NOT EXISTS weight_pct      NUMERIC(6,2) NOT NULL DEFAULT 100,
    ADD COLUMN IF NOT EXISTS target_quantity NUMERIC,
    ADD COLUMN IF NOT EXISTS progress_pct    NUMERIC(5,2) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS actual_start    DATE,
    ADD COLUMN IF NOT EXISTS actual_end      DATE,
    ADD COLUMN IF NOT EXISTS closed_at       TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS closed_by_id    INTEGER,
    ADD COLUMN IF NOT EXISTS closed_by_role  TEXT,
    ADD COLUMN IF NOT EXISTS close_summary   TEXT;

  IF first_run THEN
    -- a) Every task must belong to an activity. Tasks with none go under one
    --    "General works (migrated)" activity per project and side.
    INSERT INTO planning_execution
      (project_id, side, title, description, start_date, end_date,
       activity_type, status, creator_id, creator_role)
    SELECT w.project_id, w.side, 'General works (migrated)',
           'Created by the migration to hold tasks that were not linked to an activity.',
           MIN(w.start_date), GREATEST(MAX(w.end_date), MIN(w.start_date)),
           'percentage', 'ongoing',
           (ARRAY_AGG(w.creator_id   ORDER BY w.id))[1],
           (ARRAY_AGG(w.creator_role ORDER BY w.id))[1]
    FROM workspace_work_center w
    WHERE w.activity_id IS NULL
    GROUP BY w.project_id, w.side;

    UPDATE workspace_work_center w
    SET activity_id = pe.id
    FROM planning_execution pe
    WHERE w.activity_id IS NULL
      AND pe.project_id = w.project_id
      AND pe.side       = w.side
      AND pe.title      = 'General works (migrated)';
    GET DIAGNOSTICS n_orphans = ROW_COUNT;

    -- b) Existing member reports are percentages, so activities that already have tasks become
    --    the percentage type. Their planned quantity and unit are kept as information.
    UPDATE planning_execution pe
    SET activity_type = 'percentage'
    WHERE EXISTS (SELECT 1 FROM workspace_work_center w WHERE w.activity_id = pe.id);
    GET DIAGNOSTICS n_converted = ROW_COUNT;

    -- c) Equal task weights per activity (the last task takes the rounding remainder).
    WITH ranked AS (
      SELECT id,
             COUNT(*)     OVER (PARTITION BY activity_id)           AS n,
             ROW_NUMBER() OVER (PARTITION BY activity_id ORDER BY id) AS rn
      FROM workspace_work_center
    )
    UPDATE workspace_work_center w
    SET weight_pct = CASE WHEN r.rn = r.n
                          THEN 100 - ROUND(100.0 / r.n, 2) * (r.n - 1)
                          ELSE ROUND(100.0 / r.n, 2) END
    FROM ranked r
    WHERE w.id = r.id;

    -- d) Equal activity weights inside each milestone group. Existing activities only have a typed
    --    milestone name, so they start as standalone milestones; relink them to schedule milestones later.
    WITH ranked AS (
      SELECT id,
             COUNT(*)     OVER (PARTITION BY project_id, side, baseline_milestone_id, additional_milestone_id,
                                             LOWER(BTRIM(COALESCE(milestone_name, '')))) AS n,
             ROW_NUMBER() OVER (PARTITION BY project_id, side, baseline_milestone_id, additional_milestone_id,
                                             LOWER(BTRIM(COALESCE(milestone_name, ''))) ORDER BY id) AS rn
      FROM planning_execution
    )
    UPDATE planning_execution pe
    SET milestone_weight_pct = CASE WHEN r.rn = r.n
                                    THEN 100 - ROUND(100.0 / r.n, 2) * (r.n - 1)
                                    ELSE ROUND(100.0 / r.n, 2) END
    FROM ranked r
    WHERE pe.id = r.id;

    -- e) Task progress = latest approved report (approved-only rule).
    UPDATE workspace_work_center w
    SET progress_pct = COALESCE((
      SELECT p.progress_pct FROM workspace_work_center_progress p
      WHERE p.task_id = w.id AND p.validation_status = 'approved'
      ORDER BY p.report_date DESC, p.id DESC LIMIT 1
    ), 0);

    -- f) Activity progress: weighted sum of its tasks; with no tasks, quantity done over planned.
    --    These numbers replace the old average-of-entries figure, so some cards will change.
    UPDATE planning_execution pe
    SET progress_pct = LEAST(100, ROUND((
      SELECT SUM(w.weight_pct * w.progress_pct) / 100
      FROM workspace_work_center w WHERE w.activity_id = pe.id
    ), 2))
    WHERE EXISTS (SELECT 1 FROM workspace_work_center w WHERE w.activity_id = pe.id);

    UPDATE planning_execution pe
    SET progress_pct = LEAST(100, ROUND(
      COALESCE((SELECT SUM(t.actual_quantity) FROM planning_execution_tracking t WHERE t.activity_id = pe.id), 0)
      / pe.planned_quantity * 100, 2))
    WHERE pe.planned_quantity > 0
      AND NOT EXISTS (SELECT 1 FROM workspace_work_center w WHERE w.activity_id = pe.id);

    -- g) Actual dates from the existing execution entries.
    UPDATE planning_execution pe
    SET actual_start = (SELECT MIN(t.report_date) FROM planning_execution_tracking t WHERE t.activity_id = pe.id),
        actual_end   = CASE WHEN pe.status IN ('completed', 'closed')
                            THEN (SELECT MAX(t.report_date) FROM planning_execution_tracking t WHERE t.activity_id = pe.id)
                       END;

    RAISE NOTICE 'Activity/task conversion: % tasks moved under "General works (migrated)", % activities set to the percentage type.',
      n_orphans, n_converted;
  END IF;
END;
$$;

-- A task can no longer exist without an activity, and an activity that still has tasks cannot be deleted.
-- NO ACTION (not RESTRICT) is deliberate: deleting a whole project removes tasks and activities in one
-- statement, and RESTRICT would stop that purge.
ALTER TABLE workspace_work_center ALTER COLUMN activity_id SET NOT NULL;
ALTER TABLE workspace_work_center DROP CONSTRAINT IF EXISTS workspace_work_center_activity_id_fkey;
ALTER TABLE workspace_work_center
  ADD CONSTRAINT workspace_work_center_activity_id_fkey
  FOREIGN KEY (activity_id) REFERENCES planning_execution(id) ON DELETE NO ACTION;
CREATE INDEX IF NOT EXISTS idx_wc_activity ON workspace_work_center (activity_id);

-- 4) Stages (for tasks of a "stages" activity) --------------------------------------------------
CREATE TABLE IF NOT EXISTS task_stages (
  id           SERIAL PRIMARY KEY,
  task_id      INTEGER NOT NULL REFERENCES workspace_work_center(id) ON DELETE CASCADE,
  project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  seq          INTEGER NOT NULL,
  title        TEXT    NOT NULL,
  weight_pct   NUMERIC(6,2) NOT NULL CHECK (weight_pct > 0 AND weight_pct <= 100),
  completed_at TIMESTAMPTZ,
  UNIQUE (task_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_task_stages_task ON task_stages (task_id);

-- 5) Member reports ------------------------------------------------------------------------------
ALTER TABLE workspace_work_center_progress
  ADD COLUMN IF NOT EXISTS quantity_done     NUMERIC,
  ADD COLUMN IF NOT EXISTS quantity_failed   NUMERIC NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS stage_id          INTEGER REFERENCES task_stages(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS validated_by_role TEXT;

-- 6) Daily execution entries ---------------------------------------------------------------------
-- Entries built from approved reports are recomputed per (activity, date); the unique index from
-- 2026-09-10 stays and is what the recompute upserts against.
ALTER TABLE planning_execution_tracking
  ADD COLUMN IF NOT EXISTS source        TEXT NOT NULL DEFAULT 'manual',
  ADD COLUMN IF NOT EXISTS contributions JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS recomputed_at TIMESTAMPTZ;

-- 7) Weight history ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS activity_weight_changes (
  id              BIGSERIAL PRIMARY KEY,
  project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  activity_id     INTEGER NOT NULL REFERENCES planning_execution(id) ON DELETE CASCADE,
  changed_by_id   INTEGER NOT NULL,
  changed_by_role TEXT    NOT NULL,
  reason          TEXT,
  before_weights  JSONB   NOT NULL,
  after_weights   JSONB   NOT NULL,
  progress_before NUMERIC(5,2),
  progress_after  NUMERIC(5,2),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_activity_weight_changes_activity
  ON activity_weight_changes (activity_id, created_at);

-- 8) Constraints ---------------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'planning_execution_type_check' AND conrelid = 'planning_execution'::regclass) THEN
    ALTER TABLE planning_execution ADD CONSTRAINT planning_execution_type_check
      CHECK (activity_type IN ('quantity', 'count', 'stages', 'percentage'));
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'planning_execution_one_milestone_check' AND conrelid = 'planning_execution'::regclass) THEN
    ALTER TABLE planning_execution ADD CONSTRAINT planning_execution_one_milestone_check
      CHECK (baseline_milestone_id IS NULL OR additional_milestone_id IS NULL);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'planning_execution_weights_check' AND conrelid = 'planning_execution'::regclass) THEN
    ALTER TABLE planning_execution ADD CONSTRAINT planning_execution_weights_check
      CHECK (milestone_weight_pct BETWEEN 0 AND 100 AND progress_pct BETWEEN 0 AND 100);
  END IF;

  -- NOT VALID: checked for every new or changed row, without failing on old rows that were saved
  -- before these rules existed.
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'planning_execution_measure_check' AND conrelid = 'planning_execution'::regclass) THEN
    ALTER TABLE planning_execution ADD CONSTRAINT planning_execution_measure_check
      CHECK (activity_type NOT IN ('quantity', 'count')
             OR (planned_quantity > 0 AND unit IS NOT NULL AND BTRIM(unit) <> '')) NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'planning_execution_dates_check' AND conrelid = 'planning_execution'::regclass) THEN
    ALTER TABLE planning_execution ADD CONSTRAINT planning_execution_dates_check
      CHECK (end_date >= start_date) NOT VALID;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'workspace_work_center_weight_check' AND conrelid = 'workspace_work_center'::regclass) THEN
    ALTER TABLE workspace_work_center ADD CONSTRAINT workspace_work_center_weight_check
      CHECK (weight_pct > 0 AND weight_pct <= 100 AND progress_pct BETWEEN 0 AND 100
             AND (target_quantity IS NULL OR target_quantity >= 0));
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'wc_progress_quantity_check' AND conrelid = 'workspace_work_center_progress'::regclass) THEN
    ALTER TABLE workspace_work_center_progress ADD CONSTRAINT wc_progress_quantity_check
      CHECK ((quantity_done IS NULL OR quantity_done >= 0) AND quantity_failed >= 0);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'pe_tracking_source_check' AND conrelid = 'planning_execution_tracking'::regclass) THEN
    ALTER TABLE planning_execution_tracking ADD CONSTRAINT pe_tracking_source_check
      CHECK (source IN ('manual', 'work_center'));
  END IF;
END;
$$;

-- 9) Approved reports stay -----------------------------------------------------------------------
-- An approved report cannot be deleted, and its figures cannot be edited. A member leaving the project
-- or the leader who approved it leaving does not touch it. Project purge is allowed through the same
-- switch the lifecycle migration uses.
CREATE OR REPLACE FUNCTION lock_approved_progress()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF current_setting('app.project_deletion_purge', true) = 'on' THEN
    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
  END IF;

  IF OLD.validation_status = 'approved' THEN
    IF TG_OP = 'DELETE' THEN
      RAISE EXCEPTION 'Approved progress reports are part of the project record and cannot be deleted.'
        USING ERRCODE = '55000';
    END IF;
    IF NEW.task_id         IS DISTINCT FROM OLD.task_id
       OR NEW.member_id    IS DISTINCT FROM OLD.member_id
       OR NEW.report_date  IS DISTINCT FROM OLD.report_date
       OR NEW.work_done    IS DISTINCT FROM OLD.work_done
       OR NEW.progress_pct IS DISTINCT FROM OLD.progress_pct
       OR NEW.quantity_done   IS DISTINCT FROM OLD.quantity_done
       OR NEW.quantity_failed IS DISTINCT FROM OLD.quantity_failed
       OR NEW.stage_id     IS DISTINCT FROM OLD.stage_id THEN
      RAISE EXCEPTION 'Approved progress reports cannot be edited.'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$;

DROP TRIGGER IF EXISTS lock_approved_progress ON public.workspace_work_center_progress;
CREATE TRIGGER lock_approved_progress
  BEFORE UPDATE OR DELETE ON public.workspace_work_center_progress
  FOR EACH ROW EXECUTE FUNCTION lock_approved_progress();

-- 10) Keep the new tables read-only while a project is pending deletion -------------------------
-- (both carry project_id, which guard_pending_project_mutation reads directly)
DROP TRIGGER IF EXISTS guard_pending_project_mutation ON public.task_stages;
CREATE TRIGGER guard_pending_project_mutation
  BEFORE INSERT OR UPDATE OR DELETE ON public.task_stages
  FOR EACH ROW EXECUTE FUNCTION guard_pending_project_mutation();

DROP TRIGGER IF EXISTS guard_pending_project_mutation ON public.activity_weight_changes;
CREATE TRIGGER guard_pending_project_mutation
  BEFORE INSERT OR UPDATE OR DELETE ON public.activity_weight_changes
  FOR EACH ROW EXECUTE FUNCTION guard_pending_project_mutation();

COMMIT;

-- End of 2026-11-01-activity-task-progress.sql
