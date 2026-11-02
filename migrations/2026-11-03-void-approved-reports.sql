-- Voiding an approved report.
-- Apply after 2026-11-02-verification-and-milestone-link.sql.
-- Safe to run more than once.
--
-- Approved reports cannot be deleted or edited (2026-11-01). That leaves no way to fix a report that
-- was approved by mistake, and the progress rules for percentages do not allow a lower value. This adds
-- one controlled way out: a leader voids the report with a written reason. The report stays in the
-- record, is marked voided, and no longer counts toward progress. A voided report can never change again.

BEGIN;

ALTER TABLE workspace_work_center_progress
  ADD COLUMN IF NOT EXISTS voided_by_id   INTEGER,
  ADD COLUMN IF NOT EXISTS voided_by_role TEXT,
  ADD COLUMN IF NOT EXISTS voided_at      TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS void_reason    TEXT;

ALTER TABLE workspace_work_center_progress
  DROP CONSTRAINT IF EXISTS workspace_work_center_progress_validation_status_check;
ALTER TABLE workspace_work_center_progress
  ADD CONSTRAINT workspace_work_center_progress_validation_status_check
  CHECK (validation_status IN ('pending', 'approved', 'rejected', 'voided'));

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'wc_progress_void_check'
                 AND conrelid = 'workspace_work_center_progress'::regclass) THEN
    ALTER TABLE workspace_work_center_progress ADD CONSTRAINT wc_progress_void_check
      CHECK (validation_status <> 'voided'
             OR (voided_at IS NOT NULL AND voided_by_id IS NOT NULL
                 AND void_reason IS NOT NULL AND BTRIM(void_reason) <> ''));
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION lock_approved_progress()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF current_setting('app.project_deletion_purge', true) = 'on' THEN
    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
  END IF;

  IF OLD.validation_status = 'voided' THEN
    RAISE EXCEPTION 'A voided progress report is part of the project record and cannot be changed or deleted.'
      USING ERRCODE = '55000';
  END IF;

  IF OLD.validation_status = 'approved' THEN
    IF TG_OP = 'DELETE' THEN
      RAISE EXCEPTION 'Approved progress reports are part of the project record and cannot be deleted. Void the report with a reason instead.'
        USING ERRCODE = '55000';
    END IF;
    IF NEW.validation_status NOT IN ('approved', 'voided') THEN
      RAISE EXCEPTION 'An approved progress report cannot be rejected. Void it with a reason instead.'
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

COMMIT;

-- End of 2026-11-03-void-approved-reports.sql
