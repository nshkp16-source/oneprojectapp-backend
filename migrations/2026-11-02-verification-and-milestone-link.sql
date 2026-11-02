-- Consultant verification, certified progress, and the link between activities and schedule milestones.
-- Apply after 2026-11-01-activity-task-progress.sql.
-- Safe to run more than once: columns and tables use IF NOT EXISTS and constraints are checked first.
--
-- Decisions this file implements (design document, items D14 to D16, N1 to N3, C1 to C10)
--   * Progress has two levels. Claimed = approved by the contractor leader (already stored as
--     planning_execution.progress_pct). Certified = verified by the consultant (new column).
--   * The consultant answers a verification request: verified, verified with changes, or rejected.
--     A rejection creates rework. A completion verification ends the activity (completion certification).
--   * A contractor activity can only become closed after a completion certification and with no open
--     rework or snags. Activities of the Consultant and Client sides close without verification.
--   * A milestone either takes typed progress (manual, as today) or progress derived from its
--     contractor activities. For derived milestones, milestones.progress_pct stays the single figure the
--     schedule already reads: it is the consultant's temporary value when one is active, otherwise the
--     derived value (the API caps it at 99 while a breakdown request is open).
--
-- Rules that stay in the API (a plain CHECK cannot enforce them):
--   * only the contractor leader or PM requests verification; the consultant inspector answers first,
--     then a consultant leader decides
--   * a temporary milestone value can only lower the derived value
--   * the cap at 99% and the block on milestone completion while a breakdown request is open
--   * when the first activity is linked to a milestone that has typed progress, the typed entries are
--     marked superseded in the same transaction (superseded_at) and progress_source becomes 'activities'

BEGIN;

-- Same switch the purge job uses, so a project waiting for deletion does not fail this migration.
SELECT set_config('app.project_deletion_purge', 'on', true);

-- 1) Project setting: days the consultant has to respond ------------------------------------------
ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS verification_response_days INTEGER NOT NULL DEFAULT 7;

-- 2) Activities: certified progress and completion request ---------------------------------------
ALTER TABLE planning_execution
  ADD COLUMN IF NOT EXISTS drives_milestone              BOOLEAN GENERATED ALWAYS AS (side = 'Contractor') STORED,
  ADD COLUMN IF NOT EXISTS certified_progress_pct        NUMERIC(5,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS certified_at                  TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS completion_requested_at       TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS completion_requested_by_id    INTEGER,
  ADD COLUMN IF NOT EXISTS completion_requested_by_role  TEXT;

CREATE INDEX IF NOT EXISTS idx_pe_driving_milestone
  ON planning_execution (baseline_milestone_id, additional_milestone_id)
  WHERE drives_milestone;

-- 3) Hold points on stages -------------------------------------------------------------------------
ALTER TABLE task_stages
  ADD COLUMN IF NOT EXISTS is_hold_point     BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS hold_verified_at  TIMESTAMPTZ;

-- 4) Verification requests -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS activity_verifications (
  id                      BIGSERIAL PRIMARY KEY,
  project_id              INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  activity_id             INTEGER NOT NULL REFERENCES planning_execution(id) ON DELETE CASCADE,
  kind                    TEXT    NOT NULL DEFAULT 'progress',          -- progress | hold_point | completion
  stage_id                INTEGER REFERENCES task_stages(id) ON DELETE SET NULL,
  cut_off_date            DATE    NOT NULL,
  claimed_progress_pct    NUMERIC(5,2) NOT NULL,
  claimed_figures         JSONB   NOT NULL DEFAULT '[]'::jsonb,          -- per task snapshot at request time
  requested_by_id         INTEGER NOT NULL,
  requested_by_role       TEXT    NOT NULL,
  requested_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  request_note            TEXT,
  attachments             JSONB   NOT NULL DEFAULT '[]'::jsonb,
  respond_by              DATE    NOT NULL,
  status                  TEXT    NOT NULL DEFAULT 'pending',
  certified_progress_pct  NUMERIC(5,2),
  certified_figures       JSONB,                                         -- per task, for joint measurement
  decision_reason         TEXT,
  decision_attachments    JSONB   NOT NULL DEFAULT '[]'::jsonb,
  decided_by_id           INTEGER,
  decided_by_role         TEXT,
  decided_at              TIMESTAMPTZ,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_av_activity ON activity_verifications (activity_id, status);
CREATE INDEX IF NOT EXISTS idx_av_due      ON activity_verifications (project_id, respond_by) WHERE status = 'pending';
-- one open request per activity, kind and stage
CREATE UNIQUE INDEX IF NOT EXISTS ux_av_one_pending
  ON activity_verifications (activity_id, kind, COALESCE(stage_id, 0)) WHERE status = 'pending';

-- Named signers, in the same style as record_signers: an inspector (team member) first, then a leader.
CREATE TABLE IF NOT EXISTS verification_signers (
  id                    SERIAL PRIMARY KEY,
  verification_id       BIGINT  NOT NULL REFERENCES activity_verifications(id) ON DELETE CASCADE,
  project_id            INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  signer_role           TEXT    NOT NULL,
  signer_user_id        INTEGER NOT NULL,
  signer_position       TEXT,
  is_team_member        BOOLEAN NOT NULL DEFAULT FALSE,
  is_decider            BOOLEAN NOT NULL DEFAULT FALSE,
  order_no              INTEGER NOT NULL DEFAULT 0,
  status                TEXT    NOT NULL DEFAULT 'pending',              -- pending | signed | replaced
  outcome               TEXT,
  note                  TEXT,
  signed_at             TIMESTAMPTZ,
  first_viewed_at       TIMESTAMPTZ,
  last_viewed_at        TIMESTAMPTZ,
  replaced_at           TIMESTAMPTZ,
  replaced_by_user_id   INTEGER,
  replaced_by_role      TEXT,
  reminder_sent_at      TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (verification_id, signer_role, signer_user_id)
);
CREATE INDEX IF NOT EXISTS idx_vs_user ON verification_signers (signer_role, signer_user_id, status);

-- 5) Rework and snags ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rework_items (
  id               BIGSERIAL PRIMARY KEY,
  project_id       INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  activity_id      INTEGER NOT NULL REFERENCES planning_execution(id) ON DELETE CASCADE,
  task_id          INTEGER REFERENCES workspace_work_center(id) ON DELETE CASCADE,
  verification_id  BIGINT  REFERENCES activity_verifications(id) ON DELETE SET NULL,
  kind             TEXT    NOT NULL DEFAULT 'rework',                    -- rework | snag
  reason           TEXT    NOT NULL,
  raised_by_id     INTEGER NOT NULL,
  raised_by_role   TEXT    NOT NULL,
  raised_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status           TEXT    NOT NULL DEFAULT 'open',                      -- open | corrected | closed
  corrected_at     TIMESTAMPTZ,
  corrected_by_id  INTEGER,
  corrected_by_role TEXT,
  correction_note  TEXT,
  closed_at        TIMESTAMPTZ,
  closed_by_id     INTEGER,
  closed_by_role   TEXT
);
CREATE INDEX IF NOT EXISTS idx_rework_activity ON rework_items (activity_id, status);

-- 6) Milestones: progress source, derived value and the consultant's temporary value ---------------
ALTER TABLE milestones
  ADD COLUMN IF NOT EXISTS progress_source       TEXT NOT NULL DEFAULT 'manual',
  ADD COLUMN IF NOT EXISTS derived_progress_pct  NUMERIC(5,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS linked_at             TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS override_pct          NUMERIC(5,2),
  ADD COLUMN IF NOT EXISTS override_reason       TEXT,
  ADD COLUMN IF NOT EXISTS override_by_id        INTEGER,
  ADD COLUMN IF NOT EXISTS override_by_role      TEXT,
  ADD COLUMN IF NOT EXISTS override_at           TIMESTAMPTZ;

ALTER TABLE additional_milestones
  ADD COLUMN IF NOT EXISTS progress_source       TEXT NOT NULL DEFAULT 'manual',
  ADD COLUMN IF NOT EXISTS derived_progress_pct  NUMERIC(5,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS linked_at             TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS override_pct          NUMERIC(5,2),
  ADD COLUMN IF NOT EXISTS override_reason       TEXT,
  ADD COLUMN IF NOT EXISTS override_by_id        INTEGER,
  ADD COLUMN IF NOT EXISTS override_by_role      TEXT,
  ADD COLUMN IF NOT EXISTS override_at           TIMESTAMPTZ;

-- Typed entries replaced by a link are kept as history, never deleted. The recalculation must skip
-- rows where superseded_at is set.
ALTER TABLE milestone_progress_entries            ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ;
ALTER TABLE additional_milestone_progress_entries ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ;

-- Daily figures written by the system for derived milestones. They live in their own table so the
-- one-entry-per-date rule on typed entries is untouched and no typed history is ever overwritten.
CREATE TABLE IF NOT EXISTS milestone_activity_progress (
  id                      BIGSERIAL PRIMARY KEY,
  project_id              INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  baseline_milestone_id   INTEGER REFERENCES milestones(id) ON DELETE CASCADE,
  additional_milestone_id INTEGER REFERENCES additional_milestones(id) ON DELETE CASCADE,
  report_date             DATE    NOT NULL,
  derived_progress_pct    NUMERIC(5,2) NOT NULL,
  executed_equivalent     NUMERIC(18,3),                                  -- progress x milestone quantity
  contributions           JSONB   NOT NULL DEFAULT '[]'::jsonb,           -- certified figure per activity
  recomputed_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (num_nonnulls(baseline_milestone_id, additional_milestone_id) = 1)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_map_baseline   ON milestone_activity_progress (baseline_milestone_id, report_date)   WHERE baseline_milestone_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_map_additional ON milestone_activity_progress (additional_milestone_id, report_date) WHERE additional_milestone_id IS NOT NULL;

-- History of the consultant's temporary values.
CREATE TABLE IF NOT EXISTS milestone_progress_overrides (
  id                      BIGSERIAL PRIMARY KEY,
  project_id              INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  baseline_milestone_id   INTEGER REFERENCES milestones(id) ON DELETE CASCADE,
  additional_milestone_id INTEGER REFERENCES additional_milestones(id) ON DELETE CASCADE,
  set_pct                 NUMERIC(5,2) NOT NULL CHECK (set_pct BETWEEN 0 AND 100),
  derived_pct_at_time     NUMERIC(5,2) NOT NULL,
  reason                  TEXT    NOT NULL CHECK (BTRIM(reason) <> ''),
  set_by_id               INTEGER NOT NULL,
  set_by_role             TEXT    NOT NULL,
  set_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at                TIMESTAMPTZ,
  ended_reason            TEXT CHECK (ended_reason IS NULL OR ended_reason IN
                            ('replaced_by_verification', 'withdrawn', 'replaced_by_new_value')),
  CHECK (num_nonnulls(baseline_milestone_id, additional_milestone_id) = 1)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_mpo_active_baseline   ON milestone_progress_overrides (baseline_milestone_id)   WHERE ended_at IS NULL AND baseline_milestone_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_mpo_active_additional ON milestone_progress_overrides (additional_milestone_id) WHERE ended_at IS NULL AND additional_milestone_id IS NOT NULL;

-- Breakdown requests from the consultant.
CREATE TABLE IF NOT EXISTS milestone_breakdown_requests (
  id                      BIGSERIAL PRIMARY KEY,
  project_id              INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  baseline_milestone_id   INTEGER REFERENCES milestones(id) ON DELETE CASCADE,
  additional_milestone_id INTEGER REFERENCES additional_milestones(id) ON DELETE CASCADE,
  note                    TEXT    NOT NULL CHECK (BTRIM(note) <> ''),
  requested_by_id         INTEGER NOT NULL,
  requested_by_role       TEXT    NOT NULL,
  requested_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status                  TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved', 'withdrawn')),
  closed_at               TIMESTAMPTZ,
  closed_by_id            INTEGER,
  closed_by_role          TEXT,
  close_reason            TEXT,
  CHECK (num_nonnulls(baseline_milestone_id, additional_milestone_id) = 1)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_mbr_open_baseline   ON milestone_breakdown_requests (baseline_milestone_id)   WHERE status = 'open' AND baseline_milestone_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_mbr_open_additional ON milestone_breakdown_requests (additional_milestone_id) WHERE status = 'open' AND additional_milestone_id IS NOT NULL;

-- 7) Constraints -----------------------------------------------------------------------------------
DO $$
DECLARE
  t TEXT;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'projects_verification_days_check' AND conrelid = 'projects'::regclass) THEN
    ALTER TABLE projects ADD CONSTRAINT projects_verification_days_check
      CHECK (verification_response_days BETWEEN 1 AND 60);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'planning_execution_certified_check' AND conrelid = 'planning_execution'::regclass) THEN
    ALTER TABLE planning_execution ADD CONSTRAINT planning_execution_certified_check
      CHECK (certified_progress_pct BETWEEN 0 AND 100);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'av_values_check' AND conrelid = 'activity_verifications'::regclass) THEN
    ALTER TABLE activity_verifications ADD CONSTRAINT av_values_check CHECK (
      kind IN ('progress', 'hold_point', 'completion')
      AND status IN ('pending', 'verified', 'verified_with_changes', 'rejected', 'withdrawn')
      AND claimed_progress_pct BETWEEN 0 AND 100
      AND (certified_progress_pct IS NULL OR certified_progress_pct BETWEEN 0 AND 100)
      AND (kind <> 'hold_point' OR stage_id IS NOT NULL)
    );
  END IF;

  -- A decision needs a decider and a date. A change or a rejection needs a written reason.
  -- A verified or changed answer carries the certified figure.
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'av_decision_check' AND conrelid = 'activity_verifications'::regclass) THEN
    ALTER TABLE activity_verifications ADD CONSTRAINT av_decision_check CHECK (
      (status IN ('pending', 'withdrawn') OR (decided_at IS NOT NULL AND decided_by_id IS NOT NULL AND decided_by_role IS NOT NULL))
      AND (status NOT IN ('verified_with_changes', 'rejected')
           OR (decision_reason IS NOT NULL AND BTRIM(decision_reason) <> ''))
      AND (status NOT IN ('verified', 'verified_with_changes') OR certified_progress_pct IS NOT NULL)
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'vs_values_check' AND conrelid = 'verification_signers'::regclass) THEN
    ALTER TABLE verification_signers ADD CONSTRAINT vs_values_check
      CHECK (status IN ('pending', 'signed', 'replaced'));
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'rework_values_check' AND conrelid = 'rework_items'::regclass) THEN
    ALTER TABLE rework_items ADD CONSTRAINT rework_values_check CHECK (
      kind IN ('rework', 'snag') AND status IN ('open', 'corrected', 'closed') AND BTRIM(reason) <> ''
    );
  END IF;

  FOREACH t IN ARRAY ARRAY['milestones', 'additional_milestones'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = t || '_progress_source_check' AND conrelid = ('public.' || t)::regclass) THEN
      EXECUTE FORMAT('ALTER TABLE public.%I ADD CONSTRAINT %I CHECK (progress_source IN (''manual'', ''activities'') AND derived_progress_pct BETWEEN 0 AND 100)',
                     t, t || '_progress_source_check');
    END IF;
    -- A temporary value only exists on a derived milestone, with a reason, an author and a date.
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = t || '_override_check' AND conrelid = ('public.' || t)::regclass) THEN
      EXECUTE FORMAT('ALTER TABLE public.%I ADD CONSTRAINT %I CHECK (override_pct IS NULL OR (progress_source = ''activities'' AND override_pct BETWEEN 0 AND 100 AND override_reason IS NOT NULL AND BTRIM(override_reason) <> '''' AND override_by_id IS NOT NULL AND override_at IS NOT NULL))',
                     t, t || '_override_check');
    END IF;
  END LOOP;
END;
$$;

-- 8) Closing an activity means certified ----------------------------------------------------------
-- Closed always means certified for contractor activities, and nothing can be closed with open rework.
-- Rows that were already closed before this migration are left alone because their status does not change.
CREATE OR REPLACE FUNCTION enforce_activity_close()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF current_setting('app.project_deletion_purge', true) = 'on' THEN
    RETURN NEW;
  END IF;

  IF NEW.status = 'closed' AND OLD.status IS DISTINCT FROM 'closed' THEN
    IF EXISTS (SELECT 1 FROM rework_items r WHERE r.activity_id = NEW.id AND r.status <> 'closed') THEN
      RAISE EXCEPTION 'An activity cannot be closed while rework or snags are still open.'
        USING ERRCODE = '55000';
    END IF;
    IF NEW.side = 'Contractor' AND NOT EXISTS (
         SELECT 1 FROM activity_verifications v
         WHERE v.activity_id = NEW.id AND v.kind = 'completion'
           AND v.status IN ('verified', 'verified_with_changes')) THEN
      RAISE EXCEPTION 'A contractor activity can only be closed after the consultant certifies its completion.'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS enforce_activity_close ON public.planning_execution;
CREATE TRIGGER enforce_activity_close
  BEFORE UPDATE OF status ON public.planning_execution
  FOR EACH ROW EXECUTE FUNCTION enforce_activity_close();

-- 9) A decided verification stays as it was decided ----------------------------------------------
CREATE OR REPLACE FUNCTION lock_decided_verification()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF current_setting('app.project_deletion_purge', true) = 'on' THEN
    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
  END IF;

  IF OLD.status IN ('verified', 'verified_with_changes', 'rejected') THEN
    IF TG_OP = 'DELETE' THEN
      RAISE EXCEPTION 'A decided verification is part of the project record and cannot be deleted.'
        USING ERRCODE = '55000';
    END IF;
    IF NEW.status                 IS DISTINCT FROM OLD.status
       OR NEW.claimed_progress_pct   IS DISTINCT FROM OLD.claimed_progress_pct
       OR NEW.claimed_figures        IS DISTINCT FROM OLD.claimed_figures
       OR NEW.certified_progress_pct IS DISTINCT FROM OLD.certified_progress_pct
       OR NEW.certified_figures      IS DISTINCT FROM OLD.certified_figures
       OR NEW.decision_reason        IS DISTINCT FROM OLD.decision_reason
       OR NEW.decided_by_id          IS DISTINCT FROM OLD.decided_by_id
       OR NEW.decided_at             IS DISTINCT FROM OLD.decided_at THEN
      RAISE EXCEPTION 'A decided verification cannot be changed.'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$;

DROP TRIGGER IF EXISTS lock_decided_verification ON public.activity_verifications;
CREATE TRIGGER lock_decided_verification
  BEFORE UPDATE OR DELETE ON public.activity_verifications
  FOR EACH ROW EXECUTE FUNCTION lock_decided_verification();

-- 10) Keep the new tables read-only while a project is pending deletion --------------------------
DO $$
DECLARE
  t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'activity_verifications', 'verification_signers', 'rework_items',
    'milestone_activity_progress', 'milestone_progress_overrides', 'milestone_breakdown_requests'
  ] LOOP
    EXECUTE FORMAT('DROP TRIGGER IF EXISTS guard_pending_project_mutation ON public.%I', t);
    EXECUTE FORMAT(
      'CREATE TRIGGER guard_pending_project_mutation BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION guard_pending_project_mutation()',
      t);
  END LOOP;
END;
$$;

COMMIT;

-- End of 2026-11-02-verification-and-milestone-link.sql
