-- Activity verification sharing, snag progress and consultant milestone-entry requests.
-- Apply after 2026-11-02-verification-and-milestone-link.sql.
-- Safe to run more than once.

BEGIN;

ALTER TABLE activity_verifications
  ADD COLUMN IF NOT EXISTS share_activity_summary BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS shared_activity_summary JSONB;

ALTER TABLE rework_items
  ADD COLUMN IF NOT EXISTS certified_progress_pct NUMERIC(5,2),
  ADD COLUMN IF NOT EXISTS previous_certified_progress_pct NUMERIC(5,2);

CREATE TABLE IF NOT EXISTS activity_verification_decision_revisions (
  id                         BIGSERIAL PRIMARY KEY,
  project_id                 INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  verification_id            BIGINT NOT NULL REFERENCES activity_verifications(id) ON DELETE CASCADE,
  previous_status            TEXT NOT NULL,
  previous_certified_pct     NUMERIC(5,2),
  revised_status             TEXT NOT NULL CHECK (revised_status IN ('verified', 'verified_with_changes', 'rejected')),
  revised_certified_pct      NUMERIC(5,2),
  reason                     TEXT NOT NULL CHECK (BTRIM(reason) <> ''),
  changed_by_id              INTEGER NOT NULL,
  changed_by_role            TEXT NOT NULL,
  changed_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_av_decision_revisions
  ON activity_verification_decision_revisions (verification_id, changed_at DESC);

CREATE TABLE IF NOT EXISTS milestone_progress_requests (
  id                      BIGSERIAL PRIMARY KEY,
  project_id              INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  baseline_milestone_id   INTEGER REFERENCES milestones(id) ON DELETE CASCADE,
  additional_milestone_id INTEGER REFERENCES additional_milestones(id) ON DELETE CASCADE,
  requested_by_id         INTEGER NOT NULL,
  requested_by_role       TEXT NOT NULL,
  note                    TEXT,
  status                  TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'fulfilled', 'cancelled')),
  requested_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  fulfilled_at            TIMESTAMPTZ,
  CHECK (num_nonnulls(baseline_milestone_id, additional_milestone_id) = 1)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_mpr_open_baseline
  ON milestone_progress_requests (baseline_milestone_id)
  WHERE status = 'open' AND baseline_milestone_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_mpr_open_additional
  ON milestone_progress_requests (additional_milestone_id)
  WHERE status = 'open' AND additional_milestone_id IS NOT NULL;

DO $$
BEGIN
  DROP TRIGGER IF EXISTS guard_pending_project_mutation ON public.activity_verification_decision_revisions;
  CREATE TRIGGER guard_pending_project_mutation
    BEFORE INSERT OR UPDATE OR DELETE ON public.activity_verification_decision_revisions
    FOR EACH ROW EXECUTE FUNCTION guard_pending_project_mutation();
  DROP TRIGGER IF EXISTS guard_pending_project_mutation ON public.milestone_progress_requests;
  CREATE TRIGGER guard_pending_project_mutation
    BEFORE INSERT OR UPDATE OR DELETE ON public.milestone_progress_requests
    FOR EACH ROW EXECUTE FUNCTION guard_pending_project_mutation();
END;
$$;

COMMIT;

-- End of 2026-11-06-activity-milestone-workflow.sql
