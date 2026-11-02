-- Record signing flow: named signers, queries, revisions.
-- Apply after 2026-10-13-professional-meetings.sql.
-- Safe to run more than once. server.js also creates these on startup;
-- run this file yourself if the app's database user cannot create tables,
-- and ALWAYS run section 4 (it is not done by server.js).

BEGIN;

-- 1) Revision and notice columns on the five record tables
ALTER TABLE contractual_records
  ADD COLUMN IF NOT EXISTS revision_of_id    INTEGER,
  ADD COLUMN IF NOT EXISTS revision_no       INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS superseded_by_id  INTEGER,
  ADD COLUMN IF NOT EXISTS notice_source     TEXT,
  ADD COLUMN IF NOT EXISTS respond_by        DATE;
ALTER TABLE administrative_records
  ADD COLUMN IF NOT EXISTS revision_of_id    INTEGER,
  ADD COLUMN IF NOT EXISTS revision_no       INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS superseded_by_id  INTEGER,
  ADD COLUMN IF NOT EXISTS notice_source     TEXT,
  ADD COLUMN IF NOT EXISTS respond_by        DATE;
ALTER TABLE safety_records
  ADD COLUMN IF NOT EXISTS revision_of_id    INTEGER,
  ADD COLUMN IF NOT EXISTS revision_no       INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS superseded_by_id  INTEGER,
  ADD COLUMN IF NOT EXISTS notice_source     TEXT,
  ADD COLUMN IF NOT EXISTS respond_by        DATE;
ALTER TABLE operational_records
  ADD COLUMN IF NOT EXISTS revision_of_id    INTEGER,
  ADD COLUMN IF NOT EXISTS revision_no       INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS superseded_by_id  INTEGER,
  ADD COLUMN IF NOT EXISTS notice_source     TEXT,
  ADD COLUMN IF NOT EXISTS respond_by        DATE;
ALTER TABLE financial_records
  ADD COLUMN IF NOT EXISTS revision_of_id    INTEGER,
  ADD COLUMN IF NOT EXISTS revision_no       INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS superseded_by_id  INTEGER,
  ADD COLUMN IF NOT EXISTS notice_source     TEXT,
  ADD COLUMN IF NOT EXISTS respond_by        DATE;

-- 2) Named signers: the plan, the signatures and the views in one table
CREATE TABLE IF NOT EXISTS record_signers (
  id                    SERIAL PRIMARY KEY,
  record_table          TEXT    NOT NULL,
  record_id             INTEGER NOT NULL,
  project_id            INTEGER NOT NULL,
  stage                 INTEGER NOT NULL,
  side                  TEXT    NOT NULL,
  signer_role           TEXT    NOT NULL,
  signer_user_id        INTEGER NOT NULL,
  signer_position       TEXT,
  is_team_member        BOOLEAN NOT NULL DEFAULT FALSE,
  is_decider            BOOLEAN NOT NULL DEFAULT FALSE,
  order_no              INTEGER NOT NULL DEFAULT 0,
  status                TEXT    NOT NULL DEFAULT 'pending',   -- pending | signed | replaced
  outcome               TEXT,
  findings              JSONB,
  signed_at             TIMESTAMPTZ,
  notice_id             INTEGER,
  first_viewed_at       TIMESTAMPTZ,
  last_viewed_at        TIMESTAMPTZ,
  replaced_by_signer_id INTEGER,
  replaced_at           TIMESTAMPTZ,
  replaced_by_user_id   INTEGER,
  replaced_by_role      TEXT,
  reminder_sent_at      TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS record_signers_record_idx
  ON record_signers (record_table, record_id, stage);
CREATE INDEX IF NOT EXISTS record_signers_user_idx
  ON record_signers (signer_role, signer_user_id, status);

-- 3) Queries raised in a notice, with the uploader's responses
CREATE TABLE IF NOT EXISTS record_queries (
  id                      SERIAL PRIMARY KEY,
  record_table            TEXT    NOT NULL,
  record_id               INTEGER NOT NULL,
  notice_id               INTEGER NOT NULL,
  project_id              INTEGER NOT NULL,
  seq                     INTEGER NOT NULL,
  ref                     TEXT,
  query                   TEXT    NOT NULL,
  required_action         TEXT,
  issuer_role             TEXT,
  issuer_side             TEXT,
  status                  TEXT    NOT NULL DEFAULT 'open',   -- open | answered | resolved | reopened
  response                TEXT,
  responded_at            TIMESTAMPTZ,
  responded_in_record_id  INTEGER,
  responded_by_role       TEXT,
  responded_by_id         INTEGER,
  resolved_at             TIMESTAMPTZ,
  resolved_by_role        TEXT,
  resolved_by_id          INTEGER,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS record_queries_record_idx
  ON record_queries (record_table, record_id);

-- 4) Keep both new tables read-only while a project is pending deletion.
-- The 2026-09-27 lifecycle migration only guarded tables that existed then.
-- Both tables have a project_id column, which the guard function reads directly.
DROP TRIGGER IF EXISTS guard_pending_project_mutation ON public.record_signers;
CREATE TRIGGER guard_pending_project_mutation
  BEFORE INSERT OR UPDATE OR DELETE ON public.record_signers
  FOR EACH ROW EXECUTE FUNCTION guard_pending_project_mutation();

DROP TRIGGER IF EXISTS guard_pending_project_mutation ON public.record_queries;
CREATE TRIGGER guard_pending_project_mutation
  BEFORE INSERT OR UPDATE OR DELETE ON public.record_queries
  FOR EACH ROW EXECUTE FUNCTION guard_pending_project_mutation();

COMMIT;

-- End of 2026-10-24-record-signing-flow.sql
