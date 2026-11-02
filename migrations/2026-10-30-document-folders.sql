-- Document folders, Draft, unread markers, queries, numbers, revisions, supporting files, audit trail.
-- Apply after 2026-10-27-document-flow.sql.
-- Safe to run more than once. server.js also does all of this on startup;
-- run this file yourself if the app's database user cannot alter or create tables.

BEGIN;

-- 1) Comments in Control & Reports are now queries. Old 'comment' rows stay valid.
ALTER TABLE document_comments DROP CONSTRAINT IF EXISTS document_comments_kind_check;
ALTER TABLE document_comments
  ADD CONSTRAINT document_comments_kind_check
  CHECK (kind IN ('comment', 'recommendation', 'query'));

-- 2) Which documents each person has already opened (drives the "new" markers).
--    No project_id column on purpose: opening a document must still work while a
--    project is read-only during its scheduled deletion period.
CREATE TABLE IF NOT EXISTS document_reads (
  document_id BIGINT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  user_id     TEXT   NOT NULL,
  user_role   TEXT   NOT NULL,
  seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (document_id, user_id, user_role)
);
CREATE INDEX IF NOT EXISTS idx_document_reads_user ON document_reads (user_id, user_role);

-- 3) Document number (SH-DWG-001), revision (0 = Rev A) and supporting files.
--    "deadline" already exists on documents and is used as the review-by date.
ALTER TABLE documents
  ADD COLUMN IF NOT EXISTS doc_number       TEXT,
  ADD COLUMN IF NOT EXISTS revision_no      INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS supporting_files JSONB   NOT NULL DEFAULT '[]'::jsonb;
CREATE UNIQUE INDEX IF NOT EXISTS uq_documents_project_number
  ON documents (project_id, doc_number) WHERE doc_number IS NOT NULL;

CREATE TABLE IF NOT EXISTS document_counters (    
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  prefix     TEXT    NOT NULL,
  last_no    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (project_id, prefix)
);

-- 4) Query workflow: respond-by date, open / answered / closed, answer text, attachment.
ALTER TABLE document_comments
  ADD COLUMN IF NOT EXISTS respond_by       DATE,
  ADD COLUMN IF NOT EXISTS status           TEXT NOT NULL DEFAULT 'open',
  ADD COLUMN IF NOT EXISTS answer           TEXT,
  ADD COLUMN IF NOT EXISTS answered_by_name TEXT,
  ADD COLUMN IF NOT EXISTS answered_by_role TEXT,
  ADD COLUMN IF NOT EXISTS answered_at      TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS closed_at        TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS closed_by_name   TEXT,
  ADD COLUMN IF NOT EXISTS attachment_name  TEXT,
  ADD COLUMN IF NOT EXISTS attachment_url   TEXT,
  ADD COLUMN IF NOT EXISTS attachment_id    TEXT;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'document_comments_status_check' AND conrelid = 'document_comments'::regclass) THEN
    ALTER TABLE document_comments
      ADD CONSTRAINT document_comments_status_check CHECK (status IN ('open', 'answered', 'closed'));
  END IF;
END;
$$;

-- 5) Audit trail: who did what to a document, and when.
CREATE TABLE IF NOT EXISTS document_events (
  id          BIGSERIAL PRIMARY KEY,
  document_id BIGINT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  project_id  BIGINT NOT NULL,
  actor_id    TEXT,
  actor_role  TEXT,
  actor_name  TEXT,
  action      TEXT NOT NULL,
  detail      TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_document_events_doc ON document_events (document_id, created_at);

-- 6) Keep the new tables that carry a project_id read-only while a project is pending deletion.
DROP TRIGGER IF EXISTS guard_pending_project_mutation ON public.document_events;
CREATE TRIGGER guard_pending_project_mutation
  BEFORE INSERT OR UPDATE OR DELETE ON public.document_events
  FOR EACH ROW EXECUTE FUNCTION guard_pending_project_mutation();

DROP TRIGGER IF EXISTS guard_pending_project_mutation ON public.document_counters;
CREATE TRIGGER guard_pending_project_mutation
  BEFORE INSERT OR UPDATE OR DELETE ON public.document_counters
  FOR EACH ROW EXECUTE FUNCTION guard_pending_project_mutation();

COMMIT;

-- Existing documents get their numbers from server.js a few seconds after it starts.
-- End of 2026-10-30-document-folders.sql
