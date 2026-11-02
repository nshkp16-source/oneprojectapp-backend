-- Document & Approval / Control & Reports flow: optional signing, same-side comments,
-- reject -> replace -> leader signs again. Apply after 2026-10-26-query-authors.sql.
-- Safe to run more than once. server.js also creates these on startup;
-- run this file yourself if the app's database user cannot create tables.

BEGIN;

-- 1) Signing and Control & Reports status on the existing documents table.
--    approval_status keeps its old values; 'approved' is shown to users as "Signed".
ALTER TABLE documents
  ADD COLUMN IF NOT EXISTS creator_name        TEXT,
  ADD COLUMN IF NOT EXISTS author_stamp_id     TEXT,
  ADD COLUMN IF NOT EXISTS author_signed_at    TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS signed_by_name      TEXT,
  ADD COLUMN IF NOT EXISTS signer_stamp_id     TEXT,
  ADD COLUMN IF NOT EXISTS cr_status           TEXT,
  ADD COLUMN IF NOT EXISTS cr_reject_reason    TEXT,
  ADD COLUMN IF NOT EXISTS cr_rejected_by_role TEXT,
  ADD COLUMN IF NOT EXISTS cr_rejected_at      TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS replaced_at         TIMESTAMPTZ;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'documents_cr_status_check' AND conrelid = 'documents'::regclass) THEN
    ALTER TABLE documents
      ADD CONSTRAINT documents_cr_status_check
      CHECK (cr_status IS NULL OR cr_status IN ('shared', 'rejected', 'replacement_pending'));
  END IF;
END;
$$;

-- 2) Comments and recommendations on shared documents (same side only; enforced by the API)
CREATE TABLE IF NOT EXISTS document_comments (
  id          BIGSERIAL PRIMARY KEY,
  document_id BIGINT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  project_id  BIGINT NOT NULL,
  author_id   BIGINT,
  author_role TEXT,
  author_name TEXT,
  kind        TEXT NOT NULL DEFAULT 'comment' CHECK (kind IN ('comment', 'recommendation')),
  body        TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 2000),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_document_comments_doc ON document_comments (document_id, created_at);

-- 3) Files the leader rejected, kept as history when the author replaces them
CREATE TABLE IF NOT EXISTS document_versions (
  id               BIGSERIAL PRIMARY KEY,
  document_id      BIGINT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  project_id       BIGINT NOT NULL,
  file_name        TEXT,
  file_url         TEXT,
  file_id          TEXT,
  reason           TEXT,
  rejected_by_role TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_document_versions_doc ON document_versions (document_id, created_at);

-- 4) Keep both new tables read-only while a project is pending deletion
--    (the 2026-09-27 lifecycle migration only guarded tables that existed then).
DROP TRIGGER IF EXISTS guard_pending_project_mutation ON public.document_comments;
CREATE TRIGGER guard_pending_project_mutation
  BEFORE INSERT OR UPDATE OR DELETE ON public.document_comments
  FOR EACH ROW EXECUTE FUNCTION guard_pending_project_mutation();

DROP TRIGGER IF EXISTS guard_pending_project_mutation ON public.document_versions;
CREATE TRIGGER guard_pending_project_mutation
  BEFORE INSERT OR UPDATE OR DELETE ON public.document_versions
  FOR EACH ROW EXECUTE FUNCTION guard_pending_project_mutation();

COMMIT;

-- No backfill is needed: a shared document with cr_status NULL is treated as 'shared' by the API.
-- End of 2026-10-27-document-flow.sql
