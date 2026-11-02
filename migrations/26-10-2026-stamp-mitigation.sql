BEGIN;

ALTER TABLE user_stamps ADD COLUMN IF NOT EXISTS mark_type TEXT;

CREATE TABLE IF NOT EXISTS stamp_registry (
  stamp_id        TEXT PRIMARY KEY,
  project_id      INTEGER,
  record_table    TEXT,
  record_id       INTEGER,
  kind            TEXT,
  signer_user_id  INTEGER,
  signer_role     TEXT,
  signer_name     TEXT,
  signer_position TEXT,
  company_name    TEXT,
  label           TEXT,
  tz              TEXT,
  file_hash       TEXT,
  signed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS stamp_registry_record_idx
  ON stamp_registry (record_table, record_id);

-- Same rule as the other tables: read-only while a project is pending deletion
DROP TRIGGER IF EXISTS guard_pending_project_mutation ON public.stamp_registry;
CREATE TRIGGER guard_pending_project_mutation
  BEFORE INSERT OR UPDATE OR DELETE ON public.stamp_registry
  FOR EACH ROW EXECUTE FUNCTION guard_pending_project_mutation();

COMMIT;