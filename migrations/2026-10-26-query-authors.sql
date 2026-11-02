-- Who raised each query. Apply after 2026-10-25-record-flow-hardening.sql.
-- Safe to run more than once. server.js also adds this column at start-up.

BEGIN;

ALTER TABLE record_queries ADD COLUMN IF NOT EXISTS raised_by TEXT;

COMMIT;

-- End of 2026-10-26-query-authors.sql

ALTER TABLE stamp_registry
  ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS revoked_by_user_id INTEGER,
  ADD COLUMN IF NOT EXISTS revoked_by_role TEXT,
  ADD COLUMN IF NOT EXISTS revoke_reason TEXT;