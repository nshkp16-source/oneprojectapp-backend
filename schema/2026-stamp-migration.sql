-- ================================================================
-- STAMP & SIGNATURE MIGRATION — additive only, safe on live DB
-- Run once on your Neon database
-- ================================================================

BEGIN;

-- ── 1. user_stamps ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_stamps (
  id              SERIAL PRIMARY KEY,
  user_id         INTEGER NOT NULL,
  user_role       TEXT    NOT NULL,
  project_id      INTEGER,
  signer_name     TEXT,
  signature_image TEXT,
  stamp_image_url TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT fk_user_stamps_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
  CONSTRAINT uniq_user_stamp_project UNIQUE (user_id, user_role, project_id)
);
ALTER TABLE user_stamps ADD COLUMN IF NOT EXISTS signer_name TEXT;

-- ── 2. Stamp columns on all 5 record tables ──────────────────────
ALTER TABLE contractual_records
  ADD COLUMN IF NOT EXISTS signed_by_id    INTEGER,
  ADD COLUMN IF NOT EXISTS signed_by_role  TEXT,
  ADD COLUMN IF NOT EXISTS signed_at       TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS stamp_type      TEXT,
  ADD COLUMN IF NOT EXISTS stamped_doc_url TEXT,
  ADD COLUMN IF NOT EXISTS signature_hash  TEXT;

ALTER TABLE administrative_records
  ADD COLUMN IF NOT EXISTS signed_by_id    INTEGER,
  ADD COLUMN IF NOT EXISTS signed_by_role  TEXT,
  ADD COLUMN IF NOT EXISTS signed_at       TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS stamp_type      TEXT,
  ADD COLUMN IF NOT EXISTS stamped_doc_url TEXT,
  ADD COLUMN IF NOT EXISTS signature_hash  TEXT;

ALTER TABLE safety_records
  ADD COLUMN IF NOT EXISTS signed_by_id    INTEGER,
  ADD COLUMN IF NOT EXISTS signed_by_role  TEXT,
  ADD COLUMN IF NOT EXISTS signed_at       TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS stamp_type      TEXT,
  ADD COLUMN IF NOT EXISTS stamped_doc_url TEXT,
  ADD COLUMN IF NOT EXISTS signature_hash  TEXT;

ALTER TABLE operational_records
  ADD COLUMN IF NOT EXISTS signed_by_id    INTEGER,
  ADD COLUMN IF NOT EXISTS signed_by_role  TEXT,
  ADD COLUMN IF NOT EXISTS signed_at       TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS stamp_type      TEXT,
  ADD COLUMN IF NOT EXISTS stamped_doc_url TEXT,
  ADD COLUMN IF NOT EXISTS signature_hash  TEXT;

ALTER TABLE financial_records
  ADD COLUMN IF NOT EXISTS signed_by_id    INTEGER,
  ADD COLUMN IF NOT EXISTS signed_by_role  TEXT,
  ADD COLUMN IF NOT EXISTS signed_at       TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS stamp_type      TEXT,
  ADD COLUMN IF NOT EXISTS stamped_doc_url TEXT,
  ADD COLUMN IF NOT EXISTS signature_hash  TEXT;

-- ── 3. reviewer_assigned_part on document_reviews ────────────────
ALTER TABLE document_reviews
  ADD COLUMN IF NOT EXISTS reviewer_assigned_part TEXT;

-- ── 4. Expand record_kind to include acceptance_notice ───────────
-- Drop old CHECK, add new one with the extra value

ALTER TABLE contractual_records
  DROP CONSTRAINT IF EXISTS chk_contractual_record_kind;
ALTER TABLE contractual_records
  ADD CONSTRAINT chk_contractual_record_kind
  CHECK (record_kind IN ('new','notice','rejection_notice','acceptance_notice'));

ALTER TABLE administrative_records
  DROP CONSTRAINT IF EXISTS chk_administrative_record_kind;
ALTER TABLE administrative_records
  ADD CONSTRAINT chk_administrative_record_kind
  CHECK (record_kind IN ('new','notice','rejection_notice','acceptance_notice'));

ALTER TABLE safety_records
  DROP CONSTRAINT IF EXISTS chk_safety_record_kind;
ALTER TABLE safety_records
  ADD CONSTRAINT chk_safety_record_kind
  CHECK (record_kind IN ('new','notice','rejection_notice','acceptance_notice'));

ALTER TABLE operational_records
  DROP CONSTRAINT IF EXISTS chk_operational_record_kind;
ALTER TABLE operational_records
  ADD CONSTRAINT chk_operational_record_kind
  CHECK (record_kind IN ('new','notice','rejection_notice','acceptance_notice'));

ALTER TABLE financial_records
  DROP CONSTRAINT IF EXISTS chk_financial_record_kind;
ALTER TABLE financial_records
  ADD CONSTRAINT chk_financial_record_kind
  CHECK (record_kind IN ('new','notice','rejection_notice','acceptance_notice'));

-- document_reviews record_kind also needs acceptance_notice
ALTER TABLE document_reviews
  DROP CONSTRAINT IF EXISTS chk_review_record_kind;
ALTER TABLE document_reviews
  ADD CONSTRAINT chk_review_record_kind
  CHECK (record_kind IN ('new','notice','rejection_notice','acceptance_notice'));

COMMIT;
