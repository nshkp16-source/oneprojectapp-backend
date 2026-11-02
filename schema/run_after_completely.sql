-- =============================
-- RUN AFTER: completely schema.sql
-- This file contains idempotent migrations that bring the DB
-- to the state expected by server.js and the app runtime.
-- Safe to re-run: uses IF NOT EXISTS where possible.
-- Order: run this AFTER running `completely schema.sql` unchanged.
-- =============================

BEGIN;

-- 1) Ensure user_stamps exists (final shape: per-project stamps)
CREATE TABLE IF NOT EXISTS user_stamps (
  id              SERIAL PRIMARY KEY,
  user_id         INTEGER NOT NULL,
  user_role       TEXT    NOT NULL,
  project_id      INTEGER,
  signer_name     TEXT,
  company_name    TEXT,
  signature_image TEXT,
  stamp_image_url TEXT,
  stamp_style     TEXT NOT NULL DEFAULT 'compact',
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_user_stamp_project ON user_stamps(user_id, user_role, project_id);
CREATE INDEX IF NOT EXISTS idx_user_stamps_lookup ON user_stamps(user_id, user_role, project_id);

-- 2) Stamp and signature columns on the five record tables
-- These are additive and safe to run after the canonical schema.
ALTER TABLE contractual_records
  ADD COLUMN IF NOT EXISTS signed_by_id    INTEGER,
  ADD COLUMN IF NOT EXISTS signed_by_role  TEXT,
  ADD COLUMN IF NOT EXISTS signed_at       TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS stamp_type      TEXT,
  ADD COLUMN IF NOT EXISTS stamped_doc_url TEXT,
  ADD COLUMN IF NOT EXISTS signature_hash  TEXT,
  ADD COLUMN IF NOT EXISTS stamp_status    TEXT,
  ADD COLUMN IF NOT EXISTS stamp_page      INTEGER,
  ADD COLUMN IF NOT EXISTS stamp_x         NUMERIC,
  ADD COLUMN IF NOT EXISTS stamp_y         NUMERIC;

ALTER TABLE administrative_records
  ADD COLUMN IF NOT EXISTS signed_by_id    INTEGER,
  ADD COLUMN IF NOT EXISTS signed_by_role  TEXT,
  ADD COLUMN IF NOT EXISTS signed_at       TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS stamp_type      TEXT,
  ADD COLUMN IF NOT EXISTS stamped_doc_url TEXT,
  ADD COLUMN IF NOT EXISTS signature_hash  TEXT,
  ADD COLUMN IF NOT EXISTS stamp_status    TEXT,
  ADD COLUMN IF NOT EXISTS stamp_page      INTEGER,
  ADD COLUMN IF NOT EXISTS stamp_x         NUMERIC,
  ADD COLUMN IF NOT EXISTS stamp_y         NUMERIC;

ALTER TABLE safety_records
  ADD COLUMN IF NOT EXISTS signed_by_id    INTEGER,
  ADD COLUMN IF NOT EXISTS signed_by_role  TEXT,
  ADD COLUMN IF NOT EXISTS signed_at       TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS stamp_type      TEXT,
  ADD COLUMN IF NOT EXISTS stamped_doc_url TEXT,
  ADD COLUMN IF NOT EXISTS signature_hash  TEXT,
  ADD COLUMN IF NOT EXISTS stamp_status    TEXT,
  ADD COLUMN IF NOT EXISTS stamp_page      INTEGER,
  ADD COLUMN IF NOT EXISTS stamp_x         NUMERIC,
  ADD COLUMN IF NOT EXISTS stamp_y         NUMERIC;

ALTER TABLE operational_records
  ADD COLUMN IF NOT EXISTS signed_by_id    INTEGER,
  ADD COLUMN IF NOT EXISTS signed_by_role  TEXT,
  ADD COLUMN IF NOT EXISTS signed_at       TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS stamp_type      TEXT,
  ADD COLUMN IF NOT EXISTS stamped_doc_url TEXT,
  ADD COLUMN IF NOT EXISTS signature_hash  TEXT,
  ADD COLUMN IF NOT EXISTS stamp_status    TEXT,
  ADD COLUMN IF NOT EXISTS stamp_page      INTEGER,
  ADD COLUMN IF NOT EXISTS stamp_x         NUMERIC,
  ADD COLUMN IF NOT EXISTS stamp_y         NUMERIC;

ALTER TABLE financial_records
  ADD COLUMN IF NOT EXISTS signed_by_id    INTEGER,
  ADD COLUMN IF NOT EXISTS signed_by_role  TEXT,
  ADD COLUMN IF NOT EXISTS signed_at       TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS stamp_type      TEXT,
  ADD COLUMN IF NOT EXISTS stamped_doc_url TEXT,
  ADD COLUMN IF NOT EXISTS signature_hash  TEXT,
  ADD COLUMN IF NOT EXISTS stamp_status    TEXT,
  ADD COLUMN IF NOT EXISTS stamp_page      INTEGER,
  ADD COLUMN IF NOT EXISTS stamp_x         NUMERIC,
  ADD COLUMN IF NOT EXISTS stamp_y         NUMERIC;

-- 2b) Optional supporting files stored alongside the official PDF
ALTER TABLE contractual_records ADD COLUMN IF NOT EXISTS supporting_files JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE administrative_records ADD COLUMN IF NOT EXISTS supporting_files JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE safety_records ADD COLUMN IF NOT EXISTS supporting_files JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE operational_records ADD COLUMN IF NOT EXISTS supporting_files JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE financial_records ADD COLUMN IF NOT EXISTS supporting_files JSONB NOT NULL DEFAULT '[]'::jsonb;

-- 3) Ensure document_reviews has any new columns expected by stamp migrations
ALTER TABLE document_reviews
  ADD COLUMN IF NOT EXISTS reviewer_assigned_part TEXT,
  ADD COLUMN IF NOT EXISTS record_kind TEXT;

-- 4) Expand record_kind CHECKs to include 'acceptance_notice' (idempotent)
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

ALTER TABLE document_reviews
  DROP CONSTRAINT IF EXISTS chk_review_record_kind;
ALTER TABLE document_reviews
  ADD CONSTRAINT chk_review_record_kind
  CHECK (record_kind IN ('new','notice','rejection_notice','acceptance_notice'));

-- 5) Display name columns expected by server.js
ALTER TABLE clients ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE contractors ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE consultants ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE team_members ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE contractor_project_managers ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE consultant_project_managers ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE client_project_managers ADD COLUMN IF NOT EXISTS display_name TEXT;

-- Populate clients.display_name from representative where missing
UPDATE clients SET display_name = representative WHERE display_name IS NULL AND representative IS NOT NULL;

-- 6) Ensure company_name on user_stamps (safe to run multiple times)
ALTER TABLE user_stamps ADD COLUMN IF NOT EXISTS company_name TEXT;
ALTER TABLE user_stamps ADD COLUMN IF NOT EXISTS stamp_style TEXT NOT NULL DEFAULT 'compact';

-- 7) Schedule supporting documents (kept in the transaction for re-runs)
ALTER TABLE schedule_extensions
  ADD COLUMN IF NOT EXISTS supporting_file_name TEXT,
  ADD COLUMN IF NOT EXISTS supporting_file_url TEXT,
  ADD COLUMN IF NOT EXISTS supporting_file_public_id TEXT,
  ADD COLUMN IF NOT EXISTS supporting_file_mime TEXT,
  ADD COLUMN IF NOT EXISTS supporting_file_size INTEGER;

COMMIT;

-- End of run_after_completely.sql