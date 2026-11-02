-- ================================================================
-- STAMP-ON-DOWNLOAD MIGRATION
-- Adds stamp_page, stamp_x, stamp_y columns to all 5 record tables
-- Removes stamped_doc_url and signature_hash (no longer stored)
-- Safe to run on live DB
-- ================================================================

BEGIN;

ALTER TABLE contractual_records
  ADD COLUMN IF NOT EXISTS stamp_page  INTEGER,
  ADD COLUMN IF NOT EXISTS stamp_x     NUMERIC,
  ADD COLUMN IF NOT EXISTS stamp_y     NUMERIC;

ALTER TABLE administrative_records
  ADD COLUMN IF NOT EXISTS stamp_page  INTEGER,
  ADD COLUMN IF NOT EXISTS stamp_x     NUMERIC,
  ADD COLUMN IF NOT EXISTS stamp_y     NUMERIC;

ALTER TABLE safety_records
  ADD COLUMN IF NOT EXISTS stamp_page  INTEGER,
  ADD COLUMN IF NOT EXISTS stamp_x     NUMERIC,
  ADD COLUMN IF NOT EXISTS stamp_y     NUMERIC;

ALTER TABLE operational_records
  ADD COLUMN IF NOT EXISTS stamp_page  INTEGER,
  ADD COLUMN IF NOT EXISTS stamp_x     NUMERIC,
  ADD COLUMN IF NOT EXISTS stamp_y     NUMERIC;

ALTER TABLE financial_records
  ADD COLUMN IF NOT EXISTS stamp_page  INTEGER,
  ADD COLUMN IF NOT EXISTS stamp_x     NUMERIC,
  ADD COLUMN IF NOT EXISTS stamp_y     NUMERIC;

COMMIT;
