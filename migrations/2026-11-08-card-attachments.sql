-- Multiple card attachments for planning activities and work-center tasks.
-- Safe to run more than once.

BEGIN;

CREATE TABLE IF NOT EXISTS card_attachments (
  id BIGSERIAL PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  entity_type TEXT NOT NULL CHECK (entity_type IN ('planning_activity', 'work_center_task')),
  entity_id INTEGER NOT NULL,
  file_name TEXT NOT NULL,
  file_id TEXT NOT NULL,
  file_url TEXT NOT NULL,
  mime_type TEXT,
  resource_type TEXT NOT NULL DEFAULT 'raw',
  attachment_type TEXT NOT NULL DEFAULT 'other',
  custom_attachment_type TEXT,
  uploaded_by_id INTEGER,
  uploaded_by_role TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE card_attachments
  ADD COLUMN IF NOT EXISTS mime_type TEXT,
  ADD COLUMN IF NOT EXISTS resource_type TEXT NOT NULL DEFAULT 'raw',
  ADD COLUMN IF NOT EXISTS attachment_type TEXT NOT NULL DEFAULT 'other',
  ADD COLUMN IF NOT EXISTS custom_attachment_type TEXT,
  ADD COLUMN IF NOT EXISTS uploaded_by_id INTEGER,
  ADD COLUMN IF NOT EXISTS uploaded_by_role TEXT;

ALTER TABLE card_attachments DROP CONSTRAINT IF EXISTS card_attachments_type_check;

UPDATE card_attachments
SET attachment_type = 'other',
    custom_attachment_type = COALESCE(
      custom_attachment_type,
      CASE attachment_type
        WHEN 'programme' THEN 'Programme'
        WHEN 'method_statement' THEN 'Method Statement'
        WHEN 'monthly_progress_report' THEN 'Monthly Progress Report'
        WHEN 'inspection_request' THEN 'Request for Inspection'
        WHEN 'claim' THEN 'Claim'
        WHEN 'site_diary' THEN 'Site Diary'
        WHEN 'test_record' THEN 'Test Record'
        WHEN 'as_built_information' THEN 'As-Built Information'
      END
    )
WHERE attachment_type IN (
  'programme', 'method_statement', 'monthly_progress_report', 'inspection_request',
  'claim', 'site_diary', 'test_record', 'as_built_information'
);

ALTER TABLE card_attachments
  ADD CONSTRAINT card_attachments_type_check
  CHECK (attachment_type IN (
    'site_photos', 'daily_progress', 'materials_delivery', 'equipment', 'manpower',
    'quality_test', 'inspection_hold_point', 'issue_delay', 'other'
  ));

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'card_attachments_custom_type_check'
      AND conrelid = 'card_attachments'::regclass
  ) THEN
    ALTER TABLE card_attachments
      ADD CONSTRAINT card_attachments_custom_type_check
      CHECK (custom_attachment_type IS NULL OR char_length(btrim(custom_attachment_type)) BETWEEN 1 AND 120);
  END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_card_attachments_entity
  ON card_attachments (project_id, entity_type, entity_id, created_at DESC, id DESC);

COMMIT;

-- End of 2026-11-08-card-attachments.sql
