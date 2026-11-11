-- Typed supporting evidence belongs to a submitted progress report, not a planned task.
-- Safe to run more than once.

BEGIN;

CREATE TABLE IF NOT EXISTS work_center_report_attachments (
  id BIGSERIAL PRIMARY KEY,
  report_id INTEGER NOT NULL REFERENCES workspace_work_center_progress(id) ON DELETE CASCADE,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  file_name TEXT NOT NULL,
  file_id TEXT NOT NULL,
  file_url TEXT NOT NULL,
  mime_type TEXT,
  attachment_type TEXT NOT NULL,
  custom_attachment_type TEXT,
  uploaded_by_id INTEGER,
  uploaded_by_role TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT work_center_report_attachments_type_check
    CHECK (attachment_type IN (
      'site_photos', 'daily_progress', 'materials_delivery', 'equipment', 'manpower',
      'quality_test', 'inspection_hold_point', 'issue_delay', 'other'
    )),
  CONSTRAINT work_center_report_attachments_custom_type_check
    CHECK (custom_attachment_type IS NULL OR char_length(btrim(custom_attachment_type)) BETWEEN 1 AND 120),
  CONSTRAINT work_center_report_attachments_other_label_check
    CHECK (attachment_type <> 'other' OR custom_attachment_type IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_wc_report_attachments_report
  ON work_center_report_attachments (report_id, created_at, id);
COMMIT;
