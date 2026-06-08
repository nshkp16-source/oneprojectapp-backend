-- Full schedule schema snapshot (2026-06-09)
-- Creates all tables, indexes, and photo/attachment tables used by schedule module

-- Drop existing schedule-related tables (safe to run)
DROP TABLE IF EXISTS milestone_photos CASCADE;
DROP TABLE IF EXISTS progress_entry_attachments CASCADE;
DROP TABLE IF EXISTS additional_milestone_attachments CASCADE;
DROP TABLE IF EXISTS milestone_attachments CASCADE;
DROP TABLE IF EXISTS additional_milestone_progress_entries CASCADE;
DROP TABLE IF EXISTS additional_milestones CASCADE;
DROP TABLE IF EXISTS milestone_progress_entries CASCADE;
DROP TABLE IF EXISTS schedule_extensions CASCADE;
DROP TABLE IF EXISTS milestones CASCADE;
DROP TABLE IF EXISTS project_schedules CASCADE;

BEGIN;

-- Project schedules
CREATE TABLE IF NOT EXISTS project_schedules (
  id SERIAL PRIMARY KEY,
  project_id TEXT NOT NULL UNIQUE,
  planned_start DATE NOT NULL,
  planned_finish DATE NOT NULL,
  total_duration INTEGER NOT NULL DEFAULT 0,
  location JSONB NULL,
  created_by_user_id INTEGER NULL,
  created_by_role TEXT NULL,
  created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_project_schedules_project_id ON project_schedules(project_id);
CREATE INDEX IF NOT EXISTS idx_project_schedules_updated_at ON project_schedules(updated_at);

-- Planned milestones
CREATE TABLE IF NOT EXISTS milestones (
  id SERIAL PRIMARY KEY,
  schedule_id INTEGER NOT NULL REFERENCES project_schedules(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0,
  planned_start DATE NOT NULL,
  planned_end DATE NOT NULL,
  duration_days INTEGER NOT NULL DEFAULT 0,
  float_days INTEGER NOT NULL DEFAULT 0,
  is_critical BOOLEAN NOT NULL DEFAULT FALSE,
  weight_pct NUMERIC(8,2) NOT NULL DEFAULT 0,
  quantity NUMERIC(18,3) NOT NULL DEFAULT 0,
  unit TEXT NULL,
  depends_on INTEGER NULL REFERENCES milestones(id) ON DELETE SET NULL,
  executed NUMERIC(18,3) NOT NULL DEFAULT 0,
  progress_pct NUMERIC(5,2) NOT NULL DEFAULT 0,
  activity_status TEXT NOT NULL DEFAULT 'planned',
  completed_at TIMESTAMP WITHOUT TIME ZONE NULL,
  created_by_user_id INTEGER NULL,
  created_by_role TEXT NULL,
  updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_milestones_schedule_id ON milestones(schedule_id);
CREATE INDEX IF NOT EXISTS idx_milestones_project_id ON milestones(project_id);
CREATE INDEX IF NOT EXISTS idx_milestones_sort_order ON milestones(schedule_id, sort_order);

-- Milestone progress history
CREATE TABLE IF NOT EXISTS milestone_progress_entries (
  id SERIAL PRIMARY KEY,
  milestone_id INTEGER NOT NULL REFERENCES milestones(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL,
  report_date DATE NOT NULL,
  qty_executed NUMERIC(18,3) NOT NULL,
  cumulative_after_entry NUMERIC(18,3) NOT NULL,
  progress_pct_after_entry NUMERIC(5,2) NOT NULL,
  remarks TEXT NULL,
  reported_by_user_id INTEGER NULL,
  reported_by_role TEXT NULL,
  created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
  UNIQUE(milestone_id, report_date)
);
CREATE INDEX IF NOT EXISTS idx_milestone_progress_entries_milestone_id ON milestone_progress_entries(milestone_id);
CREATE INDEX IF NOT EXISTS idx_milestone_progress_entries_project_id ON milestone_progress_entries(project_id);

-- Schedule extensions
CREATE TABLE IF NOT EXISTS schedule_extensions (
  id SERIAL PRIMARY KEY,
  schedule_id INTEGER NOT NULL REFERENCES project_schedules(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL,
  extension_days INTEGER NOT NULL,
  new_planned_start DATE NULL,
  new_planned_finish DATE NULL,
  reason TEXT NULL,
  extension_type TEXT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  requested_by_user_id INTEGER NULL,
  requested_by_role TEXT NULL,
  approved_by_user_id INTEGER NULL,
  approved_by_role TEXT NULL,
  created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_schedule_extensions_schedule_id ON schedule_extensions(schedule_id);
CREATE INDEX IF NOT EXISTS idx_schedule_extensions_project_id ON schedule_extensions(project_id);
CREATE INDEX IF NOT EXISTS idx_schedule_extensions_status ON schedule_extensions(status);
CREATE INDEX IF NOT EXISTS idx_schedule_extensions_start_finish ON schedule_extensions(new_planned_start, new_planned_finish);

-- Additional milestone scope additions (extensions)
CREATE TABLE IF NOT EXISTS additional_milestones (
  id SERIAL PRIMARY KEY,
  schedule_id INTEGER NOT NULL REFERENCES project_schedules(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL,
  schedule_extension_id INTEGER NULL REFERENCES schedule_extensions(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  description TEXT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0,
  planned_start DATE NOT NULL,
  planned_end DATE NOT NULL,
  duration_days INTEGER NOT NULL DEFAULT 0,
  float_days INTEGER NOT NULL DEFAULT 0,
  is_critical BOOLEAN NOT NULL DEFAULT FALSE,
  weight_pct NUMERIC(8,2) NOT NULL DEFAULT 0,
  quantity NUMERIC(18,3) NOT NULL DEFAULT 0,
  unit TEXT NULL,
  depends_on_baseline INTEGER NULL,
  executed NUMERIC(18,3) NOT NULL DEFAULT 0,
  progress_pct NUMERIC(5,2) NOT NULL DEFAULT 0,
  activity_status TEXT NOT NULL DEFAULT 'planned',
  completed_at TIMESTAMP WITHOUT TIME ZONE NULL,
  added_by_user_id INTEGER NULL,
  added_by_role TEXT NULL,
  updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_additional_milestones_schedule_id ON additional_milestones(schedule_id);
CREATE INDEX IF NOT EXISTS idx_additional_milestones_project_id ON additional_milestones(project_id);
CREATE INDEX IF NOT EXISTS idx_additional_milestones_extension_id ON additional_milestones(schedule_extension_id);

-- Additional milestone progress history
CREATE TABLE IF NOT EXISTS additional_milestone_progress_entries (
  id SERIAL PRIMARY KEY,
  additional_milestone_id INTEGER NOT NULL REFERENCES additional_milestones(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL,
  report_date DATE NOT NULL,
  qty_executed NUMERIC(18,3) NOT NULL,
  cumulative_after_entry NUMERIC(18,3) NOT NULL,
  progress_pct_after_entry NUMERIC(5,2) NOT NULL,
  remarks TEXT NULL,
  reported_by_user_id INTEGER NULL,
  reported_by_role TEXT NULL,
  created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
  UNIQUE(additional_milestone_id, report_date)
);
CREATE INDEX IF NOT EXISTS idx_addl_milestone_progress_addl_milestone_id ON additional_milestone_progress_entries(additional_milestone_id);
CREATE INDEX IF NOT EXISTS idx_addl_milestone_progress_project_id ON additional_milestone_progress_entries(project_id);

-- Milestone attachments stored with Cloudinary references
CREATE TABLE IF NOT EXISTS milestone_attachments (
  id SERIAL PRIMARY KEY,
  milestone_id INTEGER NOT NULL REFERENCES milestones(id) ON DELETE CASCADE,
  file_name TEXT NOT NULL,
  file_size BIGINT NULL,
  mime_type TEXT NULL,
  cloudinary_public_id TEXT NOT NULL UNIQUE,
  cloudinary_url TEXT NOT NULL,
  uploaded_by_user_id INTEGER NULL,
  uploaded_by_role TEXT NULL,
  uploaded_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_milestone_attachments_milestone_id ON milestone_attachments(milestone_id);

CREATE TABLE IF NOT EXISTS additional_milestone_attachments (
  id SERIAL PRIMARY KEY,
  additional_milestone_id INTEGER NOT NULL REFERENCES additional_milestones(id) ON DELETE CASCADE,
  file_name TEXT NOT NULL,
  file_size BIGINT NULL,
  mime_type TEXT NULL,
  cloudinary_public_id TEXT NOT NULL UNIQUE,
  cloudinary_url TEXT NOT NULL,
  uploaded_by_user_id INTEGER NULL,
  uploaded_by_role TEXT NULL,
  uploaded_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_addl_ms_attachments_addl_ms_id ON additional_milestone_attachments(additional_milestone_id);

CREATE TABLE IF NOT EXISTS progress_entry_attachments (
  id SERIAL PRIMARY KEY,
  progress_entry_id INTEGER NOT NULL REFERENCES milestone_progress_entries(id) ON DELETE CASCADE,
  file_name TEXT NOT NULL,
  file_size BIGINT NULL,
  mime_type TEXT NULL,
  cloudinary_public_id TEXT NOT NULL UNIQUE,
  cloudinary_url TEXT NOT NULL,
  uploaded_by_user_id INTEGER NULL,
  uploaded_by_role TEXT NULL,
  uploaded_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_progress_entry_attachments_progress_entry_id ON progress_entry_attachments(progress_entry_id);

-- Site photos (milestone photos)
CREATE TABLE IF NOT EXISTS milestone_photos (
  id SERIAL PRIMARY KEY,
  milestone_id INTEGER NULL REFERENCES milestones(id) ON DELETE CASCADE,
  additional_milestone_id INTEGER NULL REFERENCES additional_milestones(id) ON DELETE CASCADE,
  project_id TEXT NULL,
  file_name TEXT NOT NULL,
  cloudinary_url TEXT NOT NULL,
  cloudinary_public_id TEXT NULL,
  uploaded_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
  uploaded_by_user_id INTEGER NULL,
  uploaded_by_role TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_milestone_photos_milestone_id ON milestone_photos(milestone_id);
CREATE INDEX IF NOT EXISTS idx_milestone_photos_additional_milestone_id ON milestone_photos(additional_milestone_id);

COMMIT;
