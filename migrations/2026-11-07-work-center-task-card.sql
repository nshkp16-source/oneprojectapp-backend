-- Work Center task-card collaboration, reporting detail, and offline-safe submissions.
-- Apply after 2026-11-07-link-task-queries-to-reports.sql.
-- Safe to run more than once.

BEGIN;

ALTER TABLE workspace_work_center
  ADD COLUMN IF NOT EXISTS location_block TEXT,
  ADD COLUMN IF NOT EXISTS location_floor TEXT,
  ADD COLUMN IF NOT EXISTS location_zone TEXT,
  ADD COLUMN IF NOT EXISTS location_grid TEXT,
  ADD COLUMN IF NOT EXISTS location_drawing TEXT,
  ADD COLUMN IF NOT EXISTS reminder_sent_at TIMESTAMPTZ;

ALTER TABLE workspace_work_center_progress
  ADD COLUMN IF NOT EXISTS delay_cause TEXT,
  ADD COLUMN IF NOT EXISTS delay_note TEXT,
  ADD COLUMN IF NOT EXISTS delay_days INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_wc_progress_idempotency
  ON workspace_work_center_progress (task_id, member_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS work_center_report_photos (
  id BIGSERIAL PRIMARY KEY,
  report_id INTEGER NOT NULL REFERENCES workspace_work_center_progress(id) ON DELETE CASCADE,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  seq SMALLINT NOT NULL CHECK (seq BETWEEN 1 AND 10),
  file_name TEXT NOT NULL,
  file_id TEXT NOT NULL,
  file_url TEXT NOT NULL,
  captured_at TIMESTAMPTZ,
  latitude NUMERIC(9,6),
  longitude NUMERIC(9,6),
  accuracy_m NUMERIC(8,2),
  uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (report_id, seq)
);

CREATE TABLE IF NOT EXISTS work_center_report_resources (
  id BIGSERIAL PRIMARY KEY,
  report_id INTEGER NOT NULL REFERENCES workspace_work_center_progress(id) ON DELETE CASCADE,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  resource_type TEXT NOT NULL CHECK (resource_type IN ('manpower', 'equipment', 'material')),
  name TEXT NOT NULL,
  quantity NUMERIC(12,3),
  unit TEXT,
  hours NUMERIC(8,2),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (quantity IS NULL OR quantity >= 0),
  CHECK (hours IS NULL OR hours >= 0)
);
ALTER TABLE work_center_report_resources
  ADD COLUMN IF NOT EXISTS assigned_member_id INTEGER
    REFERENCES team_members(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_wc_report_resources_report
  ON work_center_report_resources (report_id, resource_type, id);

CREATE TABLE IF NOT EXISTS work_center_task_comments (
  id BIGSERIAL PRIMARY KEY,
  task_id INTEGER NOT NULL REFERENCES workspace_work_center(id) ON DELETE CASCADE,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  author_id INTEGER NOT NULL,
  author_role TEXT NOT NULL,
  body TEXT NOT NULL CHECK (length(btrim(body)) BETWEEN 1 AND 5000),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wc_task_comments_task
  ON work_center_task_comments (task_id, created_at, id);

CREATE TABLE IF NOT EXISTS work_center_task_history (
  id BIGSERIAL PRIMARY KEY,
  task_id INTEGER NOT NULL REFERENCES workspace_work_center(id) ON DELETE CASCADE,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  actor_id INTEGER NOT NULL,
  actor_role TEXT NOT NULL,
  action TEXT NOT NULL,
  detail JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wc_task_history_task
  ON work_center_task_history (task_id, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS work_center_checklists (
  id BIGSERIAL PRIMARY KEY,
  task_id INTEGER NOT NULL REFERENCES workspace_work_center(id) ON DELETE CASCADE,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title TEXT NOT NULL CHECK (length(btrim(title)) BETWEEN 1 AND 200),
  required_before_approval BOOLEAN NOT NULL DEFAULT FALSE,
  created_by_id INTEGER NOT NULL,
  created_by_role TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS work_center_checklist_items (
  id BIGSERIAL PRIMARY KEY,
  checklist_id BIGINT NOT NULL REFERENCES work_center_checklists(id) ON DELETE CASCADE,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title TEXT NOT NULL CHECK (length(btrim(title)) BETWEEN 1 AND 500),
  assigned_member_id INTEGER,
  is_complete BOOLEAN NOT NULL DEFAULT FALSE,
  completed_by_id INTEGER,
  completed_by_role TEXT,
  completed_at TIMESTAMPTZ,
  seq INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wc_checklist_items_checklist
  ON work_center_checklist_items (checklist_id, seq, id);

CREATE TABLE IF NOT EXISTS work_center_task_links (
  id BIGSERIAL PRIMARY KEY,
  task_id INTEGER NOT NULL REFERENCES workspace_work_center(id) ON DELETE CASCADE,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  link_type TEXT NOT NULL CHECK (link_type IN ('drawing', 'record', 'query', 'task', 'url')),
  target_id TEXT,
  title TEXT NOT NULL CHECK (length(btrim(title)) BETWEEN 1 AND 300),
  url TEXT,
  created_by_id INTEGER NOT NULL,
  created_by_role TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK ((link_type = 'url' AND url IS NOT NULL) OR link_type <> 'url')
);
CREATE INDEX IF NOT EXISTS idx_wc_task_links_task
  ON work_center_task_links (task_id, id);

CREATE TABLE IF NOT EXISTS work_center_task_dependencies (
  task_id INTEGER NOT NULL REFERENCES workspace_work_center(id) ON DELETE CASCADE,
  depends_on_task_id INTEGER NOT NULL REFERENCES workspace_work_center(id) ON DELETE CASCADE,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  created_by_id INTEGER NOT NULL,
  created_by_role TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (task_id, depends_on_task_id),
  CHECK (task_id <> depends_on_task_id)
);
CREATE INDEX IF NOT EXISTS idx_wc_dependencies_predecessor
  ON work_center_task_dependencies (depends_on_task_id);

CREATE TABLE IF NOT EXISTS work_center_task_templates (
  id BIGSERIAL PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  side TEXT NOT NULL,
  name TEXT NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
  created_by_id INTEGER NOT NULL,
  created_by_role TEXT NOT NULL,
  task_data JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wc_task_templates_project_side
  ON work_center_task_templates (project_id, side, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_wc_task_templates_name
  ON work_center_task_templates (project_id, side, lower(name));

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'wc_progress_delay_cause_check'
      AND conrelid = 'workspace_work_center_progress'::regclass
  ) THEN
    ALTER TABLE workspace_work_center_progress
      ADD CONSTRAINT wc_progress_delay_cause_check
      CHECK (delay_cause IS NULL OR delay_cause IN
        ('weather', 'materials', 'equipment', 'access', 'design', 'labor', 'other')) NOT VALID;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'wc_progress_delay_days_check'
      AND conrelid = 'workspace_work_center_progress'::regclass
  ) THEN
    ALTER TABLE workspace_work_center_progress
      ADD CONSTRAINT wc_progress_delay_days_check CHECK (delay_days BETWEEN 0 AND 365) NOT VALID;
  END IF;
END;
$$;

COMMIT;

-- End of 2026-11-07-work-center-task-card.sql
