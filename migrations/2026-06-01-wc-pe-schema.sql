-- 2026-06-01-wc-pe-schema.sql
-- Adds / ensures the schema needed by Work Center and Planning & Execution

-- Workspace Work Center
CREATE TABLE IF NOT EXISTS workspace_work_center (
  id               SERIAL PRIMARY KEY,
  project_id       INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title            TEXT NOT NULL,
  description      TEXT,
  work_package     TEXT,
  assigned_members JSONB NOT NULL DEFAULT '[]'::jsonb,
  priority         TEXT NOT NULL DEFAULT 'normal'
                     CHECK (priority IN ('low','normal','high')),
  status           TEXT NOT NULL DEFAULT 'ongoing'
                     CHECK (status IN ('ongoing','completed','closed')),
  start_date       DATE NOT NULL,
  end_date         DATE NOT NULL,
  linked_file_name TEXT,
  linked_file_id   TEXT,
  linked_file_url  TEXT,
  creator_id       INTEGER NOT NULL,
  creator_role     TEXT NOT NULL,
  side             TEXT NOT NULL
                     CHECK (side IN ('Contractor','Consultant','Client')),
  activity_id      INTEGER REFERENCES planning_execution(id) ON DELETE SET NULL,
  created_at       TIMESTAMP DEFAULT NOW(),
  updated_at       TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_wc_project_side
  ON workspace_work_center(project_id, side);
CREATE INDEX IF NOT EXISTS idx_wc_assigned_members
  ON workspace_work_center USING GIN(assigned_members);
CREATE INDEX IF NOT EXISTS idx_wc_creator
  ON workspace_work_center(project_id, creator_id, creator_role);
CREATE INDEX IF NOT EXISTS idx_wc_status
  ON workspace_work_center(project_id, side, status);
CREATE INDEX IF NOT EXISTS idx_wc_activity_id
  ON workspace_work_center(activity_id);

-- Work Center Progress
CREATE TABLE IF NOT EXISTS workspace_work_center_progress (
  id                SERIAL PRIMARY KEY,
  task_id           INTEGER NOT NULL REFERENCES workspace_work_center(id) ON DELETE CASCADE,
  report_date       DATE NOT NULL,
  member_id         INTEGER NOT NULL,
  member_role       TEXT NOT NULL DEFAULT 'TeamMember',
  work_done         TEXT,
  manpower          TEXT,
  equipment         TEXT,
  materials         TEXT,
  progress_pct      INTEGER DEFAULT 0
                      CHECK (progress_pct BETWEEN 0 AND 100),
  issues            TEXT,
  notes             TEXT,
  attachment_name   TEXT,
  attachment_id     TEXT,
  attachment_url    TEXT,
  submitted_at      TIMESTAMP DEFAULT NOW(),
  validation_status TEXT NOT NULL DEFAULT 'pending'
                      CHECK (validation_status IN ('pending','approved','rejected')),
  validation_notes  TEXT,
  validated_by      INTEGER,
  validated_at      TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_wcp_task_id
  ON workspace_work_center_progress(task_id);
CREATE INDEX IF NOT EXISTS idx_wcp_task_member
  ON workspace_work_center_progress(task_id, member_id);
CREATE INDEX IF NOT EXISTS idx_wcp_member_id
  ON workspace_work_center_progress(member_id);
CREATE INDEX IF NOT EXISTS idx_wcp_validation
  ON workspace_work_center_progress(task_id, validation_status);

-- Work Center Views
CREATE TABLE IF NOT EXISTS work_center_views (
  id         SERIAL PRIMARY KEY,
  task_id    INTEGER NOT NULL REFERENCES workspace_work_center(id) ON DELETE CASCADE,
  viewer_id  INTEGER NOT NULL,
  viewed_at  TIMESTAMP DEFAULT NOW(),
  UNIQUE(task_id, viewer_id)
);

CREATE INDEX IF NOT EXISTS idx_wcv_task_viewer
  ON work_center_views(task_id, viewer_id);

-- Planning & Execution
CREATE TABLE IF NOT EXISTS planning_execution (
  id                SERIAL PRIMARY KEY,
  project_id        INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  milestone_ref     TEXT NOT NULL,
  milestone_id      UUID REFERENCES milestones(id) ON DELETE SET NULL,
  title             TEXT NOT NULL,
  description       TEXT,
  start_date        DATE NOT NULL,
  end_date          DATE NOT NULL,
  planned_quantity  NUMERIC NOT NULL,
  unit              TEXT NOT NULL,
  planned_work      TEXT,
  planned_manpower  TEXT,
  planned_equipment TEXT,
  planned_materials TEXT,
  linked_file_name  TEXT,
  linked_file_id    TEXT,
  linked_file_url   TEXT,
  status            TEXT NOT NULL DEFAULT 'ongoing'
                    CHECK (status IN ('ongoing','completed','closed')),
  creator_id        INTEGER NOT NULL,
  creator_role      TEXT NOT NULL,
  side              TEXT NOT NULL
                    CHECK (side IN ('Contractor','Consultant','Client')),
  created_at        TIMESTAMPTZ DEFAULT NOW(),
  updated_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS planning_execution_tracking (
  id              SERIAL PRIMARY KEY,
  activity_id     INTEGER NOT NULL REFERENCES planning_execution(id) ON DELETE CASCADE,
  report_date     DATE NOT NULL,
  actual_quantity NUMERIC NOT NULL DEFAULT 0,
  unit            TEXT,
  manpower_used   TEXT,
  equipment_used  TEXT,
  materials_used  TEXT,
  progress_pct    NUMERIC(5,2) NOT NULL DEFAULT 0
                  CHECK (progress_pct BETWEEN 0 AND 100),
  issues          TEXT,
  remark          TEXT,
  delay_days      INTEGER NOT NULL DEFAULT 0,
  delay_reason    TEXT,
  attachment_name TEXT,
  attachment_id   TEXT,
  attachment_url  TEXT,
  logged_by       INTEGER NOT NULL,
  logged_by_role  TEXT NOT NULL,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pe_project
  ON planning_execution(project_id, creator_role);
CREATE INDEX IF NOT EXISTS idx_pe_side
  ON planning_execution(project_id, side);
CREATE INDEX IF NOT EXISTS idx_pe_milestone_id
  ON planning_execution(milestone_id);
CREATE INDEX IF NOT EXISTS idx_pet_activity
  ON planning_execution_tracking(activity_id, report_date DESC);
