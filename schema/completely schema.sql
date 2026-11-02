-- ================================================================
-- ONEPROJECT — FULL DATABASE RESET & REBUILD
-- Single canonical schema. Run top-to-bottom on a fresh DB or
-- to hard-reset an existing one. Every section starts with DROP
-- so re-running is safe (all old data will be lost).
-- Last updated: 2026-06-16
-- ================================================================


-- ================================================================
-- SECTION 1 — VIEWS (drop first, they depend on tables below)
-- ================================================================

DROP VIEW IF EXISTS v_project_execution_summary     CASCADE;
DROP VIEW IF EXISTS v_milestone_progress_curve      CASCADE;
DROP VIEW IF EXISTS v_milestone_effective_dates     CASCADE;
DROP VIEW IF EXISTS v_chat_messages_with_replies    CASCADE;
DROP VIEW IF EXISTS assignments_view                CASCADE;


-- ================================================================
-- SECTION 2 — DROP ALL TABLES (reverse dependency order)
-- ================================================================

-- Chat
DROP FUNCTION IF EXISTS fn_set_message_delivered_on_read()  CASCADE;
DROP FUNCTION IF EXISTS fn_set_message_delivered_on_delivered() CASCADE;
DROP TABLE    IF EXISTS project_chat_delivered_receipts      CASCADE;
DROP TABLE    IF EXISTS project_chat_read_receipts           CASCADE;
DROP TABLE    IF EXISTS project_chat_messages                CASCADE;

-- Arrets
DROP TABLE IF EXISTS arret_views        CASCADE;
DROP TABLE IF EXISTS arret_attachments  CASCADE;
DROP TABLE IF EXISTS arrets             CASCADE;

-- Notifications
DROP FUNCTION IF EXISTS create_notification_for_project(INTEGER,TEXT,INTEGER,TEXT,INTEGER,TEXT) CASCADE;
DROP FUNCTION IF EXISTS mark_notification_read(INTEGER,TEXT,INTEGER)        CASCADE;
DROP FUNCTION IF EXISTS mark_all_notifications_read_for_recipient(TEXT,INTEGER) CASCADE;
DROP TABLE    IF EXISTS notification_recipients  CASCADE;
DROP TABLE    IF EXISTS notifications            CASCADE;

-- Project Records
DROP TABLE IF EXISTS document_reviews       CASCADE;
DROP TABLE IF EXISTS reply_relationships    CASCADE;
DROP TABLE IF EXISTS meeting_attachments    CASCADE;
DROP TABLE IF EXISTS meeting_minutes        CASCADE;
DROP TABLE IF EXISTS meetings               CASCADE;
DROP TABLE IF EXISTS financial_records      CASCADE;
DROP TABLE IF EXISTS operational_records    CASCADE;
DROP TABLE IF EXISTS safety_records         CASCADE;
DROP TABLE IF EXISTS administrative_records CASCADE;
DROP TABLE IF EXISTS contractual_records    CASCADE;

-- Workspace Documents / Control & Report
DROP TABLE IF EXISTS control_and_report_comments    CASCADE;
DROP TABLE IF EXISTS control_and_report_index       CASCADE;
DROP TABLE IF EXISTS workspace_document_reviews     CASCADE;
DROP TABLE IF EXISTS workspace_documents            CASCADE;
DROP TABLE IF EXISTS report_requests                CASCADE;
DROP TABLE IF EXISTS documents                      CASCADE;
DROP TABLE IF EXISTS document_approval_notes        CASCADE;
DROP TABLE IF EXISTS document_views                 CASCADE;

-- Schedule & Progress
DROP TABLE IF EXISTS progress_entry_attachments             CASCADE;
DROP TABLE IF EXISTS milestone_photos                       CASCADE;
DROP TABLE IF EXISTS additional_milestone_attachments       CASCADE;
DROP TABLE IF EXISTS milestone_attachments                  CASCADE;
DROP TABLE IF EXISTS additional_milestone_progress_entries  CASCADE;
DROP TABLE IF EXISTS additional_milestones                  CASCADE;
DROP TABLE IF EXISTS milestone_extensions                   CASCADE;
DROP TABLE IF EXISTS milestone_progress_entries             CASCADE;
DROP TABLE IF EXISTS schedule_extensions                    CASCADE;
DROP TABLE IF EXISTS milestones                             CASCADE;
DROP TABLE IF EXISTS project_schedules                      CASCADE;

-- Planning & Execution / Work Center
DROP TABLE IF EXISTS workspace_work_center_progress CASCADE;
DROP TABLE IF EXISTS work_center_views              CASCADE;
DROP TABLE IF EXISTS workspace_work_center          CASCADE;
DROP TABLE IF EXISTS planning_execution_tracking    CASCADE;
DROP TABLE IF EXISTS planning_execution             CASCADE;

-- Assignments & Auth
DROP TABLE IF EXISTS contractor_assignments     CASCADE;
DROP TABLE IF EXISTS consultant_assignments     CASCADE;
DROP TABLE IF EXISTS team_member_assignments    CASCADE;
DROP TABLE IF EXISTS contractor_pm_assignments  CASCADE;
DROP TABLE IF EXISTS consultant_pm_assignments  CASCADE;
DROP TABLE IF EXISTS client_pm_assignments      CASCADE;
DROP TABLE IF EXISTS refresh_tokens             CASCADE;
DROP TABLE IF EXISTS email_tokens               CASCADE;

-- Projects
DROP TABLE IF EXISTS projects CASCADE;
DROP TABLE IF EXISTS user_stamps CASCADE;

-- Users
DROP TABLE IF EXISTS clients                    CASCADE;
DROP TABLE IF EXISTS contractors                CASCADE;
DROP TABLE IF EXISTS consultants                CASCADE;
DROP TABLE IF EXISTS team_members               CASCADE;
DROP TABLE IF EXISTS contractor_project_managers CASCADE;
DROP TABLE IF EXISTS consultant_project_managers CASCADE;
DROP TABLE IF EXISTS client_project_managers    CASCADE;


-- ================================================================
-- SECTION 3 — USER TABLES
-- ================================================================

CREATE TABLE clients (
  id                  SERIAL PRIMARY KEY,
  company_name        TEXT NOT NULL,
  company_email       TEXT UNIQUE NOT NULL,
  representative      TEXT,
  title               TEXT,
  telephone           TEXT,
  display_name        TEXT,
  password_hash       TEXT,
  verified            BOOLEAN DEFAULT false,
  profile_picture     TEXT,
  profile_picture_id  TEXT,
  created_at          TIMESTAMP DEFAULT NOW()
);

CREATE TABLE contractors (
  id                  SERIAL PRIMARY KEY,
  email               TEXT UNIQUE NOT NULL,
  password_hash       TEXT,
  display_name        TEXT,
  verified            BOOLEAN DEFAULT false,
  profile_picture     TEXT,
  profile_picture_id  TEXT,
  created_at          TIMESTAMP DEFAULT NOW()
);

CREATE TABLE consultants (
  id                  SERIAL PRIMARY KEY,
  email               TEXT UNIQUE NOT NULL,
  password_hash       TEXT,
  display_name        TEXT,
  verified            BOOLEAN DEFAULT false,
  profile_picture     TEXT,
  profile_picture_id  TEXT,
  created_at          TIMESTAMP DEFAULT NOW()
);

CREATE TABLE team_members (
  id                  SERIAL PRIMARY KEY,
  email               TEXT UNIQUE NOT NULL,
  password_hash       TEXT,
  display_name        TEXT,
  verified            BOOLEAN DEFAULT false,
  profile_picture     TEXT,
  profile_picture_id  TEXT,
  created_at          TIMESTAMP DEFAULT NOW()
);

CREATE TABLE contractor_project_managers (
  id                  SERIAL PRIMARY KEY,
  email               TEXT UNIQUE NOT NULL,
  password_hash       TEXT,
  display_name        TEXT,
  verified            BOOLEAN DEFAULT false,
  profile_picture     TEXT,
  profile_picture_id  TEXT,
  created_at          TIMESTAMP DEFAULT NOW()
);

CREATE TABLE consultant_project_managers (
  id                  SERIAL PRIMARY KEY,
  email               TEXT UNIQUE NOT NULL,
  password_hash       TEXT,
  display_name        TEXT,
  verified            BOOLEAN DEFAULT false,
  profile_picture     TEXT,
  profile_picture_id  TEXT,
  created_at          TIMESTAMP DEFAULT NOW()
);

CREATE TABLE client_project_managers (
  id                  SERIAL PRIMARY KEY,
  email               TEXT UNIQUE NOT NULL,
  password_hash       TEXT,
  display_name        TEXT,
  verified            BOOLEAN DEFAULT false,
  profile_picture     TEXT,
  profile_picture_id  TEXT,
  created_at          TIMESTAMP DEFAULT NOW()
);


-- ================================================================
-- SECTION 4 — PROJECTS
-- ================================================================

CREATE TABLE projects (
  id                  SERIAL PRIMARY KEY,
  name                TEXT NOT NULL,
  location            TEXT,
  contract_reference  TEXT,
  client_id           INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  created_by_user_id  INTEGER,
  created_by_role     TEXT,
  created_at          TIMESTAMP DEFAULT NOW(),
  CONSTRAINT unique_project_per_client UNIQUE (name, client_id)
);

CREATE INDEX idx_projects_client ON projects(client_id);

CREATE TABLE user_stamps (
  id              SERIAL PRIMARY KEY,
  user_id         INTEGER NOT NULL,
  user_role       TEXT NOT NULL,
  project_id      INTEGER REFERENCES projects(id) ON DELETE CASCADE,
  signer_name     TEXT,
  company_name    TEXT,
  signature_image TEXT,
  stamp_image_url TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT uniq_user_stamp_project UNIQUE (user_id, user_role, project_id)
);

CREATE INDEX idx_user_stamps_lookup ON user_stamps(user_id, user_role, project_id);


-- ================================================================
-- SECTION 5 — AUTH TABLES
-- ================================================================

CREATE TABLE refresh_tokens (
  id          SERIAL PRIMARY KEY,
  user_id     INTEGER NOT NULL,
  role        TEXT NOT NULL,
  token       TEXT NOT NULL,
  created_at  TIMESTAMP DEFAULT NOW(),
  expires_at  TIMESTAMP NOT NULL DEFAULT (NOW() + INTERVAL '24 hours')
);

CREATE TABLE email_tokens (
  id               SERIAL PRIMARY KEY,
  email            TEXT NOT NULL,
  token            TEXT NOT NULL,
  expires_at       TIMESTAMP NOT NULL,
  attempts         INTEGER DEFAULT 0,
  session_id       TEXT,
  verified         BOOLEAN DEFAULT false,
  pending_password BOOLEAN DEFAULT false,
  reset_flow       BOOLEAN DEFAULT false,
  project_flow     BOOLEAN DEFAULT false,
  created_at       TIMESTAMP DEFAULT NOW()
);


-- ================================================================
-- SECTION 6 — ASSIGNMENT TABLES
-- ================================================================

CREATE TABLE contractor_assignments (
  id              SERIAL PRIMARY KEY,
  project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  contractor_id   INTEGER NOT NULL REFERENCES contractors(id) ON DELETE CASCADE,
  company_name    TEXT,
  telephone       TEXT,
  task            TEXT,
  representative  TEXT,
  title_position  TEXT,
  created_at      TIMESTAMP DEFAULT NOW(),
  CONSTRAINT unique_contractor_per_project UNIQUE (project_id, contractor_id)
);

CREATE TABLE consultant_assignments (
  id              SERIAL PRIMARY KEY,
  project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  consultant_id   INTEGER NOT NULL REFERENCES consultants(id) ON DELETE CASCADE,
  company_name    TEXT,
  telephone       TEXT,
  task            TEXT,
  representative  TEXT,
  title_position  TEXT,
  created_at      TIMESTAMP DEFAULT NOW(),
  CONSTRAINT unique_consultant_per_project UNIQUE (project_id, consultant_id)
);

CREATE TABLE team_member_assignments (
  id               SERIAL PRIMARY KEY,
  project_id       INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  team_member_id   INTEGER NOT NULL REFERENCES team_members(id) ON DELETE CASCADE,
  name             TEXT,
  position         TEXT,
  telephone        TEXT,
  assigned_part    TEXT NOT NULL DEFAULT 'Client',
  assigned_by      INTEGER NOT NULL,
  assigned_by_role TEXT,
  created_at       TIMESTAMP DEFAULT NOW(),
  CONSTRAINT unique_team_member_per_project UNIQUE (project_id, team_member_id)
);

CREATE TABLE contractor_pm_assignments (
  id                SERIAL PRIMARY KEY,
  project_id        INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  contractor_pm_id  INTEGER NOT NULL REFERENCES contractor_project_managers(id) ON DELETE CASCADE,
  name              TEXT,
  telephone         TEXT,
  task              TEXT,
  created_at        TIMESTAMP DEFAULT NOW(),
  CONSTRAINT unique_contractor_pm_per_project UNIQUE (project_id, contractor_pm_id)
);

CREATE TABLE consultant_pm_assignments (
  id                SERIAL PRIMARY KEY,
  project_id        INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  consultant_pm_id  INTEGER NOT NULL REFERENCES consultant_project_managers(id) ON DELETE CASCADE,
  name              TEXT,
  telephone         TEXT,
  task              TEXT,
  created_at        TIMESTAMP DEFAULT NOW(),
  CONSTRAINT unique_consultant_pm_per_project UNIQUE (project_id, consultant_pm_id)
);

CREATE TABLE client_pm_assignments (
  id              SERIAL PRIMARY KEY,
  project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  client_pm_id    INTEGER NOT NULL REFERENCES client_project_managers(id) ON DELETE CASCADE,
  name            TEXT,
  telephone       TEXT,
  task            TEXT,
  created_at      TIMESTAMP DEFAULT NOW(),
  CONSTRAINT unique_client_pm_per_project UNIQUE (project_id, client_pm_id)
);


-- ================================================================
-- SECTION 7 — ASSIGNMENTS VIEW
-- ================================================================

CREATE OR REPLACE VIEW assignments_view AS

SELECT
  ca.id,
  ca.project_id,
  'Contractor'::TEXT     AS role,
  ca.contractor_id       AS role_id,
  c.email                AS role_email,
  ca.company_name,
  ca.title_position,
  ca.telephone,
  ca.task,
  ca.representative,
  NULL::TEXT             AS name,
  ca.created_at,
  NULL::TEXT             AS assigned_part,
  NULL::INTEGER          AS assigned_by,
  NULL::TEXT             AS assigned_by_role
FROM contractor_assignments ca
JOIN contractors c ON ca.contractor_id = c.id

UNION ALL

SELECT
  co.id,
  co.project_id,
  'Consultant'::TEXT     AS role,
  co.consultant_id       AS role_id,
  c.email                AS role_email,
  co.company_name,
  co.title_position,
  co.telephone,
  co.task,
  co.representative,
  NULL::TEXT             AS name,
  co.created_at,
  NULL::TEXT             AS assigned_part,
  NULL::INTEGER          AS assigned_by,
  NULL::TEXT             AS assigned_by_role
FROM consultant_assignments co
JOIN consultants c ON co.consultant_id = c.id

UNION ALL

SELECT
  tm.id,
  tm.project_id,
  'TeamMember'::TEXT     AS role,
  tm.team_member_id      AS role_id,
  t.email                AS role_email,
  NULL::TEXT             AS company_name,
  tm.position            AS title_position,
  tm.telephone,
  NULL::TEXT             AS task,
  NULL::TEXT             AS representative,
  tm.name,
  tm.created_at,
  tm.assigned_part,
  tm.assigned_by,
  tm.assigned_by_role
FROM team_member_assignments tm
JOIN team_members t ON tm.team_member_id = t.id

UNION ALL

SELECT
  cpm.id,
  cpm.project_id,
  'ContractorPM'::TEXT   AS role,
  cpm.contractor_pm_id   AS role_id,
  pm.email               AS role_email,
  NULL::TEXT             AS company_name,
  NULL::TEXT             AS title_position,
  cpm.telephone,
  cpm.task,
  NULL::TEXT             AS representative,
  cpm.name,
  cpm.created_at,
  NULL::TEXT             AS assigned_part,
  NULL::INTEGER          AS assigned_by,
  NULL::TEXT             AS assigned_by_role
FROM contractor_pm_assignments cpm
JOIN contractor_project_managers pm ON cpm.contractor_pm_id = pm.id

UNION ALL

SELECT
  copm.id,
  copm.project_id,
  'ConsultantPM'::TEXT   AS role,
  copm.consultant_pm_id  AS role_id,
  pm.email               AS role_email,
  NULL::TEXT             AS company_name,
  NULL::TEXT             AS title_position,
  copm.telephone,
  copm.task,
  NULL::TEXT             AS representative,
  copm.name,
  copm.created_at,
  NULL::TEXT             AS assigned_part,
  NULL::INTEGER          AS assigned_by,
  NULL::TEXT             AS assigned_by_role
FROM consultant_pm_assignments copm
JOIN consultant_project_managers pm ON copm.consultant_pm_id = pm.id

UNION ALL

SELECT
  clpm.id,
  clpm.project_id,
  'ClientPM'::TEXT       AS role,
  clpm.client_pm_id      AS role_id,
  pm.email               AS role_email,
  NULL::TEXT             AS company_name,
  NULL::TEXT             AS title_position,
  clpm.telephone,
  clpm.task,
  NULL::TEXT             AS representative,
  clpm.name,
  clpm.created_at,
  NULL::TEXT             AS assigned_part,
  NULL::INTEGER          AS assigned_by,
  NULL::TEXT             AS assigned_by_role
FROM client_pm_assignments clpm
JOIN client_project_managers pm ON clpm.client_pm_id = pm.id;


-- ================================================================
-- SECTION 8 — PLANNING & EXECUTION
-- ================================================================

CREATE TABLE planning_execution (
  id                SERIAL PRIMARY KEY,
  project_id        INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  milestone_name    TEXT,                          -- human label (replaces old milestone_ref)
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
  status            TEXT NOT NULL DEFAULT 'not_yet_started'
                    CHECK (status IN ('not_yet_started','ongoing','completed','closed')),
  creator_id        INTEGER NOT NULL,
  creator_role      TEXT NOT NULL,
  side              TEXT NOT NULL
                    CHECK (side IN ('Contractor','Consultant','Client')),
  created_at        TIMESTAMPTZ DEFAULT NOW(),
  updated_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_pe_project      ON planning_execution(project_id, creator_role);
CREATE INDEX idx_pe_side         ON planning_execution(project_id, side);
CREATE INDEX idx_pe_milestone    ON planning_execution(project_id, milestone_name);

CREATE TABLE planning_execution_tracking (
  id                       SERIAL PRIMARY KEY,
  activity_id              INTEGER NOT NULL REFERENCES planning_execution(id) ON DELETE CASCADE,
  report_date              DATE NOT NULL,
  actual_quantity          NUMERIC NOT NULL DEFAULT 0,
  unit                     TEXT,
  manpower_used            TEXT,
  equipment_used           TEXT,
  materials_used           TEXT,
  progress_pct             NUMERIC(5,2) NOT NULL DEFAULT 0
                           CHECK (progress_pct BETWEEN 0 AND 100),
  issues                   TEXT,
  remark                   TEXT,
  day_remark               TEXT,
  delay_days               INTEGER NOT NULL DEFAULT 0,
  delay_reason             TEXT,
  status_change_to_closed  BOOLEAN NOT NULL DEFAULT FALSE,
  attachment_name          TEXT,
  attachment_id            TEXT,
  attachment_url           TEXT,
  logged_by                INTEGER NOT NULL,
  logged_by_role           TEXT NOT NULL,
  created_at               TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_pet_activity ON planning_execution_tracking(activity_id, report_date DESC);
CREATE UNIQUE INDEX ux_planning_execution_tracking_activity_date
  ON planning_execution_tracking(activity_id, report_date);


-- ================================================================
-- SECTION 9 — WORK CENTER
-- ================================================================

CREATE TABLE workspace_work_center (
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

CREATE INDEX idx_wc_project_side    ON workspace_work_center(project_id, side);
CREATE INDEX idx_wc_assigned_members ON workspace_work_center USING GIN(assigned_members);
CREATE INDEX idx_wc_creator         ON workspace_work_center(project_id, creator_id, creator_role);
CREATE INDEX idx_wc_status          ON workspace_work_center(project_id, side, status);
CREATE INDEX idx_wc_activity_id     ON workspace_work_center(activity_id);

CREATE TABLE workspace_work_center_progress (
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

CREATE INDEX idx_wcp_task_id    ON workspace_work_center_progress(task_id);
CREATE INDEX idx_wcp_task_member ON workspace_work_center_progress(task_id, member_id);
CREATE INDEX idx_wcp_member_id  ON workspace_work_center_progress(member_id);
CREATE INDEX idx_wcp_validation ON workspace_work_center_progress(task_id, validation_status);

CREATE TABLE work_center_views (
  id        SERIAL PRIMARY KEY,
  task_id   INTEGER NOT NULL REFERENCES workspace_work_center(id) ON DELETE CASCADE,
  viewer_id INTEGER NOT NULL,
  viewed_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(task_id, viewer_id)
);

CREATE INDEX idx_wcv_task_viewer ON work_center_views(task_id, viewer_id);


-- ================================================================
-- SECTION 10 — PROJECT SCHEDULE & MILESTONES
-- ================================================================

CREATE TABLE project_schedules (
  id                  SERIAL PRIMARY KEY,
  project_id          TEXT NOT NULL UNIQUE,          -- stored as TEXT to match server.js casting
  planned_start       DATE NOT NULL,
  planned_finish      DATE NOT NULL,
  total_duration      INTEGER NOT NULL DEFAULT 0,
  location            JSONB NULL,
  created_by_user_id  INTEGER NULL,
  created_by_role     TEXT NULL,
  created_at          TIMESTAMP DEFAULT NOW(),
  updated_at          TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_project_schedules_project_id ON project_schedules(project_id);
CREATE INDEX idx_project_schedules_updated_at ON project_schedules(updated_at);

CREATE TABLE milestones (
  id                  SERIAL PRIMARY KEY,
  schedule_id         INTEGER NOT NULL REFERENCES project_schedules(id) ON DELETE CASCADE,
  project_id          TEXT NOT NULL,
  title               TEXT NOT NULL,
  description         TEXT NULL,
  sort_order          INTEGER NOT NULL DEFAULT 0,
  planned_start       DATE NOT NULL,
  planned_end         DATE NOT NULL,
  duration_days       INTEGER NOT NULL DEFAULT 0,
  float_days          INTEGER NOT NULL DEFAULT 0,
  is_critical         BOOLEAN NOT NULL DEFAULT FALSE,
  weight_pct          NUMERIC(8,2) NOT NULL DEFAULT 0,
  quantity            NUMERIC(18,3) NOT NULL DEFAULT 0,
  unit                TEXT NULL,
  depends_on          INTEGER NULL REFERENCES milestones(id) ON DELETE SET NULL,
  executed            NUMERIC(18,3) NOT NULL DEFAULT 0,
  progress_pct        NUMERIC(5,2) NOT NULL DEFAULT 0,
  activity_status     TEXT NOT NULL DEFAULT 'planned'
                      CHECK (activity_status IN ('planned','in_progress','completed')),
  completed_at        TIMESTAMP NULL,
  created_by_user_id  INTEGER NULL,
  created_by_role     TEXT NULL,
  updated_at          TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_milestones_schedule_id ON milestones(schedule_id);
CREATE INDEX idx_milestones_project_id  ON milestones(project_id);
CREATE INDEX idx_milestones_sort_order  ON milestones(schedule_id, sort_order);
CREATE INDEX idx_milestones_status      ON milestones(activity_status);

CREATE TABLE milestone_progress_entries (
  id                       SERIAL PRIMARY KEY,
  milestone_id             INTEGER NOT NULL REFERENCES milestones(id) ON DELETE CASCADE,
  project_id               TEXT NOT NULL,
  report_date              DATE NOT NULL,
  qty_executed             NUMERIC(18,3) NOT NULL,
  cumulative_after_entry   NUMERIC(18,3) NOT NULL,
  progress_pct_after_entry NUMERIC(5,2) NOT NULL,
  remarks                  TEXT NULL,
  reported_by_user_id      INTEGER NULL,
  reported_by_role         TEXT NULL,
  created_at               TIMESTAMP DEFAULT NOW(),
  UNIQUE(milestone_id, report_date)
);

CREATE INDEX idx_milestone_progress_entries_milestone_id ON milestone_progress_entries(milestone_id);
CREATE INDEX idx_milestone_progress_entries_project_id   ON milestone_progress_entries(project_id);

CREATE TABLE milestone_attachments (
  id                    SERIAL PRIMARY KEY,
  milestone_id          INTEGER NOT NULL REFERENCES milestones(id) ON DELETE CASCADE,
  file_name             TEXT NOT NULL,
  file_size             BIGINT NULL,
  mime_type             TEXT NULL,
  cloudinary_public_id  TEXT NOT NULL UNIQUE,
  cloudinary_url        TEXT NOT NULL,
  uploaded_by_user_id   INTEGER NULL,
  uploaded_by_role      TEXT NULL,
  uploaded_at           TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_milestone_attachments_milestone_id ON milestone_attachments(milestone_id);

CREATE TABLE schedule_extensions (
  id                    SERIAL PRIMARY KEY,
  schedule_id           INTEGER NOT NULL REFERENCES project_schedules(id) ON DELETE CASCADE,
  project_id            TEXT NOT NULL,
  extension_days        INTEGER NOT NULL,
  new_planned_start     DATE NOT NULL,
  new_planned_finish    DATE NOT NULL,
  reason                TEXT NOT NULL,
  extension_type        TEXT NOT NULL,
  status                TEXT NOT NULL DEFAULT 'pending',
  requested_by_user_id  INTEGER NULL,
  requested_by_role     TEXT NULL,
  approved_by_user_id   INTEGER NULL,
  approved_by_role      TEXT NULL,
  supporting_file_name  TEXT NULL,
  supporting_file_url   TEXT NULL,
  supporting_file_public_id TEXT NULL,
  supporting_file_mime  TEXT NULL,
  supporting_file_size  INTEGER NULL,
  created_at            TIMESTAMP DEFAULT NOW(),
  updated_at            TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_schedule_extensions_schedule_id   ON schedule_extensions(schedule_id);
CREATE INDEX idx_schedule_extensions_project_id    ON schedule_extensions(project_id);
CREATE INDEX idx_schedule_extensions_status        ON schedule_extensions(status);
CREATE INDEX idx_schedule_extensions_start_finish  ON schedule_extensions(new_planned_start, new_planned_finish);

CREATE TABLE additional_milestones (
  id                    SERIAL PRIMARY KEY,
  schedule_id           INTEGER NOT NULL REFERENCES project_schedules(id) ON DELETE CASCADE,
  project_id            TEXT NOT NULL,
  schedule_extension_id INTEGER NULL REFERENCES schedule_extensions(id) ON DELETE SET NULL,
  title                 TEXT NOT NULL,
  description           TEXT NULL,
  sort_order            INTEGER NOT NULL DEFAULT 0,
  planned_start         DATE NOT NULL,
  planned_end           DATE NOT NULL,
  duration_days         INTEGER NOT NULL DEFAULT 0,
  float_days            INTEGER NOT NULL DEFAULT 0,
  is_critical           BOOLEAN NOT NULL DEFAULT FALSE,
  weight_pct            NUMERIC(8,2) NOT NULL DEFAULT 0,
  quantity              NUMERIC(18,3) NOT NULL DEFAULT 0,
  unit                  TEXT NULL,
  depends_on_baseline   INTEGER NULL REFERENCES milestones(id) ON DELETE SET NULL,
  executed              NUMERIC(18,3) NOT NULL DEFAULT 0,
  progress_pct          NUMERIC(5,2) NOT NULL DEFAULT 0,
  activity_status       TEXT NOT NULL DEFAULT 'planned'
                        CHECK (activity_status IN ('planned','in_progress','completed')),
  completed_at          TIMESTAMP NULL,
  added_by_user_id      INTEGER NULL,
  added_by_role         TEXT NULL,
  updated_at            TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_additional_milestones_schedule_id   ON additional_milestones(schedule_id);
CREATE INDEX idx_additional_milestones_project_id    ON additional_milestones(project_id);
CREATE INDEX idx_additional_milestones_extension_id  ON additional_milestones(schedule_extension_id);

CREATE TABLE additional_milestone_progress_entries (
  id                       SERIAL PRIMARY KEY,
  additional_milestone_id  INTEGER NOT NULL REFERENCES additional_milestones(id) ON DELETE CASCADE,
  project_id               TEXT NOT NULL,
  report_date              DATE NOT NULL,
  qty_executed             NUMERIC(18,3) NOT NULL,
  cumulative_after_entry   NUMERIC(18,3) NOT NULL,
  progress_pct_after_entry NUMERIC(5,2) NOT NULL,
  remarks                  TEXT NULL,
  reported_by_user_id      INTEGER NULL,
  reported_by_role         TEXT NULL,
  created_at               TIMESTAMP DEFAULT NOW(),
  UNIQUE(additional_milestone_id, report_date)
);

CREATE INDEX idx_addl_milestone_progress_addl_milestone_id ON additional_milestone_progress_entries(additional_milestone_id);
CREATE INDEX idx_addl_milestone_progress_project_id        ON additional_milestone_progress_entries(project_id);

CREATE TABLE additional_milestone_attachments (
  id                      SERIAL PRIMARY KEY,
  additional_milestone_id INTEGER NOT NULL REFERENCES additional_milestones(id) ON DELETE CASCADE,
  file_name               TEXT NOT NULL,
  file_size               BIGINT NULL,
  mime_type               TEXT NULL,
  cloudinary_public_id    TEXT NOT NULL UNIQUE,
  cloudinary_url          TEXT NOT NULL,
  uploaded_by_user_id     INTEGER NULL,
  uploaded_by_role        TEXT NULL,
  uploaded_at             TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_addl_ms_attachments_addl_ms_id ON additional_milestone_attachments(additional_milestone_id);

CREATE TABLE progress_entry_attachments (
  id                    SERIAL PRIMARY KEY,
  progress_entry_id     INTEGER NOT NULL REFERENCES milestone_progress_entries(id) ON DELETE CASCADE,
  file_name             TEXT NOT NULL,
  file_size             BIGINT NULL,
  mime_type             TEXT NULL,
  cloudinary_public_id  TEXT NOT NULL UNIQUE,
  cloudinary_url        TEXT NOT NULL,
  uploaded_by_user_id   INTEGER NULL,
  uploaded_by_role      TEXT NULL,
  uploaded_at           TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_progress_entry_attachments_progress_entry_id ON progress_entry_attachments(progress_entry_id);

CREATE TABLE milestone_photos (
  id                      SERIAL PRIMARY KEY,
  milestone_id            INTEGER NULL REFERENCES milestones(id) ON DELETE CASCADE,
  additional_milestone_id INTEGER NULL REFERENCES additional_milestones(id) ON DELETE CASCADE,
  project_id              TEXT NULL,
  file_name               TEXT NOT NULL,
  cloudinary_url          TEXT NOT NULL,
  cloudinary_public_id    TEXT NULL,
  uploaded_at             TIMESTAMP DEFAULT NOW(),
  uploaded_by_user_id     INTEGER NULL,
  uploaded_by_role        TEXT NULL
);

CREATE INDEX idx_milestone_photos_milestone_id ON milestone_photos(milestone_id);
CREATE INDEX idx_milestone_photos_additional_milestone_id ON milestone_photos(additional_milestone_id);


-- ================================================================
-- SECTION 11 — SCHEDULE VIEWS
-- ================================================================

CREATE VIEW v_milestone_effective_dates AS
SELECT
  m.id                AS milestone_id,
  m.schedule_id,
  m.project_id,
  m.title,
  m.sort_order,
  m.quantity,
  m.unit,
  m.planned_start     AS baseline_start,
  m.planned_end       AS baseline_end,
  m.duration_days     AS baseline_duration,
  m.float_days        AS baseline_float,
  m.is_critical       AS baseline_critical,
  m.weight_pct        AS baseline_weight_pct,
  m.planned_start     AS effective_start,    -- no milestone_extensions table in this schema
  m.planned_end       AS effective_end,
  m.duration_days     AS effective_duration,
  m.float_days        AS effective_float,
  m.is_critical       AS effective_critical,
  m.executed,
  m.progress_pct,
  m.activity_status,
  m.completed_at
FROM milestones m;

CREATE VIEW v_milestone_progress_curve AS
SELECT
  e.milestone_id,
  e.project_id,
  e.report_date,
  e.qty_executed                              AS qty_that_day,
  e.cumulative_after_entry                    AS cumulative_executed,
  e.progress_pct_after_entry                  AS actual_pct_on_date,
  m.quantity                                  AS planned_quantity,
  m.weight_pct                                AS milestone_weight,
  ROUND(
    100.0 * GREATEST(0, e.report_date - m.planned_start)
    / NULLIF(m.duration_days, 0),
  2)                                          AS planned_pct_on_date,
  ROUND(
    e.progress_pct_after_entry -
    (100.0 * GREATEST(0, e.report_date - m.planned_start)
     / NULLIF(m.duration_days, 0)),
  2)                                          AS schedule_variance_pct,
  e.reported_by_user_id,
  e.reported_by_role
FROM milestone_progress_entries e
JOIN milestones m ON m.id = e.milestone_id;

CREATE VIEW v_project_execution_summary AS
SELECT
  ps.project_id,
  ps.id                                                               AS schedule_id,
  ps.planned_start                                                    AS baseline_project_start,
  ps.planned_finish                                                   AS baseline_project_finish,
  ps.total_duration                                                   AS baseline_total_days,
  COALESCE(
    (SELECT new_planned_finish FROM schedule_extensions
     WHERE schedule_id = ps.id AND status = 'approved'
     ORDER BY created_at DESC LIMIT 1),
    ps.planned_finish
  )                                                                   AS current_planned_finish,
  COUNT(m.id)                                                         AS total_milestones,
  COUNT(m.id) FILTER (WHERE m.activity_status = 'planned')            AS not_started_count,
  COUNT(m.id) FILTER (WHERE m.activity_status = 'in_progress')        AS in_progress_count,
  COUNT(m.id) FILTER (WHERE m.activity_status = 'completed')          AS completed_count,
  ROUND(
    SUM(m.weight_pct * m.progress_pct) / NULLIF(SUM(m.weight_pct), 0),
  2)                                                                  AS overall_execution_pct,
  ROUND(
    100.0 * GREATEST(0, CURRENT_DATE - ps.planned_start)
    / NULLIF(ps.total_duration, 0),
  2)                                                                  AS planned_pct_today,
  ROUND(
    (SUM(m.weight_pct * m.progress_pct) / NULLIF(SUM(m.weight_pct), 0))
    - (100.0 * GREATEST(0, CURRENT_DATE - ps.planned_start)
       / NULLIF(ps.total_duration, 0)),
  2)                                                                  AS execution_vs_plan_variance,
  SUM(m.quantity)                                                     AS total_planned_qty,
  SUM(m.executed)                                                     AS total_executed_qty,
  COUNT(se.id)                                                        AS total_extensions,
  COALESCE(SUM(se.extension_days) FILTER (WHERE se.status = 'approved'), 0) AS total_days_extended,
  COUNT(m.id) FILTER (WHERE m.is_critical)                            AS critical_path_count
FROM project_schedules ps
LEFT JOIN milestones m           ON m.schedule_id = ps.id
LEFT JOIN schedule_extensions se ON se.schedule_id = ps.id
GROUP BY ps.project_id, ps.id;


-- ================================================================
-- SECTION 12 — DOCUMENT APPROVAL (legacy documents table)
-- ================================================================

CREATE TABLE documents (
  id              BIGSERIAL PRIMARY KEY,
  project_id      BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  category        TEXT,
  document_date   DATE,
  deadline        DATE,
  file_name       TEXT,
  file_id         TEXT,
  file_url        TEXT,
  creator_id      BIGINT NOT NULL,
  creator_role    TEXT NOT NULL,
  side            TEXT NOT NULL CHECK (side IN ('Contractor','Consultant','Client')),
  approval_status TEXT NOT NULL DEFAULT 'draft'
                  CHECK (approval_status IN ('draft','pending_approval','approved','rejected')),
  approved_by_id    BIGINT,
  approved_by_role  TEXT,
  approval_date     TIMESTAMP,
  rejection_reason  TEXT,
  is_shared         BOOLEAN DEFAULT FALSE,
  shared_at         TIMESTAMP,
  is_read_only      BOOLEAN DEFAULT FALSE,
  created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_documents_project_side     ON documents(project_id, side);
CREATE INDEX idx_documents_creator          ON documents(creator_id);
CREATE INDEX idx_documents_approval_status  ON documents(approval_status);
CREATE INDEX idx_documents_is_shared        ON documents(is_shared);

CREATE TABLE document_approval_notes (
  id                     BIGSERIAL PRIMARY KEY,
  document_id            BIGINT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  note_text              TEXT NOT NULL,
  created_by_id          BIGINT NOT NULL,
  created_by_role        TEXT NOT NULL,
  is_visible_to_creator  BOOLEAN DEFAULT FALSE,
  created_at             TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_document_approval_notes_document ON document_approval_notes(document_id);

CREATE TABLE document_views (
  id          BIGSERIAL PRIMARY KEY,
  document_id BIGINT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  viewer_id   BIGINT NOT NULL,
  viewed_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(document_id, viewer_id)
);

CREATE INDEX idx_document_views_document ON document_views(document_id);


-- ================================================================
-- SECTION 13 — WORKSPACE DOCUMENTS & CONTROL/REPORT
-- ================================================================

CREATE TABLE report_requests (
  id             SERIAL PRIMARY KEY,
  project_id     INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  activity_id    INTEGER REFERENCES planning_execution(id) ON DELETE CASCADE,
  requested_by   INTEGER NOT NULL,
  requested_role TEXT NOT NULL,
  assigned_to    INTEGER NOT NULL,
  assigned_role  TEXT NOT NULL,
  title          TEXT NOT NULL,
  description    TEXT,
  due_date       DATE,
  status         TEXT DEFAULT 'pending'
                 CHECK (status IN ('pending','in_progress','submitted','reviewed','completed')),
  remark         TEXT,
  created_at     TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_report_requests_project_id  ON report_requests(project_id);
CREATE INDEX idx_report_requests_assigned_to ON report_requests(assigned_to);

CREATE TABLE workspace_documents (
  id             SERIAL PRIMARY KEY,
  project_id     INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  activity_id    INTEGER REFERENCES planning_execution(id) ON DELETE CASCADE,
  request_id     INTEGER REFERENCES report_requests(id) ON DELETE SET NULL,
  title          TEXT NOT NULL,
  description    TEXT,
  category       TEXT NOT NULL,
  file_name      TEXT NOT NULL,
  file_id        TEXT NOT NULL,
  submitted_by   INTEGER NOT NULL,
  submitted_role TEXT NOT NULL,
  submitted_at   TIMESTAMP DEFAULT NOW(),
  status         TEXT DEFAULT 'draft'
                 CHECK (status IN ('draft','needs_revision','validated','ready_for_control','ready_for_external')),
  visibility     TEXT DEFAULT 'private'
                 CHECK (visibility IN ('private','internal','external')),
  remark         TEXT,
  team_reader_id INTEGER,
  validated_by   INTEGER,
  validated_at   TIMESTAMP,
  validation_note TEXT,
  required_schema JSONB,
  created_at     TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_workspace_documents_project_id   ON workspace_documents(project_id);
CREATE INDEX idx_workspace_documents_request_id   ON workspace_documents(request_id);
CREATE INDEX idx_workspace_documents_submitted_by ON workspace_documents(submitted_by);

CREATE TABLE workspace_document_reviews (
  id            SERIAL PRIMARY KEY,
  document_id   INTEGER NOT NULL REFERENCES workspace_documents(id) ON DELETE CASCADE,
  reviewer_id   INTEGER NOT NULL,
  reviewer_role TEXT NOT NULL,
  review_stage  TEXT NOT NULL,
  decision      TEXT DEFAULT 'pending'
                CHECK (decision IN ('pending','accepted','needs_revision')),
  remark        TEXT,
  delay_days    INTEGER DEFAULT 0,
  delay_reason  TEXT,
  reviewed_at   TIMESTAMP
);

CREATE INDEX idx_workspace_document_reviews_document_id ON workspace_document_reviews(document_id);
CREATE INDEX idx_workspace_document_reviews_reviewer_id ON workspace_document_reviews(reviewer_id);

CREATE TABLE control_and_report_index (
  id           SERIAL PRIMARY KEY,
  document_id  INTEGER NOT NULL REFERENCES workspace_documents(id) ON DELETE CASCADE,
  project_id   INTEGER NOT NULL,
  part         TEXT NOT NULL,
  title        TEXT NOT NULL,
  category     TEXT NOT NULL,
  validated_by INTEGER NOT NULL,
  validated_at TIMESTAMP NOT NULL,
  visibility   TEXT DEFAULT 'internal' CHECK (visibility IN ('internal','shared')),
  promoted     BOOLEAN DEFAULT FALSE,
  promoted_by  INTEGER,
  promoted_at  TIMESTAMP
);

CREATE INDEX idx_control_and_report_index_project_id  ON control_and_report_index(project_id);
CREATE INDEX idx_control_and_report_index_document_id ON control_and_report_index(document_id);

CREATE TABLE control_and_report_comments (
  id             SERIAL PRIMARY KEY,
  report_id      INTEGER NOT NULL REFERENCES control_and_report_index(id) ON DELETE CASCADE,
  commentator_id INTEGER NOT NULL,
  position       TEXT,
  comment_text   TEXT NOT NULL,
  commented_at   TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_control_and_report_comments_report_id ON control_and_report_comments(report_id);


-- ================================================================
-- SECTION 14 — PROJECT RECORDS
-- ================================================================

CREATE TABLE contractual_records (
  id              SERIAL PRIMARY KEY,
  project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  file_path       TEXT,
  attachment_id   TEXT,
  supporting_files JSONB NOT NULL DEFAULT '[]'::jsonb,
  issued_date     TIMESTAMP DEFAULT NOW(),
  uploaded_by     INTEGER NOT NULL,
  role            TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending_review',
  review_required BOOLEAN DEFAULT true,
  record_kind     TEXT NOT NULL DEFAULT 'new',
  notice_tied_id  INTEGER REFERENCES contractual_records(id) ON DELETE CASCADE,
  signed_by_id    INTEGER,
  signed_by_role  TEXT,
  signed_at       TIMESTAMPTZ,
  stamp_type      TEXT,
  stamped_doc_url TEXT,
  signature_hash  TEXT,
  stamp_status    TEXT,
  stamp_page      INTEGER,
  stamp_x         NUMERIC,
  stamp_y         NUMERIC,
  CONSTRAINT chk_contractual_status CHECK (status IN (
    'pending_review','pending_consultant_approval','pending_client_acceptance',
    'pending_client_approval','pending_contractor_acceptance','approved_record','rejected'
  )),
  CONSTRAINT chk_contractual_record_kind CHECK (record_kind IN ('new','notice','rejection_notice','acceptance_notice'))
);

CREATE TABLE administrative_records (
  id              SERIAL PRIMARY KEY,
  project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  file_path       TEXT,
  attachment_id   TEXT,
  supporting_files JSONB NOT NULL DEFAULT '[]'::jsonb,
  issued_date     TIMESTAMP DEFAULT NOW(),
  uploaded_by     INTEGER NOT NULL,
  role            TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending_review',
  review_required BOOLEAN DEFAULT true,
  record_kind     TEXT NOT NULL DEFAULT 'new',
  notice_tied_id  INTEGER REFERENCES administrative_records(id) ON DELETE CASCADE,
  signed_by_id    INTEGER,
  signed_by_role  TEXT,
  signed_at       TIMESTAMPTZ,
  stamp_type      TEXT,
  stamped_doc_url TEXT,
  signature_hash  TEXT,
  stamp_status    TEXT,
  stamp_page      INTEGER,
  stamp_x         NUMERIC,
  stamp_y         NUMERIC,
  CONSTRAINT chk_administrative_status CHECK (status IN (
    'pending_review','pending_consultant_approval','pending_client_acceptance',
    'pending_client_approval','pending_contractor_acceptance','approved_record','rejected'
  )),
  CONSTRAINT chk_administrative_record_kind CHECK (record_kind IN ('new','notice','rejection_notice','acceptance_notice'))
);

CREATE TABLE safety_records (
  id              SERIAL PRIMARY KEY,
  project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  file_path       TEXT,
  attachment_id   TEXT,
  supporting_files JSONB NOT NULL DEFAULT '[]'::jsonb,
  issued_date     TIMESTAMP DEFAULT NOW(),
  uploaded_by     INTEGER NOT NULL,
  role            TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending_review',
  review_required BOOLEAN DEFAULT true,
  record_kind     TEXT NOT NULL DEFAULT 'new',
  notice_tied_id  INTEGER REFERENCES safety_records(id) ON DELETE CASCADE,
  signed_by_id    INTEGER,
  signed_by_role  TEXT,
  signed_at       TIMESTAMPTZ,
  stamp_type      TEXT,
  stamped_doc_url TEXT,
  signature_hash  TEXT,
  stamp_status    TEXT,
  stamp_page      INTEGER,
  stamp_x         NUMERIC,
  stamp_y         NUMERIC,
  CONSTRAINT chk_safety_status CHECK (status IN (
    'pending_review','pending_consultant_approval','pending_client_acceptance',
    'pending_client_approval','pending_contractor_acceptance','approved_record','rejected'
  )),
  CONSTRAINT chk_safety_record_kind CHECK (record_kind IN ('new','notice','rejection_notice','acceptance_notice'))
);

CREATE TABLE operational_records (
  id              SERIAL PRIMARY KEY,
  project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  file_path       TEXT,
  attachment_id   TEXT,
  supporting_files JSONB NOT NULL DEFAULT '[]'::jsonb,
  issued_date     TIMESTAMP DEFAULT NOW(),
  uploaded_by     INTEGER NOT NULL,
  role            TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending_review',
  review_required BOOLEAN DEFAULT true,
  record_kind     TEXT NOT NULL DEFAULT 'new',
  notice_tied_id  INTEGER REFERENCES operational_records(id) ON DELETE CASCADE,
  signed_by_id    INTEGER,
  signed_by_role  TEXT,
  signed_at       TIMESTAMPTZ,
  stamp_type      TEXT,
  stamped_doc_url TEXT,
  signature_hash  TEXT,
  stamp_status    TEXT,
  stamp_page      INTEGER,
  stamp_x         NUMERIC,
  stamp_y         NUMERIC,
  CONSTRAINT chk_operational_status CHECK (status IN (
    'pending_review','pending_consultant_approval','pending_client_acceptance',
    'pending_client_approval','pending_contractor_acceptance','approved_record','rejected'
  )),
  CONSTRAINT chk_operational_record_kind CHECK (record_kind IN ('new','notice','rejection_notice','acceptance_notice'))
);

CREATE TABLE financial_records (
  id              SERIAL PRIMARY KEY,
  project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  file_path       TEXT,
  attachment_id   TEXT,
  supporting_files JSONB NOT NULL DEFAULT '[]'::jsonb,
  issued_date     TIMESTAMP DEFAULT NOW(),
  uploaded_by     INTEGER NOT NULL,
  role            TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending_review',
  review_required BOOLEAN DEFAULT true,
  record_kind     TEXT NOT NULL DEFAULT 'new',
  notice_tied_id  INTEGER REFERENCES financial_records(id) ON DELETE CASCADE,
  signed_by_id    INTEGER,
  signed_by_role  TEXT,
  signed_at       TIMESTAMPTZ,
  stamp_type      TEXT,
  stamped_doc_url TEXT,
  signature_hash  TEXT,
  stamp_status    TEXT,
  stamp_page      INTEGER,
  stamp_x         NUMERIC,
  stamp_y         NUMERIC,
  CONSTRAINT chk_financial_status CHECK (status IN (
    'pending_review','pending_consultant_approval','pending_client_acceptance',
    'pending_client_approval','pending_contractor_acceptance','approved_record','rejected'
  )),
  CONSTRAINT chk_financial_record_kind CHECK (record_kind IN ('new','notice','rejection_notice','acceptance_notice'))
);

CREATE TABLE document_reviews (
  id                SERIAL PRIMARY KEY,
  record_type       TEXT NOT NULL,
  record_id         INTEGER NOT NULL,
  record_kind       TEXT NOT NULL DEFAULT 'new',
  reviewer_id       INTEGER NOT NULL,
  reviewer_role     TEXT NOT NULL,
  reviewer_email    TEXT,
  reviewer_position TEXT,
  reviewer_assigned_part TEXT,
  action            TEXT NOT NULL DEFAULT 'no_action',
  comment           TEXT,
  action_date       TIMESTAMP DEFAULT NOW(),
  CONSTRAINT document_reviews_unique_per_role
    UNIQUE (record_type, record_id, reviewer_id, reviewer_role),
  CONSTRAINT chk_review_action CHECK (action IN ('no_action','approved','accepted','rejected')),
  CONSTRAINT chk_review_record_kind CHECK (record_kind IN ('new','notice','rejection_notice','acceptance_notice'))
);

CREATE INDEX idx_doc_reviews_record   ON document_reviews(record_type, record_id);
CREATE INDEX idx_doc_reviews_reviewer ON document_reviews(reviewer_id);

CREATE TABLE reply_relationships (
  id            SERIAL PRIMARY KEY,
  record_id     INTEGER NOT NULL,
  record_type   TEXT NOT NULL,
  notice_id     INTEGER NOT NULL,
  reviewer_id   INTEGER NOT NULL,
  reviewer_role TEXT NOT NULL,
  created_at    TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_reply_notice ON reply_relationships(notice_id, record_type);


-- ================================================================
-- SECTION 15 — MEETINGS
-- ================================================================

CREATE TABLE meetings (
  id            SERIAL PRIMARY KEY,
  project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  meeting_type  VARCHAR(20) NOT NULL CHECK (meeting_type IN ('site','office','virtual')),
  title         TEXT NOT NULL,
  date_time     TIMESTAMP NOT NULL,
  scheduled_at  TIMESTAMPTZ,
  location      TEXT NOT NULL,
  participants  TEXT NOT NULL,
  participant_details JSONB NOT NULL DEFAULT '[]'::jsonb,
  purpose       TEXT NOT NULL DEFAULT '',
  agenda        TEXT NOT NULL,
  scope         VARCHAR(10) NOT NULL CHECK (scope IN ('global','side')),
  scope_value   VARCHAR(20),
  created_by    INTEGER NOT NULL,
  created_role  TEXT NOT NULL,
  created_at    TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_meetings_project ON meetings(project_id);
CREATE INDEX idx_meetings_scope   ON meetings(scope, scope_value);
CREATE INDEX idx_meetings_date    ON meetings(date_time);

CREATE TABLE meeting_minutes (
  id                SERIAL PRIMARY KEY,
  meeting_id        INTEGER NOT NULL REFERENCES meetings(id) ON DELETE CASCADE,
  project_id        INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  attendees         TEXT NOT NULL,
  agenda_discussed  TEXT NOT NULL,
  decisions         TEXT NOT NULL,
  action_items      TEXT NOT NULL,
  next_meeting_date TIMESTAMP,
  scope             VARCHAR(10) NOT NULL,
  scope_value       VARCHAR(20),
  created_by        INTEGER NOT NULL,
  created_role      TEXT NOT NULL,
  created_at        TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_minutes_meeting ON meeting_minutes(meeting_id);

CREATE TABLE meeting_attachments (
  id          SERIAL PRIMARY KEY,
  meeting_id  INTEGER REFERENCES meetings(id) ON DELETE CASCADE,
  minute_id   INTEGER REFERENCES meeting_minutes(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  url         TEXT NOT NULL,
  public_id   TEXT,
  uploaded_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_attachments_meeting ON meeting_attachments(meeting_id);
CREATE INDEX idx_attachments_minute  ON meeting_attachments(minute_id);


-- ================================================================
-- SECTION 16 — ARRETS (Stop-Work Issues)
-- ================================================================

CREATE TABLE arrets (
  id                  SERIAL PRIMARY KEY,
  project_id          INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title               TEXT NOT NULL,
  description         TEXT NOT NULL,
  attachment_url      TEXT,
  attachment_name     TEXT,
  attachment_mime     TEXT,
  attachment_public_id TEXT,
  issued_date         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by          INTEGER NOT NULL,
  creator_role        TEXT NOT NULL,
  creator_email       TEXT,
  status              TEXT NOT NULL DEFAULT 'open',
  is_resolved         BOOLEAN NOT NULL DEFAULT false,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_arrets_project_id ON arrets(project_id);
CREATE INDEX idx_arrets_status     ON arrets(status);
CREATE INDEX idx_arrets_created_by ON arrets(created_by);

CREATE TABLE arret_attachments (
  id          SERIAL PRIMARY KEY,
  arret_id    INTEGER NOT NULL REFERENCES arrets(id) ON DELETE CASCADE,
  file_name   TEXT NOT NULL,
  file_mime   TEXT NOT NULL,
  file_url    TEXT NOT NULL,
  public_id   TEXT,
  uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_arret_attachments_arret_id ON arret_attachments(arret_id);

CREATE TABLE arret_views (
  id           SERIAL PRIMARY KEY,
  arret_id     INTEGER NOT NULL REFERENCES arrets(id) ON DELETE CASCADE,
  viewer_id    INTEGER NOT NULL,
  viewer_role  TEXT NOT NULL,
  viewer_email TEXT,
  viewed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(arret_id, viewer_id, viewer_role)
);

CREATE INDEX idx_arret_views_arret_id ON arret_views(arret_id);


-- ================================================================
-- SECTION 17 — NOTIFICATIONS
-- ================================================================

CREATE TABLE notifications (
  id             SERIAL PRIMARY KEY,
  project_id     INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  entity_type    TEXT NOT NULL,
  entity_id      INTEGER NOT NULL,
  message        TEXT NOT NULL,
  added_by_id    INTEGER,
  added_by_role  TEXT,
  created_at     TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_notifications_project_entity_created
  ON notifications(project_id, entity_type, created_at DESC);
CREATE INDEX idx_notifications_entity
  ON notifications(entity_id, entity_type);

CREATE TABLE notification_recipients (
  id                 SERIAL PRIMARY KEY,
  notification_id    INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
  recipient_role     TEXT NOT NULL,
  recipient_role_id  INTEGER NOT NULL,
  is_read            BOOLEAN DEFAULT false,
  read_at            TIMESTAMP,
  created_at         TIMESTAMP DEFAULT NOW(),
  CONSTRAINT uniq_notif_recipient_per_role
    UNIQUE (notification_id, recipient_role, recipient_role_id)
);

CREATE INDEX idx_notif_recipients_unread_by_role_id
  ON notification_recipients(recipient_role, recipient_role_id)
  WHERE is_read = false;
CREATE INDEX idx_notif_recipients_notification
  ON notification_recipients(notification_id);

CREATE OR REPLACE FUNCTION create_notification_for_project(
  p_project_id       INTEGER,
  p_entity_type      TEXT,
  p_entity_id        INTEGER,
  p_message          TEXT,
  p_added_by_id      INTEGER,
  p_added_by_role    TEXT
) RETURNS INTEGER AS $$
DECLARE nid INTEGER;
BEGIN
  INSERT INTO notifications (
    project_id, entity_type, entity_id, message,
    added_by_id, added_by_role, created_at
  ) VALUES (
    p_project_id, p_entity_type, p_entity_id, p_message,
    p_added_by_id, p_added_by_role, NOW()
  ) RETURNING id INTO nid;

  INSERT INTO notification_recipients
    (notification_id, recipient_role, recipient_role_id, created_at)
  SELECT nid, av.role, av.role_id, NOW()
  FROM   assignments_view av
  WHERE  av.project_id = p_project_id
  ON CONFLICT ON CONSTRAINT uniq_notif_recipient_per_role DO NOTHING;

  PERFORM pg_notify('notifications_channel', nid::text);
  RETURN nid;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION mark_notification_read(
  p_notification_id   INTEGER,
  p_recipient_role    TEXT,
  p_recipient_role_id INTEGER
) RETURNS VOID AS $$
BEGIN
  UPDATE notification_recipients
  SET    is_read = true, read_at = NOW()
  WHERE  notification_id   = p_notification_id
    AND  recipient_role    = p_recipient_role
    AND  recipient_role_id = p_recipient_role_id
    AND  is_read           = false;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION mark_all_notifications_read_for_recipient(
  p_recipient_role    TEXT,
  p_recipient_role_id INTEGER
) RETURNS VOID AS $$
BEGIN
  UPDATE notification_recipients
  SET    is_read = true, read_at = NOW()
  WHERE  recipient_role    = p_recipient_role
    AND  recipient_role_id = p_recipient_role_id
    AND  is_read           = false;
END;
$$ LANGUAGE plpgsql;


-- ================================================================
-- SECTION 18 — PROJECT CHAT
-- ================================================================

CREATE TABLE project_chat_messages (
  id                  SERIAL PRIMARY KEY,
  project_id          INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  sender_role         TEXT NOT NULL,
  sender_id           INTEGER NOT NULL,
  sender_email        TEXT NOT NULL DEFAULT '',
  recipient_role      TEXT,
  recipient_id        INTEGER,
  recipient_email     TEXT,
  is_group            BOOLEAN NOT NULL DEFAULT FALSE,
  content             TEXT NOT NULL DEFAULT '',
  attachment_url      TEXT,
  attachment_name     TEXT,
  attachment_mime     TEXT,
  attachment_size     BIGINT,
  attachment_duration NUMERIC(10,2),
  reply_to_message_id INTEGER REFERENCES project_chat_messages(id) ON DELETE SET NULL,
  delivered           BOOLEAN DEFAULT FALSE,
  delivered_at        TIMESTAMP,
  created_at          TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_chat_msg_project_time
  ON project_chat_messages(project_id, created_at DESC);
CREATE INDEX idx_chat_msg_group_lookup
  ON project_chat_messages(project_id, created_at DESC)
  WHERE is_group = TRUE;
CREATE INDEX idx_chat_msg_direct_lookup
  ON project_chat_messages(project_id, sender_role, sender_id, recipient_role, recipient_id)
  WHERE is_group = FALSE;
CREATE INDEX idx_chat_msg_project_sender
  ON project_chat_messages(project_id, sender_role, sender_id);
CREATE INDEX idx_chat_msg_project_recipient
  ON project_chat_messages(project_id, recipient_role, recipient_id);
CREATE INDEX idx_chat_msg_reply_to
  ON project_chat_messages(reply_to_message_id)
  WHERE reply_to_message_id IS NOT NULL;
CREATE INDEX idx_chat_msg_attachment_mime
  ON project_chat_messages(project_id, attachment_mime)
  WHERE attachment_mime IS NOT NULL;

CREATE TABLE project_chat_read_receipts (
  id         SERIAL PRIMARY KEY,
  message_id INTEGER NOT NULL REFERENCES project_chat_messages(id) ON DELETE CASCADE,
  user_id    INTEGER NOT NULL,
  user_role  TEXT,
  read_at    TIMESTAMP NOT NULL DEFAULT NOW(),
  UNIQUE (message_id, user_id)
);

CREATE INDEX idx_chat_receipts_message      ON project_chat_read_receipts(message_id);
CREATE INDEX idx_chat_receipts_user         ON project_chat_read_receipts(user_id);
CREATE INDEX idx_chat_receipts_user_message ON project_chat_read_receipts(user_id, message_id);

CREATE TABLE project_chat_delivered_receipts (
  id           SERIAL PRIMARY KEY,
  message_id   INTEGER NOT NULL REFERENCES project_chat_messages(id) ON DELETE CASCADE,
  user_id      INTEGER NOT NULL,
  user_role    TEXT,
  delivered_at TIMESTAMP NOT NULL DEFAULT NOW(),
  UNIQUE (message_id, user_id)
);

CREATE INDEX idx_chat_delivered_message ON project_chat_delivered_receipts(message_id);
CREATE INDEX idx_chat_delivered_user    ON project_chat_delivered_receipts(user_id);

-- Trigger: mark delivered on first read receipt
CREATE OR REPLACE FUNCTION fn_set_message_delivered_on_read()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE project_chat_messages
  SET    delivered = TRUE, delivered_at = NOW()
  WHERE  id        = NEW.message_id AND delivered = FALSE;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_set_message_delivered_on_read
  AFTER INSERT ON project_chat_read_receipts
  FOR EACH ROW EXECUTE PROCEDURE fn_set_message_delivered_on_read();

-- Trigger: mark delivered on first delivered receipt
CREATE OR REPLACE FUNCTION fn_set_message_delivered_on_delivered()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE project_chat_messages
  SET    delivered = TRUE, delivered_at = NOW()
  WHERE  id        = NEW.message_id AND delivered = FALSE;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_set_message_delivered_on_delivered
  AFTER INSERT ON project_chat_delivered_receipts
  FOR EACH ROW EXECUTE PROCEDURE fn_set_message_delivered_on_delivered();

-- View: messages with reply-to pre-joined
CREATE VIEW v_chat_messages_with_replies AS
SELECT
  m.id, m.project_id,
  m.sender_role, m.sender_id, m.sender_email,
  m.recipient_role, m.recipient_id, m.recipient_email,
  m.is_group, m.content,
  m.attachment_url, m.attachment_name, m.attachment_mime,
  m.attachment_size, m.attachment_duration,
  m.delivered, m.delivered_at, m.created_at,
  m.reply_to_message_id,
  rm.content      AS reply_to_content,
  rm.sender_role  AS reply_to_sender_role,
  rm.sender_email AS reply_to_sender_email,
  rm.sender_id    AS reply_to_sender_id
FROM  project_chat_messages m
LEFT JOIN project_chat_messages rm ON rm.id = m.reply_to_message_id;


-- ================================================================
-- END OF SCHEMA
-- ================================================================

BEGIN;

WITH missing_notifications AS (
  SELECT n.id AS notification_id, n.project_id
  FROM notifications n
  LEFT JOIN notification_recipients nr ON nr.notification_id = n.id
  WHERE nr.id IS NULL
)
INSERT INTO notification_recipients (
  notification_id,
  recipient_role,
  recipient_role_id,
  created_at
)
SELECT
  m.notification_id,
  av.role,
  av.role_id,
  NOW()
FROM missing_notifications m
JOIN assignments_view av
  ON av.project_id = m.project_id
ON CONFLICT ON CONSTRAINT uniq_notif_recipient_per_role DO NOTHING;

COMMIT;