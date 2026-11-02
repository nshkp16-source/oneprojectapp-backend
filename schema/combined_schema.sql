-- ================================================================
-- ONEPROJECT — COMBINED SCHEMA + MIGRATIONS (core first, full)
-- Generated: 2026-09-01
-- WARNING: This file is destructive. It drops the default schema
-- and recreates it before applying the canonical schema and
-- the recorded migrations. Run only on a test or freshly-provisioned
-- database, or where you intend to fully reset the database.
-- ================================================================

-- Drop and recreate public schema (PostgreSQL)
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;
GRANT ALL ON SCHEMA public TO public;
SET search_path = public;


-- ==================================================================
-- CORE SCHEMA (verbatim from `completely schema.sql`)
-- ==================================================================


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
DROP TRIGGER  IF EXISTS trg_set_message_delivered_on_read   ON project_chat_read_receipts;
DROP TRIGGER  IF EXISTS trg_set_message_delivered_on_delivered ON project_chat_delivered_receipts;
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
  verified            BOOLEAN DEFAULT false,
  profile_picture     TEXT,
  profile_picture_id  TEXT,
  created_at          TIMESTAMP DEFAULT NOW()
);

CREATE TABLE consultants (
  id                  SERIAL PRIMARY KEY,
  email               TEXT UNIQUE NOT NULL,
  password_hash       TEXT,
  verified            BOOLEAN DEFAULT false,
  profile_picture     TEXT,
  profile_picture_id  TEXT,
  created_at          TIMESTAMP DEFAULT NOW()
);

CREATE TABLE team_members (
  id                  SERIAL PRIMARY KEY,
  email               TEXT UNIQUE NOT NULL,
  password_hash       TEXT,
  verified            BOOLEAN DEFAULT false,
  profile_picture     TEXT,
  profile_picture_id  TEXT,
  created_at          TIMESTAMP DEFAULT NOW()
);

CREATE TABLE contractor_project_managers (
  id                  SERIAL PRIMARY KEY,
  email               TEXT UNIQUE NOT NULL,
  password_hash       TEXT,
  verified            BOOLEAN DEFAULT false,
  profile_picture     TEXT,
  profile_picture_id  TEXT,
  created_at          TIMESTAMP DEFAULT NOW()
);

CREATE TABLE consultant_project_managers (
  id                  SERIAL PRIMARY KEY,
  email               TEXT UNIQUE NOT NULL,
  password_hash       TEXT,
  verified            BOOLEAN DEFAULT false,
  profile_picture     TEXT,
  profile_picture_id  TEXT,
  created_at          TIMESTAMP DEFAULT NOW()
);

CREATE TABLE client_project_managers (
  id                  SERIAL PRIMARY KEY,
  email               TEXT UNIQUE NOT NULL,
  password_hash       TEXT,
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

CREATE INDEX idx_wcp_task_id    ON workspace_work_center_progress(task_id);
*** End Patch