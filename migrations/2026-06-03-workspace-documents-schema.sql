-- ═══════════════════════════════════════════════════════════════════════════════
-- Workspace Document + Control & Report Schema Update
-- ═══════════════════════════════════════════════════════════════════════════════

-- Drop dependent tables first to avoid foreign key conflicts.
DROP TABLE IF EXISTS control_and_report_comments CASCADE;
DROP TABLE IF EXISTS control_and_report_index CASCADE;
DROP TABLE IF EXISTS workspace_document_reviews CASCADE;
DROP TABLE IF EXISTS workspace_documents CASCADE;
DROP TABLE IF EXISTS report_requests CASCADE;

-- 1. Report Requests (PM/Leader assignments)
CREATE TABLE IF NOT EXISTS report_requests (
  id SERIAL PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  activity_id INTEGER REFERENCES planning_execution(id) ON DELETE CASCADE,
  requested_by INTEGER NOT NULL,
  requested_role TEXT NOT NULL,
  assigned_to INTEGER NOT NULL,
  assigned_role TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  due_date DATE,
  status TEXT DEFAULT 'pending',
  remark TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_report_requests_project_id ON report_requests(project_id);
CREATE INDEX IF NOT EXISTS idx_report_requests_assigned_to ON report_requests(assigned_to);

-- 2. Workspace Documents (drafts & uploads)
CREATE TABLE IF NOT EXISTS workspace_documents (
  id SERIAL PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  activity_id INTEGER REFERENCES planning_execution(id) ON DELETE CASCADE,
  request_id INTEGER REFERENCES report_requests(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  description TEXT,
  category TEXT NOT NULL,
  file_name TEXT NOT NULL,
  file_id TEXT NOT NULL,
  submitted_by INTEGER NOT NULL,
  submitted_role TEXT NOT NULL,
  submitted_at TIMESTAMP DEFAULT NOW(),
  status TEXT DEFAULT 'draft',
  visibility TEXT DEFAULT 'private',
  remark TEXT,
  team_reader_id INTEGER,
  validated_by INTEGER,
  validated_at TIMESTAMP,
  validation_note TEXT,
  required_schema JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workspace_documents_project_id ON workspace_documents(project_id);
CREATE INDEX IF NOT EXISTS idx_workspace_documents_request_id ON workspace_documents(request_id);
CREATE INDEX IF NOT EXISTS idx_workspace_documents_submitted_by ON workspace_documents(submitted_by);

-- 3. Workspace Document Reviews (review trail)
CREATE TABLE IF NOT EXISTS workspace_document_reviews (
  id SERIAL PRIMARY KEY,
  document_id INTEGER NOT NULL REFERENCES workspace_documents(id) ON DELETE CASCADE,
  reviewer_id INTEGER NOT NULL,
  reviewer_role TEXT NOT NULL,
  review_stage TEXT NOT NULL,
  decision TEXT DEFAULT 'pending',
  remark TEXT,
  delay_days INTEGER DEFAULT 0,
  delay_reason TEXT,
  reviewed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_workspace_document_reviews_document_id ON workspace_document_reviews(document_id);
CREATE INDEX IF NOT EXISTS idx_workspace_document_reviews_reviewer_id ON workspace_document_reviews(reviewer_id);

-- 4. Control & Report Index (validated internal feed)
CREATE TABLE IF NOT EXISTS control_and_report_index (
  id SERIAL PRIMARY KEY,
  document_id INTEGER NOT NULL REFERENCES workspace_documents(id) ON DELETE CASCADE,
  project_id INTEGER NOT NULL,
  part TEXT NOT NULL,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  validated_by INTEGER NOT NULL,
  validated_at TIMESTAMP NOT NULL,
  visibility TEXT DEFAULT 'internal',
  promoted BOOLEAN DEFAULT FALSE,
  promoted_by INTEGER,
  promoted_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_control_and_report_index_project_id ON control_and_report_index(project_id);
CREATE INDEX IF NOT EXISTS idx_control_and_report_index_document_id ON control_and_report_index(document_id);

-- 5. Control & Report Comments (team member feedback)
CREATE TABLE IF NOT EXISTS control_and_report_comments (
  id SERIAL PRIMARY KEY,
  report_id INTEGER NOT NULL REFERENCES control_and_report_index(id) ON DELETE CASCADE,
  commentator_id INTEGER NOT NULL,
  position TEXT,
  comment_text TEXT NOT NULL,
  commented_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_control_and_report_comments_report_id ON control_and_report_comments(report_id);

-- 6. Legacy Document Approval Schema (restored for backend compatibility)
CREATE TABLE IF NOT EXISTS documents (
  id BIGSERIAL PRIMARY KEY,
  project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT,
  category TEXT,
  document_date DATE,
  deadline DATE,
  file_name TEXT,
  file_id TEXT,
  file_url TEXT,
  creator_id BIGINT NOT NULL,
  creator_role TEXT NOT NULL,
  side TEXT NOT NULL CHECK (side IN ('Contractor', 'Consultant', 'Client')),
  approval_status TEXT NOT NULL DEFAULT 'draft' CHECK (approval_status IN ('draft', 'pending_approval', 'approved', 'rejected')),
  approved_by_id BIGINT,
  approved_by_role TEXT,
  approval_date TIMESTAMP,
  rejection_reason TEXT,
  is_shared BOOLEAN DEFAULT FALSE,
  shared_at TIMESTAMP,
  is_read_only BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_documents_project_side ON documents(project_id, side);
CREATE INDEX IF NOT EXISTS idx_documents_creator ON documents(creator_id);
CREATE INDEX IF NOT EXISTS idx_documents_approval_status ON documents(approval_status);
CREATE INDEX IF NOT EXISTS idx_documents_is_shared ON documents(is_shared);

CREATE TABLE IF NOT EXISTS document_approval_notes (
  id BIGSERIAL PRIMARY KEY,
  document_id BIGINT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  note_text TEXT NOT NULL,
  created_by_id BIGINT NOT NULL,
  created_by_role TEXT NOT NULL,
  is_visible_to_creator BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_document_approval_notes_document ON document_approval_notes(document_id);

CREATE TABLE IF NOT EXISTS document_views (
  id BIGSERIAL PRIMARY KEY,
  document_id BIGINT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  viewer_id BIGINT NOT NULL,
  viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(document_id, viewer_id)
);

CREATE INDEX IF NOT EXISTS idx_document_views_document ON document_views(document_id);
