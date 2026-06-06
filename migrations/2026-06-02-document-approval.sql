-- ═══════════════════════════════════════════════════════════════════════════════
-- Document & Approval System Schema
-- ═══════════════════════════════════════════════════════════════════════════════

-- Approval statuses: pending, approved, rejected
-- Once approved/rejected: becomes visible to creator with reason/comment

CREATE TABLE IF NOT EXISTS documents (
  id BIGSERIAL PRIMARY KEY,
  project_id BIGINT NOT NULL,
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
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

-- Track approval comments visible only to leader during review, then to creator after decision
CREATE TABLE IF NOT EXISTS document_approval_notes (
  id BIGSERIAL PRIMARY KEY,
  document_id BIGINT NOT NULL,
  note_text TEXT NOT NULL,
  created_by_id BIGINT NOT NULL,
  created_by_role TEXT NOT NULL,
  is_visible_to_creator BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
);

-- Track document views
CREATE TABLE IF NOT EXISTS document_views (
  id BIGSERIAL PRIMARY KEY,
  document_id BIGINT NOT NULL,
  viewer_id BIGINT NOT NULL,
  viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(document_id, viewer_id),
  FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_documents_project_side ON documents(project_id, side);
CREATE INDEX IF NOT EXISTS idx_documents_creator ON documents(creator_id);
CREATE INDEX IF NOT EXISTS idx_documents_approval_status ON documents(approval_status);
CREATE INDEX IF NOT EXISTS idx_documents_is_shared ON documents(is_shared);
CREATE INDEX IF NOT EXISTS idx_document_approval_notes_document ON document_approval_notes(document_id);
CREATE INDEX IF NOT EXISTS idx_document_views_document ON document_views(document_id);
