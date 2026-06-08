-- 2026-06-11 - add arrets table for stop-work issue reporting

CREATE TABLE IF NOT EXISTS arrets (
  id SERIAL PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  attachment_url TEXT,
  attachment_name TEXT,
  attachment_mime TEXT,
  attachment_public_id TEXT,
  issued_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by INTEGER NOT NULL,
  creator_role TEXT NOT NULL,
  creator_email TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  is_resolved BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_arrets_project_id ON arrets(project_id);
CREATE INDEX IF NOT EXISTS idx_arrets_status ON arrets(status);
CREATE INDEX IF NOT EXISTS idx_arrets_created_by ON arrets(created_by);
