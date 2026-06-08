-- 2026-06-12 - add arret attachments and view tracking

CREATE TABLE IF NOT EXISTS arret_attachments (
  id SERIAL PRIMARY KEY,
  arret_id INTEGER NOT NULL REFERENCES arrets(id) ON DELETE CASCADE,
  file_name TEXT NOT NULL,
  file_mime TEXT NOT NULL,
  file_url TEXT NOT NULL,
  public_id TEXT,
  uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_arret_attachments_arret_id ON arret_attachments(arret_id);

CREATE TABLE IF NOT EXISTS arret_views (
  id SERIAL PRIMARY KEY,
  arret_id INTEGER NOT NULL REFERENCES arrets(id) ON DELETE CASCADE,
  viewer_id INTEGER NOT NULL,
  viewer_role TEXT NOT NULL,
  viewer_email TEXT,
  viewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(arret_id, viewer_id, viewer_role)
);

CREATE INDEX IF NOT EXISTS idx_arret_views_arret_id ON arret_views(arret_id);
