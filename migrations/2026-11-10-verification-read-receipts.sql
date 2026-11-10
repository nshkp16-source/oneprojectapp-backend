-- Read receipts for verification requests.
-- A row is written the first time a consultant-side reader (a consultant leader or a named inspector) opens a request,
-- or decides it. The contractor sees "opened, no decision yet" from the earliest row, never who opened it.
-- The consultant's own "unread" marker is the absence of that person's row.
CREATE TABLE IF NOT EXISTS verification_reads (
  verification_id INTEGER NOT NULL REFERENCES activity_verifications(id) ON DELETE CASCADE,
  project_id      INTEGER NOT NULL,
  reader_role     TEXT NOT NULL,
  reader_id       INTEGER NOT NULL,
  first_read_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_read_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (verification_id, reader_role, reader_id)
);
CREATE INDEX IF NOT EXISTS verification_reads_reader_idx ON verification_reads (project_id, reader_role, reader_id);
