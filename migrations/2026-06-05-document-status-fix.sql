-- Fix document approval workflow statuses
-- Convert legacy 'pending' values to 'pending_approval' and allow draft/pending_approval in the documents status constraint

BEGIN;

UPDATE documents
SET approval_status = 'pending_approval'
WHERE approval_status = 'pending';

ALTER TABLE documents DROP CONSTRAINT IF EXISTS documents_approval_status_check;

ALTER TABLE documents
  ALTER COLUMN approval_status SET DEFAULT 'draft';

ALTER TABLE documents
  ADD CONSTRAINT documents_approval_status_check CHECK (approval_status IN ('draft', 'pending_approval', 'approved', 'rejected'));

COMMIT;
