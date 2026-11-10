-- Opt-in evidence sharing for verification requests.
-- When the contractor leader ticks "share approved reports", the request stores a frozen copy of the
-- approved reports up to the cut-off date. The consultant reads only this copy, never the live task or report tables.
ALTER TABLE activity_verifications
  ADD COLUMN IF NOT EXISTS share_evidence BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS shared_evidence JSONB;
