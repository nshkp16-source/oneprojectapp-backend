-- Store the last overdue reminder so the scheduled job sends one notification per request.
BEGIN;

ALTER TABLE activity_verifications
  ADD COLUMN IF NOT EXISTS reminder_sent_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_activity_verifications_overdue_reminders
  ON activity_verifications (respond_by, reminder_sent_at)
  WHERE status = 'pending';

COMMIT;
