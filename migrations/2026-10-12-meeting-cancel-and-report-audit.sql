-- Meeting cancellation + report audit trail.
-- Safe to run more than once. The API works before this runs (cancel returns a clear message),
-- and picks the new columns up within a minute after it runs.

-- 1. Cancel a meeting without deleting it
ALTER TABLE meetings ADD COLUMN IF NOT EXISTS status            VARCHAR(20) NOT NULL DEFAULT 'scheduled';
ALTER TABLE meetings ADD COLUMN IF NOT EXISTS cancelled_at      TIMESTAMPTZ;
ALTER TABLE meetings ADD COLUMN IF NOT EXISTS cancelled_by      INTEGER;
ALTER TABLE meetings ADD COLUMN IF NOT EXISTS cancelled_by_role VARCHAR(40);
ALTER TABLE meetings ADD COLUMN IF NOT EXISTS cancel_reason     TEXT;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'meetings_status_check') THEN
    ALTER TABLE meetings
      ADD CONSTRAINT meetings_status_check CHECK (status IN ('scheduled', 'cancelled'));
  END IF;
END $$;

-- 2. Who uploaded the report, when, and which version
ALTER TABLE meeting_minutes ADD COLUMN IF NOT EXISTS report_uploaded_at TIMESTAMPTZ;
ALTER TABLE meeting_minutes ADD COLUMN IF NOT EXISTS report_version     INTEGER NOT NULL DEFAULT 1;

-- 3. Faster meeting lists per project / scope / date
CREATE INDEX IF NOT EXISTS idx_meetings_project_scope_time
  ON meetings (project_id, scope, scheduled_at);
CREATE INDEX IF NOT EXISTS idx_meeting_minutes_meeting
  ON meeting_minutes (meeting_id);
