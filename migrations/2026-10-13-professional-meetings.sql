BEGIN;

ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS time_zone TEXT;

ALTER TABLE meetings
  ADD COLUMN IF NOT EXISTS meeting_number TEXT,
  ADD COLUMN IF NOT EXISTS end_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS time_zone TEXT,
  ADD COLUMN IF NOT EXISTS virtual_link TEXT,
  ADD COLUMN IF NOT EXISTS safety_notes TEXT,
  ADD COLUMN IF NOT EXISTS chairperson TEXT,
  ADD COLUMN IF NOT EXISTS minute_taker TEXT,
  ADD COLUMN IF NOT EXISTS agenda_items JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS is_draft BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS recurrence_group UUID,
  ADD COLUMN IF NOT EXISTS recurrence_rule JSONB,
  ADD COLUMN IF NOT EXISTS reminder_sent_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS meeting_rsvps (
  id                  SERIAL PRIMARY KEY,
  meeting_id          INTEGER NOT NULL REFERENCES meetings(id) ON DELETE CASCADE,
  participant_key     TEXT NOT NULL,
  participant_name    TEXT NOT NULL,
  participant_email   TEXT,
  participant_role    TEXT,
  participant_role_id INTEGER,
  participant_source  TEXT NOT NULL CHECK (participant_source IN ('project', 'manual')),
  response            TEXT NOT NULL DEFAULT 'pending' CHECK (response IN ('pending', 'accepted', 'declined')),
  token_hash          TEXT,
  responded_at        TIMESTAMPTZ,
  reminder_sent_at    TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (meeting_id, participant_key)
);

CREATE INDEX IF NOT EXISTS idx_meeting_rsvps_meeting ON meeting_rsvps(meeting_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_meeting_rsvps_token ON meeting_rsvps(token_hash)
  WHERE token_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_meetings_reminders ON meetings(scheduled_at)
  WHERE is_draft = false AND reminder_sent_at IS NULL;

COMMIT;
