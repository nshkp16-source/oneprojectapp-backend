-- Chat feature extensions
-- Run this migration once against the application PostgreSQL database.
-- User references are intentionally stored as (user_id, user_role) because
-- the application uses separate role-specific user tables.

BEGIN;

-- Message editing and soft-delete metadata.
ALTER TABLE project_chat_messages
  ADD COLUMN IF NOT EXISTS edited_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS deleted_by_user_id INTEGER,
  ADD COLUMN IF NOT EXISTS deleted_by_role TEXT;

-- One reaction per user/reaction type/message.
CREATE TABLE IF NOT EXISTS project_chat_reactions (
  id              SERIAL PRIMARY KEY,
  message_id      INTEGER NOT NULL REFERENCES project_chat_messages(id) ON DELETE CASCADE,
  user_id         INTEGER NOT NULL,
  user_role       TEXT NOT NULL,
  reaction        TEXT NOT NULL CHECK (char_length(reaction) BETWEEN 1 AND 32),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (message_id, user_id, user_role, reaction)
);
CREATE INDEX IF NOT EXISTS idx_chat_reactions_message
  ON project_chat_reactions(message_id);

-- Pinned messages. Only one active pin row is needed per message.
CREATE TABLE IF NOT EXISTS project_chat_pins (
  id              SERIAL PRIMARY KEY,
  message_id      INTEGER NOT NULL REFERENCES project_chat_messages(id) ON DELETE CASCADE,
  pinned_by_user_id INTEGER NOT NULL,
  pinned_by_role   TEXT NOT NULL,
  pinned_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (message_id)
);
CREATE INDEX IF NOT EXISTS idx_chat_pins_message
  ON project_chat_pins(message_id);

-- Per-user conversation/project mute preferences.
CREATE TABLE IF NOT EXISTS project_chat_mutes (
  id              SERIAL PRIMARY KEY,
  project_id      INTEGER NOT NULL,
  user_id         INTEGER NOT NULL,
  user_role       TEXT NOT NULL,
  muted_until     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (project_id, user_id, user_role)
);
CREATE INDEX IF NOT EXISTS idx_chat_mutes_user
  ON project_chat_mutes(user_id, user_role, project_id);

-- User blocking. A NULL project_id means the block applies globally.
CREATE TABLE IF NOT EXISTS project_chat_blocks (
  id              SERIAL PRIMARY KEY,
  project_id      INTEGER,
  blocker_user_id INTEGER NOT NULL,
  blocker_role    TEXT NOT NULL,
  blocked_user_id INTEGER NOT NULL,
  blocked_role    TEXT NOT NULL,
  reason          TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (project_id, blocker_user_id, blocker_role, blocked_user_id, blocked_role)
);
CREATE INDEX IF NOT EXISTS idx_chat_blocks_blocker
  ON project_chat_blocks(blocker_user_id, blocker_role);
CREATE INDEX IF NOT EXISTS idx_chat_blocks_blocked
  ON project_chat_blocks(blocked_user_id, blocked_role);

-- Reports for inappropriate messages/users. Review workflow can be added later.
CREATE TABLE IF NOT EXISTS project_chat_reports (
  id              SERIAL PRIMARY KEY,
  project_id      INTEGER NOT NULL,
  message_id      INTEGER REFERENCES project_chat_messages(id) ON DELETE SET NULL,
  reported_user_id INTEGER,
  reported_user_role TEXT,
  reporter_user_id INTEGER NOT NULL,
  reporter_role   TEXT NOT NULL,
  reason          TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','reviewing','resolved','dismissed')),
  resolution_note TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_chat_reports_project_status
  ON project_chat_reports(project_id, status, created_at DESC);

-- Project group membership and administrator controls.
CREATE TABLE IF NOT EXISTS project_chat_group_members (
  id              SERIAL PRIMARY KEY,
  project_id      INTEGER NOT NULL,
  user_id         INTEGER NOT NULL,
  user_role       TEXT NOT NULL,
  is_admin        BOOLEAN NOT NULL DEFAULT FALSE,
  joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  removed_at      TIMESTAMPTZ,
  UNIQUE (project_id, user_id, user_role)
);
CREATE INDEX IF NOT EXISTS idx_chat_group_members_project
  ON project_chat_group_members(project_id, removed_at);

-- Call records and participants. WebRTC signaling still requires a realtime
-- transport; these tables retain call history and participant state.
CREATE TABLE IF NOT EXISTS project_chat_calls (
  id              SERIAL PRIMARY KEY,
  project_id      INTEGER NOT NULL,
  conversation_key TEXT,
  initiated_by_user_id INTEGER NOT NULL,
  initiated_by_role TEXT NOT NULL,
  call_type       TEXT NOT NULL CHECK (call_type IN ('audio','video')),
  status          TEXT NOT NULL DEFAULT 'ringing' CHECK (status IN ('ringing','active','completed','missed','declined','failed')),
  started_at      TIMESTAMPTZ,
  ended_at        TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_chat_calls_project_created
  ON project_chat_calls(project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS project_chat_call_participants (
  id              SERIAL PRIMARY KEY,
  call_id         INTEGER NOT NULL REFERENCES project_chat_calls(id) ON DELETE CASCADE,
  user_id         INTEGER NOT NULL,
  user_role       TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'invited' CHECK (status IN ('invited','ringing','joined','left','declined','missed')),
  joined_at       TIMESTAMPTZ,
  left_at         TIMESTAMPTZ,
  UNIQUE (call_id, user_id, user_role)
);
CREATE INDEX IF NOT EXISTS idx_chat_call_participants_call
  ON project_chat_call_participants(call_id);

-- Cached metadata for safe link previews. The frontend should only display
-- previews returned by a backend fetcher, never scrape arbitrary URLs in JS.
CREATE TABLE IF NOT EXISTS project_chat_link_previews (
  id              SERIAL PRIMARY KEY,
  message_id      INTEGER NOT NULL REFERENCES project_chat_messages(id) ON DELETE CASCADE,
  url             TEXT NOT NULL,
  canonical_url   TEXT,
  site_name       TEXT,
  title           TEXT,
  description     TEXT,
  image_url       TEXT,
  fetched_at      TIMESTAMPTZ,
  fetch_error     TEXT,
  UNIQUE (message_id, url)
);
CREATE INDEX IF NOT EXISTS idx_chat_link_previews_message
  ON project_chat_link_previews(message_id);

COMMIT;
