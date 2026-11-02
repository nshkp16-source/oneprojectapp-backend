-- Apply after the base schema, run_after_completely.sql, and chat-features migration.
-- Adds the 15-day member-exit and 60-day client project-deletion workflows.
BEGIN;

ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS lifecycle_status TEXT NOT NULL DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS deletion_requested_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS deletion_scheduled_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS deletion_requested_by INTEGER,
  ADD COLUMN IF NOT EXISTS lifecycle_paused_seconds BIGINT NOT NULL DEFAULT 0;

ALTER TABLE project_chat_messages
  ADD COLUMN IF NOT EXISTS attachment_public_id TEXT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'projects_lifecycle_status_check'
      AND conrelid = 'projects'::regclass
  ) THEN
    ALTER TABLE projects
      ADD CONSTRAINT projects_lifecycle_status_check
      CHECK (lifecycle_status IN ('active', 'pending_deletion'));
  END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_projects_pending_deletion
  ON projects(deletion_scheduled_at)
  WHERE lifecycle_status = 'pending_deletion';

CREATE TABLE IF NOT EXISTS project_exit_requests (
  id BIGSERIAL PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL,
  user_role TEXT NOT NULL,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  effective_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'cancelled', 'completed')),
  completed_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_project_exit_requests_pending_user
  ON project_exit_requests(project_id, user_id, user_role)
  WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_project_exit_requests_due
  ON project_exit_requests(effective_at)
  WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS project_deletion_asset_cleanup (
  id BIGSERIAL PRIMARY KEY,
  project_id INTEGER NOT NULL,
  public_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'deleted')),
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ,
  UNIQUE (project_id, public_id)
);
CREATE INDEX IF NOT EXISTS idx_project_deletion_asset_cleanup_pending
  ON project_deletion_asset_cleanup(id) WHERE status = 'pending';

CREATE OR REPLACE FUNCTION guard_project_lifecycle_row()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF current_setting('app.project_deletion_purge', true) = 'on' THEN
    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
  END IF;

  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Projects must be deleted through the scheduled deletion workflow.'
      USING ERRCODE = '55000';
  END IF;

  IF OLD.lifecycle_status = 'pending_deletion' THEN
    IF NEW.lifecycle_status = 'active'
       AND NEW.deletion_requested_at IS NULL
       AND NEW.deletion_scheduled_at IS NULL
       AND NEW.deletion_requested_by IS NULL THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'Project is read-only during its scheduled deletion period.'
      USING ERRCODE = '55000';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_project_lifecycle_row ON projects;
CREATE TRIGGER guard_project_lifecycle_row
  BEFORE UPDATE OR DELETE ON projects
  FOR EACH ROW EXECUTE FUNCTION guard_project_lifecycle_row();

CREATE OR REPLACE FUNCTION guard_pending_project_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  new_row JSONB;
  old_row JSONB;
  project_text TEXT;
  project_status TEXT;
  parent_id INTEGER;
  record_type TEXT;
  record_id INTEGER;
BEGIN
  IF current_setting('app.project_deletion_purge', true) = 'on' THEN
    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
  END IF;

  IF TG_OP <> 'DELETE' THEN new_row := to_jsonb(NEW); END IF;
  IF TG_OP <> 'INSERT' THEN old_row := to_jsonb(OLD); END IF;

  project_text := COALESCE(new_row->>'project_id', old_row->>'project_id');

  IF project_text IS NULL THEN
    CASE TG_TABLE_NAME
      WHEN 'planning_execution_tracking' THEN
        parent_id := COALESCE((new_row->>'activity_id')::INTEGER, (old_row->>'activity_id')::INTEGER);
        SELECT project_id::TEXT INTO project_text FROM planning_execution WHERE id = parent_id;
      WHEN 'workspace_work_center_progress', 'work_center_views' THEN
        parent_id := COALESCE((new_row->>'task_id')::INTEGER, (old_row->>'task_id')::INTEGER);
        SELECT project_id::TEXT INTO project_text FROM workspace_work_center WHERE id = parent_id;
      WHEN 'document_approval_notes', 'document_views' THEN
        parent_id := COALESCE((new_row->>'document_id')::INTEGER, (old_row->>'document_id')::INTEGER);
        SELECT project_id::TEXT INTO project_text FROM documents WHERE id = parent_id;
      WHEN 'workspace_document_reviews' THEN
        parent_id := COALESCE((new_row->>'document_id')::INTEGER, (old_row->>'document_id')::INTEGER);
        SELECT project_id::TEXT INTO project_text FROM workspace_documents WHERE id = parent_id;
      WHEN 'control_and_report_comments' THEN
        parent_id := COALESCE((new_row->>'report_id')::INTEGER, (old_row->>'report_id')::INTEGER);
        SELECT project_id::TEXT INTO project_text FROM control_and_report_index WHERE id = parent_id;
      WHEN 'meeting_attachments' THEN
        SELECT project_id::TEXT INTO project_text FROM meetings
          WHERE id = COALESCE((new_row->>'meeting_id')::INTEGER, (old_row->>'meeting_id')::INTEGER);
        IF project_text IS NULL THEN
          SELECT project_id::TEXT INTO project_text FROM meeting_minutes
            WHERE id = COALESCE((new_row->>'minute_id')::INTEGER, (old_row->>'minute_id')::INTEGER);
        END IF;
      WHEN 'arret_attachments', 'arret_views' THEN
        parent_id := COALESCE((new_row->>'arret_id')::INTEGER, (old_row->>'arret_id')::INTEGER);
        SELECT project_id::TEXT INTO project_text FROM arrets WHERE id = parent_id;
      WHEN 'notification_recipients' THEN
        parent_id := COALESCE((new_row->>'notification_id')::INTEGER, (old_row->>'notification_id')::INTEGER);
        SELECT project_id::TEXT INTO project_text FROM notifications WHERE id = parent_id;
      WHEN 'project_chat_reactions', 'project_chat_pins', 'project_chat_link_previews' THEN
        parent_id := COALESCE((new_row->>'message_id')::INTEGER, (old_row->>'message_id')::INTEGER);
        SELECT project_id::TEXT INTO project_text FROM project_chat_messages WHERE id = parent_id;
      WHEN 'project_chat_call_participants' THEN
        parent_id := COALESCE((new_row->>'call_id')::INTEGER, (old_row->>'call_id')::INTEGER);
        SELECT project_id::TEXT INTO project_text FROM project_chat_calls WHERE id = parent_id;
      WHEN 'milestone_attachments' THEN
        parent_id := COALESCE((new_row->>'milestone_id')::INTEGER, (old_row->>'milestone_id')::INTEGER);
        SELECT project_id INTO project_text FROM milestones WHERE id = parent_id;
      WHEN 'additional_milestone_attachments' THEN
        parent_id := COALESCE((new_row->>'additional_milestone_id')::INTEGER, (old_row->>'additional_milestone_id')::INTEGER);
        SELECT project_id INTO project_text FROM additional_milestones WHERE id = parent_id;
      WHEN 'progress_entry_attachments' THEN
        parent_id := COALESCE((new_row->>'progress_entry_id')::INTEGER, (old_row->>'progress_entry_id')::INTEGER);
        SELECT project_id INTO project_text FROM milestone_progress_entries WHERE id = parent_id;
      WHEN 'milestone_photos' THEN
        parent_id := COALESCE((new_row->>'milestone_id')::INTEGER, (old_row->>'milestone_id')::INTEGER);
        IF parent_id IS NOT NULL THEN
          SELECT project_id INTO project_text FROM milestones WHERE id = parent_id;
        ELSE
          parent_id := COALESCE((new_row->>'additional_milestone_id')::INTEGER, (old_row->>'additional_milestone_id')::INTEGER);
          SELECT project_id INTO project_text FROM additional_milestones WHERE id = parent_id;
        END IF;
      WHEN 'document_reviews', 'reply_relationships' THEN
        record_type := LOWER(COALESCE(new_row->>'record_type', old_row->>'record_type', ''));
        record_id := COALESCE((new_row->>'record_id')::INTEGER, (old_row->>'record_id')::INTEGER);
        IF record_type IN ('contractual_records', 'administrative_records', 'safety_records', 'operational_records', 'financial_records') THEN
          EXECUTE FORMAT('SELECT project_id::TEXT FROM %I WHERE id = $1', record_type)
            INTO project_text USING record_id;
        END IF;
      ELSE
        NULL;
    END CASE;
  END IF;

  IF project_text ~ '^[0-9]+$' THEN
    SELECT lifecycle_status INTO project_status
    FROM projects WHERE id = project_text::INTEGER
    FOR SHARE;
    IF project_status = 'pending_deletion' THEN
      RAISE EXCEPTION 'Project is read-only during its scheduled deletion period.'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$;

DO $$
DECLARE
  target_table RECORD;
  target_table_name TEXT;
BEGIN
  FOREACH target_table_name IN ARRAY ARRAY['arret_views', 'document_views', 'work_center_views']
  LOOP
    IF TO_REGCLASS(FORMAT('public.%I', target_table_name)) IS NOT NULL THEN
      EXECUTE FORMAT('DROP TRIGGER IF EXISTS guard_pending_project_mutation ON public.%I', target_table_name);
    END IF;
  END LOOP;

  FOR target_table IN
    SELECT DISTINCT c.relname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid
    WHERE n.nspname = 'public'
      AND c.relkind IN ('r', 'p')
      AND a.attname = 'project_id'
      AND a.attnum > 0
      AND NOT a.attisdropped
      AND c.relname <> 'projects'
      AND c.relname <> 'project_deletion_asset_cleanup'
      AND c.relname NOT IN ('arret_views', 'document_views', 'work_center_views')
  LOOP
    EXECUTE FORMAT('DROP TRIGGER IF EXISTS guard_pending_project_mutation ON public.%I', target_table.relname);
    EXECUTE FORMAT(
      'CREATE TRIGGER guard_pending_project_mutation BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION guard_pending_project_mutation()',
      target_table.relname
    );
  END LOOP;

  FOREACH target_table_name IN ARRAY ARRAY[
    'planning_execution_tracking', 'workspace_work_center_progress',
    'document_approval_notes', 'workspace_document_reviews',
    'control_and_report_comments', 'meeting_attachments', 'arret_attachments',
    'project_chat_reactions', 'project_chat_pins', 'project_chat_link_previews',
    'project_chat_call_participants', 'milestone_attachments', 'additional_milestone_attachments',
    'progress_entry_attachments', 'milestone_photos', 'document_reviews', 'reply_relationships'
  ]
  LOOP
    IF TO_REGCLASS(FORMAT('public.%I', target_table_name)) IS NOT NULL THEN
      EXECUTE FORMAT('DROP TRIGGER IF EXISTS guard_pending_project_mutation ON public.%I', target_table_name);
      EXECUTE FORMAT(
        'CREATE TRIGGER guard_pending_project_mutation BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION guard_pending_project_mutation()',
        target_table_name
      );
    END IF;
  END LOOP;
END;
$$;

COMMIT;
