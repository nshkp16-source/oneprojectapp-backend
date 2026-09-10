ALTER TABLE schedule_extensions
  ADD COLUMN IF NOT EXISTS supporting_file_name TEXT,
  ADD COLUMN IF NOT EXISTS supporting_file_url TEXT,
  ADD COLUMN IF NOT EXISTS supporting_file_public_id TEXT,
  ADD COLUMN IF NOT EXISTS supporting_file_mime TEXT,
  ADD COLUMN IF NOT EXISTS supporting_file_size INTEGER;