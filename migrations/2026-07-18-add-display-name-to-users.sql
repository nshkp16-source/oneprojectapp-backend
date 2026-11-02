-- Add display_name to core user tables so we can store a human-friendly signer name
-- Safe to re-run: uses ALTER ... ADD COLUMN IF NOT EXISTS

ALTER TABLE clients ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE contractors ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE consultants ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE team_members ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE contractor_project_managers ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE consultant_project_managers ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE client_project_managers ADD COLUMN IF NOT EXISTS display_name TEXT;

-- Optional: populate display_name for clients from representative if present
UPDATE clients SET display_name = representative WHERE display_name IS NULL AND representative IS NOT NULL;
