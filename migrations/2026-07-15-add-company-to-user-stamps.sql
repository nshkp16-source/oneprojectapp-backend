-- Add company_name to user_stamps to store company/organization for stamps
ALTER TABLE user_stamps ADD COLUMN IF NOT EXISTS company_name text;
