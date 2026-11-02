# Fix for Arret & Notification Issues

## Problem Summary
After dropping and recreating the users table, the following issues occurred:
1. **Arrets table existed but had no API endpoints** - Frontend couldn't create/fetch/manage arrets
2. **Column mismatch errors** - `column m.recipient_role does not exist` errors in logs
3. **Missing record tables** - `safety_records`, `contractual_records`, etc. tables were never created
4. **Cascade delete destroyed dependent tables** - `project_chat_messages`, `notification_recipients`, etc.

## Solutions Applied

### 1. Database Migration: `2026-06-16-fix-missing-tables-and-columns.sql`
This migration fixes the database schema by:
- Creating all missing record tables (safety_records, contractual_records, administrative_records, operational_records, financial_records)
- Recreating `project_chat_messages` with all required columns:
  - `recipient_role`, `recipient_id`, `recipient_email`
  - `attachment_mime`, `attachment_size`, `attachment_duration`
- Adding missing columns to `notification_recipients`:
  - `recipient_role`, `recipient_role_id`, `recipient_email`
- Recreating `notifications` and support tables
- Recreating `assignments_view` for permission checks

**⚠️ IMPORTANT**: Run this migration before restarting the server:
```bash
# In your database client (psql for PostgreSQL):
\i migrations/2026-06-16-fix-missing-tables-and-columns.sql
```

### 2. New Arret API Endpoints in `server.js`
Added complete ARRET module with 5 endpoints:

#### GET `/api/arrets`
- Fetch all arrets for a project
- Query params: `projectId`
- Returns: Array of arrets with view count
- Auth: Required

#### POST `/api/arrets`
- Create a new arret (stop-work issue)
- Body: `projectId`, `title`, `description`, `attachment` (optional)
- Returns: Created arret object
- Features:
  - Automatic file upload to Cloudinary
  - Automatic notification creation
  - Sent to all project participants
- Auth: Required

#### GET `/api/arrets/:id`
- Get a specific arret details
- Query params: `projectId`
- Returns: Arret object
- Features: Tracks view when accessed
- Auth: Required

#### PUT `/api/arrets/:id`
- Update arret status (open/closed/resolved)
- Body: `projectId`, `status`, `is_resolved`
- Returns: Updated arret
- Features: Creates resolution notification
- Auth: Required

#### DELETE `/api/arrets/:id`
- Delete an arret (creator only)
- Body: `projectId`
- Returns: Success confirmation
- Auth: Required (creator must match)

### 3. Frontend Integration
The frontend is already set up to use the new endpoints:
- `ARRET_RECORD_TYPE = 'safety_records'`
- Arret bar UI in dashboards references `/api/arrets`
- No frontend changes needed

## Deployment Steps

1. **Apply the database migration**:
   ```bash
   # Using PostgreSQL client
   psql -U postgres -d oneproject < migrations/2026-06-16-fix-missing-tables-and-columns.sql
   ```

2. **Verify migration success**:
   ```sql
   -- Check that tables were created
   SELECT table_name FROM information_schema.tables 
   WHERE table_schema = 'public' 
   AND table_name IN ('safety_records', 'arrets', 'project_chat_messages', 'notification_recipients');
   
   -- Should return 4 rows
   ```

3. **Restart the backend server**:
   ```bash
   npm restart
   # or
   node server.js
   ```

4. **Test the arret functionality**:
   - Log into consultant or client-project-manager dashboard
   - Click the ARRET bar
   - Try to create a new arret
   - Verify it appears in the list
   - Check notifications system receives updates

## What Was Fixed

| Issue | Before | After |
|-------|--------|-------|
| Arrets API | ❌ No routes | ✅ 5 endpoints |
| Chat messages | ❌ Column missing | ✅ All columns added |
| Notifications | ❌ Column errors | ✅ Schema fixed |
| Record tables | ❌ Not created | ✅ All 5 created |
| Permissions | ❌ View broken | ✅ Recreated |

## Troubleshooting

### Error: "column m.recipient_role does not exist"
- **Cause**: Migration not applied
- **Fix**: Run the 2026-06-16 migration

### Error: "relation 'safety_records' does not exist"
- **Cause**: Migration not applied or failed
- **Fix**: Check migration logs and re-run migration

### Arrets don't appear in UI
- **Cause**: Frontend cache or API not responding
- **Fix**: 
  1. Clear browser cache
  2. Check browser console for errors
  3. Verify backend is running: `curl http://localhost:3000/api/me` (with auth token)

### Notifications not showing
- **Cause**: notification_recipients table issues
- **Fix**: Check that all columns exist in notification_recipients table

## Files Modified

1. **New Migration**: `migrations/2026-06-16-fix-missing-tables-and-columns.sql`
   - Creates all missing tables and columns
   - ~300 lines

2. **Backend**: `server.js`
   - Added arret routes (lines ~3160-3310)
   - ~150 lines of new code
   - No changes to existing routes

## Testing Checklist

- [ ] Migration runs without errors
- [ ] Can create a new arret via POST /api/arrets
- [ ] Can fetch arrets via GET /api/arrets
- [ ] Arret appears in consultant dashboard
- [ ] Arret appears in client-project-manager dashboard
- [ ] Notification is created when arret issued
- [ ] Can mark arret as resolved
- [ ] Can view individual arrets
- [ ] Chat messages load without errors
- [ ] Notifications are received without "column" errors

## Support

If issues persist:
1. Check the backend logs for specific error messages
2. Verify the migration ran completely
3. Confirm database credentials are correct
4. Check that all 5 record tables exist
5. Verify project_chat_messages has recipient_role column
