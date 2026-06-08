# Schedule Module Deployment Guide (2026-06-09)

## Overview
This guide deploys the complete schedule module with:
- New database schema (`project_schedules`, `milestones`, `progress tracking`, `extensions`)
- Data migration from old schema to new schedule structure
- Frontend weather integration with coordinates

---

## Step 1: Deploy Schema to Neon Database

### Option A: Using psql CLI (Recommended)
```bash
# Set your Neon database connection string
export DATABASE_URL="postgresql://user:password@host/database"

# Apply the schema (creates all tables with safe DROP IF EXISTS)
psql $DATABASE_URL -f schema/2026-06-09-complete-schedule-schema.sql

# Verify tables were created
psql $DATABASE_URL -c "\dt"
```

### Option B: Using Neon Console
1. Go to Neon Dashboard → SQL Editor
2. Copy contents of `backend/schema/2026-06-09-complete-schedule-schema.sql`
3. Paste into editor and execute
4. Verify all tables created

---

## Step 2: Migrate Existing Data

### Option A: Using psql CLI
```bash
# Apply data migration (populates new tables from old schema)
psql $DATABASE_URL -f migrations/2026-06-09-migrate-data-to-schedule-schema.sql

# Verify data was migrated
psql $DATABASE_URL -c "SELECT COUNT(*) FROM project_schedules;"
psql $DATABASE_URL -c "SELECT COUNT(*) FROM milestones;"
```

### Option B: Using Neon Console
1. Go to SQL Editor
2. Copy contents of `backend/migrations/2026-06-09-migrate-data-to-schedule-schema.sql`
3. Paste and execute
4. Verify with SELECT queries

---

## Step 3: Verify Data Integrity

Run these queries to confirm migration succeeded:

```sql
-- Check project schedules
SELECT COUNT(*) as total_schedules FROM project_schedules;

-- Check milestones
SELECT COUNT(*) as total_milestones FROM milestones;

-- Check progress entries
SELECT COUNT(*) as total_progress_entries FROM milestone_progress_entries;

-- Check a sample project schedule
SELECT ps.id, ps.project_id, ps.planned_start, ps.planned_finish, 
       (SELECT COUNT(*) FROM milestones WHERE schedule_id = ps.id) as milestone_count
FROM project_schedules ps LIMIT 5;
```

---

## Step 4: Verify Frontend Changes

**What was fixed:**
- `loadSummaryPanelData()` now uses `authFetch()` instead of plain `fetch()`
- Auto-refresh logic handles expired JWT tokens
- Summary panel displays from `/api/project-summary` endpoint

**Test in browser:**
1. Open `consultant-dashboard.html`
2. Navigate to Dashboard → Summary
3. Verify:
   - ✅ Location displays (saved from Nominatim)
   - ✅ Weather loads (current + 2-day forecast)
   - ✅ Remaining project days shown
   - ✅ Current milestone displayed
   - ✅ Progress bar shows overall %
   - ✅ Chart shows planned vs actual bars
   - ✅ Previous/Next buttons navigate milestones

**Check browser console (F12 → Console):**
```
[Summary] Weather: Using location coordinates {lat: X, lng: Y}
[Weather API] Fetching from Open-Meteo: {lat: X, lng: Y, url: "..."}
[Weather] Current: "Clear sky, 22°C · Wind 5 km/h"
[Weather] Forecast: "Today 25°C / 18°C · Tomorrow Partly cloudy 24°C / 17°C"
```

---

## Step 5: Test Complete Workflow

1. **Create a new project with schedule:**
   - Go to Schedule tab
   - Save milestones with location (using street map search)
   - Verify location coordinates are saved

2. **View Summary Panel:**
   - Open Summary view
   - Verify all data loads correctly
   - Check weather displays actual forecast

3. **Navigate Chart:**
   - Click `<` and `>` buttons
   - Each milestone should show planned vs actual bars
   - Verify red color appears if delayed

---

## Troubleshooting

### Issue: 403 Forbidden on Summary Load
**Solution:** User token expired. The fix ensures auto-refresh now:
1. Frontend calls `authFetch()` which auto-refreshes JWT
2. If refresh fails, user is redirected to login

### Issue: No weather displays
**Ensure:**
- Location has valid `lat` and `lng` coordinates (from Nominatim)
- Open-Meteo API is reachable (public, no auth needed)
- Check console for error messages

### Issue: Migration creates empty tables
**Verify:**
1. Old schema tables exist: `planning_execution`, `planning_execution_tracking`
2. Migration ran without errors
3. Run: `SELECT * FROM project_schedules LIMIT 1;`

---

## Rollback (if needed)

To revert to old schema:
```sql
-- Delete new tables (they have CASCADE deletes)
DROP TABLE IF EXISTS milestone_photos CASCADE;
DROP TABLE IF EXISTS progress_entry_attachments CASCADE;
DROP TABLE IF EXISTS additional_milestone_attachments CASCADE;
DROP TABLE IF EXISTS milestone_attachments CASCADE;
DROP TABLE IF EXISTS additional_milestone_progress_entries CASCADE;
DROP TABLE IF EXISTS additional_milestones CASCADE;
DROP TABLE IF EXISTS milestone_progress_entries CASCADE;
DROP TABLE IF EXISTS schedule_extensions CASCADE;
DROP TABLE IF EXISTS milestones CASCADE;
DROP TABLE IF EXISTS project_schedules CASCADE;

-- Old schema tables remain for recovery
```

---

## Files Modified

- `backend/schema/2026-06-09-complete-schedule-schema.sql` - ✅ Schema snapshot
- `backend/migrations/2026-06-09-migrate-data-to-schedule-schema.sql` - ✅ Data migration
- `frontend/consultant-dashboard.html` - ✅ Fixed 403 auth error (line 1794: `authFetch()`)

---

## Next Steps

After successful deployment:
1. ✅ Monitor `/api/project-summary` endpoint for errors
2. ✅ Test with multiple projects
3. ✅ Verify weather accuracy with real location data
4. ✅ Backup database before deploying to production
