# Activity, task, report and verification model

This repository contains the backend application and the activity, task, report, verification, and milestone redesign. `server.js` is the backend entry point and imports the route modules from this repository.

## What is in this folder

| File | What it is |
|---|---|
| `server.js` | Backend application entry point. |
| `progressRules.js` | Pure rules: weights, progress per activity type, claimed and certified progress, milestone derivation, delay. |
| `activityRoutes.js` | Create/edit activities, create/add tasks with a weight preview, milestone sync. |
| `reportRoutes.js` | Member reports, leader approval, rejection and voiding, automatic recompute, close-out export. |
| `verificationRoutes.js` | Verification requests, inspector and leader answers, rework and snags, completion certification. |
| `milestoneRoutes.js` | Breakdown request, consultant's temporary value, milestone progress detail, completion check. |
| `notificationTarget.js` | Authenticated workflow notification target resolution. |
| `verificationReminderJob.js` | Scheduled overdue verification notifications. |
| `docRules.js`, `stamp-renderer.js` | Unchanged copies of your files, so this folder runs on its own. |
| `migrations/` | The dated SQL migrations, in order. |
| `*.test.js`, `run-tests.sh` | Backend tests and a script that runs them on a scratch database. |

## Step 1: back up, then migrate a COPY first

1. Make a backup of your database. The migrations convert existing data and are not reversible, so the backup is your way back.
2. Restore that backup into a scratch database and apply, in this order:
   `migrations/2026-11-01-activity-task-progress.sql`, `2026-11-02-verification-and-milestone-link.sql`,
   `2026-11-03-void-approved-reports.sql`, `migrations/2026-11-04-verification-reminders.sql`,
   then `migrations/2026-11-05-standalone-work-center-tasks.sql`.
3. Look at the notice printed by the first migration. It says how many tasks were moved under "General works (migrated)" and how many activities became the percentage type.
4. Only when the copy looks right, apply the same five files to the real database.

What the first migration does to existing data: tasks without an activity go under one "General works (migrated)" activity per project and side. Activities that already have tasks become the percentage type. Task weights and milestone weights start equal. Task and activity progress are recalculated from approved reports only (weighted, no more averages). Existing contractor activities start at 0% certified. The fifth migration allows new Work Center tasks without a parent activity and stores their own progress type, target, unit, or stages.

## Step 2: run the tests

The tests need a THROWAWAY PostgreSQL database. The script drops and recreates it for every test file.

    SCHEMA_DIR=/path/to/folder/with/your/sql/files \
    PGHOST=localhost PGPORT=5432 PGUSER=postgres PGPASSWORD=yourpassword \
    bash ./run-tests.sh

`SCHEMA_DIR` must contain `completely_schema.sql`, `run_after_completely.sql` and your dated migrations. Install this backend repository's dependencies first; `jsdom` and `acorn` are used by the dashboard tests. Expected last line: `ALL TESTS PASSED`.

## Step 3: deploy the backend

Deploy this repository's `server.js` together with its imported route modules and support files. The dashboard is hosted separately; deploy its UI assets with the frontend rather than treating them as backend server files.

## What was patched in server.js

1. Imports for the four route modules.
2. A registration block just before the first planning-execution route. Because it comes first, the new `POST /api/work-center-progress` and `PUT /api/work-center-progress/:progressId/validate` answer instead of the old ones (same paths).
3. `POST /api/work-center` creates standalone tasks. Linked tasks are created with an activity or added through the activity task route.
4. Delete guards: an activity with tasks or verification history, and a task with approved reports, answer 409 with a clear message instead of a database error.
5. `POST /api/report-progress` and `POST /api/report-additional-progress` now check `canEditSchedule` (they had no role check) and refuse typed entry on a milestone that takes its progress from activities.
6. `POST /api/complete-milestone` also runs the new completion check for derived milestones.
7. `recalculateScheduleProgress` skips derived milestones and ignores superseded typed entries.
8. The three average-based activity progress queries now use the weighted progress when the activity has tasks, and the latest entry otherwise.
9. The simple activity list returns the new columns.
10. The execution-log route and the activity update route answer 409 (not 500) when a database rule refuses, for example closing a contractor activity that the consultant has not certified.
11. Workflow notifications resolve to their activity, task, verification, or milestone destination after project-membership and entity access checks.
12. Execution-entry delay values are calculated from the activity's planned end and actual finish (or the current date while open); submitted delay values are ignored.
13. Pending verification requests past their response date notify consultant leaders and pending inspectors once per day.

## Try it by hand

Use the JWT your app issues at login. Replace the ids and tokens.

    API=http://localhost:3000
    H='content-type: application/json'

1. Contractor leader creates an activity with two tasks (weights default to 50 / 50):

       curl -X POST $API/api/planning-execution/create-with-tasks -H "$H" -H "authorization: Bearer $CONTRACTOR_TOKEN" -d '{
         "projectId": 1, "title": "Excavation", "activity_type": "quantity", "planned_quantity": 400, "unit": "m3",
         "start_date": "2026-03-01", "end_date": "2026-04-30", "baseline_milestone_id": 1,
         "tasks": [ {"title": "Block A", "assigned_members": [{"id": 101}]}, {"title": "Block B", "assigned_members": [{"id": 102}]} ] }'

   If milestone 1 has typed progress, the answer is 409 with `CONFIRM_REPLACE_MANUAL` and a preview. Send the same request again with `"confirm_replace_manual": "true"`.

2. Team member reports (the fields depend on the type: `quantityDone`, or `quantityDone` and `quantityFailed`, or `stageId`, or `progressPct`):

       curl -X POST $API/api/work-center-progress -H "$H" -H "authorization: Bearer $MEMBER_TOKEN" \
         -d '{"projectId":1,"taskId":5,"reportDate":"2026-03-10","workDone":"Excavated block A","quantityDone":100}'

3. Contractor leader approves (this fills the task, the activity and the day's execution entry):

       curl -X PUT $API/api/work-center-progress/12/validate -H "$H" -H "authorization: Bearer $CONTRACTOR_TOKEN" \
         -d '{"projectId":1,"validation_status":"approved"}'

   Other values: `rejected` (reason required), `voided` (an approved report, reason required), `comment_only`.

4. Contractor leader asks the consultant to verify:

       curl -X POST $API/api/activities/3/verifications -H "$H" -H "authorization: Bearer $CONTRACTOR_TOKEN" -d '{"kind":"progress","note":"Block A excavated"}'

   Other kinds: `hold_point` (with `stageId`) and `completion`. Optional `signers: [{"role":"TeamMember","user_id":201}]` names a consultant inspector.

5. Consultant leader decides:

       curl -X PUT $API/api/verifications/7/decide -H "$H" -H "authorization: Bearer $CONSULTANT_TOKEN" \
         -d '{"status":"verified_with_changes","certified_progress_pct":20,"reason":"Measured 80 m3 on site"}'

   Other values: `verified`, `rejected` (reason required, creates rework).

6. Look at the milestone card data. The client side only receives certified figures:

       curl $API/api/milestones/baseline/1/progress-detail -H "authorization: Bearer $CONSULTANT_TOKEN"

7. Consultant: breakdown request and temporary value:

       curl -X POST $API/api/milestones/baseline/1/breakdown-request -H "$H" -H "authorization: Bearer $CONSULTANT_TOKEN" -d '{"note":"Split into excavation, blinding, rebar, pour"}'
       curl -X POST $API/api/milestones/baseline/1/override -H "$H" -H "authorization: Bearer $CONSULTANT_TOKEN" -d '{"value":60,"reason":"Cracks in certified slab"}'

## Dashboard status

- Implemented in the dashboard: activity creation and task breakdown; activity cards with task weights/progress and Add Task; activity-type-specific member reports; leader approval/rejection and approved-report voiding; verification requests, inspector recommendations, consultant decisions, rework/snags; linked-milestone progress, breakdown requests and temporary values; activity-plan editing; client-safe activity views; close-out CSV download; calculated delay; overdue verification reminders; and workflow notification deep links.
- The member report and workflow screens use `workflow-dashboard.js`; frontend hosting and deployment are separate from this backend repository.
- Activity-driven milestones show certified activity breakdown, coverage, temporary values and breakdown requests in the schedule detail. Typed progress entry is disabled for those milestones.

## Not built yet

- Authenticated real-browser and database verification. Apply migrations to a backup/test database first; production data has not been changed or tested here.
- Frontend deployment is separate and was not performed as part of this backend work.

## Known limits

- All tests run with the project-membership lookup replaced by a stub. The real lookup (against `assignments_view`, matching both the id and the role) was exercised once, by booting the patched `server.js` on a scratch database and calling it with real tokens.
- The project-selection recovery is implemented in the dashboard; the three affected loaders wait for startup selection, retry project lookup, and distinguish an unassigned account from a server outage.
- The PostgreSQL-backed route tests require the user's base schema files and a disposable database. Do not point `run-tests.sh` at a production database.
- `run-tests.sh` is a bash script. On Windows, run it from Git Bash or WSL, or run the SQL files and `node --test` files by hand in the same order.
