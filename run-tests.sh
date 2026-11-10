#!/bin/bash
# Runs every test file against a THROWAWAY database, rebuilt from scratch before each file
# (each test file assumes an empty database with the schema and the migrations applied).
#
# Usage:
#   SCHEMA_DIR=/path/to/your/sql/files ./run-tests.sh
# Optional: PGHOST PGPORT PGUSER PGPASSWORD (standard psql variables), SCRATCH_DB (default: oneproject_scratch)
#
# SCHEMA_DIR must contain completely_schema.sql, run_after_completely.sql and your dated migrations.
# Never point this at a real database: it drops and recreates SCRATCH_DB.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
SCHEMA_DIR="${SCHEMA_DIR:?Set SCHEMA_DIR to the folder with your .sql files}"
DB="${SCRATCH_DB:-oneproject_scratch}"
PSQL="psql -q -v ON_ERROR_STOP=1"
ADMIN_DB="${ADMIN_DB:-postgres}"

load() {
  for f in "$SCHEMA_DIR/completely_schema.sql" "$SCHEMA_DIR/run_after_completely.sql" \
           "$SCHEMA_DIR/2026-09-10-prevent-duplicate-execution-entries.sql" \
           "$SCHEMA_DIR/2026-09-24-chat-features.sql" "$SCHEMA_DIR/2026-09-27-project-lifecycle.sql" \
           "$HERE/migrations/2026-11-01-activity-task-progress.sql" \
           "$HERE/migrations/2026-11-02-verification-and-milestone-link.sql" \
           "$HERE/migrations/2026-11-03-void-approved-reports.sql" \
           "$HERE/migrations/2026-11-04-verification-reminders.sql" \
           "$HERE/migrations/2026-11-05-standalone-work-center-tasks.sql" \
           "$HERE/migrations/2026-11-06-activity-milestone-workflow.sql" \
           "$HERE/migrations/2026-11-06-work-center-queries.sql" \
           "$HERE/migrations/2026-11-07-link-task-queries-to-reports.sql" \
           "$HERE/migrations/2026-11-07-work-center-task-card.sql" \
           "$HERE/migrations/2026-11-08-card-attachments.sql" \
           "$HERE/migrations/2026-11-09-verification-shared-evidence.sql" \
           "$HERE/migrations/2026-11-10-verification-read-receipts.sql" \
           "$HERE/migrations/2026-11-11-report-supporting-attachments.sql"; do
    $PSQL -d "$DB" -f "$f" > /dev/null 2>/tmp/run-tests-load.err || { echo "Failed loading $f"; cat /tmp/run-tests-load.err; exit 1; }
  done
}

FAILED=0
node --test \
  "$HERE/progressRules.test.js" "$HERE/workflow-dashboard.test.js" \
  "$HERE/activity-card-ui.test.js" \
  "$HERE/cloudinaryUploadTracker.test.js" \
  "$HERE/project-resolution.test.js" "$HERE/activity-form-v2.test.js" \
  "$HERE/wc-reports-v2.test.js" "$HERE/wc-views.test.js" "$HERE/supportingAttachmentTypes.test.js" \
  "$HERE/notificationTarget.test.js" "$HERE/verificationReminderJob.test.js" \
  "$HERE/pending-list.test.js" "$HERE/consultant-activity-open.test.js" || FAILED=1
for t in activityRoutes reportRoutes verificationRoutes milestoneRoutes taskQueryRoutes; do
  $PSQL -d "$ADMIN_DB" -c "DROP DATABASE IF EXISTS $DB" -c "CREATE DATABASE $DB"
  load
  echo "== $t"
  TEST_DATABASE_URL="${TEST_DATABASE_URL_BASE:-postgres://${PGUSER:-postgres}${PGPASSWORD:+:$PGPASSWORD}@${PGHOST:-localhost}:${PGPORT:-5432}}/$DB" \
    node --test --test-timeout=60000 "$HERE/$t.test.js" || FAILED=1
done
[ "$FAILED" = "0" ] && echo "ALL TESTS PASSED" || { echo "SOME TESTS FAILED"; exit 1; }
