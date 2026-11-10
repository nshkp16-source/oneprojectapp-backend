// Work Center progress reports and their related team-member queries.
import {
  taskProgress, activityProgress, buildDailyEntry, checkPercentageReport, stageUnlocked, delayDays,
} from './progressRules.js';
import { parseSupportingAttachmentType } from './supportingAttachmentTypes.js';
import { createCloudinaryUploadTracker } from './cloudinaryUploadTracker.js';

const reports = (function () {
// Member reports and leader approval, with the recompute that fills the activity automatically.
//
// A team member reports on a task (quantity, count, stage or percentage, depending on the activity type).
// A leader of the same side approves, rejects or voids it. Whenever a report becomes approved or voided,
// the task progress, the activity (claimed) progress and the day's execution entry are recomputed from the
// approved reports, so nobody retypes anything at the activity level.
//
// Wiring in server.js: delete the old handlers for
//     POST /api/work-center-progress
//     PUT  /api/work-center-progress/:progressId/validate
// (same paths, so the dashboard keeps working), then add:
//
//   import { registerReportRoutes } from './workCenterRoutes.js';
//   registerReportRoutes(app, {
//     pool, authenticateToken, upload, requireProjectLifecycleWrite, scheduleCloudinaryUpload,
//     wcSide, isWCLeader, sideRoles,
//     notify: ({ projectId, entityId, entityType, message, actorId, actorRole, recipients }) =>
//       notifyRecordUsers({ projectId, recordId: entityId, table: entityType, message, actorId, actorRole, recipients }),
//     flowKey,
//   });


const DAY = (v) => String(v || '').slice(0, 10);
function reportDelayDays(reportDate, plannedEndDate) {
  const reportDay = DAY(reportDate), endDay = DAY(plannedEndDate);
  if (!isDate(reportDay) || !isDate(endDay) || reportDay <= endDay) return 0;
  const reportTime = Date.parse(`${reportDay}T00:00:00Z`);
  const endTime = Date.parse(`${endDay}T00:00:00Z`);
  return Math.floor((reportTime - endTime) / 86400000);
}
const DATE = (v) => v instanceof Date
  ? `${v.getFullYear()}-${String(v.getMonth() + 1).padStart(2, '0')}-${String(v.getDate()).padStart(2, '0')}`
  : DAY(v);
const isDate = (v) => /^\d{4}-\d{2}-\d{2}$/.test(String(v || '')) && !Number.isNaN(Date.parse(String(v)));
const round2 = (x) => Math.round((Number(x) + Number.EPSILON) * 100) / 100;

class HttpError extends Error {
  constructor(status, message, extra = {}) { super(message); this.status = status; this.extra = extra; }
}
function fail(res, err, label) {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message, ...err.extra });
  console.error(label, err);
  return res.status(500).json({ error: 'Server error.' });
}

function parseOptionalCoordinate(value, minimum, maximum) {
  if (value == null || value === '') return null;
  const coordinate = Number(value);
  if (!Number.isFinite(coordinate) || coordinate < minimum || coordinate > maximum)
    throw new HttpError(400, 'Photo location metadata is invalid.');
  return coordinate;
}

function parseReportResources(value, assignedMembers = []) {
  if (!value) return [];
  let rows = value;
  if (typeof value === 'string') {
    try { rows = JSON.parse(value); }
    catch { throw new HttpError(400, 'Resource details are invalid.'); }
  }
  if (!Array.isArray(rows) || rows.length > 60)
    throw new HttpError(400, 'A report can include at most 60 resource entries.');
  return rows.map((row) => {
    const type = String(row?.type || '');
    const name = String(row?.name || '').trim();
    const quantity = row?.quantity === '' || row?.quantity == null ? null : Number(row.quantity);
    const hours = row?.hours === '' || row?.hours == null ? null : Number(row.hours);
    const unit = String(row?.unit || '').trim() || null;
    const assignedMemberId = row?.assignedMemberId == null || row.assignedMemberId === ''
      ? null : Number(row.assignedMemberId);
    if (!['manpower', 'equipment', 'material'].includes(type) || !name || name.length > 200)
      throw new HttpError(400, 'Each resource needs a valid type and name.');
    if (assignedMemberId != null && (!Number.isSafeInteger(assignedMemberId)
      || !assignedMembers.some((member) => String(member.id) === String(assignedMemberId))))
      throw new HttpError(400, 'Resource attribution must be an assigned member on this task.');
    if ((quantity != null && (!Number.isFinite(quantity) || quantity < 0))
      || (hours != null && (!Number.isFinite(hours) || hours < 0)))
      throw new HttpError(400, 'Resource quantities and hours must be zero or more.');
    if (unit && unit.length > 60) throw new HttpError(400, 'Resource units cannot exceed 60 characters.');
    return { type, name, quantity, unit, hours, assignedMemberId };
  });
}

// ── recompute ────────────────────────────────────────────────────────────────

/**
 * Recompute one activity from its approved reports: task progress and status, stage completion,
 * activity claimed progress and status, actual start, and the daily execution entries for `dates`.
 * Call it inside the caller's transaction.
 */
async function recomputeActivity(client, activityId, { dates = [], actor = null } = {}) {
  const act = (await client.query(`SELECT * FROM planning_execution WHERE id = $1 FOR UPDATE`, [activityId])).rows[0];
  if (!act) return null;
  const tasks = (await client.query(
    `SELECT id, weight_pct, target_quantity, status FROM workspace_work_center WHERE activity_id = $1 ORDER BY id FOR UPDATE`, [activityId])).rows;
  const reports = (await client.query(
    `SELECT p.*, to_char(p.report_date, 'YYYY-MM-DD') AS day
     FROM workspace_work_center_progress p JOIN workspace_work_center w ON w.id = p.task_id
     WHERE w.activity_id = $1 ORDER BY p.report_date, p.id`, [activityId])).rows
    .map((r) => ({ ...r, report_date: r.day }));
  const stages = (await client.query(
    `SELECT s.* FROM task_stages s JOIN workspace_work_center w ON w.id = s.task_id
     WHERE w.activity_id = $1 ORDER BY s.task_id, s.seq`, [activityId])).rows;

  const approved = reports.filter((r) => r.validation_status === 'approved');
  const type = act.activity_type;
  const tasksProgress = (cutoff) => tasks.map((t) => {
    const mine = approved.filter((r) => r.task_id === t.id && (!cutoff || r.day <= cutoff));
    return { id: t.id, weight_pct: Number(t.weight_pct),
             progress_pct: taskProgress(type, t, mine, stages.filter((s) => s.task_id === t.id)) };
  });

  // tasks
  const current = tasksProgress(null);
  for (const t of tasks) {
    const prog = current.find((c) => c.id === t.id).progress_pct;
    const mine = approved.filter((r) => r.task_id === t.id);
    const start = mine.length ? mine[0].day : null;
    let status = t.status;
    if (status === 'ongoing' && prog >= 100) status = 'completed';
    else if (status === 'completed' && prog < 100) status = 'ongoing';
    await client.query(
      `UPDATE workspace_work_center SET progress_pct = $2, actual_start = $3, status = $4, updated_at = NOW() WHERE id = $1`,
      [t.id, prog, start, status]);
  }

  // stage completion cache
  const doneStages = new Set(approved.map((r) => r.stage_id).filter((id) => id != null));
  for (const s of stages) {
    await client.query(
      `UPDATE task_stages SET completed_at = CASE WHEN $2 THEN COALESCE(completed_at, NOW()) ELSE NULL END WHERE id = $1`,
      [s.id, doneStages.has(s.id)]);
  }

  // activity
  const progress = tasks.length ? activityProgress(current) : Number(act.progress_pct);
  let status = act.status;
  if (status !== 'closed') {
    if (progress >= 100) status = 'completed';
    else status = approved.length ? 'ongoing' : 'not_yet_started';
  }
  const actualStart = approved.length ? approved[0].day : null;
  await client.query(
    `UPDATE planning_execution SET progress_pct = $2, status = $3, actual_start = $4, updated_at = NOW() WHERE id = $1`,
    [activityId, progress, status, actualStart]);

  // daily execution entries
  for (const day of [...new Set(dates.map(DAY))]) {
    const todays = approved.filter((r) => r.day === day);
    if (!todays.length) {
      await client.query(
        `DELETE FROM planning_execution_tracking WHERE activity_id = $1 AND report_date = $2 AND source = 'work_center'`, [activityId, day]);
      continue;
    }
    const entry = buildDailyEntry(todays);
    const join = (field) => todays.map((r) => String(r[field] || '').trim()).filter(Boolean).join('; ') || null;
    const asOf = tasks.length ? activityProgress(tasksProgress(day)) : 0;
    const calculatedDelay = delayDays({
      plannedEnd: DATE(act.end_date),
      actualEnd: DATE(act.actual_end),
      status: act.status,
    });
    await client.query(`
      INSERT INTO planning_execution_tracking
        (activity_id, report_date, actual_quantity, unit, manpower_used, equipment_used, materials_used,
         progress_pct, issues, day_remark, delay_days, status_change_to_closed, logged_by, logged_by_role,
         source, contributions, recomputed_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,false,$12,$13,'work_center',$14::jsonb,NOW())
      ON CONFLICT (activity_id, report_date) DO UPDATE SET
        -- a typed entry on the same date keeps its own figures; only the contributions are added to it
        actual_quantity = CASE WHEN planning_execution_tracking.source = 'work_center' THEN EXCLUDED.actual_quantity ELSE planning_execution_tracking.actual_quantity END,
        unit            = CASE WHEN planning_execution_tracking.source = 'work_center' THEN EXCLUDED.unit            ELSE planning_execution_tracking.unit END,
        manpower_used   = CASE WHEN planning_execution_tracking.source = 'work_center' THEN EXCLUDED.manpower_used   ELSE planning_execution_tracking.manpower_used END,
        equipment_used  = CASE WHEN planning_execution_tracking.source = 'work_center' THEN EXCLUDED.equipment_used  ELSE planning_execution_tracking.equipment_used END,
        materials_used  = CASE WHEN planning_execution_tracking.source = 'work_center' THEN EXCLUDED.materials_used  ELSE planning_execution_tracking.materials_used END,
        progress_pct    = CASE WHEN planning_execution_tracking.source = 'work_center' THEN EXCLUDED.progress_pct    ELSE planning_execution_tracking.progress_pct END,
        issues          = CASE WHEN planning_execution_tracking.source = 'work_center' THEN EXCLUDED.issues          ELSE planning_execution_tracking.issues END,
        day_remark      = CASE WHEN planning_execution_tracking.source = 'work_center' THEN EXCLUDED.day_remark      ELSE planning_execution_tracking.day_remark END,
        delay_days      = CASE WHEN planning_execution_tracking.source = 'work_center' THEN EXCLUDED.delay_days      ELSE planning_execution_tracking.delay_days END,
        contributions   = EXCLUDED.contributions,
        recomputed_at   = NOW()`,
      [activityId, day, entry.actual_quantity, act.unit, join('manpower'), join('equipment'), join('materials'),
       asOf, join('issues'), entry.day_remark || null, calculatedDelay, actor?.id ?? act.creator_id, actor?.role ?? act.creator_role,
       JSON.stringify(entry.contributions)]);
  }

  return { progress_pct: progress, status, tasks: current };
}

async function recomputeStandaloneTask(client, taskId) {
  const task = (await client.query(
    `SELECT * FROM workspace_work_center WHERE id = $1 AND activity_id IS NULL FOR UPDATE`, [taskId])).rows[0];
  if (!task) return null;
  const reports = (await client.query(
    `SELECT *, to_char(report_date, 'YYYY-MM-DD') AS day
     FROM workspace_work_center_progress WHERE task_id = $1 ORDER BY report_date, id`, [taskId])).rows;
  const stages = (await client.query(
    `SELECT * FROM task_stages WHERE task_id = $1 ORDER BY seq`, [taskId])).rows;
  const approved = reports.filter((report) => report.validation_status === 'approved');
  const progress = taskProgress(task.activity_type, task, approved, stages);
  const actualStart = approved.length ? approved[0].day : null;
  let status = task.status;
  if (status !== 'closed') {
    if (progress >= 100) status = 'completed';
    else status = approved.length ? 'ongoing' : 'not_yet_started';
  }
  await client.query(
    `UPDATE workspace_work_center SET progress_pct = $2, actual_start = $3, status = $4, updated_at = NOW() WHERE id = $1`,
    [taskId, progress, actualStart, status]);
  const doneStages = new Set(approved.map((report) => report.stage_id).filter((id) => id != null));
  for (const stage of stages) {
    await client.query(
      `UPDATE task_stages SET completed_at = CASE WHEN $2 THEN COALESCE(completed_at, NOW()) ELSE NULL END WHERE id = $1`,
      [stage.id, doneStages.has(stage.id)]);
  }
  return { id: taskId, progress_pct: progress, status };
}

// ── helpers ──────────────────────────────────────────────────────────────────

async function isMember(deps, projectId, userId, role) {
  if (deps.isProjectMember) return deps.isProjectMember(projectId, userId, role);
  const r = await deps.pool.query(`SELECT 1 FROM assignments_view WHERE project_id = $1 AND role_id = $2 AND role = $3 LIMIT 1`, [projectId, userId, role]);
  return r.rows.length > 0;
}

async function leadersOf(deps, projectId, side) {
  if (deps.leadersOf) return deps.leadersOf(projectId, side);
  if (!deps.sideRoles) return [];
  const r = await deps.pool.query(
    `SELECT role, role_id FROM assignments_view WHERE project_id = $1 AND role = ANY($2::text[])`, [projectId, deps.sideRoles(side)]);
  return r.rows.map((x) => deps.flowKey(x.role, x.role_id));
}

async function notifySafe(deps, args) {
  if (!deps.notify || !args.recipients?.length) return;
  try { await deps.notify(args); } catch (err) { console.error('[report] notification failed (non-fatal):', err.message); }
}

// ── routes ───────────────────────────────────────────────────────────────────

function registerReportRoutes(app, deps) {
  const { pool, authenticateToken, upload, requireProjectLifecycleWrite, wcSide, isWCLeader } = deps;
  const reportUpload = deps.reportUpload || upload;

  // Member report. What the member fills in depends on the activity type:
  //   quantity: quantityDone   count: quantityDone and quantityFailed   stages: stageId   percentage: progressPct
  app.post('/api/work-center-progress', authenticateToken,
    reportUpload.fields([
      { name: 'attachment', maxCount: 1 },
      { name: 'photos', maxCount: 10 },
      { name: 'supporting_attachments', maxCount: 20 },
    ]),
    requireProjectLifecycleWrite, async (req, res) => {
    let client;
    const uploads = createCloudinaryUploadTracker(deps);
    try {
      const { user_id: userId, role } = req.user;
      if (role !== 'TeamMember') throw new HttpError(403, 'Only assigned team members can submit progress reports.');

      const b = req.body || {};
      const projectId = parseInt(b.projectId, 10);
      const taskId = parseInt(b.taskId, 10);
      if (!projectId) throw new HttpError(400, 'projectId is required.');
      if (!taskId) throw new HttpError(400, 'taskId is required.');
      if (!isDate(b.reportDate)) throw new HttpError(400, 'reportDate must be a valid date (YYYY-MM-DD).');
      if (!String(b.workDone || '').trim()) throw new HttpError(400, 'workDone is required.');

      const task = (await pool.query(
        `SELECT w.*, COALESCE(w.activity_type, pe.activity_type) AS activity_type,
                pe.status AS activity_status, pe.title AS activity_title
         FROM workspace_work_center w LEFT JOIN planning_execution pe ON pe.id = w.activity_id
         WHERE w.id = $1 AND w.project_id = $2`, [taskId, projectId])).rows[0];
      if (!task) throw new HttpError(404, 'Task not found.');
      const assigned = Array.isArray(task.assigned_members) ? task.assigned_members : [];
      if (!assigned.some((m) => String(m.id) === String(userId))) throw new HttpError(403, 'You are not assigned to this task.');
      if (!(await isMember(deps, projectId, userId, role))) throw new HttpError(403, 'You are not a member of this project.');
      const sideAssignment = await pool.query(
        `SELECT 1 FROM team_member_assignments
         WHERE project_id = $1 AND team_member_id = $2 AND assigned_part = $3 LIMIT 1`,
        [projectId, userId, task.side]);
      if (!sideAssignment.rows.length) throw new HttpError(403, 'You are not assigned to this task.');
      if (task.status === 'closed' || task.activity_status === 'closed') throw new HttpError(409, 'This task is closed. Reports can no longer be added.');
      const idempotencyKey = String(b.idempotencyKey || '').trim();
      if (idempotencyKey && (idempotencyKey.length > 100 || !/^[\w-]+$/.test(idempotencyKey)))
        throw new HttpError(400, 'idempotencyKey is invalid.');
      if (idempotencyKey) {
        const existing = (await pool.query(
          `SELECT * FROM workspace_work_center_progress
           WHERE task_id = $1 AND member_id = $2 AND idempotency_key = $3`,
          [taskId, userId, idempotencyKey])).rows[0];
        if (existing) return res.status(200).json({ success: true, entry: existing, duplicate: true });
      }

      const photos = req.files?.photos || [];
      const supportingFiles = req.files?.supporting_attachments || [];
      let supportingMetadata = [];
      if (supportingFiles.length) {
        try { supportingMetadata = JSON.parse(b.supportingAttachmentMetadata || ''); }
        catch { throw new HttpError(400, 'Supporting attachment details are invalid.'); }
        if (!Array.isArray(supportingMetadata) || supportingMetadata.length !== supportingFiles.length)
          throw new HttpError(400, 'Supporting attachment details do not match the selected files.');
        supportingMetadata = supportingMetadata.map((metadata) => {
          const parsed = parseSupportingAttachmentType(metadata);
          if (parsed.error) throw new HttpError(400, parsed.error);
          return parsed;
        });
      } else if (b.supportingAttachmentMetadata) {
        throw new HttpError(400, 'Choose supporting files before setting their titles.');
      }
      if (photos.length > 10) throw new HttpError(400, 'A report can include at most 10 photos.');
      let photoMeta = [];
      if (b.photoMeta) {
        try { photoMeta = JSON.parse(b.photoMeta); }
        catch { throw new HttpError(400, 'Photo metadata is invalid.'); }
      }
      if (!Array.isArray(photoMeta) || photoMeta.length !== photos.length)
        throw new HttpError(400, 'Photo metadata does not match the selected photos.');
      photoMeta = photoMeta.map((meta) => ({
        latitude: parseOptionalCoordinate(meta?.latitude, -90, 90),
        longitude: parseOptionalCoordinate(meta?.longitude, -180, 180),
        accuracy: meta?.accuracy === '' || meta?.accuracy == null ? null : Number(meta.accuracy),
        capturedAt: meta?.capturedAt && !Number.isNaN(Date.parse(meta.capturedAt)) ? new Date(meta.capturedAt) : null,
      }));
      if (photoMeta.some((meta) => meta.accuracy != null && (!Number.isFinite(meta.accuracy) || meta.accuracy < 0)))
        throw new HttpError(400, 'Photo accuracy metadata is invalid.');
      const resources = parseReportResources(b.resources, assigned);
      const delayCause = String(b.delayCause || '').trim() || null;
      const delayNote = String(b.delayNote || '').trim();
      const delayDaysCount = reportDelayDays(b.reportDate, task.end_date);
      if (delayCause && !['weather', 'materials', 'equipment', 'access', 'design', 'labor', 'other'].includes(delayCause))
        throw new HttpError(400, 'Choose a valid delay cause.');
      if (!Number.isInteger(delayDaysCount) || delayDaysCount < 0 || delayDaysCount > 365)
        throw new HttpError(400, 'Delay days must be a whole number from 0 to 365.');
      if (delayNote.length > 2000) throw new HttpError(400, 'The delay note cannot exceed 2000 characters.');
      if (delayNote && !delayCause)
        throw new HttpError(400, 'Choose a delay cause when reporting a delay.');

      const today = (await pool.query(`SELECT to_char(CURRENT_DATE + 1, 'YYYY-MM-DD') AS d`)).rows[0].d;   // one day of tolerance for time zones
      if (b.reportDate > today) throw new HttpError(400, 'The report date cannot be in the future.');
      const taskStart = DAY(task.start_date instanceof Date
        ? `${task.start_date.getFullYear()}-${String(task.start_date.getMonth() + 1).padStart(2, '0')}-${String(task.start_date.getDate()).padStart(2, '0')}`
        : task.start_date);
      if (b.reportDate < taskStart) throw new HttpError(400, `The report date cannot be before the task start (${taskStart}).`);

      const reports = (await pool.query(
        `SELECT id, task_id, stage_id, report_date, validation_status, quantity_done, quantity_failed, progress_pct
         FROM workspace_work_center_progress WHERE task_id = $1`, [taskId])).rows
        .map((r) => ({ ...r, report_date: DAY(r.report_date instanceof Date ? r.report_date.toISOString() : r.report_date) }));
      const stages = (await pool.query(`SELECT * FROM task_stages WHERE task_id = $1 ORDER BY seq`, [taskId])).rows;
      const approved = reports.filter((r) => r.validation_status === 'approved');

      const type = task.activity_type;
      let quantityDone = null, quantityFailed = 0, stageId = null, pct = 0, warning = null;
      if (type === 'quantity' || type === 'count') {
        quantityDone = Number(b.quantityDone);
        if (!(quantityDone > 0)) throw new HttpError(400, 'quantityDone must be above 0.');
        if (type === 'count') {
          quantityFailed = Number(b.quantityFailed || 0);
          if (!Number.isInteger(quantityDone)) throw new HttpError(400, 'For a count activity, quantityDone must be a whole number.');
          if (!Number.isInteger(quantityFailed) || quantityFailed < 0 || quantityFailed > quantityDone)
            throw new HttpError(400, 'quantityFailed must be a whole number from 0 up to quantityDone.');
        }
        const already = reports.filter((r) => ['approved', 'pending'].includes(r.validation_status))
          .reduce((t, r) => t + (Number(r.quantity_done) || 0), 0);
        if (Number(task.target_quantity) > 0 && already + quantityDone > Number(task.target_quantity))
          warning = `With this report the total is ${already + quantityDone}, above the task target of ${Number(task.target_quantity)}.`;
      } else if (type === 'stages') {
        stageId = parseInt(b.stageId, 10);
        const stage = stages.find((s) => s.id === stageId);
        if (!stage) throw new HttpError(400, 'Choose one of the stages of this task.');
        if (approved.some((r) => r.stage_id === stageId)) throw new HttpError(409, 'This stage is already completed.');
        if (reports.some((r) => r.stage_id === stageId && r.validation_status === 'pending'))
          throw new HttpError(409, 'A report for this stage is already waiting for validation.');
        const verifiedHolds = stages.filter((s) => s.is_hold_point && s.hold_verified_at).map((s) => s.id);
        if (!stageUnlocked(stages, stageId, verifiedHolds))
          throw new HttpError(409, 'An earlier hold point has not been verified by the consultant yet.');
      } else {
        pct = parseInt(b.progressPct, 10);
        const problem = checkPercentageReport(pct, approved);
        if (problem) throw new HttpError(400, problem);
      }

      // what the task would show if this report were approved (kept in progress_pct so lists still render)
      const projected = taskProgress(type, task,
        [...approved, { validation_status: 'approved', report_date: b.reportDate, id: 1e9, quantity_done: quantityDone, quantity_failed: quantityFailed, stage_id: stageId, progress_pct: pct }],
        stages);
      const stored = Math.round(projected);

      let file = { name: null, id: null, url: null };
      client = await pool.connect();
      await client.query('BEGIN');
      let entry = (await client.query(`
        INSERT INTO workspace_work_center_progress
          (task_id, report_date, member_id, member_role, work_done, manpower, equipment, materials,
           progress_pct, issues, notes, attachment_name, attachment_id, attachment_url,
           quantity_done, quantity_failed, stage_id, delay_cause, delay_note, delay_days, idempotency_key)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,NULL,NULL,$12,$13,$14,$15,$16,$17,$18)
        ON CONFLICT (task_id, member_id, idempotency_key) WHERE idempotency_key IS NOT NULL
        DO NOTHING RETURNING *`,
        [taskId, b.reportDate, userId, role, String(b.workDone).trim(), b.manpower || '', b.equipment || '', b.materials || '',
         stored, b.issues || '', b.notes || '', quantityDone, quantityFailed, stageId,
         delayCause, delayNote || null, delayDaysCount, idempotencyKey || null])).rows[0];
      if (!entry) {
        await client.query('ROLLBACK');
        const existing = (await pool.query(
          `SELECT * FROM workspace_work_center_progress
           WHERE task_id = $1 AND member_id = $2 AND idempotency_key = $3`,
          [taskId, userId, idempotencyKey])).rows[0];
        if (existing) return res.status(200).json({ success: true, entry: existing, duplicate: true });
        throw new HttpError(409, 'This report was already submitted.');
      }

      const attachment = req.files?.attachment?.[0];
      if (attachment) {
        const up = await uploads.upload(attachment.buffer, attachment.originalname, 'work_center/progress');
        file = { name: attachment.originalname, id: up.public_id, url: up.secure_url };
        entry = (await client.query(
          `UPDATE workspace_work_center_progress
           SET attachment_name=$1, attachment_id=$2, attachment_url=$3 WHERE id=$4 RETURNING *`,
          [file.name, file.id, file.url, entry.id])).rows[0];
      }

      for (let i = 0; i < supportingFiles.length; i++) {
        const supportingFile = supportingFiles[i];
        const metadata = supportingMetadata[i];
        const up = await uploads.upload(
          supportingFile.buffer, supportingFile.originalname, 'work_center/progress-supporting-attachments');
        await client.query(
          `INSERT INTO work_center_report_attachments
             (report_id, project_id, file_name, file_id, file_url, mime_type,
              attachment_type, custom_attachment_type, uploaded_by_id, uploaded_by_role)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [entry.id, projectId, supportingFile.originalname, up.public_id, up.secure_url,
            supportingFile.mimetype || null, metadata.attachmentType, metadata.customAttachmentType,
            userId, role]);
      }

      for (let i = 0; i < photos.length; i++) {
        const photo = photos[i];
        const meta = photoMeta[i];
        const up = await uploads.upload(photo.buffer, `report-${entry.id}-photo-${i + 1}`, 'work_center/progress');
        await client.query(
          `INSERT INTO work_center_report_photos
             (report_id, project_id, seq, file_name, file_id, file_url, captured_at, latitude, longitude, accuracy_m)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [entry.id, projectId, i + 1, photo.originalname, up.public_id, up.secure_url, meta.capturedAt,
            meta.latitude, meta.longitude, meta.accuracy]);
      }
      for (const resource of resources) {
        await client.query(
          `INSERT INTO work_center_report_resources
             (report_id, project_id, resource_type, name, quantity, unit, hours, assigned_member_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [entry.id, projectId, resource.type, resource.name, resource.quantity, resource.unit,
            resource.hours, resource.assignedMemberId]);
      }
      await client.query(
        `INSERT INTO work_center_task_history
           (task_id, project_id, actor_id, actor_role, action, detail)
         VALUES ($1,$2,$3,$4,'report_submitted',$5::jsonb)`,
        [taskId, projectId, userId, role, JSON.stringify({ reportId: entry.id })]);
      await client.query('COMMIT');
      uploads.keepAll();

      const blockedDependencies = (await pool.query(
        `SELECT d.depends_on_task_id, predecessor.title
         FROM work_center_task_dependencies d
         JOIN workspace_work_center predecessor ON predecessor.id = d.depends_on_task_id
         WHERE d.task_id = $1 AND predecessor.progress_pct < 100`,
        [taskId])).rows;
      if (blockedDependencies.length) {
        const warningText = `Earlier task${blockedDependencies.length === 1 ? '' : 's'} not yet complete: ${blockedDependencies.map((x) => x.title).join(', ')}.`;
        warning = warning ? `${warning} ${warningText}` : warningText;
      }

      await notifySafe(deps, {
        projectId, entityId: entry.id, entityType: 'work_center_progress',
        message: `A progress report on "${task.title}"${task.activity_title ? ` (${task.activity_title})` : ''} is waiting for validation.`,
        actorId: userId, actorRole: role, recipients: await leadersOf(deps, projectId, task.side),
      });
      return res.status(201).json({ success: true, entry, warning });
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      await uploads.discard();
      return fail(res, err, 'POST /api/work-center-progress:');
    } finally { if (client) client.release(); }
  });

  // Leader decision: approved, rejected, voided (an approved report, with a reason) or comment_only.
  app.put('/api/work-center-progress/:progressId/validate',
    authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
    let client;
    try {
      const { user_id: userId, role } = req.user;
      if (!isWCLeader(role)) throw new HttpError(403, 'Only leaders and PMs can validate progress entries.');
      const b = req.body || {};
      const projectId = parseInt(b.projectId, 10);
      if (!projectId) throw new HttpError(400, 'projectId is required.');
      const decision = b.validation_status || 'comment_only';
      if (!['approved', 'rejected', 'voided', 'comment_only'].includes(decision))
        throw new HttpError(400, 'validation_status must be approved, rejected, voided, or comment_only.');
      const notes = String(b.validation_notes || '').trim();
      if (['rejected', 'voided'].includes(decision) && !notes)
        throw new HttpError(400, decision === 'voided' ? 'A reason is required to void a report.' : 'A reason is required to reject a report.');
      if (!(await isMember(deps, projectId, userId, role))) throw new HttpError(403, 'You are not a member of this project.');

      client = await pool.connect();
      await client.query('BEGIN');
      const row = (await client.query(`
        SELECT p.*, w.side, w.title AS task_title, w.activity_id, w.status AS task_status,
               pe.status AS activity_status, pe.title AS activity_title,
               to_char(p.report_date, 'YYYY-MM-DD') AS day
        FROM workspace_work_center_progress p
        JOIN workspace_work_center w ON w.id = p.task_id
        LEFT JOIN planning_execution pe ON pe.id = w.activity_id
        WHERE p.id = $1 AND w.project_id = $2
        FOR UPDATE OF p`, [req.params.progressId, projectId])).rows[0];
      if (!row) throw new HttpError(404, 'Progress entry not found.');
      if (row.side !== wcSide(role)) throw new HttpError(403, 'You cannot validate progress from another side.');
      if (decision === 'approved') {
        const incomplete = await client.query(
          `SELECT c.title, COUNT(i.id)::int AS incomplete_count
           FROM work_center_checklists c
           JOIN work_center_checklist_items i ON i.checklist_id = c.id
           WHERE c.task_id = $1 AND c.project_id = $2 AND i.project_id = $2
             AND c.required_before_approval
             AND NOT i.is_complete
           GROUP BY c.id, c.title`,
          [row.task_id, projectId]);
        if (incomplete.rows.length) {
          const names = incomplete.rows.map((item) => item.title).join(', ');
          throw new HttpError(409, `Complete the required checklist items before approving: ${names}.`);
        }
      }

      if (decision === 'comment_only') {
        const u = await client.query(`UPDATE workspace_work_center_progress SET validation_notes = $1 WHERE id = $2 RETURNING *`, [notes, row.id]);
        await client.query(
          `INSERT INTO work_center_task_history
             (task_id, project_id, actor_id, actor_role, action, detail)
           VALUES ($1,$2,$3,$4,'report_note_added',$5::jsonb)`,
          [row.task_id, projectId, userId, role, JSON.stringify({ reportId: row.id })]);
        await client.query('COMMIT');
        return res.json({ success: true, entry: u.rows[0] });
      }

      if (decision === 'voided') {
        if (row.validation_status !== 'approved') throw new HttpError(409, 'Only an approved report can be voided.');
      } else if (row.validation_status !== 'pending') {
        throw new HttpError(409, row.validation_status === 'approved'
          ? 'This report is already approved. To correct it, void it with a reason.'
          : `This report is already ${row.validation_status}.`);
      }
      if (row.activity_status === 'closed' || row.task_status === 'closed')
        throw new HttpError(409, 'The activity or task is closed, so its reports can no longer change.');

      let updated;
      if (decision === 'voided') {
        updated = await client.query(
          `UPDATE workspace_work_center_progress
           SET validation_status = 'voided', voided_by_id = $1, voided_by_role = $2, voided_at = NOW(), void_reason = $3
           WHERE id = $4 RETURNING *`, [userId, role, notes, row.id]);
      } else {
        updated = await client.query(
          `UPDATE workspace_work_center_progress
           SET validation_status = $1, validation_notes = $2, validated_by = $3, validated_by_role = $4, validated_at = NOW()
           WHERE id = $5 RETURNING *`, [decision, notes, userId, role, row.id]);
      }
      await client.query(
        `INSERT INTO work_center_task_history
            (task_id, project_id, actor_id, actor_role, action, detail)
         VALUES ($1,$2,$3,$4,'report_decision',$5::jsonb)`,
        [row.task_id, projectId, userId, role, JSON.stringify({ reportId: row.id, decision })]);

      let result = null;
      if (decision !== 'rejected') {
        result = row.activity_id
          ? await recomputeActivity(client, row.activity_id, { dates: [row.day], actor: { id: userId, role } })
          : await recomputeStandaloneTask(client, row.task_id);
      }
      await client.query('COMMIT');

      const verb = { approved: 'approved', rejected: 'rejected', voided: 'voided' }[decision];
      await notifySafe(deps, {
        projectId, entityId: row.id, entityType: 'work_center_progress',
        message: `Your report on "${row.task_title}" (${row.report_date instanceof Date ? row.day : row.day}) was ${verb}${notes ? `: ${notes}` : '.'}`,
        actorId: userId, actorRole: role, recipients: [deps.flowKey('TeamMember', row.member_id)],
      });
      return res.json({
        success: true,
        entry: updated.rows[0],
        activity: row.activity_id && result ? { id: row.activity_id, progress_pct: result.progress_pct, status: result.status } : null,
        task: result && (row.activity_id ? result.tasks.find((t) => t.id === row.task_id) : result),
      });
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      return fail(res, err, 'PUT /api/work-center-progress/:progressId/validate:');
    } finally { if (client) client.release(); }
  });

  app.get('/api/planning-execution/closeout-report', authenticateToken, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const projectId = parseInt(req.query.projectId, 10);
      const audience = String(req.query.audience || 'side');
      if (!projectId) throw new HttpError(400, 'projectId is required.');
      if (audience !== 'side') throw new HttpError(400, 'audience must be side.');
      const reportSide = wcSide(role);
      if (!['Contractor', 'Consultant', 'Client', 'ContractorPM', 'ConsultantPM', 'ClientPM',
        'Contractor Project Manager', 'Consultant Project Manager', 'Client Project Manager'].includes(role)
        || !['Contractor', 'Consultant', 'Client'].includes(reportSide))
        throw new HttpError(403, 'Only project-side leaders and project managers can download this report.');
      if (!(await isMember(deps, projectId, userId, role))) throw new HttpError(403, 'You are not a member of this project.');

      const rows = (await pool.query(`
        SELECT pe.id AS activity_id, pe.title AS activity_title, pe.activity_type,
               pe.status,
               pe.status AS delay_status,
               to_char(pe.start_date, 'YYYY-MM-DD') AS start_date,
               to_char(pe.end_date, 'YYYY-MM-DD') AS end_date,
               to_char(pe.actual_end, 'YYYY-MM-DD') AS actual_end,
               pe.planned_quantity, pe.unit,
               pe.progress_pct AS activity_progress_pct,
               w.title AS task_title,
               w.weight_pct AS task_weight_pct,
               w.target_quantity AS task_target_quantity,
               w.progress_pct AS task_progress_pct,
               p.approved_report_count,
               p.approved_quantity,
               v.pending_verifications
        FROM planning_execution pe
        LEFT JOIN workspace_work_center w ON w.activity_id = pe.id AND w.side = $2
        LEFT JOIN LATERAL (
          SELECT COUNT(*)::int AS approved_report_count,
                 COALESCE(SUM(quantity_done), 0) AS approved_quantity
          FROM workspace_work_center_progress
          WHERE task_id = w.id AND validation_status = 'approved'
        ) p ON true
        LEFT JOIN LATERAL (
          SELECT COUNT(*)::int AS pending_verifications
          FROM activity_verifications
          WHERE activity_id = pe.id AND status = 'pending'
        ) v ON true
        WHERE pe.project_id = $1 AND pe.side = $2
        ORDER BY pe.start_date, pe.id, w.id`, [projectId, reportSide])).rows;
      const reportRows = rows.map((row) => ({
        ...row,
        calculated_delay_days: delayDays({
          plannedEnd: row.end_date,
          actualEnd: row.actual_end,
          status: row.delay_status,
        }),
      }));
      const headers = [
        'Activity ID', 'Activity', 'Type', 'Status', 'Start date', 'End date',
        'Planned quantity', 'Unit', 'Activity progress (%)', 'Calculated delay (days)', 'Task', 'Task share (%)',
        'Task target', 'Task progress (%)', 'Approved reports', 'Approved quantity',
        'Pending verifications',
      ];
      const quote = (value) => {
        let text = value == null ? '' : String(value);
        if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
        return `"${text.replace(/"/g, '""')}"`;
      };
      const csv = [headers, ...reportRows.map((row) => [
        row.activity_id, row.activity_title, row.activity_type, row.status, row.start_date, row.end_date,
        row.planned_quantity, row.unit, row.activity_progress_pct, row.calculated_delay_days, row.task_title, row.task_weight_pct,
        row.task_target_quantity, row.task_progress_pct, row.approved_report_count, row.approved_quantity,
        row.pending_verifications,
      ])].map((line) => line.map(quote).join(',')).join('\r\n');
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="oneproject-closeout-${reportSide.toLowerCase()}-${projectId}.csv"`);
      return res.status(200).send(`\uFEFF${csv}`);
    } catch (err) { return fail(res, err, 'GET /api/planning-execution/closeout-report:'); }
  });
}

return { recomputeActivity, registerReportRoutes };
})();
const queries = (function () {
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function fail(res, err, label) {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  console.error(label, err);
  return res.status(500).json({ error: 'Server error.' });
}

const validId = (value) => {
  const id = Number(value);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
};

async function isMember(deps, projectId, userId, role) {
  if (deps.isProjectMember) return deps.isProjectMember(projectId, userId, role);
  const result = await deps.pool.query(
    `SELECT 1 FROM assignments_view WHERE project_id = $1 AND role_id = $2 AND role = $3 LIMIT 1`,
    [projectId, userId, role]);
  return result.rows.length > 0;
}

function registerTaskQueryRoutes(app, deps) {
  const { pool, authenticateToken, requireProjectLifecycleWrite, wcSide, isWCLeader } = deps;
  const leaderOn = (role, side) => isWCLeader(role) && wcSide(role) === side;
  const notify = async (args) => {
    if (!deps.notify || !args.recipients?.length) return;
    try { await deps.notify(args); }
    catch (err) { console.error('[task query] notification failed (non-fatal):', err.message); }
  };

  async function loadTask(taskId, projectId) {
    const result = await pool.query(
      `SELECT id, project_id, side, status, assigned_members
       FROM workspace_work_center WHERE id = $1 AND project_id = $2`,
      [taskId, projectId]);
    return result.rows[0] || null;
  }

  async function requireProjectMember(projectId, userId, role) {
    if (!(await isMember(deps, projectId, userId, role)))
      throw new HttpError(403, 'You are not a member of this project.');
  }

  function isAssigned(task, userId) {
    const assigned = Array.isArray(task.assigned_members) ? task.assigned_members : [];
    return assigned.some((member) => String(member.id) === String(userId));
  }

  async function requireLeader(task, projectId, userId, role) {
    await requireProjectMember(projectId, userId, role);
    if (!leaderOn(role, task.side))
      throw new HttpError(403, 'Only a leader on this task’s side can manage queries.');
  }

  async function requireAssignedMember(task, projectId, userId, role) {
    await requireProjectMember(projectId, userId, role);
    if (role !== 'TeamMember' || !isAssigned(task, userId))
      throw new HttpError(403, 'Only a team member assigned to this task can answer its queries.');
    const assignment = await pool.query(
      `SELECT 1 FROM team_member_assignments
       WHERE project_id = $1 AND team_member_id = $2 AND assigned_part = $3 LIMIT 1`,
      [projectId, userId, task.side]);
    if (!assignment.rows.length)
      throw new HttpError(403, 'You are no longer assigned to this task’s project side.');
  }

  app.get('/api/work-center/:taskId/queries', authenticateToken, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const taskId = validId(req.params.taskId);
      const projectId = validId(req.query.projectId);
      if (!taskId || !projectId) throw new HttpError(400, 'taskId and projectId are required.');
      const task = await loadTask(taskId, projectId);
      if (!task) throw new HttpError(404, 'Task not found.');
      if (leaderOn(role, task.side)) {
        await requireLeader(task, projectId, userId, role);
      } else {
        await requireAssignedMember(task, projectId, userId, role);
      }

      const params = [taskId, projectId];
      let memberFilter = '';
      if (role === 'TeamMember') {
        params.push(userId);
        memberFilter = 'AND q.recipient_id = $3';
      }
      const result = await pool.query(
        `SELECT q.id, q.task_id, q.project_id, q.asked_by_id, q.asked_by_role,
                q.recipient_id, recipient.email AS recipient_email,
                q.report_id, to_char(p.report_date, 'YYYY-MM-DD') AS report_date,
                p.work_done AS report_work_done,
                q.question, q.answer, q.status, q.created_at,
                q.answered_at, q.answered_by_id, q.resolved_at,
                q.resolved_by_id, q.resolved_by_role
         FROM work_center_queries q
         LEFT JOIN team_members recipient ON recipient.id = q.recipient_id
         LEFT JOIN workspace_work_center_progress p ON p.id = q.report_id
         WHERE q.task_id = $1 AND q.project_id = $2 ${memberFilter}
         ORDER BY q.created_at DESC, q.id DESC`,
        params);
      return res.json({ queries: result.rows });
    } catch (err) { return fail(res, err, 'GET /api/work-center/:taskId/queries:'); }
  });

  app.post('/api/work-center/:taskId/queries', authenticateToken,
    requireProjectLifecycleWrite, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const taskId = validId(req.params.taskId);
      const projectId = validId(req.body?.projectId);
      const reportId = validId(req.body?.reportId);
      const question = String(req.body?.question || '').trim();
      if (!taskId || !projectId) throw new HttpError(400, 'taskId and projectId are required.');
      if (!reportId) throw new HttpError(400, 'Choose a progress report to ask about.');
      if (!question) throw new HttpError(400, 'Enter a question.');
      if (question.length > 5000) throw new HttpError(400, 'The question cannot exceed 5000 characters.');
      const task = await loadTask(taskId, projectId);
      if (!task) throw new HttpError(404, 'Task not found.');
      await requireLeader(task, projectId, userId, role);
      const report = (await pool.query(
        `SELECT id, task_id, member_id
         FROM workspace_work_center_progress
         WHERE id = $1 AND task_id = $2`,
        [reportId, taskId])).rows[0];
      if (!report) throw new HttpError(400, 'Choose a report submitted for this task.');
      const recipientId = Number(report.member_id);
      if (!isAssigned(task, recipientId))
        throw new HttpError(400, 'The report submitter is no longer assigned to this task.');
      const assignment = await pool.query(
        `SELECT 1 FROM team_member_assignments
         WHERE project_id = $1 AND team_member_id = $2 AND assigned_part = $3 LIMIT 1`,
        [projectId, recipientId, task.side]);
      if (!assignment.rows.length)
        throw new HttpError(400, 'The report submitter is no longer assigned to this task’s side.');

      const result = await pool.query(
        `INSERT INTO work_center_queries
           (task_id, project_id, asked_by_id, asked_by_role, recipient_id, report_id, question)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, task_id, project_id, asked_by_id, asked_by_role,
                   recipient_id, report_id, question, answer, status, created_at,
                   answered_at, answered_by_id, resolved_at, resolved_by_id, resolved_by_role`,
        [taskId, projectId, userId, role, recipientId, reportId, question]);
      await notify({
        projectId, entityId: result.rows[0].id, entityType: 'work_center_query',
        message: 'A task leader has asked you a question. Open the task report to respond.',
        actorId: userId, actorRole: role,
        recipients: [deps.flowKey('TeamMember', recipientId)],
      });
      return res.status(201).json({ query: result.rows[0] });
    } catch (err) { return fail(res, err, 'POST /api/work-center/:taskId/queries:'); }
  });

  app.put('/api/work-center/queries/:queryId/answer', authenticateToken,
    requireProjectLifecycleWrite, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const queryId = validId(req.params.queryId);
      const projectId = validId(req.body?.projectId);
      const answer = String(req.body?.answer || '').trim();
      if (!queryId || !projectId) throw new HttpError(400, 'queryId and projectId are required.');
      if (!answer) throw new HttpError(400, 'Enter an answer.');
      if (answer.length > 5000) throw new HttpError(400, 'The answer cannot exceed 5000 characters.');
      const query = (await pool.query(
        `SELECT q.*, w.side, w.assigned_members
         FROM work_center_queries q
         JOIN workspace_work_center w ON w.id = q.task_id
         WHERE q.id = $1 AND q.project_id = $2`,
        [queryId, projectId])).rows[0];
      if (!query) throw new HttpError(404, 'Query not found.');
      await requireAssignedMember(query, projectId, userId, role);
      if (String(query.recipient_id) !== String(userId))
        throw new HttpError(403, 'This query was addressed to another team member.');
      if (query.status !== 'open') throw new HttpError(409, 'Only an unanswered query can be answered.');
      const result = await pool.query(
        `UPDATE work_center_queries
         SET answer = $2, status = 'answered', answered_at = NOW(), answered_by_id = $3
         WHERE id = $1 AND status = 'open'
         RETURNING id, task_id, project_id, asked_by_id, asked_by_role,
                   recipient_id, report_id, question, answer, status, created_at,
                   answered_at, answered_by_id, resolved_at, resolved_by_id, resolved_by_role`,
        [queryId, answer, userId]);
      if (!result.rows.length) throw new HttpError(409, 'This query has already been answered.');
      await notify({
        projectId, entityId: queryId, entityType: 'work_center_query',
        message: 'A team member answered a question. Open the task report to review it.',
        actorId: userId, actorRole: role,
        recipients: [deps.flowKey(query.asked_by_role, query.asked_by_id)],
      });
      return res.json({ query: result.rows[0] });
    } catch (err) { return fail(res, err, 'PUT /api/work-center/queries/:queryId/answer:'); }
  });

  app.put('/api/work-center/queries/:queryId/resolve', authenticateToken,
    requireProjectLifecycleWrite, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const queryId = validId(req.params.queryId);
      const projectId = validId(req.body?.projectId);
      if (!queryId || !projectId) throw new HttpError(400, 'queryId and projectId are required.');
      const query = (await pool.query(
        `SELECT q.*, w.side FROM work_center_queries q
         JOIN workspace_work_center w ON w.id = q.task_id
         WHERE q.id = $1 AND q.project_id = $2`,
        [queryId, projectId])).rows[0];
      if (!query) throw new HttpError(404, 'Query not found.');
      await requireLeader(query, projectId, userId, role);
      if (query.status !== 'answered') throw new HttpError(409, 'Only an answered query can be resolved.');
      const result = await pool.query(
        `UPDATE work_center_queries
         SET status = 'resolved', resolved_at = NOW(), resolved_by_id = $2, resolved_by_role = $3
         WHERE id = $1 AND status = 'answered'
         RETURNING id, task_id, project_id, asked_by_id, asked_by_role,
                   recipient_id, report_id, question, answer, status, created_at,
                   answered_at, answered_by_id, resolved_at, resolved_by_id, resolved_by_role`,
        [queryId, userId, role]);
      if (!result.rows.length) throw new HttpError(409, 'This query is no longer awaiting resolution.');
      await notify({
        projectId, entityId: queryId, entityType: 'work_center_query',
        message: 'Your task question has been marked as resolved.',
        actorId: userId, actorRole: role,
        recipients: [deps.flowKey('TeamMember', query.recipient_id)],
      });
      return res.json({ query: result.rows[0] });
    } catch (err) { return fail(res, err, 'PUT /api/work-center/queries/:queryId/resolve:'); }
  });
}

return { registerTaskQueryRoutes };
})();

const taskCards = (function () {
  class HttpError extends Error {
    constructor(status, message) { super(message); this.status = status; }
  }
  const validId = (value) => {
    const id = Number(value);
    return Number.isSafeInteger(id) && id > 0 ? id : null;
  };
  const fail = (res, error, label) => {
    if (error instanceof HttpError) return res.status(error.status).json({ error: error.message });
    console.error(label, error);
    return res.status(500).json({ error: 'Server error.' });
  };

  function registerTaskCardRoutes(app, deps) {
    const { pool, authenticateToken, upload, requireProjectLifecycleWrite, cloudinary, wcSide, isWCLeader } = deps;
    async function isProjectMember(projectId, userId, role) {
      if (deps.isProjectMember) return deps.isProjectMember(projectId, userId, role);
      const result = await pool.query(
        `SELECT 1 FROM assignments_view
         WHERE project_id = $1 AND role_id = $2 AND role = $3 LIMIT 1`,
        [projectId, userId, role]);
      return result.rows.length > 0;
    }
    async function sideLeaders(projectId, side) {
      if (deps.leadersOf) return deps.leadersOf(projectId, side);
      if (!deps.sideRoles) return [];
      const result = await pool.query(
        `SELECT role, role_id FROM assignments_view
         WHERE project_id = $1 AND role = ANY($2::text[])`,
        [projectId, deps.sideRoles(side)]);
      return result.rows.map((row) => deps.flowKey(row.role, row.role_id));
    }
    const member = (task, userId) => {
      const assigned = Array.isArray(task.assigned_members) ? task.assigned_members : [];
      return assigned.some((item) => String(item.id) === String(userId));
    };
    async function loadTask(taskId, projectId) {
      return (await pool.query(
        `SELECT * FROM workspace_work_center WHERE id = $1 AND project_id = $2`,
        [taskId, projectId])).rows[0] || null;
    }
    async function authorize(task, projectId, userId, role, leadersOnly = false) {
      if (!task) throw new HttpError(404, 'Task not found.');
      if (!(await isProjectMember(projectId, userId, role)))
        throw new HttpError(403, 'You are not a member of this project.');
      if (isWCLeader(role) && wcSide(role) === task.side) return 'leader';
      if (!leadersOnly && role === 'TeamMember' && member(task, userId)) {
        const sideAssignment = await pool.query(
          `SELECT 1 FROM team_member_assignments
           WHERE project_id = $1 AND team_member_id = $2 AND assigned_part = $3 LIMIT 1`,
          [projectId, userId, task.side]);
        if (sideAssignment.rows.length) return 'member';
      }
      throw new HttpError(403, leadersOnly
        ? 'Only a leader on this task’s side can manage these details.'
        : 'You are not assigned to this task.');
    }
    async function audit(task, projectId, userId, role, action, detail = {}) {
      await pool.query(
        `INSERT INTO work_center_task_history
           (task_id, project_id, actor_id, actor_role, action, detail)
         VALUES ($1,$2,$3,$4,$5,$6::jsonb)`,
        [task.id, projectId, userId, role, action, JSON.stringify(detail)]);
    }
    async function notifyTask(task, projectId, userId, role, message) {
      if (!deps.notify) return;
      const recipients = [];
      for (const assigned of Array.isArray(task.assigned_members) ? task.assigned_members : []) {
        if (String(assigned.id) !== String(userId)) recipients.push(deps.flowKey('TeamMember', assigned.id));
      }
      const leaders = await sideLeaders(projectId, task.side);
      recipients.push(...leaders.filter((recipient) =>
        !(String(recipient.id) === String(userId) && recipient.role === role)));
      const unique = [...new Map(recipients.map((recipient) =>
        [`${recipient.role}:${recipient.id}`, recipient])).values()];
      if (unique.length) {
        try {
          await deps.notify({
            projectId, entityId: task.id, entityType: 'work_center_task',
            message, actorId: userId, actorRole: role, recipients: unique,
          });
        } catch (error) {
          console.error('[task card] notification failed (non-fatal):', error.message);
        }
      }
    }
    const bodyId = (body, key) => validId(body?.[key]);

    app.get('/api/work-center/:taskId/card', authenticateToken, async (req, res) => {
      try {
        const taskId = validId(req.params.taskId), projectId = validId(req.query.projectId);
        if (!taskId || !projectId) throw new HttpError(400, 'taskId and projectId are required.');
        const task = await loadTask(taskId, projectId);
        await authorize(task, projectId, req.user.user_id, req.user.role);
        const [comments, history, checklists, links, dependencies, attachments] = await Promise.all([
          pool.query(
            `SELECT id, author_id, author_role, body, created_at
             FROM work_center_task_comments WHERE task_id = $1 AND project_id = $2
             ORDER BY created_at, id`, [taskId, projectId]),
          pool.query(
            `SELECT id, actor_id, actor_role, action, detail, created_at
             FROM work_center_task_history WHERE task_id = $1 AND project_id = $2
             ORDER BY created_at DESC, id DESC LIMIT 100`, [taskId, projectId]),
          pool.query(
            `SELECT c.id, c.title, c.required_before_approval,
                    COALESCE(json_agg(json_build_object(
                      'id', i.id, 'title', i.title, 'assigned_member_id', i.assigned_member_id,
                      'is_complete', i.is_complete, 'completed_at', i.completed_at
                    ) ORDER BY i.seq, i.id) FILTER (WHERE i.id IS NOT NULL), '[]'::json) AS items
             FROM work_center_checklists c LEFT JOIN work_center_checklist_items i ON i.checklist_id = c.id
             WHERE c.task_id = $1 AND c.project_id = $2
             GROUP BY c.id ORDER BY c.id`, [taskId, projectId]),
          pool.query(
            `SELECT id, link_type, target_id, title, url, created_at
             FROM work_center_task_links WHERE task_id = $1 AND project_id = $2 ORDER BY id`,
            [taskId, projectId]),
          pool.query(
            `SELECT d.depends_on_task_id AS id, w.title, w.progress_pct
             FROM work_center_task_dependencies d
             JOIN workspace_work_center w ON w.id = d.depends_on_task_id
             WHERE d.task_id = $1 AND d.project_id = $2 ORDER BY w.id`,
            [taskId, projectId]),
          pool.query(
            `SELECT id, file_name, file_id, file_url, mime_type, created_at
             FROM card_attachments
             WHERE project_id = $1 AND entity_type = 'work_center_task' AND entity_id = $2
             ORDER BY created_at, id`, [projectId, taskId]),
        ]);
        let visibleLinks = links.rows;
        if (req.user.role === 'TeamMember') {
          const accessChecks = await Promise.all(visibleLinks.map(async (link) => {
            if (link.link_type === 'task') {
              const linkedTask = await loadTask(validId(link.target_id), projectId);
              return Boolean(linkedTask && linkedTask.side === task.side && member(linkedTask, req.user.user_id));
            }
            if (link.link_type === 'query') {
              const match = /^(\d+):(\d+)$/.exec(String(link.target_id || ''));
              if (!match) return false;
              const linked = (await pool.query(
                `SELECT 1 FROM work_center_queries q
                 JOIN workspace_work_center w ON w.id = q.task_id
                 WHERE q.task_id = $1 AND q.id = $2 AND q.project_id = $3
                   AND q.recipient_id = $4 AND w.side = $5
                   AND EXISTS (SELECT 1 FROM jsonb_array_elements(w.assigned_members) am
                               WHERE am->>'id' = $4::text)`,
                [Number(match[1]), Number(match[2]), projectId, req.user.user_id, task.side]));
              return linked.rows.length > 0;
            }
            return true;
          }));
          visibleLinks = visibleLinks.filter((_link, index) => accessChecks[index]);
        }
        return res.json({
          location: {
            block: task.location_block, floor: task.location_floor, zone: task.location_zone,
            grid: task.location_grid, drawing: task.location_drawing,
          },
          comments: comments.rows, history: history.rows, checklists: checklists.rows,
          links: visibleLinks, dependencies: dependencies.rows, attachments: attachments.rows,
        });
      } catch (error) { return fail(res, error, 'GET /api/work-center/:taskId/card:'); }
    });

    app.post('/api/work-center/:taskId/attachments', authenticateToken,
      upload.array('attachments', 20), requireProjectLifecycleWrite, async (req, res) => {
      const uploads = createCloudinaryUploadTracker(deps);
      try {
        const taskId = validId(req.params.taskId), projectId = bodyId(req.body, 'projectId');
        if (!taskId || !projectId) throw new HttpError(400, 'taskId and projectId are required.');
        if (!req.files?.length) throw new HttpError(400, 'Choose at least one attachment.');
        const task = await loadTask(taskId, projectId);
        await authorize(task, projectId, req.user.user_id, req.user.role, true);
        const saved = [];
        for (const file of req.files) {
          const uploaded = await uploads.upload(file.buffer, file.originalname, 'work_center/attachments');
          const attachment = (await pool.query(
            `INSERT INTO card_attachments
               (project_id, entity_type, entity_id, file_name, file_id, file_url, mime_type,
                resource_type, uploaded_by_id, uploaded_by_role)
             VALUES ($1,'work_center_task',$2,$3,$4,$5,$6,$7,$8,$9)
             RETURNING id, file_name, file_id, file_url, mime_type, created_at`,
            [projectId, taskId, file.originalname, uploaded.public_id, uploaded.secure_url,
              file.mimetype || null, uploaded.resource_type || 'raw', req.user.user_id, req.user.role])).rows[0];
          saved.push(attachment);
          uploads.keep(uploaded);
        }
        await audit(task, projectId, req.user.user_id, req.user.role, 'attachments_added',
          { attachment_ids: saved.map((item) => item.id) });
        return res.status(201).json({ attachments: saved });
      } catch (error) {
        await uploads.discard();
        return fail(res, error, 'POST /api/work-center/:taskId/attachments:');
      }
    });

    app.delete('/api/work-center/:taskId/attachments/:attachmentId', authenticateToken,
      requireProjectLifecycleWrite, async (req, res) => {
      try {
        const taskId = validId(req.params.taskId), attachmentId = validId(req.params.attachmentId);
        const projectId = bodyId(req.body, 'projectId') || validId(req.query.projectId);
        if (!taskId || !attachmentId || !projectId)
          throw new HttpError(400, 'taskId, projectId and attachmentId are required.');
        const task = await loadTask(taskId, projectId);
        await authorize(task, projectId, req.user.user_id, req.user.role, true);
        const attachment = (await pool.query(
          `SELECT id, file_id, resource_type FROM card_attachments
           WHERE id = $1 AND project_id = $2 AND entity_type = 'work_center_task' AND entity_id = $3`,
          [attachmentId, projectId, taskId])).rows[0];
        if (!attachment) throw new HttpError(404, 'Attachment not found.');
        if (!cloudinary?.uploader) throw new HttpError(503, 'File storage is unavailable.');
        const result = await cloudinary.uploader.destroy(attachment.file_id, {
          resource_type: attachment.resource_type || 'raw',
        });
        if (!['ok', 'not found'].includes(result?.result))
          throw new HttpError(502, 'The file could not be removed from storage.');
        await pool.query(`DELETE FROM card_attachments WHERE id = $1`, [attachmentId]);
        await audit(task, projectId, req.user.user_id, req.user.role, 'attachment_removed',
          { attachment_id: attachmentId });
        return res.json({ success: true });
      } catch (error) { return fail(res, error, 'DELETE /api/work-center/:taskId/attachments:'); }
    });

    app.get('/api/work-center/:taskId/link-options', authenticateToken, async (req, res) => {
      try {
        const taskId = validId(req.params.taskId), projectId = validId(req.query.projectId);
        if (!taskId || !projectId) throw new HttpError(400, 'taskId and projectId are required.');
        const task = await loadTask(taskId, projectId);
        await authorize(task, projectId, req.user.user_id, req.user.role, true);

        const [tasks, queries] = await Promise.all([
          pool.query(
            `SELECT id, title FROM workspace_work_center
             WHERE project_id = $1 AND side = $2 AND id <> $3
             ORDER BY lower(title), id LIMIT 200`,
            [projectId, task.side, taskId]),
          pool.query(
            `SELECT q.id, q.task_id, q.question, w.title AS task_title
             FROM work_center_queries q
             JOIN workspace_work_center w ON w.id = q.task_id
             WHERE q.project_id = $1 AND w.side = $2
             ORDER BY q.created_at DESC, q.id DESC LIMIT 200`,
            [projectId, task.side]),
        ]);
        const recordTables = [
          ['contractual_records', 'Contractual'],
          ['administrative_records', 'Administrative'],
          ['safety_records', 'Safety'],
          ['operational_records', 'Operational'],
          ['financial_records', 'Financial'],
        ];
        const records = [];
        for (const [table, label] of recordTables) {
          const result = await pool.query(
            `SELECT id, title FROM ${table} WHERE project_id = $1 ORDER BY issued_date DESC, id DESC LIMIT 100`,
            [projectId]);
          records.push(...result.rows.map((row) => ({
            targetId: `${table}:${row.id}`,
            title: `${label}: ${row.title}`,
          })));
        }
        const drawingRows = await pool.query(
          `SELECT id, title FROM operational_records
           WHERE project_id = $1
             AND (record_kind::text ILIKE '%drawing%' OR title ILIKE '%drawing%')
           ORDER BY issued_date DESC, id DESC LIMIT 100`,
          [projectId]);
        return res.json({
          tasks: tasks.rows.map((row) => ({ targetId: String(row.id), title: row.title })),
          queries: queries.rows.map((row) => ({
            targetId: `${row.task_id}:${row.id}`,
            title: `${row.task_title}: ${row.question}`,
          })),
          records,
          drawings: drawingRows.rows.map((row) => ({
            targetId: `operational_records:${row.id}`,
            title: row.title,
          })),
        });
      } catch (error) { return fail(res, error, 'GET /api/work-center/:taskId/link-options:'); }
    });

    app.post('/api/work-center/:taskId/comments', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
      try {
        const taskId = validId(req.params.taskId), projectId = bodyId(req.body, 'projectId');
        const body = String(req.body?.body || '').trim();
        if (!taskId || !projectId) throw new HttpError(400, 'taskId and projectId are required.');
        if (!body || body.length > 5000) throw new HttpError(400, 'Comments must be between 1 and 5000 characters.');
        const task = await loadTask(taskId, projectId);
        const access = await authorize(task, projectId, req.user.user_id, req.user.role);
        const result = await pool.query(
          `INSERT INTO work_center_task_comments (task_id, project_id, author_id, author_role, body)
           VALUES ($1,$2,$3,$4,$5) RETURNING id, author_id, author_role, body, created_at`,
          [taskId, projectId, req.user.user_id, req.user.role, body]);
        await audit(task, projectId, req.user.user_id, req.user.role, 'comment_added');
        await notifyTask(task, projectId, req.user.user_id, req.user.role,
          `${access === 'leader' ? 'A task leader' : 'A team member'} added a comment to "${task.title}".`);
        return res.status(201).json({ comment: result.rows[0] });
      } catch (error) { return fail(res, error, 'POST /api/work-center/:taskId/comments:'); }
    });

    app.patch('/api/work-center/:taskId/location', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
      try {
        const taskId = validId(req.params.taskId), projectId = bodyId(req.body, 'projectId');
        if (!taskId || !projectId) throw new HttpError(400, 'taskId and projectId are required.');
        const task = await loadTask(taskId, projectId);
        await authorize(task, projectId, req.user.user_id, req.user.role, true);
        const values = ['block', 'floor', 'zone', 'grid', 'drawing'].map((key) => {
          const value = String(req.body?.[key] || '').trim();
          if (value.length > 150) throw new HttpError(400, `Location ${key} cannot exceed 150 characters.`);
          return value || null;
        });
        const updated = await pool.query(
          `UPDATE workspace_work_center SET
             location_block=$1, location_floor=$2, location_zone=$3, location_grid=$4,
             location_drawing=$5, updated_at=NOW()
           WHERE id=$6 AND project_id=$7
           RETURNING location_block AS block, location_floor AS floor, location_zone AS zone,
                     location_grid AS grid, location_drawing AS drawing`,
          [...values, taskId, projectId]);
        await audit(task, projectId, req.user.user_id, req.user.role, 'location_updated', updated.rows[0]);
        return res.json({ location: updated.rows[0] });
      } catch (error) { return fail(res, error, 'PATCH /api/work-center/:taskId/location:'); }
    });

    app.post('/api/work-center/:taskId/checklists', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
      let client;
      try {
        const taskId = validId(req.params.taskId), projectId = bodyId(req.body, 'projectId');
        const title = String(req.body?.title || '').trim();
        const items = req.body?.items;
        if (!taskId || !projectId) throw new HttpError(400, 'taskId and projectId are required.');
        if (!title || title.length > 200 || !Array.isArray(items) || items.length > 100)
          throw new HttpError(400, 'A checklist needs a title and no more than 100 items.');
        if (items.some((item) => !String(item?.title || '').trim() || String(item.title).trim().length > 500))
          throw new HttpError(400, 'Each checklist item needs a title of 1 to 500 characters.');
        const task = await loadTask(taskId, projectId);
        await authorize(task, projectId, req.user.user_id, req.user.role, true);
        const assignedIds = new Set((Array.isArray(task.assigned_members) ? task.assigned_members : []).map((item) => String(item.id)));
        for (const item of items) {
          if (item.assignedMemberId != null && !assignedIds.has(String(item.assignedMemberId)))
            throw new HttpError(400, 'Checklist assignments must be selected from members assigned to this task.');
        }
        client = await pool.connect();
        await client.query('BEGIN');
        const checklist = (await client.query(
          `INSERT INTO work_center_checklists
             (task_id, project_id, title, required_before_approval, created_by_id, created_by_role)
           VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, title, required_before_approval`,
          [taskId, projectId, title, Boolean(req.body.requiredBeforeApproval), req.user.user_id, req.user.role])).rows[0];
        for (let seq = 0; seq < items.length; seq++) {
          const item = items[seq];
          await client.query(
            `INSERT INTO work_center_checklist_items
               (checklist_id, project_id, title, assigned_member_id, seq)
             VALUES ($1,$2,$3,$4,$5)`,
            [checklist.id, projectId, String(item.title).trim(), item.assignedMemberId || null, seq]);
        }
        await client.query('COMMIT');
        await audit(task, projectId, req.user.user_id, req.user.role, 'checklist_created', { title });
        return res.status(201).json({ checklist });
      } catch (error) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        return fail(res, error, 'POST /api/work-center/:taskId/checklists:');
      } finally { if (client) client.release(); }
    });

    app.patch('/api/work-center/:taskId/checklist-items/:itemId', authenticateToken,
      requireProjectLifecycleWrite, async (req, res) => {
      try {
        const taskId = validId(req.params.taskId), itemId = validId(req.params.itemId);
        const projectId = bodyId(req.body, 'projectId');
        if (!taskId || !itemId || !projectId) throw new HttpError(400, 'taskId, itemId and projectId are required.');
        const task = await loadTask(taskId, projectId);
        const access = await authorize(task, projectId, req.user.user_id, req.user.role);
        const row = (await pool.query(
          `SELECT i.* FROM work_center_checklist_items i
           JOIN work_center_checklists c ON c.id = i.checklist_id
           WHERE i.id=$1 AND c.task_id=$2 AND i.project_id=$3`,
          [itemId, taskId, projectId])).rows[0];
        if (!row) throw new HttpError(404, 'Checklist item not found.');
        if (access === 'member' && row.assigned_member_id != null
          && String(row.assigned_member_id) !== String(req.user.user_id))
          throw new HttpError(403, 'This checklist item is assigned to another member.');
        const complete = Boolean(req.body?.isComplete);
        const updated = await pool.query(
          `UPDATE work_center_checklist_items
           SET is_complete=$1, completed_by_id=CASE WHEN $1 THEN $2 ELSE NULL END,
               completed_by_role=CASE WHEN $1 THEN $3 ELSE NULL END,
               completed_at=CASE WHEN $1 THEN NOW() ELSE NULL END
           WHERE id=$4 RETURNING id, title, is_complete, completed_at`,
          [complete, req.user.user_id, req.user.role, itemId]);
        await audit(task, projectId, req.user.user_id, req.user.role, 'checklist_item_updated',
          { itemId, isComplete: complete });
        return res.json({ item: updated.rows[0] });
      } catch (error) { return fail(res, error, 'PATCH /api/work-center/:taskId/checklist-items/:itemId:'); }
    });

    app.post('/api/work-center/:taskId/links', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
      try {
        const taskId = validId(req.params.taskId), projectId = bodyId(req.body, 'projectId');
        const type = String(req.body?.type || '');
        const targetId = type === 'url' ? null : String(req.body?.targetId || '').trim() || null;
        const url = String(req.body?.url || '').trim() || null;
        if (!taskId || !projectId) throw new HttpError(400, 'taskId and projectId are required.');
        if (!['drawing', 'record', 'query', 'task', 'url'].includes(type))
          throw new HttpError(400, 'Choose a link type and enter a title.');
        const task = await loadTask(taskId, projectId);
        await authorize(task, projectId, req.user.user_id, req.user.role, true);
        let title = '';
        if (type === 'url') {
          title = String(req.body?.title || '').trim();
          if (!title || title.length > 300 || !url || !/^https?:\/\//i.test(url))
            throw new HttpError(400, 'Enter a title and a valid http or https address.');
        } else if (type === 'task') {
          const linkedTaskId = validId(targetId);
          if (!linkedTaskId || linkedTaskId === taskId)
            throw new HttpError(400, 'Choose another task in this project.');
          const linkedTask = await loadTask(linkedTaskId, projectId);
          if (!linkedTask || linkedTask.side !== task.side)
            throw new HttpError(400, 'Choose a task on the same project side.');
          title = linkedTask.title;
        } else if (type === 'query') {
          const match = /^(\d+):(\d+)$/.exec(targetId || '');
          if (!match) throw new HttpError(400, 'Choose an existing task question.');
          const linkedTaskId = validId(match[1]), queryId = validId(match[2]);
          if (!linkedTaskId || !queryId) throw new HttpError(400, 'Choose an existing task question.');
          const linkedQuery = (await pool.query(
            `SELECT q.question, w.title AS task_title
             FROM work_center_queries q
             JOIN workspace_work_center w ON w.id = q.task_id
             WHERE q.id = $1 AND q.task_id = $2 AND q.project_id = $3 AND w.side = $4`,
            [queryId, linkedTaskId, projectId, task.side])).rows[0];
          if (!linkedQuery) throw new HttpError(400, 'Choose a question from this project side.');
          title = `${linkedQuery.task_title}: ${linkedQuery.question}`;
        } else {
          const match = /^([a-z_]+):(\d+)$/.exec(targetId || '');
          const recordTables = new Set([
            'contractual_records', 'administrative_records', 'safety_records',
            'operational_records', 'financial_records',
          ]);
          if (!match || !recordTables.has(match[1]) || (type === 'drawing' && match[1] !== 'operational_records'))
            throw new HttpError(400, 'Choose an existing project record.');
          const recordId = validId(match[2]);
          if (!recordId) throw new HttpError(400, 'Choose an existing project record.');
          const recordSql = type === 'drawing'
            ? `SELECT title FROM operational_records
               WHERE id = $1 AND project_id = $2
                 AND (record_kind::text ILIKE '%drawing%' OR title ILIKE '%drawing%')`
            : `SELECT title FROM ${match[1]} WHERE id = $1 AND project_id = $2`;
          const record = (await pool.query(recordSql, [recordId, projectId])).rows[0];
          if (!record) throw new HttpError(400, 'That record is not available in this project.');
          title = record.title;
        }
        const result = await pool.query(
          `INSERT INTO work_center_task_links
             (task_id, project_id, link_type, target_id, title, url, created_by_id, created_by_role)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id, link_type, target_id, title, url`,
          [taskId, projectId, type, targetId, title, url, req.user.user_id, req.user.role]);
        await audit(task, projectId, req.user.user_id, req.user.role, 'link_added', { title, type });
        return res.status(201).json({ link: result.rows[0] });
      } catch (error) { return fail(res, error, 'POST /api/work-center/:taskId/links:'); }
    });

    app.post('/api/work-center/:taskId/dependencies', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
      try {
        const taskId = validId(req.params.taskId), projectId = bodyId(req.body, 'projectId');
        const predecessorId = bodyId(req.body, 'dependsOnTaskId');
        if (!taskId || !projectId || !predecessorId) throw new HttpError(400, 'Task, project and earlier task are required.');
        const task = await loadTask(taskId, projectId);
        await authorize(task, projectId, req.user.user_id, req.user.role, true);
        const predecessor = await loadTask(predecessorId, projectId);
        if (!predecessor || predecessor.side !== task.side)
          throw new HttpError(400, 'Dependencies must link tasks on the same project side.');
        const cycle = await pool.query(
          `WITH RECURSIVE successors(id) AS (
             SELECT task_id FROM work_center_task_dependencies WHERE depends_on_task_id = $1
             UNION
             SELECT d.task_id FROM work_center_task_dependencies d JOIN successors s ON d.depends_on_task_id = s.id
           ) SELECT 1 FROM successors WHERE id = $2 LIMIT 1`,
          [taskId, predecessorId]);
        if (cycle.rows.length) throw new HttpError(409, 'This dependency would create a cycle.');
        await pool.query(
          `INSERT INTO work_center_task_dependencies
             (task_id, depends_on_task_id, project_id, created_by_id, created_by_role)
           VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
          [taskId, predecessorId, projectId, req.user.user_id, req.user.role]);
        await audit(task, projectId, req.user.user_id, req.user.role, 'dependency_added',
          { dependsOnTaskId: predecessorId, title: predecessor.title });
        return res.status(201).json({ success: true, warningOnly: true });
      } catch (error) { return fail(res, error, 'POST /api/work-center/:taskId/dependencies:'); }
    });

    app.get('/api/work-center/templates', authenticateToken, async (req, res) => {
      try {
        const projectId = validId(req.query.projectId);
        if (!projectId) throw new HttpError(400, 'projectId is required.');
        if (!(await isProjectMember(projectId, req.user.user_id, req.user.role)))
          throw new HttpError(403, 'You are not a member of this project.');
        const side = wcSide(req.user.role);
        const result = await pool.query(
          `SELECT id, side, name, task_data, created_at FROM work_center_task_templates
           WHERE project_id=$1 AND side=$2 ORDER BY lower(name), id`, [projectId, side]);
        return res.json({ templates: result.rows });
      } catch (error) { return fail(res, error, 'GET /api/work-center/templates:'); }
    });

    app.post('/api/work-center/templates', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
      try {
        const projectId = bodyId(req.body, 'projectId'), taskId = bodyId(req.body, 'taskId');
        const name = String(req.body?.name || '').trim();
        if (!projectId || !taskId || !name || name.length > 200)
          throw new HttpError(400, 'projectId, taskId and a template name are required.');
        const task = await loadTask(taskId, projectId);
        await authorize(task, projectId, req.user.user_id, req.user.role, true);
        const stages = (await pool.query(
          `SELECT title, weight_pct, is_hold_point FROM task_stages
           WHERE task_id = $1 ORDER BY seq`,
          [taskId])).rows;
        const measure = (await pool.query(
          `SELECT COALESCE(w.activity_type, pe.activity_type) AS activity_type,
                  COALESCE(w.standalone_unit, pe.unit) AS activity_unit
           FROM workspace_work_center w
           LEFT JOIN planning_execution pe ON pe.id = w.activity_id
           WHERE w.id = $1`,
          [taskId])).rows[0];
        const taskData = {
          title: task.title, description: task.description, work_package: task.work_package,
          activity_type: measure.activity_type, target_quantity: task.target_quantity,
          activity_unit: measure.activity_unit, weight_pct: task.weight_pct,
          stages,
          assigned_members: Array.isArray(task.assigned_members) ? task.assigned_members : [],
          location: {
            block: task.location_block, floor: task.location_floor, zone: task.location_zone,
            grid: task.location_grid, drawing: task.location_drawing,
          },
        };
        const template = await pool.query(
          `INSERT INTO work_center_task_templates
             (project_id, side, name, created_by_id, created_by_role, task_data)
           VALUES ($1,$2,$3,$4,$5,$6::jsonb)
           ON CONFLICT (project_id, side, lower(name))
           DO UPDATE SET task_data=EXCLUDED.task_data, created_by_id=EXCLUDED.created_by_id,
             created_by_role=EXCLUDED.created_by_role, created_at=NOW()
           RETURNING id, name, side, task_data`,
          [projectId, task.side, name, req.user.user_id, req.user.role, JSON.stringify(taskData)]);
        return res.status(201).json({ template: template.rows[0] });
      } catch (error) { return fail(res, error, 'POST /api/work-center/templates:'); }
    });
  }

  return { registerTaskCardRoutes };
})();

export const { recomputeActivity, registerReportRoutes } = reports;
export const { registerTaskQueryRoutes } = queries;
export const { registerTaskCardRoutes } = taskCards;
