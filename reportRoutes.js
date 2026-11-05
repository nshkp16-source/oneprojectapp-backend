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
//   import { registerReportRoutes } from './reportRoutes.js';
//   registerReportRoutes(app, {
//     pool, authenticateToken, upload, requireProjectLifecycleWrite, scheduleCloudinaryUpload,
//     wcSide, isWCLeader, sideRoles,
//     notify: ({ projectId, entityId, entityType, message, actorId, actorRole, recipients }) =>
//       notifyRecordUsers({ projectId, recordId: entityId, table: entityType, message, actorId, actorRole, recipients }),
//     flowKey,
//   });

import {
  taskProgress, activityProgress, buildDailyEntry, checkPercentageReport, stageUnlocked, delayDays,
} from './progressRules.js';

const DAY = (v) => String(v || '').slice(0, 10);
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

// ── recompute ────────────────────────────────────────────────────────────────

/**
 * Recompute one activity from its approved reports: task progress and status, stage completion,
 * activity claimed progress and status, actual start, and the daily execution entries for `dates`.
 * Call it inside the caller's transaction.
 */
export async function recomputeActivity(client, activityId, { dates = [], actor = null } = {}) {
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

export function registerReportRoutes(app, deps) {
  const { pool, authenticateToken, upload, requireProjectLifecycleWrite, scheduleCloudinaryUpload, wcSide, isWCLeader } = deps;

  // Member report. What the member fills in depends on the activity type:
  //   quantity: quantityDone   count: quantityDone and quantityFailed   stages: stageId   percentage: progressPct
  app.post('/api/work-center-progress', authenticateToken,
    upload.single('attachment'), requireProjectLifecycleWrite, async (req, res) => {
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
      if (task.status === 'closed' || task.activity_status === 'closed') throw new HttpError(409, 'This task is closed. Reports can no longer be added.');

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
      if (req.file) {
        const up = await scheduleCloudinaryUpload(req.file.buffer, req.file.originalname, 'work_center/progress');
        file = { name: req.file.originalname, id: up.public_id, url: up.secure_url };
      }

      const entry = (await pool.query(`
        INSERT INTO workspace_work_center_progress
          (task_id, report_date, member_id, member_role, work_done, manpower, equipment, materials,
           progress_pct, issues, notes, attachment_name, attachment_id, attachment_url,
           quantity_done, quantity_failed, stage_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING *`,
        [taskId, b.reportDate, userId, role, String(b.workDone).trim(), b.manpower || '', b.equipment || '', b.materials || '',
         stored, b.issues || '', b.notes || '', file.name, file.id, file.url, quantityDone, quantityFailed, stageId])).rows[0];

      await notifySafe(deps, {
        projectId, entityId: entry.id, entityType: 'work_center_progress',
        message: `A progress report on "${task.title}"${task.activity_title ? ` (${task.activity_title})` : ''} is waiting for validation.`,
        actorId: userId, actorRole: role, recipients: await leadersOf(deps, projectId, task.side),
      });
      return res.status(201).json({ success: true, entry, warning });
    } catch (err) { return fail(res, err, 'POST /api/work-center-progress:'); }
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

      if (decision === 'comment_only') {
        const u = await client.query(`UPDATE workspace_work_center_progress SET validation_notes = $1 WHERE id = $2 RETURNING *`, [notes, row.id]);
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
