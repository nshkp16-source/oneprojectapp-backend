// Activity and milestone routes share milestone linking and progress synchronization.
import {
  ACTIVITY_TYPES, splitEqual, weightsValid, rebalanceForNew, rebalanceAfterRemoval, activityProgress,
  milestoneDerivedProgress, milestoneCoverage, effectiveMilestoneProgress, delayDays,
  checkOverride, canCompleteMilestone, visibleProgress,
} from './progressRules.js';
import { createCloudinaryUploadTracker } from './cloudinaryUploadTracker.js';
import { buildActivityReport, shapeReportForViewer } from './activityReport.js';

const activity = (function () {
// Routes for activities and their tasks: create an activity together with its tasks, add a task later
// with a weight preview, and keep a linked schedule milestone in step.
//
// Wiring in server.js (after the other planning-execution routes, so these win over the old create route):
//
//   import { registerActivityRoutes } from './planningRoutes.js';
//   registerActivityRoutes(app, {
//     pool, authenticateToken, upload, requireProjectLifecycleWrite, scheduleCloudinaryUpload,
//     wcSide, isWCLeader,
//     notify: ({ projectId, entityId, entityType, message, actorId, actorRole, recipients }) =>
//       notifyRecordUsers({ projectId, recordId: entityId, table: entityType, message, actorId, actorRole, recipients }),
//     flowKey,
//   });
//
// All rules (weights, defaults, caps) come from progressRules.js. This file only does I/O.


const isDate = (v) => /^\d{4}-\d{2}-\d{2}$/.test(String(v || '')) && !Number.isNaN(Date.parse(String(v)));
// pg returns DATE columns as local-midnight Date objects: format them without shifting the day
const dateOnly = (v) => {
  if (v instanceof Date) return `${v.getFullYear()}-${String(v.getMonth() + 1).padStart(2, '0')}-${String(v.getDate()).padStart(2, '0')}`;
  return String(v || '').slice(0, 10);
};
const round3 = (x) => Math.round((Number(x) + Number.EPSILON) * 1000) / 1000;

const DEFAULT_TYPE = { Contractor: 'quantity', Consultant: 'count', Client: 'stages' };

const MILESTONE = {
  baseline:   { table: 'milestones',            col: 'baseline_milestone_id',   entries: 'milestone_progress_entries',            entryFk: 'milestone_id' },
  additional: { table: 'additional_milestones', col: 'additional_milestone_id', entries: 'additional_milestone_progress_entries', entryFk: 'additional_milestone_id' },
};

class HttpError extends Error {
  constructor(status, message, extra = {}) { super(message); this.status = status; this.extra = extra; }
}

function parseJson(value, fallback, label) {
  if (value == null || value === '') return fallback;
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value); } catch { throw new HttpError(400, `${label} must be valid JSON.`); }
}

function parsePlannedResources(value) {
  const rows = parseJson(value, [], 'planned_resources');
  if (!Array.isArray(rows) || rows.length > 60)
    throw new HttpError(400, 'planned_resources must be a list of at most 60 resources.');
  return rows.map((row) => {
    const id = row?.id == null || row.id === '' ? null : Number(row.id);
    const type = String(row?.type || row?.resource_type || '');
    const name = String(row?.name || '').trim();
    const plannedQuantity = row?.planned_quantity === '' || row?.planned_quantity == null
      ? null : Number(row.planned_quantity);
    const plannedHours = row?.planned_hours === '' || row?.planned_hours == null
      ? null : Number(row.planned_hours);
    const unit = String(row?.unit || '').trim() || null;
    if (id != null && (!Number.isSafeInteger(id) || id <= 0))
      throw new HttpError(400, 'A planned resource id is invalid.');
    if (!['manpower', 'equipment', 'material'].includes(type) || !name || name.length > 200)
      throw new HttpError(400, 'Each planned resource needs a valid type and name.');
    if ((plannedQuantity != null && (!Number.isFinite(plannedQuantity) || plannedQuantity < 0))
      || (plannedHours != null && (!Number.isFinite(plannedHours) || plannedHours < 0)))
      throw new HttpError(400, 'Planned resource quantities and hours must be zero or more.');
    if (unit && unit.length > 60) throw new HttpError(400, 'Planned resource units cannot exceed 60 characters.');
    return { id, type, name, plannedQuantity, plannedHours, unit };
  });
}

async function insertPlannedResources(db, projectId, activityId, taskId, rows) {
  for (const row of rows) {
    await db.query(
      `INSERT INTO planned_resources
         (project_id, activity_id, task_id, resource_type, name, planned_quantity, unit, planned_hours)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [projectId, activityId, taskId, row.type, row.name, row.plannedQuantity, row.unit, row.plannedHours]);
  }
}

async function syncActivityPlannedResources(db, projectId, activityId, rows) {
  const existing = (await db.query(
    `SELECT id FROM planned_resources WHERE activity_id = $1 AND task_id IS NULL FOR UPDATE`, [activityId])).rows;
  const existingIds = new Set(existing.map((row) => Number(row.id)));
  const submittedIds = new Set();
  for (const row of rows) {
    if (row.id != null) {
      if (!existingIds.has(row.id) || submittedIds.has(row.id))
        throw new HttpError(400, 'A planned resource does not belong to this activity or is duplicated.');
      submittedIds.add(row.id);
      await db.query(
        `UPDATE planned_resources
         SET resource_type = $2, name = $3, planned_quantity = $4, unit = $5, planned_hours = $6
         WHERE id = $1 AND activity_id = $7 AND task_id IS NULL`,
        [row.id, row.type, row.name, row.plannedQuantity, row.unit, row.plannedHours, activityId]);
    } else {
      await insertPlannedResources(db, projectId, activityId, null, [row]);
    }
  }
  const removedIds = [...existingIds].filter((id) => !submittedIds.has(id));
  if (removedIds.length) {
    await db.query(
      `DELETE FROM planned_resources WHERE activity_id = $1 AND task_id IS NULL AND id = ANY($2::bigint[])`,
      [activityId, removedIds]);
  }
}

// ── milestone sync ───────────────────────────────────────────────────────────

/**
 * Recompute a derived milestone from the certified progress of its contractor activities and write the
 * figure the schedule reads (progress_pct). Also resolves an open breakdown request once the activities
 * give full coverage with at least two activities. Call it inside the caller's transaction.
 */
async function syncMilestone(client, kind, milestoneId, actor = null) {
  const m = MILESTONE[kind];
  const ms = (await client.query(
    `SELECT id, project_id, quantity, override_pct FROM ${m.table} WHERE id = $1 FOR UPDATE`, [milestoneId])).rows[0];
  if (!ms) return null;

  const acts = (await client.query(
    `SELECT id, title, status, drives_milestone, milestone_weight_pct, certified_progress_pct
     FROM planning_execution WHERE ${m.col} = $1 ORDER BY id`, [milestoneId])).rows;
  const drivers = acts.filter((a) => a.drives_milestone);

  const breakdownCol = kind === 'baseline' ? 'baseline_milestone_id' : 'additional_milestone_id';
  let open = (await client.query(
    `SELECT id FROM milestone_breakdown_requests WHERE ${breakdownCol} = $1 AND status = 'open'`, [milestoneId])).rows[0];
  const weighted = drivers.filter((a) => Number(a.milestone_weight_pct) > 0);
  if (open && weighted.length >= 2 && milestoneCoverage(acts) === 100) {
    await client.query(
      `UPDATE milestone_breakdown_requests
       SET status = 'resolved', closed_at = NOW(), closed_by_id = $2, closed_by_role = $3, close_reason = 'Activities were added to cover the breakdown.'
       WHERE id = $1`, [open.id, actor?.id ?? null, actor?.role ?? null]);
    open = null;
  }

  const latestCert = new Map((drivers.length ? (await client.query(
    `SELECT DISTINCT ON (activity_id) activity_id, id, certificate_no, certification_note, decided_at
     FROM activity_verifications
     WHERE activity_id = ANY($1::int[]) AND status IN ('verified', 'verified_with_changes') AND certificate_no IS NOT NULL
     ORDER BY activity_id, decided_at DESC, id DESC`, [drivers.map((a) => a.id)])).rows : []).map((row) => [row.activity_id, row]));

  const derived = milestoneDerivedProgress(acts);
  const effective = effectiveMilestoneProgress({ derived, override: ms.override_pct, breakdownOpen: !!open });
  const executed = Number(ms.quantity) > 0 ? round3((effective / 100) * Number(ms.quantity)) : null;

  await client.query(
    `UPDATE ${m.table}
     SET derived_progress_pct = $2, progress_pct = $3, executed = COALESCE($4, executed), updated_at = NOW(),
         activity_status = CASE WHEN activity_status = 'completed' THEN activity_status WHEN $3::numeric > 0 THEN 'in_progress' ELSE activity_status END
     WHERE id = $1`, [milestoneId, derived, effective, executed]);

  await client.query(
    `INSERT INTO milestone_activity_progress
       (project_id, ${breakdownCol}, report_date, derived_progress_pct, executed_equivalent, contributions)
     VALUES ($1, $2, CURRENT_DATE, $3, $4, $5::jsonb)
     ON CONFLICT (${breakdownCol}, report_date) WHERE ${breakdownCol} IS NOT NULL
     DO UPDATE SET derived_progress_pct = EXCLUDED.derived_progress_pct,
                   executed_equivalent  = EXCLUDED.executed_equivalent,
                   contributions        = EXCLUDED.contributions,
                   recomputed_at        = NOW()`,
    [Number(ms.project_id), milestoneId, derived, executed,
     JSON.stringify(drivers.map((a) => {
       const cert = latestCert.get(a.id);
       return {
         activity_id: a.id, title: a.title, weight_pct: Number(a.milestone_weight_pct), certified_progress_pct: Number(a.certified_progress_pct),
         // the latest certificate of this activity: its short note is shown beside the activity in the milestone log
         verification_id: cert ? cert.id : null, certificate_no: cert ? cert.certificate_no : null,
         note: cert ? cert.certification_note || '' : '', certified_at: cert ? cert.decided_at : null,
       };
     }))]);

  return { derived, progress_pct: effective, executed, breakdown_open: !!open };
}

// ── shared pieces ────────────────────────────────────────────────────────────

async function assertTeamMembers(client, projectId, side, members) {
  const ids = members.map((m) => parseInt(m.id, 10)).filter(Boolean);
  if (!ids.length) throw new HttpError(400, 'At least one team member must be assigned to each task.');
  const check = await client.query(
    `SELECT COUNT(*) AS cnt FROM team_member_assignments
     WHERE project_id = $1 AND team_member_id = ANY($2::int[]) AND assigned_part = $3`, [projectId, ids, side]);
  if (parseInt(check.rows[0].cnt, 10) !== new Set(ids).size)
    throw new HttpError(403, 'One or more assigned members do not belong to your side.');
  return ids;
}

/** Targets and weights of the tasks of a quantity or count activity (they are two views of the same thing). */
function resolveTaskShares(type, plannedQuantity, tasks) {
  const n = tasks.length;
  if (!n) return [];
  const needsTarget = type === 'quantity' || type === 'count';
  const givenWeights = tasks.map((t) => (t.weight_pct == null || t.weight_pct === '' ? null : Number(t.weight_pct)));
  const givenTargets = tasks.map((t) => (t.target_quantity == null || t.target_quantity === '' ? null : Number(t.target_quantity)));

  let weights;
  if (needsTarget && givenTargets.every((v) => v != null)) {
    if (givenTargets.some((v) => !(v > 0))) throw new HttpError(400, 'Each task target must be above 0.');
    const total = givenTargets.reduce((t, v) => t + v, 0);
    if (Math.abs(total - plannedQuantity) > 0.0005 * Math.max(1, plannedQuantity))
      throw new HttpError(400, `Task targets add up to ${round3(total)}, but the activity plan is ${plannedQuantity}.`);
    const raw = givenTargets.map((v) => Math.max(1, Math.round((v / total) * 10000)));
    raw[raw.indexOf(Math.max(...raw))] += 10000 - raw.reduce((t, c) => t + c, 0);
    weights = raw.map((c) => c / 100);
  } else if (givenWeights.every((v) => v != null)) {
    weights = givenWeights;
  } else if (givenWeights.every((v) => v == null)) {
    weights = splitEqual(n);
  } else {
    throw new HttpError(400, 'Give a weight for every task, or for none of them.');
  }
  if (!weightsValid(weights)) throw new HttpError(400, 'Task weights must be above 0 and add up to exactly 100.');

  return weights.map((w) => ({
    weight_pct: w,
    target_quantity: needsTarget ? round3((plannedQuantity * w) / 100) : null,
  }));
}

function validateStages(stages) {
  const list = Array.isArray(stages) ? stages : [];
  if (!list.length) throw new HttpError(400, 'A task in a stages activity needs at least one stage.');
  if (list.some((s) => !String(s.title || '').trim())) throw new HttpError(400, 'Every stage needs a title.');
  const weights = list.map((s) => Number(s.weight_pct));
  if (!weightsValid(weights)) throw new HttpError(400, 'Stage weights must be above 0 and add up to exactly 100.');
  return list;
}

async function insertTask(client, ctx, task, share, stages, file = null) {
  const members = parseJson(task.assigned_members, [], 'assigned_members');
  await assertTeamMembers(client, ctx.projectId, ctx.side, members);
  const start = task.start_date || ctx.start_date;
  const end = task.end_date || ctx.end_date;
  if (!isDate(start) || !isDate(end) || end < start) throw new HttpError(400, `Task "${task.title}" has invalid dates.`);
  if (start < ctx.start_date || end > ctx.end_date)
    throw new HttpError(400, `Task "${task.title}" must stay inside the activity dates (${ctx.start_date} to ${ctx.end_date}).`);
  if (!['low', 'normal', 'high'].includes(task.priority || 'normal'))
    throw new HttpError(400, 'priority must be low, normal, or high.');

  const row = (await client.query(`
    INSERT INTO workspace_work_center
      (project_id, title, description, work_package, assigned_members, priority, status,
       start_date, end_date, creator_id, creator_role, side, activity_id, weight_pct, target_quantity,
       linked_file_name, linked_file_id, linked_file_url,
       location_block, location_floor, location_zone, location_grid, location_drawing)
    VALUES ($1,$2,$3,$4,$5::jsonb,$6,'ongoing',$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
    RETURNING *`,
    [ctx.projectId, String(task.title).trim(), task.description || '', task.work_package || '',
     JSON.stringify(members), task.priority || 'normal', start, end,
     ctx.userId, ctx.role, ctx.side, ctx.activityId, share.weight_pct, share.target_quantity,
     file?.name || null, file?.id || null, file?.url || null,
     task.location_block || null, task.location_floor || null, task.location_zone || null,
     task.location_grid || null, task.location_drawing || null])).rows[0];

  await client.query(
    `INSERT INTO work_center_task_history
       (task_id, project_id, actor_id, actor_role, action, detail)
     VALUES ($1,$2,$3,$4,'task_created',$5::jsonb)`,
    [row.id, ctx.projectId, ctx.userId, ctx.role, JSON.stringify({ title: row.title })]);

  if (ctx.type === 'stages') {
    let seq = 0;
    for (const s of stages) {
      seq += 1;
      await client.query(
        `INSERT INTO task_stages (task_id, project_id, seq, title, weight_pct, is_hold_point)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [row.id, ctx.projectId, seq, String(s.title).trim(), Number(s.weight_pct), !!s.is_hold_point]);
    }
  }
  return row;
}

async function notifyAssigned(deps, ctx, activityTitle, tasks) {
  if (!deps.notify || !deps.flowKey) return;
  for (const t of tasks) {
    try {
      const ids = (Array.isArray(t.assigned_members) ? t.assigned_members : []).map((m) => parseInt(m.id, 10)).filter(Boolean);
      if (!ids.length) continue;
      await deps.notify({
        projectId: ctx.projectId, entityId: t.id, entityType: 'work_center_task',
        message: `New task assigned: ${t.title} (activity: ${activityTitle})`,
        actorId: ctx.userId, actorRole: ctx.role,
        recipients: ids.map((id) => deps.flowKey('TeamMember', id)),
      });
    } catch (err) { console.error('[activity] task notification failed (non-fatal):', err.message); }
  }
}

async function isMember(deps, projectId, userId, role) {
  if (deps.isProjectMember) return deps.isProjectMember(projectId, userId, role);
  const r = await deps.pool.query(`SELECT 1 FROM assignments_view WHERE project_id = $1 AND role_id = $2 AND role = $3 LIMIT 1`, [projectId, userId, role]);
  return r.rows.length > 0;
}

function fail(res, err, label) {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message, ...err.extra });
  console.error(label, err);
  return res.status(500).json({ error: 'Server error.' });
}

// ── routes ───────────────────────────────────────────────────────────────────

function registerActivityRoutes(app, deps) {
  const { pool, authenticateToken, upload, requireProjectLifecycleWrite, wcSide, isWCLeader } = deps;
  const attachmentFiles = (req) => req.files?.attachments || [];
  const legacyFile = (req) => req.files?.linked_file?.[0] || null;

  async function saveAttachments(db, files, { projectId, entityType, entityId, userId, role }, uploads, retainImmediately = false) {
    const saved = [];
    for (const file of files) {
      const uploaded = await uploads.upload(file.buffer, file.originalname, 'planning_execution/attachments');
      const row = (await db.query(
        `INSERT INTO card_attachments
           (project_id, entity_type, entity_id, file_name, file_id, file_url, mime_type,
            resource_type, uploaded_by_id, uploaded_by_role)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         RETURNING id, file_name, file_id, file_url, mime_type, created_at`,
        [projectId, entityType, entityId, file.originalname, uploaded.public_id, uploaded.secure_url,
         file.mimetype || null, uploaded.resource_type || 'raw', userId, role])).rows[0];
      saved.push(row);
      if (retainImmediately) uploads.keep(uploaded);
    }
    return saved;
  }

  app.post('/api/planning-execution/:activityId/attachments', authenticateToken,
    upload.array('attachments', 20), requireProjectLifecycleWrite, async (req, res) => {
    const uploads = createCloudinaryUploadTracker(deps);
    try {
      const { user_id: userId, role } = req.user;
      const projectId = parseInt(req.body?.projectId, 10);
      const activityId = parseInt(req.params.activityId, 10);
      if (!projectId || !activityId) throw new HttpError(400, 'projectId and activityId are required.');
      if (!isWCLeader(role)) throw new HttpError(403, 'Only leaders and PMs can add activity attachments.');
      if (!req.files?.length) throw new HttpError(400, 'Choose at least one attachment.');
      const activity = (await pool.query(
        `SELECT id, side, creator_id, status FROM planning_execution WHERE id = $1 AND project_id = $2`,
        [activityId, projectId])).rows[0];
      if (!activity) throw new HttpError(404, 'Activity not found.');
      if (activity.side !== wcSide(role)) throw new HttpError(403, 'You cannot edit an activity from the other side.');
      if (String(activity.creator_id) !== String(userId)) throw new HttpError(403, 'Only the creating leader can edit this activity.');
      if (activity.status === 'closed') throw new HttpError(409, 'A closed activity cannot be edited.');
      if (!(await isMember(deps, projectId, userId, role))) throw new HttpError(403, 'You are not a member of this project.');
      const attachments = await saveAttachments(pool, req.files, {
        projectId, entityType: 'planning_activity', entityId: activityId, userId, role,
      }, uploads, true);
      return res.status(201).json({ attachments });
    } catch (err) {
      await uploads.discard();
      return fail(res, err, 'POST /api/planning-execution/:activityId/attachments:');
    }
  });

  app.delete('/api/planning-execution/:activityId/attachments/:attachmentId', authenticateToken,
    requireProjectLifecycleWrite, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const projectId = parseInt(req.body?.projectId || req.query.projectId, 10);
      const activityId = parseInt(req.params.activityId, 10);
      const attachmentId = parseInt(req.params.attachmentId, 10);
      if (!projectId || !activityId || !attachmentId) throw new HttpError(400, 'projectId, activityId and attachmentId are required.');
      if (!isWCLeader(role)) throw new HttpError(403, 'Only leaders and PMs can remove activity attachments.');
      const activity = (await pool.query(
        `SELECT id, side, creator_id, status FROM planning_execution WHERE id = $1 AND project_id = $2`,
        [activityId, projectId])).rows[0];
      if (!activity) throw new HttpError(404, 'Activity not found.');
      if (activity.side !== wcSide(role) || String(activity.creator_id) !== String(userId))
        throw new HttpError(403, 'Only the creating leader on this activity’s side can remove attachments.');
      if (activity.status === 'closed') throw new HttpError(409, 'A closed activity cannot be edited.');
      if (!(await isMember(deps, projectId, userId, role))) throw new HttpError(403, 'You are not a member of this project.');
      const attachment = (await pool.query(
        `SELECT id, file_id, resource_type FROM card_attachments
         WHERE id = $1 AND project_id = $2 AND entity_type = 'planning_activity' AND entity_id = $3`,
        [attachmentId, projectId, activityId])).rows[0];
      if (!attachment) throw new HttpError(404, 'Attachment not found.');
      if (!deps.cloudinary?.uploader) throw new HttpError(503, 'File storage is unavailable.');
      const result = await deps.cloudinary.uploader.destroy(attachment.file_id, {
        resource_type: attachment.resource_type || 'raw',
      });
      if (!['ok', 'not found'].includes(result?.result))
        throw new HttpError(502, 'The file could not be removed from storage.');
      await pool.query(`DELETE FROM card_attachments WHERE id = $1`, [attachmentId]);
      return res.json({ success: true });
    } catch (err) { return fail(res, err, 'DELETE /api/planning-execution/:activityId/attachments:'); }
  });

  app.get('/api/planning-execution/:activityId/activity-card', authenticateToken, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const projectId = parseInt(req.query.projectId, 10);
      const activityId = parseInt(req.params.activityId, 10);
      if (!projectId) throw new HttpError(400, 'projectId is required.');
      if (!activityId) throw new HttpError(400, 'activityId is required.');
      if (!(await isMember(deps, projectId, userId, role)))
        throw new HttpError(403, 'You are not a member of this project.');

      const activity = (await pool.query(
        `SELECT id, project_id, side, creator_id, creator_role, created_at, milestone_name, title, description, start_date, end_date,
                planned_quantity, unit, status, activity_type, done_when, planned_work,
                planned_manpower, planned_equipment, planned_materials, progress_pct,
                certified_progress_pct, certified_at, baseline_milestone_id, additional_milestone_id,
                drives_milestone, milestone_weight_pct, actual_end, linked_file_name,
                linked_file_id, linked_file_url,
                (SELECT title FROM milestones WHERE id = planning_execution.baseline_milestone_id) AS baseline_milestone_title,
                (SELECT to_char(planned_start, 'YYYY-MM-DD') FROM milestones WHERE id = planning_execution.baseline_milestone_id) AS baseline_milestone_start,
                (SELECT to_char(planned_end, 'YYYY-MM-DD') FROM milestones WHERE id = planning_execution.baseline_milestone_id) AS baseline_milestone_end,
                (SELECT title FROM additional_milestones WHERE id = planning_execution.additional_milestone_id) AS additional_milestone_title,
                (SELECT to_char(planned_start, 'YYYY-MM-DD') FROM additional_milestones WHERE id = planning_execution.additional_milestone_id) AS additional_milestone_start,
                (SELECT to_char(planned_end, 'YYYY-MM-DD') FROM additional_milestones WHERE id = planning_execution.additional_milestone_id) AS additional_milestone_end
         FROM planning_execution WHERE id = $1 AND project_id = $2`,
        [activityId, projectId])).rows[0];
      if (!activity) throw new HttpError(404, 'Activity not found.');
      activity.calculated_delay_days = delayDays({
        plannedEnd: dateOnly(activity.end_date),
        actualEnd: dateOnly(activity.actual_end),
        status: activity.status,
      });

      let viewerSide = wcSide(role);
      if (!viewerSide && role === 'TeamMember') {
        const membership = await pool.query(
          `SELECT assigned_part FROM team_member_assignments
           WHERE project_id = $1 AND team_member_id = $2 LIMIT 1`, [projectId, userId]);
        viewerSide = membership.rows[0]?.assigned_part || null;
      }
      const canViewContractorActivity = ['Consultant', 'Client'].includes(viewerSide) && activity.side === 'Contractor';
      if (!viewerSide || (viewerSide !== activity.side && !canViewContractorActivity))
        throw new HttpError(403, 'You cannot view this activity.');

      const clientView = viewerSide === 'Client';
      const consultantView = viewerSide === 'Consultant' && activity.side === 'Contractor';
      const taskRows = clientView || consultantView ? [] : (await pool.query(
        `SELECT w.id, w.title, w.description, w.assigned_members, w.status, w.start_date, w.end_date,
                w.weight_pct, w.target_quantity, w.progress_pct, w.priority,
                (SELECT COUNT(*)::int FROM workspace_work_center_progress p
                 WHERE p.task_id = w.id AND p.validation_status = 'pending') AS pending_report_count
         FROM workspace_work_center w WHERE w.activity_id = $1 ORDER BY w.id`, [activityId])).rows;
      const stages = clientView || consultantView ? [] : (await pool.query(
        `SELECT s.id, s.task_id, s.seq, s.title, s.weight_pct, s.is_hold_point,
                s.completed_at, s.hold_verified_at
         FROM task_stages s JOIN workspace_work_center w ON w.id = s.task_id
         WHERE w.activity_id = $1 ORDER BY s.task_id, s.seq`, [activityId])).rows;
      const stagesByTask = new Map();
      for (const stage of stages) {
        if (!stagesByTask.has(stage.task_id)) stagesByTask.set(stage.task_id, []);
        stagesByTask.get(stage.task_id).push(stage);
      }
      const progressReports = clientView || consultantView || !taskRows.length ? [] : (await pool.query(
        `SELECT p.id, p.task_id, w.title AS task_title, p.report_date, p.member_id,
                tm.email AS member_email, p.work_done, p.quantity_done, p.quantity_failed,
                p.progress_pct, p.stage_id, p.manpower, p.equipment, p.materials,
                p.issues, p.notes, p.submitted_at, p.validated_at,
                p.attachment_name, p.attachment_url,
                COALESCE((SELECT json_agg(json_build_object(
                  'id', ph.id, 'file_name', ph.file_name, 'file_url', ph.file_url,
                  'captured_at', ph.captured_at, 'latitude', ph.latitude,
                  'longitude', ph.longitude, 'accuracy_m', ph.accuracy_m
                ) ORDER BY ph.seq) FROM work_center_report_photos ph
                  WHERE ph.report_id = p.id), '[]'::json) AS photos,
                COALESCE((SELECT json_agg(json_build_object(
                  'id', ra.id, 'file_name', ra.file_name, 'file_url', ra.file_url, 'mime_type', ra.mime_type,
                  'attachment_type', ra.attachment_type, 'custom_attachment_type', ra.custom_attachment_type
                ) ORDER BY ra.created_at, ra.id) FROM work_center_report_attachments ra
                  WHERE ra.report_id = p.id), '[]'::json) AS supporting_attachments,
                COALESCE((SELECT json_agg(json_build_object(
                  'resource_type', rr.resource_type, 'name', rr.name, 'quantity', rr.quantity,
                  'unit', rr.unit, 'hours', rr.hours
                ) ORDER BY rr.id) FROM work_center_report_resources rr
                  WHERE rr.report_id = p.id), '[]'::json) AS resources
         FROM workspace_work_center_progress p
         JOIN workspace_work_center w ON w.id = p.task_id
         JOIN team_members tm ON tm.id = p.member_id
         WHERE w.activity_id = $1 AND p.validation_status = 'approved'
         ORDER BY p.report_date, p.submitted_at, p.id`, [activityId])).rows;
      const activitySummary = consultantView ? (await pool.query(
        `SELECT COUNT(*)::int AS task_count,
                COUNT(*) FILTER (WHERE status = 'completed')::int AS completed_task_count,
                COALESCE(SUM(target_quantity), 0)::numeric AS planned_quantity
         FROM workspace_work_center WHERE activity_id = $1`, [activityId])).rows[0] : null;
      const reportSummary = consultantView ? (await pool.query(
        `SELECT COUNT(*)::int AS approved_report_count,
                COALESCE(SUM(quantity_done), 0)::numeric AS approved_quantity,
                MAX(report_date) AS latest_report_date
         FROM workspace_work_center_progress p
         JOIN workspace_work_center w ON w.id = p.task_id
         WHERE w.activity_id = $1 AND p.validation_status = 'approved'`, [activityId])).rows[0] : null;
      const visibleActivity = consultantView ? {
        id: activity.id,
        project_id: activity.project_id,
        title: activity.title,
        side: activity.side,
        activity_type: activity.activity_type,
        start_date: activity.start_date,
        end_date: activity.end_date,
        planned_quantity: activity.planned_quantity,
        unit: activity.unit,
        drives_milestone: activity.drives_milestone,
        milestone_weight_pct: activity.milestone_weight_pct,
        baseline_milestone_title: activity.baseline_milestone_title,
        additional_milestone_title: activity.additional_milestone_title,
        milestone_name: activity.milestone_name,
        status: activity.status,
        progress_pct: Number(activity.progress_pct) || 0,
        claimed_progress_pct: Number(activity.progress_pct) || 0,
        certified_progress_pct: Number(activity.certified_progress_pct) || 0,
        baseline_milestone_id: activity.baseline_milestone_id,
        additional_milestone_id: activity.additional_milestone_id,
        calculated_delay_days: activity.calculated_delay_days,
        linked_file_name: activity.linked_file_name,
        linked_file_id: activity.linked_file_id,
        linked_file_url: activity.linked_file_url,
      } : {
        ...activity,
        progress_pct: clientView ? null : Number(activity.progress_pct) || 0,
        status: clientView ? null : activity.status,
        claimed_progress_pct: clientView ? null : Number(activity.progress_pct) || 0,
        certified_progress_pct: Number(activity.certified_progress_pct) || 0,
        client_view: clientView,
      };
      const attachments = (await pool.query(
        `SELECT id, file_name, file_id, file_url, mime_type, created_at
         FROM card_attachments
         WHERE project_id = $1 AND entity_type = 'planning_activity' AND entity_id = $2
         ORDER BY created_at, id`, [projectId, activityId])).rows;
      const plannedResources = activity.side === viewerSide ? (await pool.query(
        `SELECT id, task_id, resource_type AS type, name, planned_quantity, unit, planned_hours
         FROM planned_resources WHERE activity_id = $1 ORDER BY task_id NULLS FIRST, id`, [activityId])).rows : undefined;
      // The consultant sees the approved work of each task (titles, shares and approved figures), never the members,
      // notes or report details. Report details and files reach the consultant only when the contractor shares them.
      const workByTask = consultantView ? (await pool.query(
        `SELECT w.title, w.weight_pct, w.progress_pct, w.target_quantity,
                COUNT(p.id) FILTER (WHERE p.validation_status = 'approved')::int AS approved_report_count,
                COALESCE(SUM(p.quantity_done) FILTER (WHERE p.validation_status = 'approved'), 0) AS approved_quantity,
                to_char(MAX(p.report_date) FILTER (WHERE p.validation_status = 'approved'), 'YYYY-MM-DD') AS last_approved_date
         FROM workspace_work_center w
         LEFT JOIN workspace_work_center_progress p ON p.task_id = w.id
         WHERE w.activity_id = $1 AND w.project_id = $2
         GROUP BY w.id, w.title, w.weight_pct, w.progress_pct, w.target_quantity
         ORDER BY w.id`, [activityId, projectId])).rows.map((row) => ({
        title: row.title,
        weight_pct: Number(row.weight_pct) || 0,
        progress_pct: Number(row.progress_pct) || 0,
        target_quantity: row.target_quantity == null ? null : Number(row.target_quantity),
        approved_report_count: Number(row.approved_report_count) || 0,
        approved_quantity: Number(row.approved_quantity) || 0,
        last_approved_date: row.last_approved_date || null,
      })) : undefined;
      return res.json({
        activity: visibleActivity,
        attachments,
        planned_resources: plannedResources,
        work_by_task: workByTask,
        activity_summary: consultantView ? {
          task_count: Number(activitySummary.task_count),
          completed_task_count: Number(activitySummary.completed_task_count),
          planned_quantity: Number(activitySummary.planned_quantity),
          approved_report_count: Number(reportSummary.approved_report_count),
          approved_quantity: Number(reportSummary.approved_quantity),
          latest_report_date: reportSummary.latest_report_date,
        } : null,
        tasks: taskRows.map((task) => ({
          ...task,
          assigned_members: parseJson(task.assigned_members, [], 'assigned_members'),
          progress_pct: clientView ? null : Number(task.progress_pct) || 0,
          weight_pct: Number(task.weight_pct) || 0,
          target_quantity: task.target_quantity == null ? null : Number(task.target_quantity),
          stages: stagesByTask.get(task.id) || [],
        })),
        progress_reports: progressReports,
        can_add_task: isWCLeader(role) && activity.side === viewerSide && activity.status !== 'closed',
        can_edit_activity: isWCLeader(role) && String(activity.creator_id) === String(userId) && activity.status !== 'closed',
        can_delete_activity: isWCLeader(role) && activity.side === viewerSide,
        viewer_side: viewerSide,
      });
    } catch (err) { return fail(res, err, 'GET /api/planning-execution/:activityId/activity-card:'); }
  });

  // One report for the Overview screen and the PDF. A past certificate returns its frozen copy.
  app.get('/api/planning-execution/:activityId/activity-report', authenticateToken, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const projectId = parseInt(req.query.projectId, 10);
      const activityId = parseInt(req.params.activityId, 10);
      const verificationId = req.query.verificationId ? parseInt(req.query.verificationId, 10) : null;
      if (!projectId) throw new HttpError(400, 'projectId is required.');
      if (!activityId) throw new HttpError(400, 'activityId is required.');
      if (!(await isMember(deps, projectId, userId, role)))
        throw new HttpError(403, 'You are not a member of this project.');

      const activity = (await pool.query(
        `SELECT pe.*,
                (SELECT title FROM milestones WHERE id = pe.baseline_milestone_id) AS baseline_milestone_title,
                (SELECT title FROM additional_milestones WHERE id = pe.additional_milestone_id) AS additional_milestone_title
         FROM planning_execution pe WHERE pe.id = $1 AND pe.project_id = $2`, [activityId, projectId])).rows[0];
      if (!activity) throw new HttpError(404, 'Activity not found.');
      activity.baseline_milestone_title = activity.baseline_milestone_title || null;
      activity.additional_milestone_title = activity.additional_milestone_title || activity.milestone_name || null;

      let viewerSide = wcSide(role);
      if (!viewerSide && role === 'TeamMember') {
        const membership = await pool.query(
          `SELECT assigned_part FROM team_member_assignments
           WHERE project_id = $1 AND team_member_id = $2 LIMIT 1`, [projectId, userId]);
        viewerSide = membership.rows[0]?.assigned_part || null;
      }
      const canViewContractorActivity = ['Consultant', 'Client'].includes(viewerSide) && activity.side === 'Contractor';
      if (!viewerSide || (viewerSide !== activity.side && !canViewContractorActivity))
        throw new HttpError(403, 'You cannot view this activity.');
      const mode = viewerSide === 'Client' ? 'client' : (viewerSide === 'Consultant' && activity.side === 'Contractor') ? 'consultant' : 'own';

      let report = null;
      let asOfDate = null;
      if (verificationId) {
        const v = (await pool.query(
          `SELECT report_snapshot, decided_at FROM activity_verifications WHERE id = $1 AND activity_id = $2`,
          [verificationId, activityId])).rows[0];
        if (!v) throw new HttpError(404, 'Certificate not found.');
        report = v.report_snapshot || null;
        asOfDate = v.decided_at ? dateOnly(v.decided_at) : null;
      }
      if (!report) report = await buildActivityReport(pool, { activity, asOfDate });

      let pendingReports = null;
      if (mode === 'own' && !verificationId) {
        pendingReports = (await pool.query(
          `SELECT p.id, w.title AS task_title, to_char(p.report_date, 'YYYY-MM-DD') AS date, p.quantity_done,
                  split_part(COALESCE(tm.display_name, tm.email), '@', 1) AS reported_by_name
           FROM workspace_work_center_progress p
           JOIN workspace_work_center w ON w.id = p.task_id
           JOIN team_members tm ON tm.id = p.member_id
           WHERE w.activity_id = $1 AND p.validation_status = 'pending'
           ORDER BY p.report_date, p.id`, [activityId])).rows;
      }
      const shaped = shapeReportForViewer(report, mode, { pendingReports });
      shaped.viewer.side = viewerSide;
      shaped.viewer.can_certify = mode === 'consultant' && isWCLeader(role) && !!activity.drives_milestone;
      return res.json(shaped);
    } catch (err) { return fail(res, err, 'GET /api/planning-execution/:activityId/activity-report:'); }
  });

  app.put('/api/planning-execution/:activityId/plan', authenticateToken,
    upload.single('linked_file'), requireProjectLifecycleWrite, async (req, res) => {
    let client;
    const uploads = createCloudinaryUploadTracker(deps);
    try {
      const { user_id: userId, role } = req.user;
      if (!isWCLeader(role)) throw new HttpError(403, 'Only leaders and PMs can update an activity.');
      const projectId = parseInt(req.body?.projectId, 10);
      const activityId = parseInt(req.params.activityId, 10);
      if (!projectId || !activityId) throw new HttpError(400, 'projectId and activityId are required.');
      client = await pool.connect();
      await client.query('BEGIN');
      const activity = (await client.query(
        `SELECT * FROM planning_execution WHERE id = $1 AND project_id = $2 FOR UPDATE`,
        [activityId, projectId])).rows[0];
      if (!activity) throw new HttpError(404, 'Activity not found.');
      if (String(activity.creator_id) !== String(userId)) throw new HttpError(403, 'Only the creating leader can edit this activity.');
      if (activity.status === 'closed') throw new HttpError(409, 'A closed activity cannot be edited.');
      if (wcSide(role) !== activity.side) throw new HttpError(403, 'You cannot edit an activity from the other side.');
      if (!(await isMember(deps, projectId, userId, role))) throw new HttpError(403, 'You are not a member of this project.');

      const title = String(req.body?.title || '').trim();
      const start = String(req.body?.start_date || '').slice(0, 10);
      const end = String(req.body?.end_date || '').slice(0, 10);
      const type = String(req.body?.activity_type || '');
      if (!title) throw new HttpError(400, 'title is required.');
      if (!isDate(start) || !isDate(end) || end < start) throw new HttpError(400, 'Enter valid activity dates with the end date on or after the start date.');
      if (!ACTIVITY_TYPES.includes(type)) throw new HttpError(400, `activity_type must be one of: ${ACTIVITY_TYPES.join(', ')}.`);

      const tasks = (await client.query(
        `SELECT id, weight_pct, to_char(start_date, 'YYYY-MM-DD') AS start_date,
                to_char(end_date, 'YYYY-MM-DD') AS end_date
         FROM workspace_work_center WHERE activity_id = $1 ORDER BY id FOR UPDATE`, [activityId])).rows;
      if (tasks.some((task) => task.start_date < start || task.end_date > end))
        throw new HttpError(409, 'Activity dates must contain the date range of every existing task.');
      const linkedMilestone = activity.baseline_milestone_id
        ? { kind: 'baseline', id: activity.baseline_milestone_id }
        : activity.additional_milestone_id
          ? { kind: 'additional', id: activity.additional_milestone_id }
          : null;
      if (linkedMilestone) {
        const milestone = MILESTONE[linkedMilestone.kind];
        const bounds = (await client.query(
          `SELECT planned_start, planned_end FROM ${milestone.table} WHERE id = $1 AND project_id = $2::text`,
          [linkedMilestone.id, String(projectId)])).rows[0];
        if (bounds?.planned_start && start < dateOnly(bounds.planned_start))
          throw new HttpError(400, `The activity cannot start before its milestone (${dateOnly(bounds.planned_start)}).`);
        if (bounds?.planned_end && end > dateOnly(bounds.planned_end))
          throw new HttpError(400, `The activity cannot end after its milestone (${dateOnly(bounds.planned_end)}).`);
      }

      const typeChanged = type !== activity.activity_type;
      const reports = (await client.query(
          `SELECT 1 FROM workspace_work_center_progress p
           JOIN workspace_work_center w ON w.id = p.task_id
           WHERE w.activity_id = $1 LIMIT 1`, [activityId])).rows.length;
      const execution = (await client.query(
          `SELECT 1 FROM planning_execution_tracking WHERE activity_id = $1 LIMIT 1`, [activityId])).rows.length;
      const hasProgress = reports > 0 || execution > 0;
      if (typeChanged && hasProgress)
        throw new HttpError(409, 'The activity type cannot change after reports or execution entries exist.');

      const measured = type === 'quantity' || type === 'count';
      const plannedQuantity = req.body?.planned_quantity === '' || req.body?.planned_quantity == null
        ? null : Number(req.body.planned_quantity);
      const unit = String(req.body?.unit || '').trim();
      if (measured && !(plannedQuantity > 0)) throw new HttpError(400, 'planned_quantity must be above 0 for quantity and count activities.');
      if (measured && !unit) throw new HttpError(400, 'unit is required for quantity and count activities.');
      if (hasProgress && measured && (
        plannedQuantity !== Number(activity.planned_quantity) || unit !== String(activity.unit || '')
      )) throw new HttpError(409, 'The planned amount and unit cannot change after reports or execution entries exist.');
      const reportDates = (await client.query(
        `SELECT to_char(MIN(report_date), 'YYYY-MM-DD') AS first_day,
                to_char(MAX(report_date), 'YYYY-MM-DD') AS last_day
         FROM (
           SELECT p.report_date FROM workspace_work_center_progress p
           JOIN workspace_work_center w ON w.id = p.task_id WHERE w.activity_id = $1
           UNION ALL
           SELECT report_date FROM planning_execution_tracking WHERE activity_id = $1
         ) reports`, [activityId])).rows[0];
      if ((reportDates.first_day && reportDates.first_day < start) ||
          (reportDates.last_day && reportDates.last_day > end))
        throw new HttpError(409, 'Activity dates must contain every existing report and execution date.');
      if (type === 'stages' && tasks.length) {
        const counts = (await client.query(
          `SELECT w.id, COUNT(s.id)::int AS stage_count FROM workspace_work_center w
           LEFT JOIN task_stages s ON s.task_id = w.id
           WHERE w.activity_id = $1 GROUP BY w.id`, [activityId])).rows;
        if (counts.some((row) => row.stage_count < 1))
          throw new HttpError(409, 'Every existing task needs at least one configured stage before this can be a stages activity.');
      }
      if (measured && tasks.length) {
        const weights = tasks.map((task) => Number(task.weight_pct));
        if (!weightsValid(weights)) throw new HttpError(409, 'Existing task weights are invalid; fix the task breakdown before editing this activity.');
      }

      let file = null;
      if (req.file) {
        file = await uploads.upload(req.file.buffer, req.file.originalname, 'planning_execution/plans');
      }
      const updated = (await client.query(`
        UPDATE planning_execution SET
          title = $1, description = $2, done_when = $3, start_date = $4, end_date = $5,
          activity_type = $6, planned_quantity = $7, unit = $8, planned_work = $9,
          planned_manpower = $10, planned_equipment = $11, planned_materials = $12,
          linked_file_name = COALESCE($13, linked_file_name),
          linked_file_id = COALESCE($14, linked_file_id),
          linked_file_url = COALESCE($15, linked_file_url),
          updated_at = NOW()
        WHERE id = $16 RETURNING *`,
      [title, req.body.description || '', req.body.done_when || '', start, end, type,
       measured ? plannedQuantity : null, measured ? unit : null,
       req.body.planned_work || '', req.body.planned_manpower || '',
       req.body.planned_equipment || '', req.body.planned_materials || '',
       req.file?.originalname || null, file?.public_id || null, file?.secure_url || null, activityId])).rows[0];

      if (Object.prototype.hasOwnProperty.call(req.body || {}, 'planned_resources')) {
        await syncActivityPlannedResources(
          client, projectId, activityId, parsePlannedResources(req.body.planned_resources));
      }

      if (measured && tasks.length) {
        for (const task of tasks) {
          await client.query(
            `UPDATE workspace_work_center SET target_quantity = $2, updated_at = NOW() WHERE id = $1`,
            [task.id, Math.round((plannedQuantity * Number(task.weight_pct) / 100 + Number.EPSILON) * 1000) / 1000]);
        }
      }
      await client.query('COMMIT');
      uploads.keepAll();
      return res.json({ success: true, activity: updated });
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      await uploads.discard();
      return fail(res, err, 'PUT /api/planning-execution/:activityId/plan:');
    } finally { if (client) client.release(); }
  });

  // Create an activity, its tasks (with weights and stages) and the milestone link in one transaction.
  app.post('/api/planning-execution/create-with-tasks', authenticateToken,
    upload.fields([{ name: 'linked_file', maxCount: 1 }, { name: 'attachments', maxCount: 20 }]),
    requireProjectLifecycleWrite, async (req, res) => {
    let client;
    const uploads = createCloudinaryUploadTracker(deps);
    try {
      const { user_id: userId, role } = req.user;
      if (!isWCLeader(role)) throw new HttpError(403, 'Only leaders and PMs can create activities.');
      const side = wcSide(role);
      if (!side) throw new HttpError(403, 'Cannot determine your side.');

      const b = req.body || {};
      const projectId = parseInt(b.projectId, 10);
      if (!projectId) throw new HttpError(400, 'projectId is required.');
      if (!String(b.title || '').trim()) throw new HttpError(400, 'title is required.');
      if (!isDate(b.start_date) || !isDate(b.end_date)) throw new HttpError(400, 'start_date and end_date must be valid dates (YYYY-MM-DD).');
      if (b.end_date < b.start_date) throw new HttpError(400, 'end_date cannot be before start_date.');
      if (!(await isMember(deps, projectId, userId, role))) throw new HttpError(403, 'You are not a member of this project.');

      const type = b.activity_type || DEFAULT_TYPE[side];
      if (!ACTIVITY_TYPES.includes(type)) throw new HttpError(400, `activity_type must be one of: ${ACTIVITY_TYPES.join(', ')}.`);
      const needsMeasure = type === 'quantity' || type === 'count';
      const planned = needsMeasure ? Number(b.planned_quantity) : (b.planned_quantity ? Number(b.planned_quantity) : null);
      const unit = String(b.unit || '').trim() || null;
      if (needsMeasure && !(planned > 0)) throw new HttpError(400, 'planned_quantity must be above 0 for this activity type.');
      if (needsMeasure && !unit) throw new HttpError(400, 'unit is required for this activity type.');
      const plannedResources = parsePlannedResources(b.planned_resources);

      const taskInputs = parseJson(b.tasks, [], 'tasks');
      if (!Array.isArray(taskInputs)) throw new HttpError(400, 'tasks must be a list.');
      if (taskInputs.some((t) => !String(t.title || '').trim())) throw new HttpError(400, 'Every task needs a title.');
      const shares = resolveTaskShares(type, planned, taskInputs);
      const stageSets = taskInputs.map((t) => (type === 'stages' ? validateStages(t.stages) : []));

      const baselineId = b.baseline_milestone_id ? parseInt(b.baseline_milestone_id, 10) : null;
      const additionalId = b.additional_milestone_id ? parseInt(b.additional_milestone_id, 10) : null;
      if (baselineId && additionalId) throw new HttpError(400, 'Link either a baseline or an additional milestone, not both.');
      const kind = baselineId ? 'baseline' : additionalId ? 'additional' : null;
      const milestoneId = baselineId || additionalId || null;

      let file = { name: null, id: null, url: null };
      const planFile = legacyFile(req);
      if (planFile) {
        const up = await uploads.upload(planFile.buffer, planFile.originalname, 'planning_execution/plans');
        file = { name: planFile.originalname, id: up.public_id, url: up.secure_url };
      }

      client = await pool.connect();
      await client.query('BEGIN');

      // milestone link
      let milestoneTitle = null;
      let milestoneWeight = 0;
      let siblingWeights = null;
      const drives = side === 'Contractor';
      if (kind) {
        const m = MILESTONE[kind];
        const ms = (await client.query(
          `SELECT id, title, planned_start, planned_end, progress_source, executed, progress_pct, quantity, unit FROM ${m.table}
           WHERE id = $1 AND project_id = $2::text FOR UPDATE`, [milestoneId, String(projectId)])).rows[0];
        if (!ms) throw new HttpError(400, 'That milestone does not belong to this project.');
        if (ms.planned_start && b.start_date < dateOnly(ms.planned_start))
          throw new HttpError(400, `The activity cannot start before its milestone (${dateOnly(ms.planned_start)}).`);
        if (ms.planned_end && b.end_date > dateOnly(ms.planned_end))
          throw new HttpError(400, `The activity cannot end after its milestone (${dateOnly(ms.planned_end)}).`);
        milestoneTitle = ms.title;

        if (drives) {
          if (ms.progress_source === 'manual') {
            const entries = (await client.query(
              `SELECT COUNT(*)::int AS n FROM ${m.entries} WHERE ${m.entryFk} = $1 AND superseded_at IS NULL`, [milestoneId])).rows[0].n;
            const typed = entries > 0 || Number(ms.executed) > 0 || Number(ms.progress_pct) > 0;
            if (typed && String(b.confirm_replace_manual) !== 'true') {
              throw new HttpError(409, 'This milestone has typed progress that linking will replace.', {
                code: 'CONFIRM_REPLACE_MANUAL',
                typed_progress_pct: Number(ms.progress_pct), typed_executed: Number(ms.executed),
                quantity: ms.quantity == null ? null : Number(ms.quantity), unit: ms.unit, will_become: 0,
              });
            }
            await client.query(`UPDATE ${m.entries} SET superseded_at = NOW() WHERE ${m.entryFk} = $1 AND superseded_at IS NULL`, [milestoneId]);
            await client.query(`UPDATE ${m.table} SET progress_source = 'activities', linked_at = NOW() WHERE id = $1`, [milestoneId]);
          }
          const sibs = (await client.query(
            `SELECT id, milestone_weight_pct FROM planning_execution
             WHERE ${m.col} = $1 AND drives_milestone ORDER BY id FOR UPDATE`, [milestoneId])).rows;
          if (!sibs.length) milestoneWeight = 100;
          else {
            const asked = b.milestone_weight_pct == null || b.milestone_weight_pct === '' ? undefined : Number(b.milestone_weight_pct);
            const after = rebalanceForNew(sibs.map((s) => Number(s.milestone_weight_pct)), asked);
            milestoneWeight = after[after.length - 1];
            siblingWeights = { before: sibs.map((s) => ({ activity_id: s.id, weight_pct: Number(s.milestone_weight_pct) })),
                               after: sibs.map((s, i) => ({ activity_id: s.id, weight_pct: after[i] })) };
            for (const s of siblingWeights.after)
              await client.query(`UPDATE planning_execution SET milestone_weight_pct = $2 WHERE id = $1`, [s.activity_id, s.weight_pct]);
          }
        }
      }

      const activity = (await client.query(`
        INSERT INTO planning_execution
          (project_id, side, milestone_name, title, description, start_date, end_date,
           planned_quantity, unit, planned_work, planned_manpower, planned_equipment, planned_materials,
           linked_file_name, linked_file_id, linked_file_url, status, creator_id, creator_role,
           activity_type, done_when, baseline_milestone_id, additional_milestone_id, milestone_weight_pct)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'not_yet_started',$17,$18,$19,$20,$21,$22,$23)
        RETURNING *`,
        [projectId, side, milestoneTitle,
         String(b.title).trim(), b.description || '', b.start_date, b.end_date,
         planned, unit, b.planned_work || '', b.planned_manpower || '', b.planned_equipment || '', b.planned_materials || '',
         file.name, file.id, file.url, userId, role,
         type, String(b.done_when || '').trim() || null, baselineId, additionalId, milestoneWeight])).rows[0];
      await insertPlannedResources(client, projectId, activity.id, null, plannedResources);
      if (attachmentFiles(req).length) await saveAttachments(client, attachmentFiles(req), {
        projectId, entityType: 'planning_activity', entityId: activity.id, userId, role,
      }, uploads);

      const ctx = { projectId, side, userId, role, activityId: activity.id, type, start_date: b.start_date, end_date: b.end_date };
      const tasks = [];
      for (let i = 0; i < taskInputs.length; i++)
        tasks.push(await insertTask(client, ctx, taskInputs[i], shares[i], stageSets[i]));

      if (siblingWeights) {
        await client.query(
          `INSERT INTO activity_weight_changes (project_id, activity_id, changed_by_id, changed_by_role, reason, before_weights, after_weights)
           VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb)`,
          [projectId, activity.id, userId, role, 'Activity added to milestone',
           JSON.stringify({ scope: 'milestone', weights: siblingWeights.before }),
           JSON.stringify({ scope: 'milestone', weights: [...siblingWeights.after, { activity_id: activity.id, weight_pct: milestoneWeight }] })]);
      }

      let milestone = null;
      if (kind && drives) milestone = await syncMilestone(client, kind, milestoneId, { id: userId, role });

      await client.query('COMMIT');
      uploads.keepAll();
      notifyAssigned(deps, { projectId, userId, role }, activity.title,
        tasks.map((t) => ({ ...t, assigned_members: parseJson(t.assigned_members, [], 'assigned_members') }))).catch(() => {});
      return res.status(201).json({ success: true, activity, tasks, milestone });
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      await uploads.discard();
      return fail(res, err, 'POST /api/planning-execution/create-with-tasks:');
    } finally { if (client) client.release(); }
  });

  // Add a task to an existing activity. With preview=true nothing is written: the response shows the
  // weights and the activity progress before and after, so the leader can confirm.
  app.post('/api/planning-execution/:activityId/tasks', authenticateToken,
    upload.fields([{ name: 'linked_file', maxCount: 1 }, { name: 'attachments', maxCount: 20 }]),
    requireProjectLifecycleWrite, async (req, res) => {
    let client;
    const uploads = createCloudinaryUploadTracker(deps);
    try {
      const { user_id: userId, role } = req.user;
      if (!isWCLeader(role)) throw new HttpError(403, 'Only leaders and PMs can add tasks.');
      const side = wcSide(role);
      const activityId = parseInt(req.params.activityId, 10);
      const b = req.body || {};
      let task = b.task || {};
      if (typeof task === 'string') {
        try { task = JSON.parse(task); } catch { task = {}; }
      }
      if (!String(task.title || '').trim()) throw new HttpError(400, 'The task needs a title.');
      const plannedResources = parsePlannedResources(task.planned_resources);
      const preview = b.preview === true || b.preview === 'true';

      client = await pool.connect();
      await client.query('BEGIN');

      const act = (await client.query(
        `SELECT * FROM planning_execution WHERE id = $1 FOR UPDATE`, [activityId])).rows[0];
      if (!act || act.side !== side) throw new HttpError(404, 'Activity not found.');
      if (!(await isMember(deps, act.project_id, userId, role))) throw new HttpError(403, 'You are not a member of this project.');
      if (act.status === 'closed') throw new HttpError(409, 'This activity is closed. Tasks cannot be added.');

      const existing = (await client.query(
        `SELECT id, title, weight_pct, progress_pct FROM workspace_work_center WHERE activity_id = $1 ORDER BY id FOR UPDATE`, [activityId])).rows;

      // new weights: either the leader gives all of them, or the existing ones are rebalanced proportionally
      let after;
      if (Array.isArray(b.weights) && b.weights.length) {
        const byId = new Map(b.weights.map((w) => [Number(w.task_id), Number(w.weight_pct)]));
        after = [...existing.map((t) => byId.get(t.id)), Number(b.new_task_weight_pct)];
        if (after.some((w) => !Number.isFinite(w))) throw new HttpError(400, 'Give a weight for every existing task and for the new task.');
      } else {
        after = rebalanceForNew(existing.map((t) => Number(t.weight_pct)),
          b.new_task_weight_pct == null || b.new_task_weight_pct === '' ? undefined : Number(b.new_task_weight_pct));
      }
      if (!weightsValid(after)) throw new HttpError(400, 'Task weights must be above 0 and add up to exactly 100.');

      const progressBefore = activityProgress(existing);
      const progressAfter = activityProgress([...existing.map((t, i) => ({ weight_pct: after[i], progress_pct: t.progress_pct })),
                                              { weight_pct: after[after.length - 1], progress_pct: 0 }]);
      const summary = {
        weights: [...existing.map((t, i) => ({ task_id: t.id, title: t.title, before: Number(t.weight_pct), after: after[i] })),
                  { task_id: null, title: String(task.title).trim(), before: null, after: after[after.length - 1] }],
        progress_before: progressBefore, progress_after: progressAfter,
      };
      const visibleSummary = side === 'Client'
        ? { ...summary, weights: summary.weights.map((row, i) => ({ ...row, title: row.task_id == null ? row.title : `Task ${i + 1}` })) }
        : summary;
      if (preview) { await client.query('ROLLBACK'); return res.json({ preview: true, ...visibleSummary }); }

      const needsTarget = act.activity_type === 'quantity' || act.activity_type === 'count';
      const planned = Number(act.planned_quantity);
      const stages = act.activity_type === 'stages' ? validateStages(task.stages) : [];
      let linkedFile = null;
      const file = legacyFile(req);
      if (file) {
        linkedFile = await uploads.upload(file.buffer, file.originalname, 'planning_execution/tasks');
      }
      for (let i = 0; i < existing.length; i++) {
        await client.query(
          `UPDATE workspace_work_center SET weight_pct = $2, target_quantity = $3, updated_at = NOW() WHERE id = $1`,
          [existing[i].id, after[i], needsTarget ? round3((planned * after[i]) / 100) : null]);
      }
      const newWeight = after[after.length - 1];
      const ctx = { projectId: act.project_id, side, userId, role, activityId, type: act.activity_type,
                    start_date: dateOnly(act.start_date), end_date: dateOnly(act.end_date) };
      const created = await insertTask(client, ctx, task,
        { weight_pct: newWeight, target_quantity: needsTarget ? round3((planned * newWeight) / 100) : null }, stages,
        linkedFile ? { name: file.originalname, id: linkedFile.public_id, url: linkedFile.secure_url } : null);
      await insertPlannedResources(client, act.project_id, activityId, created.id, plannedResources);
      if (attachmentFiles(req).length) await saveAttachments(client, attachmentFiles(req), {
        projectId: act.project_id, entityType: 'work_center_task', entityId: created.id, userId, role,
      }, uploads);

      await client.query(
        `INSERT INTO activity_weight_changes
           (project_id, activity_id, changed_by_id, changed_by_role, reason, before_weights, after_weights, progress_before, progress_after)
         VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8,$9)`,
        [act.project_id, activityId, userId, role, String(b.reason || 'Task added').trim(),
         JSON.stringify(existing.map((t) => ({ task_id: t.id, weight_pct: Number(t.weight_pct) }))),
         JSON.stringify([...existing.map((t, i) => ({ task_id: t.id, weight_pct: after[i] })), { task_id: created.id, weight_pct: newWeight }]),
         progressBefore, progressAfter]);

      await client.query(`UPDATE planning_execution SET progress_pct = $2, updated_at = NOW() WHERE id = $1`, [activityId, progressAfter]);
      await client.query('COMMIT');
      uploads.keepAll();
      notifyAssigned(deps, { projectId: act.project_id, userId, role }, act.title,
        [{ ...created, assigned_members: parseJson(created.assigned_members, [], 'assigned_members') }]).catch(() => {});
      return res.status(201).json({ success: true, task: created, ...visibleSummary });
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      await uploads.discard();
      return fail(res, err, 'POST /api/planning-execution/:activityId/tasks:');
    } finally { if (client) client.release(); }
  });

  async function activityDeletePreview(db, activity) {
    const tasks = (await db.query(
      `SELECT id, title FROM workspace_work_center
       WHERE activity_id = $1 AND project_id = $2 ORDER BY id`,
      [activity.id, activity.project_id])).rows;
    const kind = activity.baseline_milestone_id ? 'baseline'
      : activity.additional_milestone_id ? 'additional' : null;
    let remainingActivities = [];
    let weights = [];
    let sourceWeights = [];
    let progressBefore = null;
    let progressAfter = null;
    let milestoneTitle = null;
    if (kind && activity.drives_milestone) {
      const m = MILESTONE[kind];
      const milestone = (await db.query(
        `SELECT id, title FROM ${m.table} WHERE id = $1 AND project_id = $2`,
        [activity[`${kind}_milestone_id`], activity.project_id])).rows[0];
      milestoneTitle = milestone?.title || null;
      const activities = (await db.query(
        `SELECT id, title, drives_milestone, milestone_weight_pct, certified_progress_pct
         FROM planning_execution WHERE project_id = $1 AND ${m.col} = $2
         ORDER BY id`,
        [activity.project_id, activity[`${kind}_milestone_id`]])).rows;
      const remainingDrivers = activities.filter((row) =>
        row.drives_milestone && Number(row.id) !== Number(activity.id));
      const before = activities.filter((row) => row.drives_milestone);
      sourceWeights = before.map((row) => ({
        activity_id: Number(row.id),
        weight_pct: Number(row.milestone_weight_pct),
        certified_progress_pct: Number(row.certified_progress_pct),
      }));
      progressBefore = milestoneDerivedProgress(before);
      const rebalanced = rebalanceAfterRemoval(remainingDrivers.map((row) => Number(row.milestone_weight_pct)));
      remainingActivities = remainingDrivers.map((row, index) => ({
        activity_id: Number(row.id),
        title: row.title,
        before_weight_pct: Number(row.milestone_weight_pct),
        after_weight_pct: rebalanced[index],
      }));
      const weightsById = new Map(remainingActivities.map((row) => [row.activity_id, row.after_weight_pct]));
      progressAfter = milestoneDerivedProgress(remainingDrivers.map((row) => ({
        ...row,
        milestone_weight_pct: weightsById.get(Number(row.id)),
      })));
      weights = remainingActivities.map(({ activity_id, after_weight_pct }) => ({
        activity_id, weight_pct: after_weight_pct,
      }));
    }
    return {
      activity: { id: Number(activity.id), title: activity.title },
      task_count: tasks.length,
      tasks,
      milestone_title: milestoneTitle,
      remaining_activities: remainingActivities,
      expected_weights: weights,
      source_weights: sourceWeights,
      progress_before: progressBefore,
      progress_after: progressAfter,
    };
  }

  async function authorizeActivityDeletion(db, activity, projectId, userId, role) {
    if (!activity) throw new HttpError(404, 'Activity not found.');
    if (!isWCLeader(role) || wcSide(role) !== activity.side)
      throw new HttpError(403, 'Only a leader on this activity’s side can delete it.');
    if (!(await isMember(deps, projectId, userId, role)))
      throw new HttpError(403, 'You are not a member of this project.');
  }

  app.get('/api/planning-execution/:activityId/delete-preview', authenticateToken, async (req, res) => {
    try {
      const projectId = Number(req.query.projectId);
      const activityId = Number(req.params.activityId);
      if (!Number.isSafeInteger(projectId) || projectId < 1
        || !Number.isSafeInteger(activityId) || activityId < 1)
        throw new HttpError(400, 'projectId and activityId are required.');
      const activity = (await pool.query(
        `SELECT * FROM planning_execution WHERE id = $1 AND project_id = $2`,
        [activityId, projectId])).rows[0];
      await authorizeActivityDeletion(pool, activity, projectId, req.user.user_id, req.user.role);
      return res.json({ preview: await activityDeletePreview(pool, activity) });
    } catch (error) { return fail(res, error, 'GET activity delete preview:'); }
  });

  app.delete('/api/planning-execution/:activityId', authenticateToken,
    requireProjectLifecycleWrite, async (req, res) => {
    let client;
    try {
      const projectId = Number(req.body?.projectId);
      const activityId = Number(req.params.activityId);
      if (!Number.isSafeInteger(projectId) || projectId < 1
        || !Number.isSafeInteger(activityId) || activityId < 1)
        throw new HttpError(400, 'projectId and activityId are required.');
      client = await pool.connect();
      await client.query('BEGIN');
      const activity = (await client.query(
        `SELECT * FROM planning_execution WHERE id = $1 AND project_id = $2 FOR UPDATE`,
        [activityId, projectId])).rows[0];
      await authorizeActivityDeletion(client, activity, projectId, req.user.user_id, req.user.role);
      const kind = activity.baseline_milestone_id ? 'baseline'
        : activity.additional_milestone_id ? 'additional' : null;
      const milestoneId = kind ? Number(activity[`${kind}_milestone_id`]) : null;
      if (kind && activity.drives_milestone) {
        await client.query(`SELECT id FROM ${MILESTONE[kind].table} WHERE id = $1 FOR UPDATE`, [milestoneId]);
        await client.query(
          `SELECT id FROM planning_execution
           WHERE project_id = $1 AND ${MILESTONE[kind].col} = $2
           ORDER BY id FOR UPDATE`, [projectId, milestoneId]);
      }
      const preview = await activityDeletePreview(client, activity);
      const expectedWeights = req.body?.expectedWeights;
      const submittedWeights = new Map(Array.isArray(expectedWeights)
        ? expectedWeights.map((row) => [Number(row?.activity_id), row])
        : []);
      if (!Array.isArray(expectedWeights)
        || submittedWeights.size !== expectedWeights.length
        || submittedWeights.size !== preview.source_weights.length
        || preview.source_weights.some((expected) => {
          const submitted = submittedWeights.get(expected.activity_id);
          return !submitted
            || !Number.isFinite(Number(submitted.weight_pct))
            || !Number.isFinite(Number(submitted.certified_progress_pct))
            || Math.abs(Number(submitted.weight_pct) - expected.weight_pct) >= 0.0001
            || Math.abs(Number(submitted.certified_progress_pct) - expected.certified_progress_pct) >= 0.0001;
        })) {
        throw new HttpError(409, 'The activity or milestone weights changed. Review the updated preview before deleting.', {
          code: 'DELETE_PREVIEW_STALE',
          preview,
        });
      }

      const tasks = (await client.query(
        `SELECT id, title FROM workspace_work_center
         WHERE activity_id = $1 AND project_id = $2 ORDER BY id FOR UPDATE`,
        [activityId, projectId])).rows;
      const taskIds = tasks.map((row) => Number(row.id));
      for (const row of preview.remaining_activities) {
        await client.query(
          `UPDATE planning_execution SET milestone_weight_pct = $2, updated_at = NOW()
           WHERE id = $1 AND project_id = $3`,
          [row.activity_id, row.after_weight_pct, projectId]);
      }
      if (taskIds.length) {
        await client.query(
          `UPDATE planned_resources SET activity_id = NULL
           WHERE activity_id = $1 AND task_id = ANY($2::int[])`,
          [activityId, taskIds]);
        await client.query(
          `UPDATE workspace_work_center
           SET activity_type = COALESCE(activity_type, $2),
               standalone_unit = COALESCE(standalone_unit, $3),
               activity_id = NULL, updated_at = NOW()
           WHERE activity_id = $1 AND project_id = $4`,
          [activityId, activity.activity_type, activity.unit, projectId]);
        for (const task of tasks) {
          await client.query(
            `INSERT INTO work_center_task_history
               (task_id, project_id, actor_id, actor_role, action, detail)
             VALUES
               ($1,$2,$3,$4,'task_unlinked',$5::jsonb),
               ($1,$2,$3,$4,'activity_deleted',$6::jsonb)`,
            [task.id, projectId, req.user.user_id, req.user.role,
              JSON.stringify({ activity_id: activityId, summary: `Task "${task.title}" was unlinked from activity "${activity.title}". Reports, files and progress were retained.` }),
              JSON.stringify({ activity_id: activityId, summary: `Activity "${activity.title}" was deleted. Task "${task.title}" and its reports were retained.` })]);
        }
      }
      await client.query(`DELETE FROM planned_resources WHERE activity_id = $1 AND task_id IS NULL`, [activityId]);

      const assets = [];
      if (activity.linked_file_id) {
        const resourceType = activity.linked_file_url?.includes('/video/upload/') ? 'video'
          : activity.linked_file_url?.includes('/image/upload/') ? 'image' : 'raw';
        assets.push({ id: activity.linked_file_id, resourceType });
      }
      assets.push(...(await client.query(
        `SELECT file_id AS id, COALESCE(resource_type, 'raw') AS "resourceType"
         FROM card_attachments
         WHERE project_id = $1 AND entity_type = 'planning_activity' AND entity_id = $2`,
        [projectId, activityId])).rows);
      assets.push(...(await client.query(
        `SELECT attachment_id AS id, 'raw'::text AS "resourceType"
         FROM planning_execution_tracking
         WHERE activity_id = $1 AND attachment_id IS NOT NULL`,
        [activityId])).rows);
      assets.push(...(await client.query(
        `SELECT attachment->>'id' AS id,
                CASE
                  WHEN attachment->>'url' LIKE '%/video/upload/%' THEN 'video'
                  WHEN attachment->>'url' LIKE '%/image/upload/%' THEN 'image'
                  ELSE 'raw'
                END AS "resourceType"
         FROM activity_verifications verification
         CROSS JOIN LATERAL jsonb_array_elements(
           COALESCE(verification.attachments, '[]'::jsonb)
           || COALESCE(verification.decision_attachments, '[]'::jsonb)
         ) AS files(attachment)
         WHERE verification.activity_id = $1
           AND NULLIF(attachment->>'id', '') IS NOT NULL`,
        [activityId])).rows);
      await client.query(`DELETE FROM card_attachments
        WHERE project_id = $1 AND entity_type = 'planning_activity' AND entity_id = $2`,
      [projectId, activityId]);
      await client.query(`DELETE FROM planning_execution_tracking WHERE activity_id = $1`, [activityId]);
      const deleted = await client.query(
        `DELETE FROM planning_execution WHERE id = $1 AND project_id = $2 RETURNING id`,
        [activityId, projectId]);
      if (!deleted.rows.length) throw new HttpError(409, 'The activity changed before it could be deleted.');

      if (kind && activity.drives_milestone)
        await syncMilestone(client, kind, milestoneId, { id: req.user.user_id, role: req.user.role });
      await client.query('COMMIT');

      const cleanupErrors = [];
      const uniqueAssets = [...new Map(assets.filter((asset) => asset.id)
        .map((asset) => [`${asset.id}|${asset.resourceType}`, asset])).values()];
      if (uniqueAssets.length && !deps.cloudinary?.uploader) {
        cleanupErrors.push('File storage is unavailable.');
      } else {
        for (const asset of uniqueAssets) {
          try {
            const result = await deps.cloudinary.uploader.destroy(asset.id, { resource_type: asset.resourceType });
            if (!['ok', 'not found'].includes(result?.result))
              cleanupErrors.push(`Could not remove activity file ${asset.id} from storage.`);
          } catch (error) {
            console.error('Activity file cleanup failed:', error);
            cleanupErrors.push(`Could not remove activity file ${asset.id} from storage.`);
          }
        }
      }
      return res.json({
        success: true,
        unlinked_tasks: taskIds.length,
        cleanup_warning: cleanupErrors.length ? cleanupErrors.join(' ') : null,
      });
    } catch (error) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      return fail(res, error, 'DELETE /api/planning-execution/:activityId:');
    } finally { if (client) client.release(); }
  });

  app.delete('/api/work-center/:taskId', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
    let client;
    let committed = false;
    let assets = [];
    let activityAfter = null;
    try {
    const { user_id: userId, role } = req.user;
    if (!isWCLeader(role)) throw new HttpError(403, 'Only leaders and PMs can delete tasks.');
    const side = wcSide(role);
    if (!side) throw new HttpError(403, 'Cannot determine your side.');

    const taskId = Number(req.params.taskId);
    const projectId = Number(req.body?.projectId ?? req.query.projectId);
    if (!Number.isInteger(taskId) || taskId <= 0 || !Number.isInteger(projectId) || projectId <= 0)
      throw new HttpError(400, 'A valid taskId and projectId are required.');
    if (!(await isMember(deps, projectId, userId, role)))
      throw new HttpError(403, 'You are not a member of this project.');

    client = await pool.connect();
    await client.query('BEGIN');
    const task = (await client.query(
      `SELECT w.id, w.project_id, w.activity_id, w.side, w.title, w.linked_file_id,
              pe.project_id AS activity_project_id, pe.side AS activity_side,
              pe.status AS activity_status, pe.activity_type, pe.planned_quantity,
              pe.progress_pct AS activity_progress_pct, pe.baseline_milestone_id,
              pe.additional_milestone_id, pe.drives_milestone
       FROM workspace_work_center w
       JOIN planning_execution pe ON pe.id = w.activity_id
       WHERE w.id = $1 AND w.project_id = $2
       FOR UPDATE OF w, pe`, [taskId, projectId])).rows[0];
    if (!task) throw new HttpError(404, 'Task not found.');
    if (task.side !== side || task.activity_side !== side)
      throw new HttpError(403, 'You cannot delete tasks from another side.');
    if (Number(task.activity_project_id) !== projectId)
      throw new HttpError(409, 'The task and its activity belong to different projects.');
    if (task.activity_status === 'closed')
      throw new HttpError(409, 'Tasks in a closed activity cannot be deleted.');

    const siblings = (await client.query(
      `SELECT id, project_id, side, title, weight_pct
       FROM workspace_work_center
       WHERE activity_id = $1
       ORDER BY id
       FOR UPDATE`, [task.activity_id])).rows;
    if (siblings.some((sibling) => Number(sibling.project_id) !== projectId || sibling.side !== side))
      throw new HttpError(409, 'The activity contains tasks linked to a different project or side.');
    if (!weightsValid(siblings.map((sibling) => Number(sibling.weight_pct))))
      throw new HttpError(409, 'The activity task weights are invalid; fix the task breakdown before deleting a task.');

    const protectedRecords = (await client.query(
      `SELECT
         EXISTS (
           SELECT 1 FROM workspace_work_center_progress
           WHERE task_id = $1 AND validation_status IN ('approved', 'voided')
         ) AS has_final_reports,
         EXISTS (SELECT 1 FROM work_center_queries WHERE task_id = $1) AS has_queries,
         EXISTS (SELECT 1 FROM activity_verifications WHERE activity_id = $2) AS has_verifications,
         EXISTS (
           SELECT 1 FROM work_center_task_dependencies
           WHERE depends_on_task_id = $1 AND project_id = $3
         ) AS has_dependents,
         EXISTS (
           SELECT 1 FROM work_center_task_links
           WHERE link_type = 'task' AND target_id = $1::text AND project_id = $3
         ) AS has_linkers`,
      [taskId, task.activity_id, projectId])).rows[0];
    if (protectedRecords.has_final_reports)
      throw new HttpError(409, 'This task has approved or voided reports, which are part of the project record and cannot be deleted.');
    if (protectedRecords.has_queries)
      throw new HttpError(409, 'This task has question history, which is part of the project record and cannot be deleted.');
    if (protectedRecords.has_verifications)
      throw new HttpError(409, 'This activity has verification history; its task breakdown cannot be changed.');
    if (protectedRecords.has_dependents || protectedRecords.has_linkers)
      throw new HttpError(409, 'Another task refers to this task. Remove or update that reference before deleting it.');

    const remaining = siblings.filter((sibling) => Number(sibling.id) !== taskId);
    const weightsAfter = rebalanceAfterRemoval(remaining.map((sibling) => Number(sibling.weight_pct)));
    const reportDates = (await client.query(
      `SELECT DISTINCT to_char(p.report_date, 'YYYY-MM-DD') AS day
       FROM workspace_work_center_progress p
       JOIN workspace_work_center w ON w.id = p.task_id
       WHERE w.activity_id = $1`, [task.activity_id])).rows.map((row) => row.day);
    const reportAssets = (await client.query(
      `SELECT p.attachment_id AS file_id, 'raw'::text AS resource_type
       FROM workspace_work_center_progress p
       JOIN workspace_work_center w ON w.id = p.task_id
       WHERE w.id = $1 AND p.attachment_id IS NOT NULL
       UNION ALL
       SELECT ph.file_id, 'image'::text AS resource_type
       FROM work_center_report_photos ph
       JOIN workspace_work_center_progress p ON p.id = ph.report_id
       WHERE p.task_id = $1
       UNION ALL
       SELECT ra.file_id,
              CASE WHEN ra.mime_type LIKE 'image/%' THEN 'image'
                   WHEN ra.mime_type LIKE 'video/%' THEN 'video'
                   ELSE 'raw' END AS resource_type
       FROM work_center_report_attachments ra
       JOIN workspace_work_center_progress p ON p.id = ra.report_id
       WHERE p.task_id = $1`, [taskId])).rows;
    const taskAssets = (await client.query(
      `SELECT file_id, resource_type FROM card_attachments
       WHERE project_id = $1 AND entity_type = 'work_center_task' AND entity_id = $2`,
      [projectId, taskId])).rows;
    assets = [
      ...(task.linked_file_id ? [{ file_id: task.linked_file_id, resource_type: 'raw' }] : []),
      ...reportAssets,
      ...taskAssets,
    ].filter((asset) => asset.file_id && asset.resource_type);

    const beforeWeights = siblings.map((sibling) => ({
      task_id: Number(sibling.id),
      title: sibling.title,
      weight_pct: Number(sibling.weight_pct),
    }));
    const measured = task.activity_type === 'quantity' || task.activity_type === 'count';
    for (let index = 0; index < remaining.length; index++) {
      const weight = weightsAfter[index];
      const target = measured
        ? Math.round((Number(task.planned_quantity) * weight / 100 + Number.EPSILON) * 1000) / 1000
        : null;
      await client.query(
        `UPDATE workspace_work_center
         SET weight_pct = $2, target_quantity = $3, updated_at = NOW()
         WHERE id = $1`, [remaining[index].id, weight, target]);
    }

    const deleted = await client.query(
      `DELETE FROM workspace_work_center WHERE id = $1 AND project_id = $2 RETURNING id`,
      [taskId, projectId]);
    if (!deleted.rows.length) throw new HttpError(409, 'The task changed before it could be deleted.');

    const recomputed = await recomputeActivity(client, task.activity_id, {
      dates: reportDates,
      actor: { id: userId, role },
    });
    activityAfter = recomputed;
    await client.query(
      `INSERT INTO activity_weight_changes
         (project_id, activity_id, changed_by_id, changed_by_role, reason,
          before_weights, after_weights, progress_before, progress_after)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8,$9)`,
      [projectId, task.activity_id, userId, role, `Task deleted: ${task.title}`,
       JSON.stringify(beforeWeights),
       JSON.stringify(remaining.map((sibling, index) => ({
         task_id: Number(sibling.id), title: sibling.title, weight_pct: weightsAfter[index],
       }))),
       Number(task.activity_progress_pct) || 0, recomputed?.progress_pct ?? 0]);

    await client.query(
      `DELETE FROM card_attachments
       WHERE project_id = $1 AND entity_type = 'work_center_task' AND entity_id = $2`,
      [projectId, taskId]);

    if (task.drives_milestone && task.baseline_milestone_id)
      await syncMilestone(client, 'baseline', task.baseline_milestone_id, { id: userId, role });
    else if (task.drives_milestone && task.additional_milestone_id)
      await syncMilestone(client, 'additional', task.additional_milestone_id, { id: userId, role });

    await client.query('COMMIT');
    committed = true;
    } catch (err) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    return fail(res, err, 'DELETE /api/work-center/:taskId:');
    } finally {
    if (client) client.release();
    }

    const cleanupWarnings = [];
    if (assets.length && !deps.cloudinary?.uploader) {
    console.error(`[task cleanup] storage unavailable for ${assets.length} file(s) after task deletion.`);
    cleanupWarnings.push('Some task files could not be removed from storage.');
    } else if (committed && deps.cloudinary?.uploader) {
    const uniqueAssets = [...new Map(
      assets.map((asset) => [`${asset.resource_type}:${asset.file_id}`, asset])
    ).values()];
    await Promise.all(uniqueAssets.map(async (asset) => {
      try {
        const result = await deps.cloudinary.uploader.destroy(asset.file_id, { resource_type: asset.resource_type });
        if (!['ok', 'not found'].includes(result?.result)) {
          console.error('[task cleanup] could not delete', asset.file_id, result?.result || 'unknown result');
          cleanupWarnings.push('Some task files could not be removed from storage.');
        }
      } catch (err) {
        console.error('[task cleanup] could not delete', asset.file_id, err.message);
        cleanupWarnings.push('Some task files could not be removed from storage.');
      }
    }));
    }

    return res.json({
    success: true,
    message: 'Task deleted.',
    activity: activityAfter,
    ...(cleanupWarnings.length ? { warning: cleanupWarnings[0] } : {}),
    });
  });
}

return { MILESTONE, syncMilestone, registerActivityRoutes };
})();
const milestone = (() => {
  const { MILESTONE, syncMilestone } = activity;
// Milestone routes for milestones whose progress comes from contractor activities:
// breakdown request, the consultant's temporary value, a progress detail for the milestone card,
// and the completion check (also exported so the existing complete-milestone route can call it).
//
// Wiring in server.js:
//   import { registerMilestoneRoutes, milestoneCompletionCheck, assertTypedProgressAllowed } from './planningRoutes.js';
//   registerMilestoneRoutes(app, { pool, authenticateToken, requireProjectLifecycleWrite, wcSide, isWCLeader, notify, flowKey, leadersOf?, isProjectMember? });
//
// kind in the URL is "baseline" (milestones) or "additional" (additional_milestones).


class HttpError extends Error {
  constructor(status, message, extra = {}) { super(message); this.status = status; this.extra = extra; }
}
function fail(res, err, label) {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message, ...err.extra });
  if (err && err.code === '55000') return res.status(409).json({ error: err.message });
  console.error(label, err);
  return res.status(500).json({ error: 'Server error.' });
}

const kindOf = (k) => { if (!MILESTONE[k]) throw new HttpError(400, 'kind must be baseline or additional.'); return k; };
const fkCol = (kind) => (kind === 'baseline' ? 'baseline_milestone_id' : 'additional_milestone_id');

/** Used by the old typed-entry routes: refuse typing on a milestone driven by activities. */
async function assertTypedProgressAllowed(db, kind, milestoneId) {
  const m = MILESTONE[kind];
  const row = (await db.query(`SELECT progress_source FROM ${m.table} WHERE id = $1`, [milestoneId])).rows[0];
  if (row && row.progress_source === 'activities')
    throw new HttpError(409, 'This milestone takes its progress from its activities, so progress cannot be typed. A consultant can set a temporary lower value with a reason.');
}

/** Same rule as assertTypedProgressAllowed, but returns the message (or null) so old routes can answer with their own 409. */
async function typedProgressBlockedReason(db, kind, milestoneId) {
  const m = MILESTONE[kind];
  const row = (await db.query(`SELECT progress_source FROM ${m.table} WHERE id = $1`, [milestoneId])).rows[0];
  return row && row.progress_source === 'activities'
    ? 'This milestone takes its progress from its activities, so progress cannot be typed. A consultant can set a temporary lower value with a reason.'
    : null;
}

/** The completion check for the existing complete-milestone route. Typed (manual) milestones are not affected. */
async function milestoneCompletionCheck(db, kind, milestoneId) {
  const m = MILESTONE[kind];
  const ms = (await db.query(`SELECT progress_source, override_pct FROM ${m.table} WHERE id = $1`, [milestoneId])).rows[0];
  if (!ms || ms.progress_source !== 'activities') return { ok: true, reasons: [] };
  const activities = (await db.query(
    `SELECT status, drives_milestone, milestone_weight_pct, certified_progress_pct FROM planning_execution WHERE ${m.col} = $1`, [milestoneId])).rows;
  const open = (await db.query(`SELECT 1 FROM milestone_breakdown_requests WHERE ${fkCol(kind)} = $1 AND status = 'open'`, [milestoneId])).rows.length > 0;
  return canCompleteMilestone({ activities, breakdownOpen: open, overrideActive: ms.override_pct != null });
}

function registerMilestoneRoutes(app, deps) {
  const { pool, authenticateToken, requireProjectLifecycleWrite, wcSide, isWCLeader } = deps;
  const consultantLeader = (role) => isWCLeader(role) && wcSide(role) === 'Consultant';

  async function isMember(projectId, userId, role) {
    if (deps.isProjectMember) return deps.isProjectMember(projectId, userId, role);
    return (await pool.query(`SELECT 1 FROM assignments_view WHERE project_id = $1 AND role_id = $2 AND role = $3 LIMIT 1`, [projectId, userId, role])).rows.length > 0;
  }
  async function leadersOf(projectId, side) {
    if (deps.leadersOf) return deps.leadersOf(projectId, side);
    if (!deps.sideRoles) return [];
    const r = await pool.query(`SELECT role, role_id FROM assignments_view WHERE project_id = $1 AND role = ANY($2::text[])`, [projectId, deps.sideRoles(side)]);
    return r.rows.map((x) => deps.flowKey(x.role, x.role_id));
  }
  async function hasConsultantSide(projectId) {
    const roles = deps.sideRoles ? deps.sideRoles('Consultant') : ['Consultant', 'ConsultantPM'];
    const result = await pool.query(
      `SELECT 1 FROM assignments_view WHERE project_id = $1 AND role = ANY($2::text[]) LIMIT 1`,
      [projectId, roles]);
    return result.rows.length > 0;
  }
  async function tell(projectId, entityId, entityType, message, actor, side) {
    if (!deps.notify) return;
    try {
      const recipients = await leadersOf(projectId, side);
      if (recipients.length) await deps.notify({ projectId, entityId, entityType, message, actorId: actor.id, actorRole: actor.role, recipients });
    } catch (err) { console.error('[milestone] notification failed (non-fatal):', err.message); }
  }

  // open a transaction on a derived milestone owned by a project the user belongs to
  async function withMilestone(req, kind, fn) {
    const { user_id: userId, role } = req.user;
    const m = MILESTONE[kind];
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const ms = (await client.query(`SELECT * FROM ${m.table} WHERE id = $1 FOR UPDATE`, [parseInt(req.params.id, 10)])).rows[0];
      if (!ms) throw new HttpError(404, 'Milestone not found.');
      const projectId = parseInt(ms.project_id, 10);
      if (!(await isMember(projectId, userId, role))) throw new HttpError(403, 'You are not a member of this project.');
      if (ms.progress_source !== 'activities') throw new HttpError(409, 'This milestone is not linked to activities.');
      const out = await fn(client, ms, projectId, { id: userId, role });
      await client.query('COMMIT');
      return out;
    } catch (err) { await client.query('ROLLBACK').catch(() => {}); throw err; } finally { client.release(); }
  }

  // Consultant asks the contractor to break the work down into more activities.
  app.post('/api/milestones/:kind/:id/breakdown-request', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
    try {
      if (!consultantLeader(req.user.role)) throw new HttpError(403, 'Only consultant leaders and PMs can request a breakdown.');
      const kind = kindOf(req.params.kind);
      const note = String(req.body?.note || '').trim();
      if (!note) throw new HttpError(400, 'A note is required, for example how the work should be split.');
      const out = await withMilestone(req, kind, async (client, ms, projectId, actor) => {
        let row;
        try {
          row = (await client.query(
            `INSERT INTO milestone_breakdown_requests (project_id, ${fkCol(kind)}, note, requested_by_id, requested_by_role)
             VALUES ($1,$2,$3,$4,$5) RETURNING *`, [projectId, ms.id, note, actor.id, actor.role])).rows[0];
        } catch (err) { if (err.code === '23505') throw new HttpError(409, 'A breakdown request is already open on this milestone.'); throw err; }
        const progress = await syncMilestone(client, kind, ms.id, actor);
        return { request: row, milestone: progress, projectId, title: ms.title };
      });
      await tell(out.projectId, out.request.id, 'milestone_breakdown_request',
        `The consultant asked for a breakdown of milestone "${out.title}": ${note}`, { id: req.user.user_id, role: req.user.role }, 'Contractor');
      return res.status(201).json({ success: true, request: out.request, milestone: out.milestone });
    } catch (err) { return fail(res, err, 'POST breakdown-request:'); }
  });

  app.put('/api/milestones/:kind/:id/breakdown-request/withdraw', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
    try {
      if (!consultantLeader(req.user.role)) throw new HttpError(403, 'Only consultant leaders and PMs can withdraw a breakdown request.');
      const kind = kindOf(req.params.kind);
      const out = await withMilestone(req, kind, async (client, ms, _projectId, actor) => {
        const r = await client.query(
          `UPDATE milestone_breakdown_requests SET status = 'withdrawn', closed_at = NOW(), closed_by_id = $2, closed_by_role = $3, close_reason = $4
           WHERE ${fkCol(kind)} = $1 AND status = 'open' RETURNING *`, [ms.id, actor.id, actor.role, String(req.body?.reason || '').trim() || 'Withdrawn by the consultant']);
        if (!r.rows.length) throw new HttpError(409, 'There is no open breakdown request on this milestone.');
        return { request: r.rows[0], milestone: await syncMilestone(client, kind, ms.id, actor) };
      });
      return res.json({ success: true, ...out });
    } catch (err) { return fail(res, err, 'PUT breakdown-request/withdraw:'); }
  });

  // Consultant's temporary value: lowers the milestone until corrected work is verified, or he withdraws it.
  app.post('/api/milestones/:kind/:id/override', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
    try {
      if (!consultantLeader(req.user.role)) throw new HttpError(403, 'Only consultant leaders and PMs can set a temporary value.');
      const kind = kindOf(req.params.kind);
      const out = await withMilestone(req, kind, async (client, ms, projectId, actor) => {
        const derived = Number(ms.derived_progress_pct);
        const problem = checkOverride({ value: req.body?.value, derived, reason: req.body?.reason });
        if (problem) throw new HttpError(400, problem);
        const value = Number(req.body.value), reason = String(req.body.reason).trim();
        await client.query(
          `UPDATE milestone_progress_overrides SET ended_at = NOW(), ended_reason = 'replaced_by_new_value' WHERE ${fkCol(kind)} = $1 AND ended_at IS NULL`, [ms.id]);
        const hist = (await client.query(
          `INSERT INTO milestone_progress_overrides (project_id, ${fkCol(kind)}, set_pct, derived_pct_at_time, reason, set_by_id, set_by_role)
           VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`, [projectId, ms.id, value, derived, reason, actor.id, actor.role])).rows[0];
        await client.query(
          `UPDATE ${MILESTONE[kind].table} SET override_pct = $2, override_reason = $3, override_by_id = $4, override_by_role = $5, override_at = NOW() WHERE id = $1`,
          [ms.id, value, reason, actor.id, actor.role]);
        return { override: hist, milestone: await syncMilestone(client, kind, ms.id, actor), projectId, title: ms.title };
      });
      await tell(out.projectId, out.override.id, 'milestone_override',
        `The consultant set milestone "${out.title}" to ${out.override.set_pct}% for now: ${out.override.reason}`, { id: req.user.user_id, role: req.user.role }, 'Contractor');
      return res.status(201).json({ success: true, override: out.override, milestone: out.milestone });
    } catch (err) { return fail(res, err, 'POST override:'); }
  });

  app.put('/api/milestones/:kind/:id/override/withdraw', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
    try {
      if (!consultantLeader(req.user.role)) throw new HttpError(403, 'Only consultant leaders and PMs can withdraw a temporary value.');
      const kind = kindOf(req.params.kind);
      const out = await withMilestone(req, kind, async (client, ms, _projectId, actor) => {
        const r = await client.query(
          `UPDATE milestone_progress_overrides SET ended_at = NOW(), ended_reason = 'withdrawn' WHERE ${fkCol(kind)} = $1 AND ended_at IS NULL RETURNING *`, [ms.id]);
        if (!r.rows.length) throw new HttpError(409, 'There is no temporary value on this milestone.');
        await client.query(
          `UPDATE ${MILESTONE[kind].table} SET override_pct = NULL, override_reason = NULL, override_by_id = NULL, override_by_role = NULL, override_at = NULL WHERE id = $1`, [ms.id]);
        return { milestone: await syncMilestone(client, kind, ms.id, actor) };
      });

      app.post('/api/milestones/:kind/:id/progress-request', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
        try {
          const { user_id: userId, role } = req.user;
          if (!leaderOn(role, 'Contractor'))
            throw new HttpError(403, 'Only contractor leaders and PMs can request consultant milestone progress.');
          const kind = kindOf(req.params.kind);
          const milestone = MILESTONE[kind];
          const row = (await pool.query(
            `SELECT id, project_id, title, progress_source FROM ${milestone.table} WHERE id = $1`,
            [parseInt(req.params.id, 10)])).rows[0];
          if (!row) throw new HttpError(404, 'Milestone not found.');
          const projectId = parseInt(row.project_id, 10);
          if (!(await isMember(projectId, userId, role)))
            throw new HttpError(403, 'You are not a member of this project.');
          if (!(await hasConsultantSide(projectId)))
            throw new HttpError(409, 'This project has no consultant assigned.');
          if (row.progress_source === 'activities')
            throw new HttpError(409, 'This milestone already gets progress from its activities.');
          const note = String(req.body?.note || '').trim();
          if (note.length > 500) throw new HttpError(400, 'The note cannot exceed 500 characters.');
          const recipients = await leadersOf(projectId, 'Consultant');
          if (!recipients.length) throw new HttpError(409, 'No consultant leader is assigned to this project.');

          let request;
          try {
            request = (await pool.query(
              `INSERT INTO milestone_progress_requests
                 (project_id, ${fkCol(kind)}, requested_by_id, requested_by_role, note)
               VALUES ($1,$2,$3,$4,$5) RETURNING *`,
              [projectId, row.id, userId, role, note || null])).rows[0];
          } catch (err) {
            if (err.code === '23505') throw new HttpError(409, 'A consultant progress request is already open for this milestone.');
            throw err;
          }

          await tell(projectId, request.id, 'milestone_progress_request',
            `The contractor asked the consultant to record progress for milestone "${row.title}".${note ? ` Note: ${note}` : ''}`,
            { id: userId, role }, 'Consultant');
          return res.status(201).json({ success: true, request });
        } catch (err) { return fail(res, err, 'POST milestone progress request:'); }
      });
      return res.json({ success: true, ...out });
    } catch (err) { return fail(res, err, 'PUT override/withdraw:'); }
  });

  // List of the project's schedule milestones (baseline and additional) for the activity form.
  // (The dashboard already called this path, but no such route existed, so its suggestions were always empty.)
  app.get('/api/project-milestones', authenticateToken, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const projectId = parseInt(req.query.projectId, 10);
      if (!projectId) throw new HttpError(400, 'projectId is required.');
      if (!(await isMember(projectId, userId, role))) throw new HttpError(403, 'You are not a member of this project.');
      const pick = (kind, table) => pool.query(
        `SELECT id, title, planned_start, planned_end, quantity, unit, progress_source, progress_pct, executed, activity_status
         FROM ${table} WHERE project_id = $1::text ORDER BY planned_start, id`, [String(projectId)])
        .then((r) => r.rows.map((x) => ({
          id: x.id, kind, title: x.title, planned_start: x.planned_start, planned_end: x.planned_end,
          quantity: x.quantity == null ? null : Number(x.quantity), unit: x.unit,
          progress_source: x.progress_source, progress_pct: Number(x.progress_pct), executed: Number(x.executed),
          completed: x.activity_status === 'completed',
          typed_progress: x.progress_source === 'manual' && (Number(x.executed) > 0 || Number(x.progress_pct) > 0),
        })));
      const [baseline, additional] = await Promise.all([pick('baseline', 'milestones'), pick('additional', 'additional_milestones')]);
      return res.json({ milestones: [...baseline, ...additional] });
    } catch (err) { return fail(res, err, 'GET /api/project-milestones:'); }
  });

  // Progress detail for the milestone card. The client side only ever receives certified figures.
  app.get('/api/milestones/:kind/:id/progress-detail', authenticateToken, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const kind = kindOf(req.params.kind);
      const m = MILESTONE[kind];
      const ms = (await pool.query(`SELECT * FROM ${m.table} WHERE id = $1`, [parseInt(req.params.id, 10)])).rows[0];
      if (!ms) throw new HttpError(404, 'Milestone not found.');
      if (!(await isMember(parseInt(ms.project_id, 10), userId, role))) throw new HttpError(403, 'You are not a member of this project.');
      const viewerSide = role === 'TeamMember' ? 'Contractor' : (wcSide(role) || 'Client');
      const acts = (await pool.query(
        `SELECT id, title, side, status, drives_milestone, milestone_weight_pct, progress_pct, certified_progress_pct, certified_at,
                (SELECT COUNT(*)::int FROM activity_verifications v WHERE v.activity_id = pe.id AND v.status = 'pending') AS pending_requests
         FROM planning_execution pe WHERE ${m.col} = $1 ORDER BY id`, [ms.id])).rows;
      const breakdown = (await pool.query(
        `SELECT id, note, requested_at FROM milestone_breakdown_requests WHERE ${fkCol(kind)} = $1 AND status = 'open'`, [ms.id])).rows[0] || null;
      const override = ms.override_pct == null ? null : { value: Number(ms.override_pct), reason: ms.override_reason, set_at: ms.override_at, set_by_role: ms.override_by_role };
      const completion = await milestoneCompletionCheck(pool, kind, ms.id);
      const activities = acts.map((a) => ({
        id: a.id, title: a.title, side: a.side, status: a.status, drives_milestone: a.drives_milestone,
        weight_pct: Number(a.milestone_weight_pct),
        ...visibleProgress(viewerSide, { claimed: a.progress_pct, certified: a.certified_progress_pct, lastVerifiedAt: a.certified_at, pendingRequests: a.pending_requests }),
      }));
      return res.json({
        id: ms.id, kind, title: ms.title, progress_source: ms.progress_source,
        progress_pct: Number(ms.progress_pct), derived_progress_pct: Number(ms.derived_progress_pct),
        coverage_pct: milestoneCoverage(acts), activities, breakdown_request: breakdown,
        temporary_value: override, can_complete: completion,
      });
    } catch (err) { return fail(res, err, 'GET progress-detail:'); }
  });
}

  return { assertTypedProgressAllowed, typedProgressBlockedReason, milestoneCompletionCheck, registerMilestoneRoutes };
})();

export const { MILESTONE, syncMilestone, registerActivityRoutes } = activity;
export const { assertTypedProgressAllowed, typedProgressBlockedReason, milestoneCompletionCheck, registerMilestoneRoutes } = milestone;
