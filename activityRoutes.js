// Routes for activities and their tasks: create an activity together with its tasks, add a task later
// with a weight preview, and keep a linked schedule milestone in step.
//
// Wiring in server.js (after the other planning-execution routes, so these win over the old create route):
//
//   import { registerActivityRoutes } from './activityRoutes.js';
//   registerActivityRoutes(app, {
//     pool, authenticateToken, upload, requireProjectLifecycleWrite, scheduleCloudinaryUpload,
//     wcSide, isWCLeader,
//     notify: ({ projectId, entityId, entityType, message, actorId, actorRole, recipients }) =>
//       notifyRecordUsers({ projectId, recordId: entityId, table: entityType, message, actorId, actorRole, recipients }),
//     flowKey,
//   });
//
// All rules (weights, defaults, caps) come from progressRules.js. This file only does I/O.

import {
  ACTIVITY_TYPES, splitEqual, weightsValid, rebalanceForNew,
  activityProgress, milestoneDerivedProgress, milestoneCoverage, effectiveMilestoneProgress, delayDays,
} from './progressRules.js';

const isDate = (v) => /^\d{4}-\d{2}-\d{2}$/.test(String(v || '')) && !Number.isNaN(Date.parse(String(v)));
// pg returns DATE columns as local-midnight Date objects: format them without shifting the day
const dateOnly = (v) => {
  if (v instanceof Date) return `${v.getFullYear()}-${String(v.getMonth() + 1).padStart(2, '0')}-${String(v.getDate()).padStart(2, '0')}`;
  return String(v || '').slice(0, 10);
};
const round3 = (x) => Math.round((Number(x) + Number.EPSILON) * 1000) / 1000;

const DEFAULT_TYPE = { Contractor: 'quantity', Consultant: 'count', Client: 'stages' };

export const MILESTONE = {
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

// ── milestone sync ───────────────────────────────────────────────────────────

/**
 * Recompute a derived milestone from the certified progress of its contractor activities and write the
 * figure the schedule reads (progress_pct). Also resolves an open breakdown request once the activities
 * give full coverage with at least two activities. Call it inside the caller's transaction.
 */
export async function syncMilestone(client, kind, milestoneId, actor = null) {
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
     JSON.stringify(drivers.map((a) => ({ activity_id: a.id, weight_pct: Number(a.milestone_weight_pct), certified_progress_pct: Number(a.certified_progress_pct) })))]);

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

async function insertTask(client, ctx, task, share, stages) {
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
       start_date, end_date, creator_id, creator_role, side, activity_id, weight_pct, target_quantity)
    VALUES ($1,$2,$3,$4,$5::jsonb,$6,'ongoing',$7,$8,$9,$10,$11,$12,$13,$14)
    RETURNING *`,
    [ctx.projectId, String(task.title).trim(), task.description || '', task.work_package || '',
     JSON.stringify(members), task.priority || 'normal', start, end,
     ctx.userId, ctx.role, ctx.side, ctx.activityId, share.weight_pct, share.target_quantity])).rows[0];

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

export function registerActivityRoutes(app, deps) {
  const { pool, authenticateToken, upload, requireProjectLifecycleWrite, scheduleCloudinaryUpload, wcSide, isWCLeader } = deps;

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
        `SELECT id, project_id, side, creator_id, milestone_name, title, description, start_date, end_date,
                planned_quantity, unit, status, activity_type, done_when, planned_work,
                planned_manpower, planned_equipment, planned_materials, progress_pct,
                certified_progress_pct, certified_at, baseline_milestone_id, additional_milestone_id,
                drives_milestone, milestone_weight_pct, actual_end
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
      const taskRows = clientView ? [] : (await pool.query(
        `SELECT id, title, description, assigned_members, status, start_date, end_date,
                weight_pct, target_quantity, progress_pct
         FROM workspace_work_center WHERE activity_id = $1 ORDER BY id`, [activityId])).rows;
      const stages = clientView ? [] : (await pool.query(
        `SELECT s.id, s.task_id, s.seq, s.title, s.weight_pct, s.is_hold_point,
                s.completed_at, s.hold_verified_at
         FROM task_stages s JOIN workspace_work_center w ON w.id = s.task_id
         WHERE w.activity_id = $1 ORDER BY s.task_id, s.seq`, [activityId])).rows;
      const stagesByTask = new Map();
      for (const stage of stages) {
        if (!stagesByTask.has(stage.task_id)) stagesByTask.set(stage.task_id, []);
        stagesByTask.get(stage.task_id).push(stage);
      }
      return res.json({
        activity: {
          ...activity,
          progress_pct: clientView ? null : Number(activity.progress_pct) || 0,
          status: clientView ? null : activity.status,
          claimed_progress_pct: clientView ? null : Number(activity.progress_pct) || 0,
          certified_progress_pct: Number(activity.certified_progress_pct) || 0,
        },
        tasks: taskRows.map((task) => ({
          ...task,
          assigned_members: parseJson(task.assigned_members, [], 'assigned_members'),
          progress_pct: clientView ? null : Number(task.progress_pct) || 0,
          weight_pct: Number(task.weight_pct) || 0,
          target_quantity: task.target_quantity == null ? null : Number(task.target_quantity),
          stages: stagesByTask.get(task.id) || [],
        })),
        can_add_task: isWCLeader(role) && activity.side === viewerSide && activity.status !== 'closed',
        can_edit_activity: isWCLeader(role) && String(activity.creator_id) === String(userId) && activity.status !== 'closed',
        viewer_side: viewerSide,
      });
    } catch (err) { return fail(res, err, 'GET /api/planning-execution/:activityId/activity-card:'); }
  });

  app.put('/api/planning-execution/:activityId/plan', authenticateToken,
    upload.single('linked_file'), requireProjectLifecycleWrite, async (req, res) => {
    let client;
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
        file = await scheduleCloudinaryUpload(req.file.buffer, req.file.originalname, 'planning_execution/plans');
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

      if (measured && tasks.length) {
        for (const task of tasks) {
          await client.query(
            `UPDATE workspace_work_center SET target_quantity = $2, updated_at = NOW() WHERE id = $1`,
            [task.id, Math.round((plannedQuantity * Number(task.weight_pct) / 100 + Number.EPSILON) * 1000) / 1000]);
        }
      }
      await client.query('COMMIT');
      return res.json({ success: true, activity: updated });
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      return fail(res, err, 'PUT /api/planning-execution/:activityId/plan:');
    } finally { if (client) client.release(); }
  });

  // Create an activity, its tasks (with weights and stages) and the milestone link in one transaction.
  app.post('/api/planning-execution/create-with-tasks', authenticateToken,
    upload.single('linked_file'), requireProjectLifecycleWrite, async (req, res) => {
    let client;
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
      if (req.file) {
        const up = await scheduleCloudinaryUpload(req.file.buffer, req.file.originalname, 'planning_execution/plans');
        file = { name: req.file.originalname, id: up.public_id, url: up.secure_url };
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
          `SELECT id, title, progress_source, executed, progress_pct, quantity, unit FROM ${m.table}
           WHERE id = $1 AND project_id = $2::text FOR UPDATE`, [milestoneId, String(projectId)])).rows[0];
        if (!ms) throw new HttpError(400, 'That milestone does not belong to this project.');
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
        [projectId, side, milestoneTitle || String(b.milestone_name || '').trim() || null,
         String(b.title).trim(), b.description || '', b.start_date, b.end_date,
         planned, unit, b.planned_work || '', b.planned_manpower || '', b.planned_equipment || '', b.planned_materials || '',
         file.name, file.id, file.url, userId, role,
         type, String(b.done_when || '').trim() || null, baselineId, additionalId, milestoneWeight])).rows[0];

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
      notifyAssigned(deps, { projectId, userId, role }, activity.title,
        tasks.map((t) => ({ ...t, assigned_members: parseJson(t.assigned_members, [], 'assigned_members') }))).catch(() => {});
      return res.status(201).json({ success: true, activity, tasks, milestone });
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      return fail(res, err, 'POST /api/planning-execution/create-with-tasks:');
    } finally { if (client) client.release(); }
  });

  // Add a task to an existing activity. With preview=true nothing is written: the response shows the
  // weights and the activity progress before and after, so the leader can confirm.
  app.post('/api/planning-execution/:activityId/tasks', authenticateToken,
    requireProjectLifecycleWrite, async (req, res) => {
    let client;
    try {
      const { user_id: userId, role } = req.user;
      if (!isWCLeader(role)) throw new HttpError(403, 'Only leaders and PMs can add tasks.');
      const side = wcSide(role);
      const activityId = parseInt(req.params.activityId, 10);
      const b = req.body || {};
      const task = b.task || {};
      if (!String(task.title || '').trim()) throw new HttpError(400, 'The task needs a title.');
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
      if (preview) { await client.query('ROLLBACK'); return res.json({ preview: true, ...summary }); }

      const needsTarget = act.activity_type === 'quantity' || act.activity_type === 'count';
      const planned = Number(act.planned_quantity);
      const stages = act.activity_type === 'stages' ? validateStages(task.stages) : [];
      for (let i = 0; i < existing.length; i++) {
        await client.query(
          `UPDATE workspace_work_center SET weight_pct = $2, target_quantity = $3, updated_at = NOW() WHERE id = $1`,
          [existing[i].id, after[i], needsTarget ? round3((planned * after[i]) / 100) : null]);
      }
      const newWeight = after[after.length - 1];
      const ctx = { projectId: act.project_id, side, userId, role, activityId, type: act.activity_type,
                    start_date: dateOnly(act.start_date), end_date: dateOnly(act.end_date) };
      const created = await insertTask(client, ctx, task,
        { weight_pct: newWeight, target_quantity: needsTarget ? round3((planned * newWeight) / 100) : null }, stages);

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
      notifyAssigned(deps, { projectId: act.project_id, userId, role }, act.title,
        [{ ...created, assigned_members: parseJson(created.assigned_members, [], 'assigned_members') }]).catch(() => {});
      return res.status(201).json({ success: true, task: created, ...summary });
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      return fail(res, err, 'POST /api/planning-execution/:activityId/tasks:');
    } finally { if (client) client.release(); }
  });
}
