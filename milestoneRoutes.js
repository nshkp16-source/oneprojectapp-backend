// Milestone routes for milestones whose progress comes from contractor activities:
// breakdown request, the consultant's temporary value, a progress detail for the milestone card,
// and the completion check (also exported so the existing complete-milestone route can call it).
//
// Wiring in server.js:
//   import { registerMilestoneRoutes, milestoneCompletionCheck, assertTypedProgressAllowed } from './milestoneRoutes.js';
//   registerMilestoneRoutes(app, { pool, authenticateToken, requireProjectLifecycleWrite, wcSide, isWCLeader, notify, flowKey, leadersOf?, isProjectMember? });
//
// kind in the URL is "baseline" (milestones) or "additional" (additional_milestones).

import {
  checkOverride, canCompleteMilestone, milestoneCoverage, visibleProgress,
} from './progressRules.js';
import { MILESTONE, syncMilestone } from './activityRoutes.js';

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
export async function assertTypedProgressAllowed(db, kind, milestoneId) {
  const m = MILESTONE[kind];
  const row = (await db.query(`SELECT progress_source FROM ${m.table} WHERE id = $1`, [milestoneId])).rows[0];
  if (row && row.progress_source === 'activities')
    throw new HttpError(409, 'This milestone takes its progress from its activities, so progress cannot be typed. A consultant can set a temporary lower value with a reason.');
}

/** Same rule as assertTypedProgressAllowed, but returns the message (or null) so old routes can answer with their own 409. */
export async function typedProgressBlockedReason(db, kind, milestoneId) {
  const m = MILESTONE[kind];
  const row = (await db.query(`SELECT progress_source FROM ${m.table} WHERE id = $1`, [milestoneId])).rows[0];
  return row && row.progress_source === 'activities'
    ? 'This milestone takes its progress from its activities, so progress cannot be typed. A consultant can set a temporary lower value with a reason.'
    : null;
}

/** The completion check for the existing complete-milestone route. Typed (manual) milestones are not affected. */
export async function milestoneCompletionCheck(db, kind, milestoneId) {
  const m = MILESTONE[kind];
  const ms = (await db.query(`SELECT progress_source, override_pct FROM ${m.table} WHERE id = $1`, [milestoneId])).rows[0];
  if (!ms || ms.progress_source !== 'activities') return { ok: true, reasons: [] };
  const activities = (await db.query(
    `SELECT status, drives_milestone, milestone_weight_pct, certified_progress_pct FROM planning_execution WHERE ${m.col} = $1`, [milestoneId])).rows;
  const open = (await db.query(`SELECT 1 FROM milestone_breakdown_requests WHERE ${fkCol(kind)} = $1 AND status = 'open'`, [milestoneId])).rows.length > 0;
  return canCompleteMilestone({ activities, breakdownOpen: open, overrideActive: ms.override_pct != null });
}

export function registerMilestoneRoutes(app, deps) {
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
