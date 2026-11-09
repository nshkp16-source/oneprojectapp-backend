// Consultant verification: requests, answers, certified progress, rework, hold points and completion certification.
//
// Flow
//   1. A contractor leader requests verification of an activity (progress up to a date, a hold point, or completion).
//      The request freezes the claimed figures and gets a respond-by date (project setting, default 7 days).
//   2. A named consultant inspector (team member) may recommend first, then a consultant leader decides:
//        verified | verified_with_changes (own figure and reason) | rejected (reason and rework).
//   3. A decision on progress sets the activity's certified progress and re-syncs the linked milestone.
//      A verified decision also ends the consultant's temporary milestone value, if one is active.
//   4. A verified completion closes the activity (and its tasks). If the consultant lists snags, the activity
//      closes automatically when the last snag is closed.
//
// Wiring in server.js:
//
//   import { registerVerificationRoutes } from './verificationRoutes.js';
//   registerVerificationRoutes(app, {
//     pool, authenticateToken, upload, requireProjectLifecycleWrite, scheduleCloudinaryUpload,
//     wcSide, isWCLeader, sideRoles, notify, flowKey,     // same dependencies as workCenterRoutes.js
//   });

import { certifiedAfterDecision, respondByDate } from './progressRules.js';
import { syncMilestone } from './planningRoutes.js';

class HttpError extends Error {
  constructor(status, message, extra = {}) { super(message); this.status = status; this.extra = extra; }
}
function fail(res, err, label) {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message, ...err.extra });
  if (err && err.code === '55000') return res.status(409).json({ error: err.message });   // a database rule said no
  console.error(label, err);
  return res.status(500).json({ error: 'Server error.' });
}

const isDate = (v) => /^\d{4}-\d{2}-\d{2}$/.test(String(v || '')) && !Number.isNaN(Date.parse(String(v)));
const dateOnly = (v) => (v instanceof Date
  ? `${v.getFullYear()}-${String(v.getMonth() + 1).padStart(2, '0')}-${String(v.getDate()).padStart(2, '0')}`
  : String(v || '').slice(0, 10));

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
  try { await deps.notify(args); } catch (err) { console.error('[verification] notification failed (non-fatal):', err.message); }
}

/** Close an activity (and its tasks) once completion is certified and nothing is open. Returns true when closed. */
export async function closeIfCertified(client, activityId, actor) {
  const act = (await client.query(`SELECT id, status, side FROM planning_execution WHERE id = $1 FOR UPDATE`, [activityId])).rows[0];
  if (!act || act.status === 'closed') return false;
  const certified = (await client.query(
    `SELECT 1 FROM activity_verifications WHERE activity_id = $1 AND kind = 'completion' AND status IN ('verified','verified_with_changes') LIMIT 1`, [activityId])).rows.length > 0;
  if (!certified) return false;
  const open = (await client.query(`SELECT 1 FROM rework_items WHERE activity_id = $1 AND status <> 'closed' LIMIT 1`, [activityId])).rows.length > 0;
  if (open) return false;
  await client.query(
    `UPDATE planning_execution
     SET status = 'closed', closed_at = NOW(), closed_by_id = $2, closed_by_role = $3,
         actual_end = CURRENT_DATE, certified_progress_pct = 100, certified_at = NOW(), updated_at = NOW()
     WHERE id = $1`, [activityId, actor.id, actor.role]);
  await client.query(
    `UPDATE workspace_work_center SET status = 'closed', closed_at = NOW(), closed_by_id = $2, closed_by_role = $3, updated_at = NOW()
     WHERE activity_id = $1 AND status <> 'closed'`, [activityId, actor.id, actor.role]);
  return true;
}

async function syncLinkedMilestone(client, act, actor) {
  const kind = act.baseline_milestone_id ? 'baseline' : act.additional_milestone_id ? 'additional' : null;
  if (!kind || !act.drives_milestone) return null;
  const id = act.baseline_milestone_id || act.additional_milestone_id;
  const table = kind === 'baseline' ? 'milestones' : 'additional_milestones';
  const col = kind === 'baseline' ? 'baseline_milestone_id' : 'additional_milestone_id';
  return { kind, id, table, col };
}

async function certifiedProgressWithSnagCaps(client, activityId, proposedProgress) {
  const { rows } = await client.query(
    `SELECT MIN(certified_progress_pct) AS cap
     FROM rework_items
     WHERE activity_id = $1 AND kind = 'snag' AND status <> 'closed'
       AND certified_progress_pct IS NOT NULL`, [activityId]);
  return rows[0].cap == null
    ? Number(proposedProgress)
    : Math.min(Number(proposedProgress), Number(rows[0].cap));
}

const MAX_SHARED_EVIDENCE_REPORTS = 200;

// Read receipt columns for a verification row aliased "v": when the consultant side first opened it, and by which role.
const SEEN_SQL = `(SELECT MIN(rd.first_read_at) FROM verification_reads rd WHERE rd.verification_id = v.id) AS seen_at,
                (SELECT rd.reader_role FROM verification_reads rd WHERE rd.verification_id = v.id
                  ORDER BY rd.first_read_at, rd.reader_id LIMIT 1) AS seen_by_role`;

const markRead = (db, verificationId, projectId, role, userId) => db.query(
  `INSERT INTO verification_reads (verification_id, project_id, reader_role, reader_id) VALUES ($1,$2,$3,$4)
   ON CONFLICT (verification_id, reader_role, reader_id) DO UPDATE SET last_read_at = NOW()
   RETURNING first_read_at, last_read_at`, [verificationId, projectId, role, userId]);

/** Frozen copy of approved report details and supporting attachments for consultant review.
 *  No member identity, private notes, or task ids are included. */
async function buildSharedEvidence(client, activityId, cutOff, includeReports) {
  const rows = (await client.query(
    `SELECT p.id, w.title AS task_title, p.report_date, p.work_done, p.quantity_done, p.quantity_failed,
            p.progress_pct, p.manpower, p.equipment, p.materials, p.issues, s.title AS stage_title,
            p.attachment_name, p.attachment_url,
            COALESCE((SELECT json_agg(json_build_object('file_name', ph.file_name, 'file_url', ph.file_url, 'captured_at', ph.captured_at)
                      ORDER BY ph.seq) FROM work_center_report_photos ph WHERE ph.report_id = p.id), '[]'::json) AS photos,
            COALESCE((SELECT json_agg(json_build_object('resource_type', rr.resource_type, 'name', rr.name,
                      'quantity', rr.quantity, 'unit', rr.unit, 'hours', rr.hours) ORDER BY rr.id)
                      FROM work_center_report_resources rr WHERE rr.report_id = p.id), '[]'::json) AS resources,
            COALESCE((SELECT json_agg(json_build_object(
              'file_name', a.file_name, 'file_url', a.file_url, 'mime_type', a.mime_type,
              'attachment_type', a.attachment_type, 'custom_attachment_type', a.custom_attachment_type
            ) ORDER BY a.created_at, a.id) FROM work_center_report_attachments a
              WHERE a.report_id = p.id AND a.project_id = w.project_id), '[]'::json) AS supporting_attachments
     FROM workspace_work_center_progress p
     JOIN workspace_work_center w ON w.id = p.task_id
     LEFT JOIN task_stages s ON s.id = p.stage_id
     WHERE w.activity_id = $1 AND p.validation_status = 'approved' AND p.report_date <= $2
     ORDER BY p.report_date DESC, p.id DESC LIMIT $3`, [activityId, cutOff, MAX_SHARED_EVIDENCE_REPORTS])).rows;
  const supportingAttachments = rows.flatMap((r) => [
    ...(r.attachment_name ? [{
      task_title: r.task_title, report_date: dateOnly(r.report_date),
      file_name: r.attachment_name, file_url: r.attachment_url,
      attachment_type: 'other', custom_attachment_type: null,
    }] : []),
    ...(Array.isArray(r.supporting_attachments) ? r.supporting_attachments : []).map((attachment) => ({
      task_title: r.task_title,
      report_date: dateOnly(r.report_date),
      ...attachment,
    })),
  ]);
  const reports = rows.map((r) => ({
    report_id: Number(r.id),
    task_title: r.task_title,
    report_date: dateOnly(r.report_date),
    work_done: r.work_done || '',
    quantity_done: r.quantity_done == null ? null : Number(r.quantity_done),
    quantity_failed: r.quantity_failed == null ? null : Number(r.quantity_failed),
    progress_pct: r.progress_pct == null ? null : Number(r.progress_pct),
    stage_title: r.stage_title || null,
    manpower: r.manpower || '', equipment: r.equipment || '', materials: r.materials || '', issues: r.issues || '',
    photos: r.photos, resources: r.resources,
    attachment_name: r.attachment_name || null,
    attachment_url: r.attachment_url || null,
    supporting_attachments: r.supporting_attachments,
  }));
  return {
    reports: includeReports ? reports : [],
    supporting_attachments: supportingAttachments,
  };
}

/** What a consultant is allowed to read of a verification request. Report supporting attachments are included
 *  for review; approved report details and the activity plan remain opt-in. */
function consultantProjection(verification) {
  const figures = Array.isArray(verification.claimed_figures) ? verification.claimed_figures : [];
  const evidence = verification.shared_evidence;
  const sharedEvidence = evidence && !Array.isArray(evidence) && typeof evidence === 'object'
    ? {
      reports: verification.share_evidence && Array.isArray(evidence.reports) ? evidence.reports : [],
      supporting_attachments: Array.isArray(evidence.supporting_attachments) ? evidence.supporting_attachments : [],
    }
    : (verification.share_evidence ? evidence : null);
  return {
    ...verification,
    activity_summary: {
      task_count: figures.length,
      approved_report_count: figures.reduce((total, figure) => total + Number(figure.approved_report_count || 0), 0),
      approved_quantity: figures.reduce((total, figure) => total + Number(figure.approved_quantity || 0), 0),
      planned_quantity: figures.reduce((total, figure) => total + Number(figure.target_quantity || 0), 0),
    },
    claimed_figures: [],
    certified_figures: null,
    shared_activity_summary: verification.share_activity_summary ? verification.shared_activity_summary : null,
    shared_evidence: verification.share_evidence || sharedEvidence?.supporting_attachments?.length
      ? sharedEvidence : null,
  };
}

export function registerVerificationRoutes(app, deps) {
  const { pool, authenticateToken, upload, requireProjectLifecycleWrite, scheduleCloudinaryUpload, wcSide, isWCLeader } = deps;
  const leaderOn = (role, side) => isWCLeader(role) && wcSide(role) === side;

  app.get('/api/verification-inspectors', authenticateToken, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const projectId = parseInt(req.query.projectId, 10);
      if (!projectId) throw new HttpError(400, 'projectId is required.');
      if (!leaderOn(role, 'Contractor')) throw new HttpError(403, 'Only contractor leaders and PMs can choose verification inspectors.');
      if (!(await isMember(deps, projectId, userId, role))) throw new HttpError(403, 'You are not a member of this project.');
      const inspectors = (await pool.query(
        `SELECT t.id, t.email, tma.name AS title, tma.position
         FROM team_member_assignments tma
         JOIN team_members t ON t.id = tma.team_member_id
         WHERE tma.project_id = $1 AND tma.assigned_part = 'Consultant'
         ORDER BY tma.position NULLS LAST, tma.name, t.email`, [projectId])).rows;
      return res.json({ inspectors });
    } catch (err) { return fail(res, err, 'GET /api/verification-inspectors:'); }
  });

  async function loadActivity(client, activityId, lock = false) {
    return (await client.query(`SELECT * FROM planning_execution WHERE id = $1 ${lock ? 'FOR UPDATE' : ''}`, [activityId])).rows[0];
  }

  // ── 1. request ─────────────────────────────────────────────────────────────
  app.post('/api/activities/:activityId/verifications', authenticateToken,
    upload.single('attachment'), requireProjectLifecycleWrite, async (req, res) => {
    let client;
    try {
      const { user_id: userId, role } = req.user;
      if (!leaderOn(role, 'Contractor')) throw new HttpError(403, 'Only contractor leaders and PMs can request verification.');
      const b = req.body || {};
      const kind = b.kind || 'progress';
      if (!['progress', 'hold_point', 'completion'].includes(kind)) throw new HttpError(400, 'kind must be progress, hold_point, or completion.');

      client = await pool.connect();
      await client.query('BEGIN');
      const act = await loadActivity(client, parseInt(req.params.activityId, 10), true);
      if (!act || act.side !== 'Contractor') throw new HttpError(404, 'Contractor activity not found.');
      if (!(await isMember(deps, act.project_id, userId, role))) throw new HttpError(403, 'You are not a member of this project.');
      if (act.status === 'closed') throw new HttpError(409, 'This activity is closed.');

      const today = (await client.query(`SELECT to_char(CURRENT_DATE, 'YYYY-MM-DD') AS d, to_char(CURRENT_DATE + 1, 'YYYY-MM-DD') AS d1`)).rows[0];
      const cutOff = b.cutOffDate || today.d;
      if (!isDate(cutOff)) throw new HttpError(400, 'cutOffDate must be a valid date (YYYY-MM-DD).');
      if (cutOff > today.d1) throw new HttpError(400, 'The cut-off date cannot be in the future.');
      if (cutOff < dateOnly(act.start_date)) throw new HttpError(400, 'The cut-off date cannot be before the activity start.');

      let stageId = null;
      if (kind === 'progress') {
        if (!(Number(act.progress_pct) > Number(act.certified_progress_pct)))
          throw new HttpError(409, 'There is nothing new to verify: claimed progress is not above certified progress.');
      } else if (kind === 'hold_point') {
        stageId = parseInt(b.stageId, 10);
        const st = (await client.query(
          `SELECT s.* FROM task_stages s JOIN workspace_work_center w ON w.id = s.task_id WHERE s.id = $1 AND w.activity_id = $2`, [stageId, act.id])).rows[0];
        if (!st) throw new HttpError(400, 'Choose a stage of this activity.');
        if (!st.is_hold_point) throw new HttpError(400, 'That stage is not a hold point.');
        if (st.hold_verified_at) throw new HttpError(409, 'That hold point is already verified.');
        if (!st.completed_at) throw new HttpError(409, 'The stage must be completed (a report approved) before its hold point is verified.');
      } else {
        if (act.status !== 'completed') throw new HttpError(409, 'Claimed progress must reach 100% before completion can be certified.');
        const open = (await client.query(`SELECT COUNT(*)::int AS n FROM rework_items WHERE activity_id = $1 AND status <> 'closed'`, [act.id])).rows[0].n;
        if (open) throw new HttpError(409, `${open} rework or snag item(s) are still open.`);
      }

      const days = (await client.query(`SELECT verification_response_days AS d FROM projects WHERE id = $1`, [act.project_id])).rows[0]?.d || 7;
      const respondBy = respondByDate(today.d, days);
      const requestNote = String(b.note || '').trim();
      if (requestNote.length > 500) throw new HttpError(400, 'The note cannot exceed 500 characters.');
      const shareActivitySummary = b.shareActivitySummary === true || String(b.shareActivitySummary) === 'true';
      const sharedActivitySummary = shareActivitySummary ? {
        title: act.title,
        description: act.description,
        done_when: act.done_when,
        activity_type: act.activity_type,
        planned_quantity: act.planned_quantity,
        unit: act.unit,
        start_date: dateOnly(act.start_date),
        end_date: dateOnly(act.end_date),
        planned_work: act.planned_work,
        planned_manpower: act.planned_manpower,
        planned_equipment: act.planned_equipment,
        planned_materials: act.planned_materials,
      } : null;

      const figures = (await client.query(
        `SELECT w.id AS task_id, w.title, w.weight_pct, w.progress_pct, w.target_quantity,
                (SELECT COUNT(*)::int FROM workspace_work_center_progress p
                 WHERE p.task_id = w.id AND p.validation_status = 'approved' AND p.report_date <= $2) AS approved_report_count,
                COALESCE((SELECT SUM(p.quantity_done) FROM workspace_work_center_progress p
                          WHERE p.task_id = w.id AND p.validation_status = 'approved' AND p.report_date <= $2), 0) AS approved_quantity
         FROM workspace_work_center w WHERE w.activity_id = $1 ORDER BY w.id`, [act.id, cutOff])).rows
        .map((r) => ({ ...r, weight_pct: Number(r.weight_pct), progress_pct: Number(r.progress_pct),
                       target_quantity: r.target_quantity == null ? null : Number(r.target_quantity),
                       approved_report_count: Number(r.approved_report_count), approved_quantity: Number(r.approved_quantity) }));

      const shareEvidence = b.shareEvidence === true || String(b.shareEvidence) === 'true';
      const evidenceSnapshot = await buildSharedEvidence(client, act.id, cutOff, shareEvidence);
      const sharedEvidence = shareEvidence || evidenceSnapshot.supporting_attachments.length
        ? evidenceSnapshot : null;

      let attachments = [];
      if (req.file) {
        const up = await scheduleCloudinaryUpload(req.file.buffer, req.file.originalname, 'verifications/requests');
        attachments = [{ name: req.file.originalname, id: up.public_id, url: up.secure_url }];
      }

      let ver;
      try {
        ver = (await client.query(`
          INSERT INTO activity_verifications
            (project_id, activity_id, kind, stage_id, cut_off_date, claimed_progress_pct, claimed_figures,
             requested_by_id, requested_by_role, request_note, attachments, respond_by,
             share_activity_summary, shared_activity_summary, share_evidence, shared_evidence)
          VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11::jsonb,$12,$13,$14::jsonb,$15,$16::jsonb) RETURNING *`,
          [act.project_id, act.id, kind, stageId, cutOff, act.progress_pct, JSON.stringify(figures), userId, role,
           requestNote || null, JSON.stringify(attachments), respondBy,
           shareActivitySummary, sharedActivitySummary ? JSON.stringify(sharedActivitySummary) : null,
           shareEvidence, sharedEvidence ? JSON.stringify(sharedEvidence) : null])).rows[0];
      } catch (err) {
        if (err.code === '23505') throw new HttpError(409, 'A request of this kind is already waiting for the consultant.');
        throw err;
      }

      // named signers: consultant inspectors (team members) first, then named consultant leaders
      const named = Array.isArray(b.signers) ? b.signers : (typeof b.signers === 'string' && b.signers ? JSON.parse(b.signers) : []);
      let order = 0;
      for (const s of named) {
        const id = parseInt(s.user_id, 10);
        const isTeam = s.role === 'TeamMember';
        if (!id) throw new HttpError(400, 'Each named signer needs a user_id.');
        if (isTeam) {
          const ok = (await client.query(
            `SELECT 1 FROM team_member_assignments WHERE project_id = $1 AND team_member_id = $2 AND assigned_part = 'Consultant'`, [act.project_id, id])).rows.length;
          if (!ok) throw new HttpError(403, 'A named inspector must be a consultant team member of this project.');
        } else if (!leaderOn(s.role || '', 'Consultant')) {
          throw new HttpError(403, 'A named leader must be a consultant leader or PM.');
        }
        await client.query(
          `INSERT INTO verification_signers (verification_id, project_id, signer_role, signer_user_id, signer_position, is_team_member, is_decider, order_no)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (verification_id, signer_role, signer_user_id) DO NOTHING`,
          [ver.id, act.project_id, s.role, id, s.position || null, isTeam, !isTeam, isTeam ? order : 100 + order]);
        order += 1;
      }
      await client.query('COMMIT');

      const recipients = [...(await leadersOf(deps, act.project_id, 'Consultant')),
        ...named.filter((s) => s.role === 'TeamMember').map((s) => deps.flowKey('TeamMember', parseInt(s.user_id, 10)))];
      const what = { progress: 'progress', hold_point: 'a hold point', completion: 'completion' }[kind];
      await notifySafe(deps, { projectId: act.project_id, entityId: ver.id, entityType: 'activity_verification',
        message: `Verification of ${what} requested for "${act.title}". Please respond by ${respondBy}.`,
        actorId: userId, actorRole: role, recipients });
      return res.status(201).json({ success: true, verification: ver });
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      return fail(res, err, 'POST /api/activities/:activityId/verifications:');
    } finally { if (client) client.release(); }
  });

  // ── 2a. inspector recommendation (named consultant team member) ───────────
  app.put('/api/verifications/:id/inspect', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      if (role !== 'TeamMember') throw new HttpError(403, 'Only a named consultant inspector can record a recommendation.');
      const outcome = req.body?.outcome;
      if (!['recommend_verify', 'recommend_changes', 'recommend_reject'].includes(outcome))
        throw new HttpError(400, 'outcome must be recommend_verify, recommend_changes, or recommend_reject.');
      const r = await pool.query(
        `UPDATE verification_signers s SET status = 'signed', outcome = $3, note = $4, signed_at = NOW(),
                first_viewed_at = COALESCE(first_viewed_at, NOW())
         FROM activity_verifications v
         WHERE s.verification_id = v.id AND v.id = $1 AND v.status = 'pending'
           AND s.signer_role = 'TeamMember' AND s.signer_user_id = $2 AND s.status = 'pending'
         RETURNING s.*, v.project_id, v.activity_id`, [req.params.id, userId, outcome, String(req.body?.note || '').trim() || null]);
      if (!r.rows.length) throw new HttpError(404, 'No pending request is waiting for you on this verification.');
      await notifySafe(deps, { projectId: r.rows[0].project_id, entityId: r.rows[0].verification_id, entityType: 'activity_verification',
        message: 'The consultant inspector has recorded a recommendation on a verification request.',
        actorId: userId, actorRole: role, recipients: await leadersOf(deps, r.rows[0].project_id, 'Consultant') });
      return res.json({ success: true, signer: r.rows[0] });
    } catch (err) { return fail(res, err, 'PUT /api/verifications/:id/inspect:'); }
  });

  // ── 2b. decision (consultant leader) ───────────────────────────────────────
  app.put('/api/verifications/:id/decide', authenticateToken, upload.single('attachment'),
    requireProjectLifecycleWrite, async (req, res) => {
    let client;
    try {
      const { user_id: userId, role } = req.user;
      if (!leaderOn(role, 'Consultant')) throw new HttpError(403, 'Only consultant leaders and PMs can decide on a verification.');
      const actor = { id: userId, role };
      const b = req.body || {};
      const status = b.status;
      if (!['verified', 'verified_with_changes', 'rejected'].includes(status))
        throw new HttpError(400, 'status must be verified, verified_with_changes, or rejected.');
      const reason = String(b.reason || '').trim();
      if (status !== 'verified' && !reason) throw new HttpError(400, 'A reason is required.');

      client = await pool.connect();
      await client.query('BEGIN');
      const v = (await client.query(`SELECT * FROM activity_verifications WHERE id = $1 FOR UPDATE`, [req.params.id])).rows[0];
      if (!v) throw new HttpError(404, 'Verification not found.');
      if (v.status !== 'pending') throw new HttpError(409, `This request is already ${v.status.replace(/_/g, ' ')}.`);
      if (!(await isMember(deps, v.project_id, userId, role))) throw new HttpError(403, 'You are not a member of this project.');
      const act = await loadActivity(client, v.activity_id, true);

      if (status === 'verified_with_changes' && v.kind !== 'progress')
        throw new HttpError(400, 'Only a progress verification can be verified with changes. Verify it, or reject it with a reason.');
      let certifiedInput = null;
      if (status === 'verified_with_changes') {
        certifiedInput = Number(b.certified_progress_pct);
        if (!Number.isFinite(certifiedInput) || certifiedInput < 0 || certifiedInput > 100)
          throw new HttpError(400, 'certified_progress_pct must be between 0 and 100.');
      }
      if (v.kind === 'completion' && status === 'verified' && Number(act.progress_pct) < 100)
        throw new HttpError(409, 'Claimed progress dropped below 100% after the request. Reject it so the contractor can request again.');

      const pendingInspectors = (await client.query(
        `SELECT id FROM verification_signers WHERE verification_id = $1 AND is_team_member AND status = 'pending'`, [v.id])).rows;
      if (pendingInspectors.length) {
        if (String(b.skip_inspectors) !== 'true')
          throw new HttpError(409, 'The named inspector has not recorded a recommendation yet.', { code: 'INSPECTOR_PENDING', pending: pendingInspectors.length });
        await client.query(
          `UPDATE verification_signers SET status = 'replaced', replaced_at = NOW(), replaced_by_user_id = $2, replaced_by_role = $3
           WHERE verification_id = $1 AND is_team_member AND status = 'pending'`, [v.id, userId, role]);
      }

      let rework = Array.isArray(b.rework) ? b.rework : (typeof b.rework === 'string' && b.rework ? JSON.parse(b.rework) : []);
      if (status === 'rejected' && !rework.length) rework = [{ reason }];
      if (rework.some((r) => !String(r.reason || '').trim())) throw new HttpError(400, 'Every rework or snag item needs a reason.');
      if (v.kind === 'completion' && status !== 'rejected') {
        const snagReason = String(b.snag_reason || '').trim();
        if (snagReason) rework.push({ reason: snagReason, certified_progress_pct: b.snag_certified_progress_pct });
        for (const item of rework) {
          const progress = Number(item.certified_progress_pct ?? b.snag_certified_progress_pct ?? 99);
          if (!Number.isFinite(progress) || progress < 0 || progress >= 100)
            throw new HttpError(400, 'Each completion snag needs a certified progress percentage below 100.');
          item.certified_progress_pct = progress;
        }
      }

      let attachments = [];
      if (req.file) {
        const up = await scheduleCloudinaryUpload(req.file.buffer, req.file.originalname, 'verifications/decisions');
        attachments = [{ name: req.file.originalname, id: up.public_id, url: up.secure_url }];
      }

      const certified = status === 'rejected' ? null
        : certifiedAfterDecision(act.certified_progress_pct, { status, claimed_progress_pct: v.claimed_progress_pct, certified_progress_pct: certifiedInput });
      const certifiedFigures = b.certified_figures ? (typeof b.certified_figures === 'string' ? JSON.parse(b.certified_figures) : b.certified_figures) : null;

      const decided = (await client.query(
        `UPDATE activity_verifications
         SET status = $2, certified_progress_pct = $3, certified_figures = $4::jsonb, decision_reason = $5,
             decision_attachments = $6::jsonb, decided_by_id = $7, decided_by_role = $8, decided_at = NOW()
         WHERE id = $1 RETURNING *`,
        [v.id, status, certified, certifiedFigures ? JSON.stringify(certifiedFigures) : null, reason || null,
         JSON.stringify(attachments), userId, role])).rows[0];
      await markRead(client, v.id, v.project_id, role, userId);

      await client.query(
        `INSERT INTO verification_signers (verification_id, project_id, signer_role, signer_user_id, is_decider, order_no, status, outcome, note, signed_at)
         VALUES ($1,$2,$3,$4,true,200,'signed',$5,$6,NOW())
         ON CONFLICT (verification_id, signer_role, signer_user_id)
         DO UPDATE SET status = 'signed', outcome = EXCLUDED.outcome, note = EXCLUDED.note, signed_at = NOW()`,
        [v.id, v.project_id, role, userId, status, reason || null]);

      for (const item of rework) {
        const itemKind = v.kind === 'completion' && status !== 'rejected' ? 'snag' : 'rework';
        await client.query(
          `INSERT INTO rework_items
             (project_id, activity_id, task_id, verification_id, kind, reason, raised_by_id, raised_by_role,
              certified_progress_pct, previous_certified_progress_pct)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [v.project_id, v.activity_id, item.task_id || null, v.id, itemKind,
           String(item.reason).trim(), userId, role,
           itemKind === 'snag' ? item.certified_progress_pct : null,
           itemKind === 'snag' ? certified : null]);
      }

      let closed = false, milestone = null;
      if (status !== 'rejected') {
        if (v.kind === 'hold_point') {
          await client.query(`UPDATE task_stages SET hold_verified_at = NOW() WHERE id = $1`, [v.stage_id]);
        } else {
          const cappedCertified = await certifiedProgressWithSnagCaps(client, act.id, v.kind === 'completion' ? 100 : certified);
          await client.query(
            `UPDATE planning_execution SET certified_progress_pct = $2, certified_at = NOW(), updated_at = NOW() WHERE id = $1`,
            [act.id, cappedCertified]);
        }
        // the consultant's temporary milestone value ends once corrected work is verified
        const link = await syncLinkedMilestone(client, act, actor);
        if (link && v.kind !== 'hold_point') {
          await client.query(
            `UPDATE milestone_progress_overrides SET ended_at = NOW(), ended_reason = 'replaced_by_verification'
             WHERE ${link.col} = $1 AND ended_at IS NULL`, [link.id]);
          await client.query(
            `UPDATE ${link.table} SET override_pct = NULL, override_reason = NULL, override_by_id = NULL, override_by_role = NULL, override_at = NULL WHERE id = $1`, [link.id]);
        }
        if (v.kind === 'completion') closed = await closeIfCertified(client, act.id, actor);
        if (link && v.kind !== 'hold_point') milestone = await syncMilestone(client, link.kind, link.id, actor);
      }
      await client.query('COMMIT');

      const label = { verified: 'verified', verified_with_changes: 'verified with changes', rejected: 'rejected' }[status];
      await notifySafe(deps, { projectId: v.project_id, entityId: v.id, entityType: 'activity_verification',
        message: `Verification for "${act.title}" was ${label}${reason ? `: ${reason}` : '.'}${closed ? ' The activity is now closed.' : ''}`,
        actorId: userId, actorRole: role,
        recipients: [...(await leadersOf(deps, v.project_id, 'Contractor'))] });
      return res.json({ success: true, verification: decided, certified_progress_pct: certified, activity_closed: closed, milestone, rework_items: rework.length });
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      return fail(res, err, 'PUT /api/verifications/:id/decide:');
    } finally { if (client) client.release(); }
  });

  // ── 2c. withdraw ───────────────────────────────────────────────────────────
  app.put('/api/verifications/:id/withdraw', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      if (!leaderOn(role, 'Contractor')) throw new HttpError(403, 'Only contractor leaders and PMs can withdraw a request.');
      const r = await pool.query(
        `UPDATE activity_verifications SET status = 'withdrawn' WHERE id = $1 AND status = 'pending' RETURNING *`, [req.params.id]);
      if (!r.rows.length) throw new HttpError(409, 'Only a pending request can be withdrawn.');
      return res.json({ success: true, verification: r.rows[0] });
    } catch (err) { return fail(res, err, 'PUT /api/verifications/:id/withdraw:'); }
  });

  // ── 3. rework and snags ────────────────────────────────────────────────────
  app.post('/api/activities/:activityId/rework', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
    let client;
    try {
      const { user_id: userId, role } = req.user;
      if (!leaderOn(role, 'Consultant')) throw new HttpError(403, 'Only consultant leaders and PMs can raise rework or snags.');
      const kind = req.body?.kind || 'rework';
      if (!['rework', 'snag'].includes(kind)) throw new HttpError(400, 'kind must be rework or snag.');
      const reason = String(req.body?.reason || '').trim();
      if (!reason) throw new HttpError(400, 'A reason is required.');
      const certifiedProgress = Number(req.body?.certified_progress_pct);
      if (kind === 'snag' && (!Number.isFinite(certifiedProgress) || certifiedProgress < 0 || certifiedProgress >= 100))
        throw new HttpError(400, 'A snag needs a certified progress percentage below 100.');
      client = await pool.connect();
      await client.query('BEGIN');
      const act = await loadActivity(client, parseInt(req.params.activityId, 10), true);
      if (!act || act.side !== 'Contractor') throw new HttpError(404, 'Contractor activity not found.');
      if (!(await isMember(deps, act.project_id, userId, role))) throw new HttpError(403, 'You are not a member of this project.');
      if (act.status === 'closed') throw new HttpError(409, 'This activity is closed.');
      const item = (await client.query(
        `INSERT INTO rework_items
           (project_id, activity_id, task_id, kind, reason, raised_by_id, raised_by_role,
            certified_progress_pct, previous_certified_progress_pct)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
        [act.project_id, act.id, req.body?.task_id || null, kind, reason, userId, role,
         kind === 'snag' ? certifiedProgress : null, kind === 'snag' ? act.certified_progress_pct : null])).rows[0];
      let milestone = null;
      if (kind === 'snag') {
        const capped = await certifiedProgressWithSnagCaps(client, act.id, act.certified_progress_pct);
        await client.query(`UPDATE planning_execution SET certified_progress_pct = $2, certified_at = NOW(), updated_at = NOW() WHERE id = $1`, [act.id, capped]);
        const link = await syncLinkedMilestone(client, act, { id: userId, role });
        if (link) milestone = await syncMilestone(client, link.kind, link.id, { id: userId, role });
      }
      await client.query('COMMIT');
      await notifySafe(deps, { projectId: act.project_id, entityId: item.id, entityType: 'rework_item',
        message: `A ${kind} item was raised on "${act.title}": ${reason}`, actorId: userId, actorRole: role,
        recipients: await leadersOf(deps, act.project_id, 'Contractor') });
      return res.status(201).json({ success: true, item, milestone });
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      return fail(res, err, 'POST /api/activities/:activityId/rework:');
    } finally { if (client) client.release(); }
  });

  app.put('/api/rework/:id/correct', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      if (!leaderOn(role, 'Contractor')) throw new HttpError(403, 'Only contractor leaders and PMs can mark rework as corrected.');
      const r = await pool.query(
        `UPDATE rework_items SET status = 'corrected', corrected_at = NOW(), corrected_by_id = $2, corrected_by_role = $3, correction_note = $4
         WHERE id = $1 AND status = 'open' RETURNING *`, [req.params.id, userId, role, String(req.body?.note || '').trim() || null]);
      if (!r.rows.length) throw new HttpError(409, 'Only an open item can be marked as corrected.');
      await notifySafe(deps, { projectId: r.rows[0].project_id, entityId: r.rows[0].id, entityType: 'rework_item',
        message: 'A rework or snag item was marked as corrected. Please check it.', actorId: userId, actorRole: role,
        recipients: await leadersOf(deps, r.rows[0].project_id, 'Consultant') });
      return res.json({ success: true, item: r.rows[0] });
    } catch (err) { return fail(res, err, 'PUT /api/rework/:id/correct:'); }
  });

  app.put('/api/rework/:id/close', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
    let client;
    try {
      const { user_id: userId, role } = req.user;
      if (!leaderOn(role, 'Consultant')) throw new HttpError(403, 'Only consultant leaders and PMs can close rework or snags.');
      client = await pool.connect();
      await client.query('BEGIN');
      const r = await client.query(
        `UPDATE rework_items SET status = 'closed', closed_at = NOW(), closed_by_id = $2, closed_by_role = $3
         WHERE id = $1 AND status IN ('open','corrected') RETURNING *`, [req.params.id, userId, role]);
      if (!r.rows.length) throw new HttpError(409, 'This item is already closed.');
      if (r.rows[0].kind === 'snag') {
        const [progress] = (await client.query(
          `SELECT MIN(certified_progress_pct) AS cap, MAX(previous_certified_progress_pct) AS previous
           FROM rework_items WHERE activity_id = $1 AND kind = 'snag' AND status <> 'closed'`, [r.rows[0].activity_id])).rows;
        const current = Number((await client.query(
          `SELECT certified_progress_pct FROM planning_execution WHERE id = $1`, [r.rows[0].activity_id])).rows[0]?.certified_progress_pct || 0);
        const restored = progress.cap == null
          ? Math.max(current, Number(r.rows[0].previous_certified_progress_pct || progress.previous || 0))
          : Math.min(current, Number(progress.cap));
        await client.query(
          `UPDATE planning_execution SET certified_progress_pct = $2, certified_at = NOW(), updated_at = NOW() WHERE id = $1`,
          [r.rows[0].activity_id, restored]);
      }
      const closed = await closeIfCertified(client, r.rows[0].activity_id, { id: userId, role });
      let milestone = null;
      const act = await loadActivity(client, r.rows[0].activity_id);
      const link = await syncLinkedMilestone(client, act, { id: userId, role });
      if (link) milestone = await syncMilestone(client, link.kind, link.id, { id: userId, role });
      await client.query('COMMIT');
      return res.json({ success: true, item: r.rows[0], activity_closed: closed, milestone });
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      return fail(res, err, 'PUT /api/rework/:id/close:');
    } finally { if (client) client.release(); }
  });

  app.post('/api/verifications/:id/revise', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
    let client;
    try {
      const { user_id: userId, role } = req.user;
      if (!leaderOn(role, 'Consultant')) throw new HttpError(403, 'Only consultant leaders and PMs can revise a verification decision.');
      const reason = String(req.body?.reason || '').trim();
      const certifiedProgress = Number(req.body?.certified_progress_pct);
      if (!reason) throw new HttpError(400, 'A reason is required to revise a decision.');
      if (!Number.isFinite(certifiedProgress) || certifiedProgress < 0 || certifiedProgress > 100)
        throw new HttpError(400, 'certified_progress_pct must be between 0 and 100.');

      client = await pool.connect();
      await client.query('BEGIN');
      const verification = (await client.query(
        `SELECT * FROM activity_verifications WHERE id = $1 FOR UPDATE`, [req.params.id])).rows[0];
      if (!verification) throw new HttpError(404, 'Verification not found.');
      if (!['verified', 'verified_with_changes'].includes(verification.status))
        throw new HttpError(409, 'Only a verified decision can be revised.');
      if (certifiedProgress > Number(verification.claimed_progress_pct))
        throw new HttpError(400, 'Revised certified progress cannot exceed the contractor’s claimed progress.');
      if (!(await isMember(deps, verification.project_id, userId, role)))
        throw new HttpError(403, 'You are not a member of this project.');
      const laterDecision = (await client.query(
        `SELECT 1 FROM activity_verifications
         WHERE activity_id = $1 AND id <> $2
           AND status IN ('verified', 'verified_with_changes')
           AND (decided_at > $3 OR (decided_at = $3 AND id > $2))
         LIMIT 1`, [verification.activity_id, verification.id, verification.decided_at])).rows.length > 0;
      if (laterDecision)
        throw new HttpError(409, 'Revise the latest verified decision for this activity first.');

      const activity = await loadActivity(client, verification.activity_id, true);
      const priorRevision = (await client.query(
        `SELECT revised_status, revised_certified_pct
         FROM activity_verification_decision_revisions
         WHERE verification_id = $1 ORDER BY changed_at DESC, id DESC LIMIT 1`, [verification.id])).rows[0];
      const previousStatus = priorRevision?.revised_status || verification.status;
      const previousCertified = priorRevision?.revised_certified_pct ?? verification.certified_progress_pct;
      const revisedStatus = certifiedProgress < Number(verification.claimed_progress_pct)
        ? 'verified_with_changes' : 'verified';
      const revision = (await client.query(
        `INSERT INTO activity_verification_decision_revisions
           (project_id, verification_id, previous_status, previous_certified_pct, revised_status,
            revised_certified_pct, reason, changed_by_id, changed_by_role)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
        [verification.project_id, verification.id, previousStatus, previousCertified, revisedStatus,
         certifiedProgress, reason, userId, role])).rows[0];

      if (certifiedProgress < 100) {
        await client.query(
          `INSERT INTO rework_items
             (project_id, activity_id, verification_id, kind, reason, raised_by_id, raised_by_role,
              certified_progress_pct, previous_certified_progress_pct)
           VALUES ($1,$2,$3,'snag',$4,$5,$6,$7,$8)`,
          [verification.project_id, activity.id, verification.id, reason, userId, role,
             certifiedProgress, Number(activity.certified_progress_pct) || 0]);
        if (activity.status === 'closed') {
          await client.query(
            `UPDATE planning_execution SET status = 'completed', closed_at = NULL, closed_by_id = NULL,
                    closed_by_role = NULL, actual_end = NULL, updated_at = NOW() WHERE id = $1`, [activity.id]);
        }
      }
      const effectiveProgress = await certifiedProgressWithSnagCaps(client, activity.id, certifiedProgress);
      await client.query(
        `UPDATE planning_execution SET certified_progress_pct = $2, certified_at = NOW(), updated_at = NOW() WHERE id = $1`,
        [activity.id, effectiveProgress]);
      const link = await syncLinkedMilestone(client, activity, { id: userId, role });
      const milestone = link ? await syncMilestone(client, link.kind, link.id, { id: userId, role }) : null;
      await client.query('COMMIT');

      await notifySafe(deps, {
        projectId: verification.project_id,
        entityId: verification.id,
        entityType: 'activity_verification',
        message: `The consultant revised the certified progress for "${activity.title}" to ${effectiveProgress}%.`,
        actorId: userId,
        actorRole: role,
        recipients: await leadersOf(deps, verification.project_id, 'Contractor'),
      });
      return res.json({ success: true, revision, certified_progress_pct: effectiveProgress, milestone });
    } catch (err) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      return fail(res, err, 'POST /api/verifications/:id/revise:');
    } finally { if (client) client.release(); }
  });

  // ── 4. lists (contractor and consultant sides only: the client never sees claimed figures) ──
  app.get('/api/activities/:activityId/verifications', authenticateToken, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const s = isWCLeader(role) ? wcSide(role) : null;
      const member = role === 'TeamMember';
      if (s !== 'Contractor' && s !== 'Consultant' && !member) throw new HttpError(403, 'You cannot see verification details.');
      const act = await loadActivity(pool, parseInt(req.params.activityId, 10));
      if (!act) throw new HttpError(404, 'Activity not found.');
      if (!(await isMember(deps, act.project_id, userId, role))) throw new HttpError(403, 'You are not a member of this project.');
      const verifications = (await pool.query(
        `SELECT v.*, (v.status = 'pending' AND v.respond_by < CURRENT_DATE) AS overdue, ${SEEN_SQL},
                COALESCE((SELECT json_agg(s ORDER BY s.order_no) FROM verification_signers s WHERE s.verification_id = v.id), '[]') AS signers,
                COALESCE((SELECT json_agg(r ORDER BY r.changed_at) FROM activity_verification_decision_revisions r WHERE r.verification_id = v.id), '[]') AS decision_revisions
         FROM activity_verifications v WHERE v.activity_id = $1 ORDER BY v.id DESC`, [act.id])).rows;
      const rework = (await pool.query(`SELECT * FROM rework_items WHERE activity_id = $1 ORDER BY id DESC`, [act.id])).rows;
      const consultantView = s === 'Consultant' || (member && (await pool.query(
        `SELECT 1 FROM team_member_assignments WHERE project_id = $1 AND team_member_id = $2 AND assigned_part = 'Consultant' LIMIT 1`,
        [act.project_id, userId])).rows.length > 0);
      const visibleVerifications = consultantView ? verifications.map(consultantProjection) : verifications;
      const visibleRework = consultantView ? rework.map(({ task_id, ...item }) => item) : rework;
      return res.json({ verifications: visibleVerifications, rework: visibleRework });
    } catch (err) { return fail(res, err, 'GET /api/activities/:activityId/verifications:'); }
  });

  app.get('/api/verifications/pending', authenticateToken, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const projectId = parseInt(req.query.projectId, 10);
      if (!projectId) throw new HttpError(400, 'projectId is required.');
      const s = isWCLeader(role) ? wcSide(role) : null;
      if (s !== 'Contractor' && s !== 'Consultant' && role !== 'TeamMember') throw new HttpError(403, 'You cannot see verification requests.');
      if (!(await isMember(deps, projectId, userId, role))) throw new HttpError(403, 'You are not a member of this project.');
      const rows = (await pool.query(
        `SELECT v.*, pe.title AS activity_title, pe.unit AS activity_unit,
                pe.certified_progress_pct AS activity_certified_progress_pct,
                st.title AS stage_title, (v.respond_by < CURRENT_DATE) AS overdue,
                (v.respond_by - CURRENT_DATE)::int AS days_left,
                (SELECT COUNT(*)::int FROM verification_signers x
                  WHERE x.verification_id = v.id AND x.is_team_member AND x.status = 'pending') AS pending_inspectors,
                NOT EXISTS (SELECT 1 FROM verification_reads me WHERE me.verification_id = v.id
                  AND me.reader_id = $3 AND me.reader_role = $4) AS is_unread, ${SEEN_SQL}
         FROM activity_verifications v JOIN planning_execution pe ON pe.id = v.activity_id
         LEFT JOIN task_stages st ON st.id = v.stage_id
         WHERE v.project_id = $1 AND v.status = 'pending'
           AND ($2 = 'Consultant' OR $2 = 'Contractor'
                OR EXISTS (SELECT 1 FROM verification_signers x WHERE x.verification_id = v.id AND x.signer_role = 'TeamMember' AND x.signer_user_id = $3))
         ORDER BY v.respond_by, v.id`, [projectId, s || 'TeamMember', userId, role])).rows;
      const consultantView = s === 'Consultant' || (role === 'TeamMember' && (await pool.query(
        `SELECT 1 FROM team_member_assignments WHERE project_id = $1 AND team_member_id = $2 AND assigned_part = 'Consultant' LIMIT 1`,
        [projectId, userId])).rows.length > 0);
      if (!consultantView) return res.json({ pending: rows.map((row) => ({ ...row, is_unread: false })) });
      const pending = rows.map(consultantProjection);
      return res.json({ pending });
    } catch (err) { return fail(res, err, 'GET /api/verifications/pending:'); }
  });

  // Earlier requests (decided or withdrawn), newest first, with search and an outcome filter.
  // Visible to the same people who can see pending requests. Heavy fields are left out: the activity card has them.
  app.get('/api/verifications/history', authenticateToken, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const projectId = parseInt(req.query.projectId, 10);
      if (!projectId) throw new HttpError(400, 'projectId is required.');
      const s = isWCLeader(role) ? wcSide(role) : null;
      if (s !== 'Contractor' && s !== 'Consultant' && role !== 'TeamMember') throw new HttpError(403, 'You cannot see verification requests.');
      if (!(await isMember(deps, projectId, userId, role))) throw new HttpError(403, 'You are not a member of this project.');
      const status = String(req.query.status || '').trim();
      if (status && !['verified', 'verified_with_changes', 'rejected', 'withdrawn'].includes(status))
        throw new HttpError(400, 'status must be verified, verified_with_changes, rejected, or withdrawn.');
      const text = String(req.query.q || '').trim().slice(0, 100);
      const like = text ? `%${text.replace(/[\\%_]/g, '\\$&')}%` : null;
      const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 25));
      const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
      const rows = (await pool.query(
        `SELECT v.*, pe.title AS activity_title, pe.unit AS activity_unit, st.title AS stage_title, ${SEEN_SQL}
         FROM activity_verifications v JOIN planning_execution pe ON pe.id = v.activity_id
         LEFT JOIN task_stages st ON st.id = v.stage_id
         WHERE v.project_id = $1 AND v.status <> 'pending'
           AND ($2 = 'Consultant' OR $2 = 'Contractor'
                OR EXISTS (SELECT 1 FROM verification_signers x WHERE x.verification_id = v.id AND x.signer_role = 'TeamMember' AND x.signer_user_id = $3))
           AND ($4::text IS NULL OR v.status = $4::text)
           AND ($5::text IS NULL OR pe.title ILIKE $5::text OR v.request_note ILIKE $5::text
                OR v.decision_reason ILIKE $5::text OR REPLACE(v.kind, '_', ' ') ILIKE $5::text)
         ORDER BY COALESCE(v.decided_at, v.requested_at) DESC, v.id DESC
         LIMIT $6 OFFSET $7`, [projectId, s || 'TeamMember', userId, status || null, like, limit + 1, offset])).rows;
      const consultantView = s === 'Consultant' || (role === 'TeamMember' && (await pool.query(
        `SELECT 1 FROM team_member_assignments WHERE project_id = $1 AND team_member_id = $2 AND assigned_part = 'Consultant' LIMIT 1`,
        [projectId, userId])).rows.length > 0);
      const slim = ({ shared_evidence, shared_activity_summary, claimed_figures, ...rest }) => rest;
      const page = rows.slice(0, limit).map((row) => slim(consultantView ? consultantProjection(row) : row));
      return res.json({ history: page, has_more: rows.length > limit });
    } catch (err) { return fail(res, err, 'GET /api/verifications/history:'); }
  });

  // Read receipt: the first time a consultant-side reader opens a request, it is recorded. Opening again only moves last_read_at.
  app.post('/api/verifications/:id/read', authenticateToken, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const id = parseInt(req.params.id, 10);
      if (!id) throw new HttpError(400, 'A verification id is required.');
      const v = (await pool.query(`SELECT id, project_id FROM activity_verifications WHERE id = $1`, [id])).rows[0];
      if (!v) throw new HttpError(404, 'Verification not found.');
      if (!(await isMember(deps, v.project_id, userId, role))) throw new HttpError(403, 'You are not a member of this project.');
      let allowed = leaderOn(role, 'Consultant');
      if (!allowed && role === 'TeamMember') {
        allowed = (await pool.query(
          `SELECT 1 FROM verification_signers WHERE verification_id = $1 AND signer_role = 'TeamMember' AND signer_user_id = $2 LIMIT 1`,
          [id, userId])).rows.length > 0;
      }
      if (!allowed) throw new HttpError(403, 'Only the consultant side can mark a request as read.');
      const r = (await markRead(pool, v.id, v.project_id, role, userId)).rows[0];
      return res.json({ success: true, first_read_at: r.first_read_at, last_read_at: r.last_read_at });
    } catch (err) { return fail(res, err, 'POST /api/verifications/:id/read:'); }
  });
}
