// Builds the system-generated Activity Report for one activity.
//
// One builder feeds both the Overview screen and the PDF, so the numbers always match. The report is computed
// from approved data (never stored); only a frozen copy is stored when a consultant certifies, as
// activity_verifications.report_snapshot, so a past certificate never changes.
//
// buildActivityReport() returns the full approved-work report. shapeReportForViewer() then removes what the
// viewer may not see: a client gets certified figures and the milestone Site photos only, and the contractor's
// pending reports are added only for the contractor's own side.

const toNum = (v) => (v == null || v === '' ? 0 : Number(v) || 0);
const round1 = (x) => Math.round((Number(x) + Number.EPSILON) * 10) / 10;
const round3 = (x) => Math.round((Number(x) + Number.EPSILON) * 1000) / 1000;

// pg returns DATE columns as local-midnight Date objects: format them without shifting the day
const dateOnly = (v) => {
  if (!v) return null;
  if (v instanceof Date) {
    return `${v.getFullYear()}-${String(v.getMonth() + 1).padStart(2, '0')}-${String(v.getDate()).padStart(2, '0')}`;
  }
  return String(v).slice(0, 10);
};
const dayStart = (iso) => {
  if (!iso) return null;
  const [y, m, d] = String(iso).slice(0, 10).split('-').map(Number);
  return new Date(y, m - 1, d);
};
const isImage = (name, mime) => /^image\//i.test(String(mime || '')) || /\.(jpe?g|png|gif|webp|bmp|heic)$/i.test(String(name || ''));
const displayName = (row) => String(row.display_name || row.email || 'Team member').split('@')[0];

/**
 * @param {import('pg').Pool} pool
 * @param {{ activity: object, asOfDate?: string }} opts  activity is the planning_execution row
 */
export async function buildActivityReport(pool, { activity, asOfDate = null }) {
  const activityId = activity.id;
  const projectId = activity.project_id;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const asOf = asOfDate ? dayStart(asOfDate) : today;

  const [tasks, stages, reports, checklists, rework, certificates, plannedRes, activityFiles, taskFiles, milestoneMeta] = await Promise.all([
    pool.query(
      `SELECT w.id, w.title, w.status, w.weight_pct, w.target_quantity, w.progress_pct,
              w.linked_file_name, w.linked_file_url
       FROM workspace_work_center w WHERE w.activity_id = $1 ORDER BY w.id`, [activityId]),
    pool.query(
      `SELECT s.task_id, w.title AS task_title, s.title, s.is_hold_point, s.completed_at, s.hold_verified_at
       FROM task_stages s JOIN workspace_work_center w ON w.id = s.task_id
       WHERE w.activity_id = $1 ORDER BY s.task_id, s.seq`, [activityId]),
    pool.query(
      `SELECT p.id, p.task_id, w.title AS task_title, p.report_date, p.work_done, p.quantity_done,
              p.progress_pct, p.issues, p.notes, p.weather, p.delay_cause, p.delay_note, p.delay_days, p.safety_note, p.next_plan,
              p.attachment_name, p.attachment_url, tm.display_name, tm.email,
              COALESCE((SELECT json_agg(json_build_object('file_name', ph.file_name, 'file_url', ph.file_url,
                          'captured_at', ph.captured_at) ORDER BY ph.seq)
                        FROM work_center_report_photos ph WHERE ph.report_id = p.id), '[]'::json) AS photos,
              COALESCE((SELECT json_agg(json_build_object('file_name', ra.file_name, 'file_url', ra.file_url,
                          'mime_type', ra.mime_type, 'type', COALESCE(ra.custom_attachment_type, ra.attachment_type))
                        ORDER BY ra.created_at, ra.id)
                        FROM work_center_report_attachments ra WHERE ra.report_id = p.id), '[]'::json) AS files,
              COALESCE((SELECT json_agg(json_build_object('resource_type', rr.resource_type, 'name', rr.name,
                          'quantity', rr.quantity, 'unit', rr.unit, 'hours', rr.hours,
                          'planned_resource_id', rr.planned_resource_id) ORDER BY rr.id)
                        FROM work_center_report_resources rr WHERE rr.report_id = p.id), '[]'::json) AS resources
       FROM workspace_work_center_progress p
       JOIN workspace_work_center w ON w.id = p.task_id
       JOIN team_members tm ON tm.id = p.member_id
       WHERE w.activity_id = $1 AND p.validation_status = 'approved'
       ORDER BY p.report_date, p.submitted_at, p.id`, [activityId]),
    pool.query(
      `SELECT c.title, w.title AS task_title,
              COUNT(i.id)::int AS items, COUNT(i.id) FILTER (WHERE i.is_complete)::int AS done
       FROM work_center_checklists c
       JOIN workspace_work_center w ON w.id = c.task_id
       LEFT JOIN work_center_checklist_items i ON i.checklist_id = c.id
       WHERE w.activity_id = $1 GROUP BY c.id, w.title ORDER BY c.id`, [activityId]),
    pool.query(
      `SELECT kind, reason, status, raised_at, closed_at FROM rework_items WHERE activity_id = $1 ORDER BY raised_at`, [activityId]),
    pool.query(
      `SELECT id, kind, cut_off_date, status, claimed_progress_pct, certified_progress_pct, certification_note,
              certificate_no, decision_reason, decided_at, decided_by_role
       FROM activity_verifications
       WHERE activity_id = $1 AND status IN ('verified', 'verified_with_changes', 'rejected')
       ORDER BY decided_at, id`, [activityId]),
    pool.query(
      `SELECT id, task_id, resource_type, name, planned_quantity, unit, planned_hours
       FROM planned_resources WHERE activity_id = $1 ORDER BY id`, [activityId]),
    pool.query(
      `SELECT file_name, file_url, mime_type, created_at FROM card_attachments
       WHERE project_id = $1 AND entity_type = 'planning_activity' AND entity_id = $2 ORDER BY created_at, id`,
      [projectId, activityId]),
    pool.query(
      `SELECT a.file_name, a.file_url, a.mime_type, a.created_at, a.entity_id AS task_id, w.title AS task_title
       FROM card_attachments a JOIN workspace_work_center w ON w.id = a.entity_id
       WHERE a.project_id = $1 AND a.entity_type = 'work_center_task' AND w.activity_id = $2 ORDER BY a.created_at, a.id`,
      [projectId, activityId]),
    activity.baseline_milestone_id || activity.additional_milestone_id
      ? pool.query(
        `SELECT id, file_name, cloudinary_url, uploaded_at FROM milestone_photos
         WHERE ${activity.baseline_milestone_id ? 'milestone_id' : 'additional_milestone_id'} = $1 ORDER BY uploaded_at, id`,
        [activity.baseline_milestone_id || activity.additional_milestone_id])
      : Promise.resolve({ rows: [] }),
  ]);

  const cutoff = asOfDate ? dateOnly(asOfDate) : null;
  const approved = reports.rows.filter((r) => !cutoff || dateOnly(r.report_date) <= cutoff);

  // ── quantities and progress ───────────────────────────────────────────────
  const plannedQty = activity.planned_quantity == null ? null : toNum(activity.planned_quantity);
  const claimedQty = round3(approved.reduce((sum, r) => sum + toNum(r.quantity_done), 0));
  const certifiedPct = toNum(activity.certified_progress_pct);
  const claimedPct = toNum(activity.progress_pct);
  const certifiedQty = plannedQty == null ? null : round3(plannedQty * certifiedPct / 100);
  const start = dayStart(dateOnly(activity.start_date));
  const end = dayStart(dateOnly(activity.end_date));
  const plannedToday = start && end && end > start
    ? Math.max(0, Math.min(100, round1((Math.min(asOf, end) - start) / (end - start) * 100)))
    : activity.status === 'completed' ? 100 : 0;
  const msDay = 86400000;
  const daysElapsed = start ? Math.max(1, Math.round((Math.min(asOf, end || asOf) - start) / msDay) + 1) : null;
  const daysLeft = end ? Math.max(0, Math.round((end - asOf) / msDay)) : null;
  const remainingQty = plannedQty == null ? null : round3(Math.max(0, plannedQty - claimedQty));

  // ── daily log with running total ──────────────────────────────────────────
  let running = 0;
  const dailyLog = approved.map((r) => {
    running = round3(running + toNum(r.quantity_done));
    return {
      report_id: r.id,
      date: dateOnly(r.report_date),
      task_id: r.task_id,
      task_title: r.task_title,
      reported_by_name: displayName(r),
      work_done: r.work_done || r.notes || '',
      quantity: toNum(r.quantity_done),
      running_total: running,
      weather: r.weather || null,
    };
  });

  // ── resources: planned versus used ────────────────────────────────────────
  const rows = new Map();
  const keyOf = (type, name, unit) => `${type}|${String(name || '').trim().toLowerCase()}|${String(unit || '').trim().toLowerCase()}`;
  const byPlannedId = new Map();
  for (const p of plannedRes.rows) {
    const row = {
      type: p.resource_type, name: p.name, unit: p.unit || '', task_id: p.task_id || null,
      planned_quantity: p.planned_quantity == null ? null : toNum(p.planned_quantity),
      planned_hours: p.planned_hours == null ? null : toNum(p.planned_hours),
      used_quantity: 0, used_hours: 0, linked: true,
    };
    rows.set(`p${p.id}`, row);
    byPlannedId.set(Number(p.id), row);
  }
  for (const r of approved) {
    for (const u of r.resources || []) {
      const linked = u.planned_resource_id != null ? byPlannedId.get(Number(u.planned_resource_id)) : null;
      const target = linked || (() => {
        const k = keyOf(u.resource_type, u.name, u.unit);
        if (!rows.has(k)) {
          rows.set(k, {
            type: u.resource_type, name: u.name, unit: u.unit || '', task_id: null,
            planned_quantity: null, planned_hours: null, used_quantity: 0, used_hours: 0, linked: false,
          });
        }
        return rows.get(k);
      })();
      target.used_quantity = round3(target.used_quantity + toNum(u.quantity));
      target.used_hours = round3(target.used_hours + toNum(u.hours));
    }
  }

  // ── photos, files, delays, safety ─────────────────────────────────────────
  const photos = [];
  const files = [];
  if (activity.linked_file_name && activity.linked_file_url && !isImage(activity.linked_file_name, '')) {
    files.push({ scope: 'activity', task_id: null, task_title: null, date: null, file_name: activity.linked_file_name, file_url: activity.linked_file_url, type: 'Planning' });
  }
  for (const f of activityFiles.rows) {
    if (isImage(f.file_name, f.mime_type)) continue;
    files.push({ scope: 'activity', task_id: null, task_title: null, date: dateOnly(f.created_at), file_name: f.file_name, file_url: f.file_url, type: 'Planning' });
  }
  for (const f of taskFiles.rows) {
    if (isImage(f.file_name, f.mime_type)) continue;
    files.push({ scope: 'task', task_id: f.task_id, task_title: f.task_title, date: dateOnly(f.created_at), file_name: f.file_name, file_url: f.file_url, type: 'Task' });
  }
  for (const task of tasks.rows) {
    if (task.linked_file_name && task.linked_file_url && !isImage(task.linked_file_name, '')) {
      files.push({ scope: 'task', task_id: task.id, task_title: task.title, date: null, file_name: task.linked_file_name, file_url: task.linked_file_url, type: 'Task plan' });
    }
  }
  const delays = [];
  const safety = [];
  let nextPlan = null;
  for (const r of approved) {
    const date = dateOnly(r.report_date);
    for (const p of r.photos || []) {
      photos.push({ task_id: r.task_id, task_title: r.task_title, date, file_name: p.file_name, file_url: p.file_url, captured_at: p.captured_at || null });
    }
    if (r.attachment_url && !isImage(r.attachment_name, '')) {
      files.push({ scope: 'task', task_id: r.task_id, task_title: r.task_title, date, file_name: r.attachment_name || 'Attachment', file_url: r.attachment_url, type: 'Report' });
    }
    for (const f of r.files || []) {
      if (isImage(f.file_name, f.mime_type)) {
        photos.push({ task_id: r.task_id, task_title: r.task_title, date, file_name: f.file_name, file_url: f.file_url, captured_at: null });
      } else {
        files.push({ scope: 'task', task_id: r.task_id, task_title: r.task_title, date, file_name: f.file_name, file_url: f.file_url, type: f.type || 'Report' });
      }
    }
    if (r.delay_cause || toNum(r.delay_days) > 0) {
      delays.push({ date, cause: r.delay_cause || 'other', days: toNum(r.delay_days), text: r.delay_note || r.issues || '', task_title: r.task_title });
    }
    if (r.safety_note) safety.push({ date, note: r.safety_note });
    if (r.next_plan) nextPlan = r.next_plan;
  }

  // ── certificates and what still needs verification ────────────────────────
  const decided = certificates.rows;
  const certified = decided.filter((c) => c.status === 'verified' || c.status === 'verified_with_changes');
  const lastCertified = certified[certified.length - 1] || null;
  const sinceDate = lastCertified ? dateOnly(lastCertified.cut_off_date || lastCertified.decided_at) : null;
  const sinceReports = approved.filter((r) => !sinceDate || dateOnly(r.report_date) > sinceDate);
  const openRequest = (await pool.query(
    `SELECT id FROM activity_verifications WHERE activity_id = $1 AND status = 'pending' ORDER BY id DESC LIMIT 1`, [activityId])).rows[0];
  const milestone = activity.baseline_milestone_id
    ? { kind: 'baseline', id: activity.baseline_milestone_id, title: activity.baseline_milestone_title }
    : activity.additional_milestone_id
      ? { kind: 'additional', id: activity.additional_milestone_id, title: activity.additional_milestone_title }
      : null;

  return {
    generated_at: new Date().toISOString(),
    as_of_date: dateOnly(asOf),
    activity: {
      id: activity.id, title: activity.title, description: activity.description || '', done_when: activity.done_when || '',
      status: activity.status, side: activity.side, activity_type: activity.activity_type,
      start_date: dateOnly(activity.start_date), end_date: dateOnly(activity.end_date),
      planned_quantity: plannedQty, unit: activity.unit || '', milestone,
      milestone_weight_pct: toNum(activity.milestone_weight_pct), drives_milestone: !!activity.drives_milestone,
      legacy_planned: {
        work: activity.planned_work || '', manpower: activity.planned_manpower || '',
        equipment: activity.planned_equipment || '', materials: activity.planned_materials || '',
      },
    },
    progress: {
      claimed_pct: claimedPct, certified_pct: certifiedPct, planned_today_pct: plannedToday,
      variance_pct: round1(claimedPct - plannedToday),
      required_pace: remainingQty != null && daysLeft ? round3(remainingQty / daysLeft) : null,
      achieved_pace: daysElapsed ? round3(claimedQty / daysElapsed) : null,
      days_left: daysLeft,
    },
    quantities: {
      claimed: claimedQty, certified: certifiedQty, claimed_not_certified: certifiedQty == null ? null : round3(Math.max(0, claimedQty - certifiedQty)),
      planned: plannedQty, remaining: remainingQty, unit: activity.unit || '',
    },
    tasks: tasks.rows.map((t) => ({
      id: t.id, title: t.title, status: t.status, weight_pct: toNum(t.weight_pct),
      target_quantity: t.target_quantity == null ? null : toNum(t.target_quantity), progress_pct: toNum(t.progress_pct),
    })),
    daily_log: dailyLog,
    resources: { rows: [...rows.values()] },
    quality: {
      checklists: checklists.rows.map((c) => ({ title: c.title, task_title: c.task_title, items: c.items, done: c.done })),
      hold_points: stages.rows.filter((s) => s.is_hold_point).map((s) => ({
        task_title: s.task_title, title: s.title, verified_at: s.hold_verified_at ? dateOnly(s.hold_verified_at) : null,
      })),
      rework: rework.rows.map((r) => ({
        kind: r.kind, reason: r.reason, status: r.status, raised_at: dateOnly(r.raised_at), closed_at: r.closed_at ? dateOnly(r.closed_at) : null,
      })),
    },
    delays,
    safety,
    photos,
    attachments: files,
    site_photos: milestoneMeta.rows.map((p) => ({ file_name: p.file_name, file_url: p.cloudinary_url, uploaded_at: dateOnly(p.uploaded_at) })),
    next_period: { text: nextPlan || '' },
    needs_verification: {
      since_certificate_no: lastCertified ? lastCertified.certificate_no : null,
      claimed_quantity_since: round3(sinceReports.reduce((sum, r) => sum + toNum(r.quantity_done), 0)),
      report_ids: sinceReports.map((r) => r.id),
      open_request_id: openRequest ? openRequest.id : null,
    },
    certificates: decided.map((c) => ({
      verification_id: c.id, certificate_no: c.certificate_no, kind: c.kind, status: c.status,
      decided_at: c.decided_at, decided_by_role: c.decided_by_role,
      claimed_pct: toNum(c.claimed_progress_pct), certified_pct: c.certified_progress_pct == null ? null : toNum(c.certified_progress_pct),
      note: c.certification_note || '', reason: c.decision_reason || '',
    })),
  };
}

/**
 * Remove what the viewer may not see. mode is 'own' (the activity's own side), 'consultant' or 'client'.
 * pendingReports are added only for 'own' and are never counted in any figure.
 */
export function shapeReportForViewer(report, mode, { pendingReports = null } = {}) {
  const viewer = { mode, can_download: true };
  if (mode === 'client') {
    return {
      generated_at: report.generated_at,
      as_of_date: report.as_of_date,
      activity: {
        id: report.activity.id, title: report.activity.title, side: report.activity.side, milestone: report.activity.milestone,
        start_date: report.activity.start_date, end_date: report.activity.end_date, unit: report.activity.unit,
        planned_quantity: report.activity.planned_quantity, milestone_weight_pct: report.activity.milestone_weight_pct,
      },
      progress: { certified_pct: report.progress.certified_pct },
      quantities: { certified: report.quantities.certified, planned: report.quantities.planned, unit: report.quantities.unit },
      site_photos: report.site_photos,
      certificates: report.certificates.filter((c) => c.status !== 'rejected').map((c) => ({
        verification_id: c.verification_id, certificate_no: c.certificate_no, decided_at: c.decided_at,
        certified_pct: c.certified_pct, note: c.note,
      })),
      viewer,
    };
  }
  const shaped = { ...report, viewer };
  if (mode === 'own' && pendingReports) shaped.pending_reports = pendingReports;
  return shaped;
}
