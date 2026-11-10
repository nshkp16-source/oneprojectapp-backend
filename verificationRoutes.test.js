// Needs a THROWAWAY PostgreSQL database with the base schema and all dated migrations applied.
// It inserts fixtures, so never point it at real data.
// Run:  TEST_DATABASE_URL=postgres://user:pass@localhost/scratch node --test verificationRoutes.test.js
// Needs the packages express, pg and multer (npm i -D express pg multer).
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import multer from 'multer';
import pg from 'pg';
import { registerActivityRoutes } from './planningRoutes.js';
import { registerReportRoutes } from './workCenterRoutes.js';
import { registerVerificationRoutes } from './verificationRoutes.js';

const pool = new pg.Pool({ connectionString: process.env.TEST_DATABASE_URL });
const notes = [];
const app = express();
app.use(express.json());
const side = (r) => (r.startsWith('Contractor') ? 'Contractor' : r.startsWith('Consultant') ? 'Consultant' : r.startsWith('Client') ? 'Client' : null);
const deps = {
  pool, authenticateToken: (req, _res, next) => { req.user = JSON.parse(req.headers['x-user']); next(); },
  upload: multer({ storage: multer.memoryStorage() }), requireProjectLifecycleWrite: (_q, _s, n) => n(),
  scheduleCloudinaryUpload: async () => ({}), wcSide: side, isWCLeader: (r) => side(r) !== null,
  isProjectMember: async () => true, notify: async (n) => { notes.push(n); }, flowKey: (role, id) => ({ role, id }),
  leadersOf: async (_p, sd) => [{ role: sd === 'Consultant' ? 'ConsultantPM' : 'ContractorPM', id: sd === 'Consultant' ? 8 : 5 }],
};
registerActivityRoutes(app, deps); registerReportRoutes(app, deps); registerVerificationRoutes(app, deps);
let server, base;
const leader = { user_id: 5, role: 'ContractorPM' };
const cons = { user_id: 8, role: 'ConsultantPM' };
const client = { user_id: 9, role: 'ClientPM' };
const m = (id) => ({ user_id: id, role: 'TeamMember' });
async function call(method, path, user, body) {
  const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json', 'x-user': JSON.stringify(user) }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}
const q = async (sql, params) => (await pool.query(sql, params)).rows;
const common = { projectId: 1, start_date: '2026-03-01', end_date: '2026-04-30' };
const report = (user, o) => call('POST', '/api/work-center-progress', user, { projectId: 1, workDone: 'Work', ...o });
const approve = (id) => call('PUT', `/api/work-center-progress/${id}/validate`, leader, { projectId: 1, validation_status: 'approved' });
async function progressTo(task, user, date, qty) { const r = await report(user, { taskId: task.id, reportDate: date, quantityDone: qty }); assert.equal(r.status, 201, JSON.stringify(r.body)); return approve(r.body.entry.id); }
const today = (await pool.query(`SELECT to_char(CURRENT_DATE,'YYYY-MM-DD') d, to_char(CURRENT_DATE + 7,'YYYY-MM-DD') d7`)).rows[0];

before(async () => {
  await pool.query(`INSERT INTO clients (id, company_name, company_email) VALUES (1,'Test client','client@test.local') ON CONFLICT DO NOTHING`);
  await pool.query(`INSERT INTO projects (id, name, client_id) VALUES (1,'Test project',1) ON CONFLICT DO NOTHING`);
  for (const t of ['workspace_work_center', 'planning_execution', 'workspace_work_center_progress'])
    await pool.query(`SELECT setval(pg_get_serial_sequence('${t}','id'), 1000)`);
  await pool.query(`INSERT INTO team_members (id, email) VALUES (101,'a@x'),(102,'b@x'),(201,'k@x')`);
  await pool.query(`INSERT INTO team_member_assignments (project_id, team_member_id, assigned_by, assigned_part) VALUES (1,101,5,'Contractor'),(1,102,5,'Contractor'),(1,201,8,'Consultant')`);
  await pool.query(`INSERT INTO project_schedules (id, project_id, planned_start, planned_finish) VALUES (1,'1','2026-01-01','2026-12-31')`);
  await pool.query(`INSERT INTO milestones (id, schedule_id, project_id, title, planned_start, planned_end, quantity, unit) VALUES (1,1,'1','Foundation','2026-01-01','2026-05-01',400,'m3')`);
  server = app.listen(0); base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { server.close(); await pool.end(); });

let act, tA, tB, v1;

test('fixture: linked activity with progress (claimed 25%)', async () => {
  const r = await call('POST', '/api/planning-execution/create-with-tasks', leader, { ...common, title: 'Excavation', activity_type: 'quantity', planned_quantity: 400, unit: 'm3', baseline_milestone_id: 1,
    tasks: [{ title: 'Block A', assigned_members: [{ id: 101 }] }, { title: 'Block B', assigned_members: [{ id: 102 }] }] });
  assert.equal(r.status, 201, JSON.stringify(r.body)); act = r.body.activity; [tA, tB] = r.body.tasks;
  const d = await progressTo(tA, m(101), '2026-03-10', 100);
  assert.equal(d.body.activity.progress_pct, 25);
});

test('request rules: only contractor leaders, and only when there is something new', async () => {
  assert.equal((await call('POST', `/api/activities/${act.id}/verifications`, cons, {})).status, 403);
  assert.equal((await call('POST', `/api/activities/${act.id}/verifications`, m(101), {})).status, 403);
  const fresh = await call('POST', '/api/planning-execution/create-with-tasks', leader, { ...common, title: 'No progress', activity_type: 'percentage', tasks: [{ title: 't', assigned_members: [{ id: 101 }] }] });
  const r = await call('POST', `/api/activities/${fresh.body.activity.id}/verifications`, leader, {});
  assert.equal(r.status, 409);
  assert.match(r.body.error, /nothing new/);
  assert.equal((await call('POST', `/api/activities/${act.id}/verifications`, leader, { cutOffDate: '2099-01-01' })).status, 400);
  assert.equal((await call('POST', `/api/activities/${act.id}/verifications`, leader, { signers: [{ role: 'TeamMember', user_id: 101 }] })).status, 403);   // contractor member is not an inspector
});

test('a request freezes the claimed figures, sets the respond-by date and notifies the consultant side', async () => {
  const r = await call('POST', `/api/activities/${act.id}/verifications`, leader, { note: 'Block A excavated', shareActivitySummary: true, signers: [{ role: 'TeamMember', user_id: 201, position: 'Inspector' }] });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  v1 = r.body.verification;
  assert.equal(Number(v1.claimed_progress_pct), 25);
  assert.equal(v1.claimed_figures.length, 2);
  assert.equal(v1.claimed_figures[0].approved_quantity, 100);
  assert.equal(v1.share_activity_summary, true);
  assert.equal(v1.shared_activity_summary.title, 'Excavation');
  assert.equal(String(v1.respond_by).slice(0, 10), today.d7);
  const n = notes.at(-1);
  assert.equal(n.entityType, 'activity_verification');
  assert.ok(n.recipients.some((x) => x.role === 'TeamMember' && x.id === 201));
  assert.equal((await call('POST', `/api/activities/${act.id}/verifications`, leader, {})).status, 409);   // one pending of this kind
});

test('shared evidence: opt-in, approved reports only, up to the cut-off, no identities, frozen copy', async () => {
  // a rejected report, a pending report and an approved report dated after the cut-off: none may reach the consultant
  const rejected = await report(m(101), { taskId: tA.id, reportDate: '2026-03-11', quantityDone: 7, manpower: '4 workers', issues: 'Rain' });
  assert.equal(rejected.status, 201, JSON.stringify(rejected.body));
  await call('PUT', `/api/work-center-progress/${rejected.body.entry.id}/validate`, leader, { projectId: 1, validation_status: 'rejected', validation_notes: 'Not on site' });
  const pendingReport = await report(m(101), { taskId: tA.id, reportDate: '2026-03-12', quantityDone: 9 });
  assert.equal(pendingReport.status, 201);
  // inserted directly so that claimed progress, which the later tests rely on, does not move
  const [late] = await q(`INSERT INTO workspace_work_center_progress (task_id, report_date, member_id, member_role, work_done, quantity_done, validation_status)
    VALUES ($1,'2026-03-13',102,'TeamMember','Late work',20,'approved') RETURNING id`, [tB.id]);
  const [approvedReport] = await q(
    `SELECT id FROM workspace_work_center_progress WHERE task_id = $1 AND report_date = '2026-03-10'`,
    [tA.id]);
  const [onTimeAttachment] = await q(
    `INSERT INTO work_center_report_attachments
       (report_id, project_id, file_name, file_id, file_url, mime_type, attachment_type, uploaded_by_id, uploaded_by_role)
     VALUES ($1,1,'Cube test results.pdf','test-results','https://files.test/Cube-test-results.pdf',
       'application/pdf','quality_test',5,'ContractorPM') RETURNING id`,
    [approvedReport.id]);
  const [privateAttachment] = await q(
    `INSERT INTO work_center_report_attachments
        (report_id, project_id, file_name, file_id, file_url, mime_type, attachment_type, uploaded_by_id, uploaded_by_role)
     VALUES ($1,1,'Private field note.pdf','private-field-note','https://files.test/Private-field-note.pdf',
        'application/pdf','other',5,'ContractorPM') RETURNING id`,
    [approvedReport.id]);
  const [onTimePhoto] = await q(
    `INSERT INTO work_center_report_photos
       (report_id, project_id, seq, file_name, file_id, file_url)
     VALUES ($1,1,1,'Foundation photo.jpg','foundation-photo','https://files.test/Foundation-photo.jpg')
     RETURNING id`,
    [approvedReport.id]);
  const [privatePhoto] = await q(
    `INSERT INTO work_center_report_photos
       (report_id, project_id, seq, file_name, file_id, file_url)
     VALUES ($1,1,2,'Private detail.jpg','private-photo','https://files.test/Private-detail.jpg')
     RETURNING id`,
    [approvedReport.id]);
  const [lateAttachment] = await q(
    `INSERT INTO work_center_report_attachments
       (report_id, project_id, file_name, file_id, file_url, mime_type, attachment_type,
        custom_attachment_type, uploaded_by_id, uploaded_by_role)
     VALUES ($1,1,'Later file.pdf','later-file','https://files.test/Later-file.pdf',
       'application/pdf','other','Later evidence',5,'ContractorPM') RETURNING id`,
    [late.id]);
  const cleanup = async () => {
    await q(`DELETE FROM work_center_report_photos WHERE id = ANY($1::bigint[])`, [[onTimePhoto.id, privatePhoto.id]]);
    await q(`DELETE FROM work_center_report_attachments WHERE id = ANY($1::bigint[])`, [[onTimeAttachment.id, privateAttachment.id, lateAttachment.id]]);
    await q(`DELETE FROM workspace_work_center_progress WHERE id = ANY($1::int[])`, [[late.id, rejected.body.entry.id, pendingReport.body.entry.id]]);
  };
  try {
    // 1. not shared: the consultant gets totals only
    const [row] = await q(`SELECT share_evidence, shared_evidence FROM activity_verifications WHERE id = $1`, [v1.id]);
    assert.equal(row.share_evidence, false);
    assert.equal(row.shared_evidence, null);
    const listed = await call('GET', `/api/activities/${act.id}/verifications`, cons);
    assert.equal(listed.status, 200);
    const first = listed.body.verifications.find((v) => v.id === v1.id);
    assert.equal(first.shared_evidence, null);
    assert.deepEqual(first.claimed_figures, []);

    // 2. Evidence must be selected by the contractor; details are a separate opt-in.
    assert.equal((await call('PUT', `/api/verifications/${v1.id}/withdraw`, leader, {})).status, 200);
    const invalidSelection = await call('POST', `/api/activities/${act.id}/verifications`, leader, {
      note: 'Invalid file', cutOffDate: '2026-03-12',
      selectedEvidence: [{ type: 'supporting_attachment', id: String(lateAttachment.id) }],
    });
    assert.equal(invalidSelection.status, 400);
    const shared = await call('POST', `/api/activities/${act.id}/verifications`, leader, {
      note: 'With evidence', cutOffDate: '2026-03-12', shareEvidence: true,
      selectedEvidence: [
        { type: 'supporting_attachment', id: String(onTimeAttachment.id) },
        { type: 'photo', id: String(onTimePhoto.id) },
      ],
    });
    assert.equal(shared.status, 201, JSON.stringify(shared.body));
    const ev = shared.body.verification;
    assert.equal(ev.share_evidence, true);
    assert.equal(ev.shared_evidence.reports.length, 1);                 // only the approved report of 10 March
    assert.equal(ev.shared_evidence.reports[0].report_date, '2026-03-10');
    assert.equal(ev.shared_evidence.reports[0].quantity_done, 100);
    assert.deepEqual(ev.shared_evidence.reports[0].photos, []);
    assert.equal(ev.shared_evidence.supporting_attachments.length, 1);
    assert.equal(ev.shared_evidence.supporting_attachments[0].file_name, 'Cube test results.pdf');
    assert.equal(ev.shared_evidence.supporting_attachments[0].attachment_type, 'quality_test');
    assert.equal(ev.shared_evidence.selected_evidence.length, 2);
    assert.deepEqual(ev.shared_evidence.selected_evidence.map((file) => file.type).sort(), ['photo', 'supporting_attachment']);
    assert.equal(ev.shared_evidence.selected_evidence.find((file) => file.type === 'photo').file_name, 'Foundation photo.jpg');
    assert.doesNotMatch(JSON.stringify(ev.shared_evidence), /Private field note|Private detail\.jpg/);

    // the consultant reads the frozen copy, with no member identity, task id, rejection note or unapproved figure
    const seen = (await call('GET', `/api/activities/${act.id}/verifications`, cons)).body.verifications.find((v) => v.id === ev.id);
    assert.equal(seen.shared_evidence.reports.length, 1);
    assert.equal(seen.shared_evidence.supporting_attachments.length, 1);
    assert.equal(seen.shared_evidence.selected_evidence.length, 2);
    assert.doesNotMatch(JSON.stringify(seen.shared_evidence), /a@x|b@x|member_id|task_id|Not on site|Rain|"quantity_done":(7|9|20)\b/);
    const pend = await call('GET', '/api/verifications/pending?projectId=1', cons);
    const row2 = pend.body.pending.find((v) => v.id === ev.id);
    assert.equal(row2.shared_evidence.reports.length, 1);
    assert.equal(row2.shared_evidence.supporting_attachments.length, 1);
    assert.equal(row2.shared_evidence.selected_evidence.length, 2);
    assert.ok('days_left' in row2 && 'activity_certified_progress_pct' in row2 && 'pending_inspectors' in row2);

    // the consultant still cannot read the contractor's task reports directly
    assert.equal((await call('GET', `/api/work-center-progress/${tA.id}?projectId=1`, cons)).status, 403);

    assert.equal((await call('PUT', `/api/verifications/${ev.id}/withdraw`, leader, {})).status, 200);
    const filesOnly = await call('POST', `/api/activities/${act.id}/verifications`, leader, {
      note: 'Share report details only', cutOffDate: '2026-03-15', shareEvidence: true,
    });
    assert.equal(filesOnly.status, 201, JSON.stringify(filesOnly.body));
    assert.equal(filesOnly.body.verification.share_evidence, true);
    assert.equal(filesOnly.body.verification.shared_evidence.reports.length, 2);
    assert.deepEqual(filesOnly.body.verification.shared_evidence.selected_evidence, []);
    assert.deepEqual(filesOnly.body.verification.shared_evidence.supporting_attachments, []);
    await call('PUT', `/api/verifications/${filesOnly.body.verification.id}/withdraw`, leader, {});
    const selectedFileOnly = await call('POST', `/api/activities/${act.id}/verifications`, leader, {
      note: 'Selected supporting attachment', cutOffDate: '2026-03-12',
      selectedEvidence: [{ type: 'supporting_attachment', id: String(onTimeAttachment.id) }],
    });
    assert.equal(selectedFileOnly.status, 201, JSON.stringify(selectedFileOnly.body));
    assert.equal(selectedFileOnly.body.verification.share_evidence, false);
    assert.deepEqual(selectedFileOnly.body.verification.shared_evidence.reports, []);
    assert.equal(selectedFileOnly.body.verification.shared_evidence.supporting_attachments.length, 1);
    assert.equal((await call('GET', `/api/activities/${act.id}/verifications`, cons)).body.verifications
      .find((v) => v.id === selectedFileOnly.body.verification.id).shared_evidence.supporting_attachments.length, 1);

    // restore what the next tests expect: one pending request (v1) with the named inspector
    assert.equal((await call('PUT', `/api/verifications/${selectedFileOnly.body.verification.id}/withdraw`, leader, {})).status, 200);
    const again = await call('POST', `/api/activities/${act.id}/verifications`, leader, { note: 'Block A excavated', shareActivitySummary: true, signers: [{ role: 'TeamMember', user_id: 201, position: 'Inspector' }] });
    assert.equal(again.status, 201, JSON.stringify(again.body));
    v1 = again.body.verification;
  } finally { await cleanup(); }
});

test('decision rules: inspector first, reason for changes, other roles refused', async () => {
  assert.equal((await call('PUT', `/api/verifications/${v1.id}/decide`, leader, { status: 'verified' })).status, 403);
  assert.equal((await call('PUT', `/api/verifications/${v1.id}/decide`, client, { status: 'verified' })).status, 403);
  const early = await call('PUT', `/api/verifications/${v1.id}/decide`, cons, { status: 'verified' });
  assert.equal(early.status, 409);
  assert.equal(early.body.code, 'INSPECTOR_PENDING');
  assert.equal((await call('PUT', `/api/verifications/${v1.id}/inspect`, m(102), { outcome: 'recommend_verify' })).status, 404);   // not the named inspector
  assert.equal((await call('PUT', `/api/verifications/${v1.id}/inspect`, m(201), { outcome: 'maybe' })).status, 400);
  assert.equal((await call('PUT', `/api/verifications/${v1.id}/inspect`, m(201), { outcome: 'recommend_changes', note: 'Measured 80 m3' })).status, 200);
  assert.equal((await call('PUT', `/api/verifications/${v1.id}/decide`, cons, { status: 'verified_with_changes', certified_progress_pct: 20 })).status, 400);   // no reason
  assert.equal((await call('PUT', `/api/verifications/${v1.id}/decide`, cons, { status: 'verified_with_changes', certified_progress_pct: 120, reason: 'x' })).status, 400);
});

test('verified with changes sets certified progress, ends the temporary milestone value and syncs the milestone', async () => {
  await pool.query(`UPDATE milestones SET override_pct=10, override_reason='Cracks', override_by_id=8, override_by_role='ConsultantPM', override_at=now() WHERE id=1`);
  await pool.query(`INSERT INTO milestone_progress_overrides (project_id, baseline_milestone_id, set_pct, derived_pct_at_time, reason, set_by_id, set_by_role) VALUES (1,1,10,25,'Cracks',8,'ConsultantPM')`);
  const d = await call('PUT', `/api/verifications/${v1.id}/decide`, cons, { status: 'verified_with_changes', certified_progress_pct: 20, reason: 'Measured 80 m3 on site' });
  assert.equal(d.status, 200, JSON.stringify(d.body));
  assert.equal(d.body.certified_progress_pct, 20);
  assert.equal(d.body.milestone.progress_pct, 20);
  const [a] = await q(`SELECT certified_progress_pct, certified_at, progress_pct FROM planning_execution WHERE id=$1`, [act.id]);
  assert.equal(Number(a.certified_progress_pct), 20);
  assert.equal(Number(a.progress_pct), 25);                          // claimed stays what the contractor reported
  assert.ok(a.certified_at);
  const [ms] = await q(`SELECT override_pct, progress_pct, executed FROM milestones WHERE id=1`);
  assert.equal(ms.override_pct, null);
  assert.equal(Number(ms.progress_pct), 20);
  assert.equal(Number(ms.executed), 80);
  assert.equal((await q(`SELECT ended_reason FROM milestone_progress_overrides WHERE baseline_milestone_id=1`))[0].ended_reason, 'replaced_by_verification');
  assert.equal(notes.at(-1).recipients[0].role, 'ContractorPM');
});

test('a decided request cannot be decided or withdrawn again', async () => {
  assert.equal((await call('PUT', `/api/verifications/${v1.id}/decide`, cons, { status: 'verified' })).status, 409);
  assert.equal((await call('PUT', `/api/verifications/${v1.id}/withdraw`, leader, {})).status, 409);
});

test('a rejection needs a reason, creates rework, and leaves certified progress alone', async () => {
  await progressTo(tB, m(102), '2026-03-11', 100);                    // claimed now 50
  const r2 = await call('POST', `/api/activities/${act.id}/verifications`, leader, {});
  assert.equal(r2.status, 201, JSON.stringify(r2.body));
  assert.equal((await call('PUT', `/api/verifications/${r2.body.verification.id}/decide`, cons, { status: 'rejected' })).status, 400);
  const rej = await call('PUT', `/api/verifications/${r2.body.verification.id}/decide`, cons, { status: 'rejected', reason: 'Levels outside tolerance in block B', rework: [{ task_id: tB.id, reason: 'Re-excavate to level' }] });
  assert.equal(rej.status, 200, JSON.stringify(rej.body));
  assert.equal(rej.body.rework_items, 1);
  assert.equal(Number((await q(`SELECT certified_progress_pct FROM planning_execution WHERE id=$1`, [act.id]))[0].certified_progress_pct), 20);
  const items = await q(`SELECT id, kind, status FROM rework_items WHERE activity_id=$1`, [act.id]);
  assert.deepEqual(items.map((i) => [i.kind, i.status]), [['rework', 'open']]);
  // contractor corrects, consultant closes
  assert.equal((await call('PUT', `/api/rework/${items[0].id}/correct`, cons, {})).status, 403);
  assert.equal((await call('PUT', `/api/rework/${items[0].id}/correct`, leader, { note: 'Done' })).status, 200);
  assert.equal((await call('PUT', `/api/rework/${items[0].id}/close`, leader, {})).status, 403);
  assert.equal((await call('PUT', `/api/rework/${items[0].id}/close`, cons, {})).status, 200);
});

test('withdraw works on a pending request and a new one can follow', async () => {
  const r = await call('POST', `/api/activities/${act.id}/verifications`, leader, {});
  assert.equal(r.status, 201);
  assert.equal((await call('PUT', `/api/verifications/${r.body.verification.id}/withdraw`, leader, {})).body.verification.status, 'withdrawn');
  const again = await call('POST', `/api/activities/${act.id}/verifications`, leader, {});
  assert.equal(again.status, 201);
  const d = await call('PUT', `/api/verifications/${again.body.verification.id}/decide`, cons, { status: 'verified' });
  assert.equal(d.body.certified_progress_pct, 50);                    // verified as claimed
  assert.equal(d.body.milestone.progress_pct, 50);
});

test('lists: contractor and consultant see requests with an overdue flag, the client is refused', async () => {
  assert.equal((await call('GET', `/api/activities/${act.id}/verifications`, client)).status, 403);
  const l = await call('GET', `/api/activities/${act.id}/verifications`, cons);
  assert.equal(l.status, 200);
  assert.ok(l.body.verifications.length >= 4);
  assert.equal(l.body.verifications[0].overdue, false);
  assert.deepEqual(l.body.verifications[0].claimed_figures, []);
  assert.equal(l.body.verifications[0].activity_summary.task_count, 2);
  const card = await call('GET', `/api/planning-execution/${act.id}/activity-card?projectId=1`, cons);
  assert.equal(card.status, 200);
  assert.deepEqual(card.body.tasks, []);
  assert.equal(card.body.activity.description, undefined);
  assert.equal(typeof card.body.activity_summary.approved_report_count, 'number');
  const pending = await call('GET', `/api/verifications/pending?projectId=1`, cons);
  assert.equal(pending.status, 200);
  assert.deepEqual(pending.body.pending[0].claimed_figures, []);
  assert.equal((await call('GET', `/api/verifications/pending?projectId=1`, client)).status, 403);
});

test('hold point: needs a completed stage, verification unlocks the next stage', async () => {
  const c = await call('POST', '/api/planning-execution/create-with-tasks', leader, { ...common, title: 'Slab', activity_type: 'stages',
    tasks: [{ title: 'Pour', assigned_members: [{ id: 101 }], stages: [{ title: 'Reinforcement', weight_pct: 40, is_hold_point: true }, { title: 'Pour', weight_pct: 60 }] }] });
  const a = c.body.activity, t = c.body.tasks[0];
  const [s1, s2] = await q(`SELECT id FROM task_stages WHERE task_id=$1 ORDER BY seq`, [t.id]);
  assert.equal((await call('POST', `/api/activities/${a.id}/verifications`, leader, { kind: 'hold_point', stageId: s1.id })).status, 409);   // stage not completed yet
  const r1 = await report(m(101), { taskId: t.id, reportDate: '2026-03-10', stageId: s1.id });
  await approve(r1.body.entry.id);
  assert.equal((await call('POST', `/api/activities/${a.id}/verifications`, leader, { kind: 'hold_point', stageId: s2.id })).status, 400);   // not a hold point
  const hp = await call('POST', `/api/activities/${a.id}/verifications`, leader, { kind: 'hold_point', stageId: s1.id });
  assert.equal(hp.status, 201, JSON.stringify(hp.body));
  assert.equal((await report(m(101), { taskId: t.id, reportDate: '2026-03-11', stageId: s2.id })).status, 409);
  assert.equal((await call('PUT', `/api/verifications/${hp.body.verification.id}/decide`, cons, { status: 'verified_with_changes', certified_progress_pct: 10, reason: 'x' })).status, 400);
  assert.equal((await call('PUT', `/api/verifications/${hp.body.verification.id}/decide`, cons, { status: 'verified' })).status, 200);
  assert.ok((await q(`SELECT hold_verified_at FROM task_stages WHERE id=$1`, [s1.id]))[0].hold_verified_at);
  assert.equal((await report(m(101), { taskId: t.id, reportDate: '2026-03-11', stageId: s2.id })).status, 201);
});

test('completion: needs 100% and no open rework; snags keep the activity open until they are closed', async () => {
  assert.equal((await call('POST', `/api/activities/${act.id}/verifications`, leader, { kind: 'completion' })).status, 409);   // only 50% claimed
  await progressTo(tA, m(101), '2026-03-12', 100);
  await progressTo(tB, m(102), '2026-03-12', 100);
  assert.equal((await q(`SELECT status FROM planning_execution WHERE id=$1`, [act.id]))[0].status, 'completed');
  const snag = await call('POST', `/api/activities/${act.id}/rework`, cons, { kind: 'snag', reason: 'Spoil heap not removed', certified_progress_pct: 40 });
  assert.equal(snag.status, 201);
  assert.equal(Number((await q(`SELECT certified_progress_pct FROM planning_execution WHERE id=$1`, [act.id]))[0].certified_progress_pct), 40);
  assert.equal((await call('POST', `/api/activities/${act.id}/rework`, leader, { kind: 'snag', reason: 'x' })).status, 403);
  assert.equal((await call('POST', `/api/activities/${act.id}/verifications`, leader, { kind: 'completion' })).status, 409);   // open snag
  await call('PUT', `/api/rework/${snag.body.item.id}/close`, cons, {});
  const req = await call('POST', `/api/activities/${act.id}/verifications`, leader, { kind: 'completion', note: 'All blocks done' });
  assert.equal(req.status, 201, JSON.stringify(req.body));
  assert.equal((await call('PUT', `/api/verifications/${req.body.verification.id}/decide`, cons, { status: 'verified_with_changes', certified_progress_pct: 90, reason: 'x' })).status, 400);   // not allowed for completion
  const d = await call('PUT', `/api/verifications/${req.body.verification.id}/decide`, cons, { status: 'verified', reason: 'Complete, one snag to clear', rework: [{ reason: 'Touch up edge protection' }] });
  assert.equal(d.status, 200, JSON.stringify(d.body));
  assert.equal(d.body.activity_closed, false);                        // a snag is open
  assert.equal(Number((await q(`SELECT certified_progress_pct FROM planning_execution WHERE id=$1`, [act.id]))[0].certified_progress_pct), 99);
  assert.equal((await q(`SELECT status FROM planning_execution WHERE id=$1`, [act.id]))[0].status, 'completed');
  const [open] = await q(`SELECT id, kind FROM rework_items WHERE activity_id=$1 AND status<>'closed'`, [act.id]);
  assert.equal(open.kind, 'snag');
  const closed = await call('PUT', `/api/rework/${open.id}/close`, cons, {});
  assert.equal(closed.body.activity_closed, true);
  assert.equal(closed.body.milestone.progress_pct, 100);
  const [a] = await q(`SELECT status, certified_progress_pct, closed_by_role, to_char(actual_end,'YYYY-MM-DD') e FROM planning_execution WHERE id=$1`, [act.id]);
  assert.deepEqual([a.status, Number(a.certified_progress_pct), a.closed_by_role, a.e], ['closed', 100, 'ConsultantPM', today.d]);
  assert.deepEqual((await q(`SELECT DISTINCT status FROM workspace_work_center WHERE activity_id=$1`, [act.id])).map((x) => x.status), ['closed']);
  assert.equal((await report(m(101), { taskId: tA.id, reportDate: '2026-03-13', quantityDone: 1 })).status, 409);   // closed
  const revised = await call('POST', `/api/verifications/${req.body.verification.id}/revise`, cons, { certified_progress_pct: 90, reason: 'A final edge section still needs correction.' });
  assert.equal(revised.status, 200, JSON.stringify(revised.body));
  assert.equal(revised.body.certified_progress_pct, 90);
  assert.equal((await q(`SELECT status FROM planning_execution WHERE id=$1`, [act.id]))[0].status, 'completed');
  const [revisionSnag] = await q(`SELECT id FROM rework_items WHERE activity_id=$1 AND kind='snag' AND status='open' ORDER BY id DESC LIMIT 1`, [act.id]);
  assert.equal((await call('PUT', `/api/rework/${revisionSnag.id}/correct`, leader, { note: 'Edge section corrected' })).status, 200);
  const revisedClosed = await call('PUT', `/api/rework/${revisionSnag.id}/close`, cons, {});
  assert.equal(revisedClosed.body.activity_closed, true);
  assert.equal(Number((await q(`SELECT certified_progress_pct FROM planning_execution WHERE id=$1`, [act.id]))[0].certified_progress_pct), 100);
});

test('read receipts, unread markers and history', async () => {
  const c = await call('POST', '/api/planning-execution/create-with-tasks', leader, { ...common, title: 'Receipt check', activity_type: 'percentage',
    tasks: [{ title: 'Receipt task', assigned_members: [{ id: 101 }] }] });
  assert.equal(c.status, 201, JSON.stringify(c.body));
  const a = c.body.activity, t1 = c.body.tasks[0];
  const claim = async (date, pct) => { const r = await report(m(101), { taskId: t1.id, reportDate: date, progressPct: pct }); assert.equal(r.status, 201, JSON.stringify(r.body)); await approve(r.body.entry.id); };
  await claim('2026-03-10', 30);
  const req1 = await call('POST', `/api/activities/${a.id}/verifications`, leader, { note: 'Receipt request', signers: [{ role: 'TeamMember', user_id: 201, position: 'Inspector' }] });
  assert.equal(req1.status, 201, JSON.stringify(req1.body));
  const id = req1.body.verification.id;
  const pendingRow = async (user) => (await call('GET', '/api/verifications/pending?projectId=1', user)).body.pending.find((v) => v.id === id);

  // nobody has opened it: unread for the consultant side, "not opened" for the contractor
  const unread = await pendingRow(cons);
  assert.equal(unread.is_unread, true);
  assert.equal(unread.seen_at, null);
  assert.equal((await pendingRow(leader)).seen_at, null);
  assert.equal((await pendingRow(leader)).is_unread, false);               // the marker is for the consultant side only

  // only the consultant side can record a read
  assert.equal((await call('POST', `/api/verifications/${id}/read`, leader, {})).status, 403);
  assert.equal((await call('POST', `/api/verifications/${id}/read`, m(102), {})).status, 403);   // contractor member
  assert.equal((await call('POST', `/api/verifications/${id}/read`, client, {})).status, 403);
  assert.equal((await call('POST', '/api/verifications/999999/read', cons, {})).status, 404);
  const first = await call('POST', `/api/verifications/${id}/read`, cons, {});
  assert.equal(first.status, 200, JSON.stringify(first.body));
  const second = await call('POST', `/api/verifications/${id}/read`, cons, {});
  assert.equal(second.body.first_read_at, first.body.first_read_at);        // the first opening is kept

  // read for the leader who opened it, still unread for the named inspector, and the contractor sees "opened"
  assert.equal((await pendingRow(cons)).is_unread, false);
  assert.equal((await pendingRow(m(201))).is_unread, true);
  assert.equal((await call('POST', `/api/verifications/${id}/read`, m(201), {})).status, 200);
  assert.equal((await pendingRow(m(201))).is_unread, false);
  const seen = await pendingRow(leader);
  assert.ok(seen.seen_at);
  assert.equal(seen.seen_by_role, 'ConsultantPM');
  assert.ok(!('reader_id' in seen));                                         // the contractor learns that it was opened, not by whom
  const onCard = (await call('GET', `/api/activities/${a.id}/verifications`, leader)).body.verifications.find((v) => v.id === id);
  assert.ok(onCard.seen_at);

  // decide, then the request moves to history; pending no longer lists it
  const decided = await call('PUT', `/api/verifications/${id}/decide`, cons, { status: 'verified', skip_inspectors: 'true' });
  assert.equal(decided.status, 200, JSON.stringify(decided.body));
  assert.equal(await pendingRow(cons), undefined);
  const hist = (user, query = '') => call('GET', `/api/verifications/history?projectId=1${query}`, user);
  const h = (await hist(cons)).body.history.find((v) => v.id === id);
  assert.equal(h.status, 'verified');
  assert.equal(h.activity_title, 'Receipt check');
  assert.ok(h.seen_at);
  assert.ok(!('shared_evidence' in h) && !('claimed_figures' in h));         // heavy fields stay on the activity card
  assert.ok((await hist(leader)).body.history.some((v) => v.id === id));
  assert.ok((await hist(m(201))).body.history.some((v) => v.id === id));     // the named inspector
  assert.ok(!(await hist(m(102))).body.history.some((v) => v.id === id));    // a contractor member who is no signer
  assert.equal((await hist(client)).status, 403);

  // outcome filter, search (a typed % is not a wildcard) and paging
  const has = async (query) => (await hist(cons, query)).body.history.some((v) => v.id === id);
  assert.equal(await has('&status=verified'), true);
  assert.equal(await has('&status=rejected'), false);
  assert.equal((await hist(cons, '&status=maybe')).status, 400);
  assert.equal(await has('&q=receipt'), true);
  assert.equal(await has('&q=Receipt%20request'), true);                     // request note
  assert.equal(await has('&q=zzzz-no-match'), false);
  assert.equal(await has('&q=%25'), false);
  const paged = (await hist(cons, '&limit=1')).body;
  assert.equal(paged.history.length, 1);
  assert.equal(paged.has_more, true);
  const next = (await hist(cons, '&limit=1&offset=1')).body;
  assert.notEqual(next.history[0]?.id, paged.history[0].id);

  // a request decided without a separate "open" still counts as opened by the decider
  await claim('2026-03-11', 50);
  const req2 = await call('POST', `/api/activities/${a.id}/verifications`, leader, { note: 'Second request' });
  assert.equal(req2.status, 201, JSON.stringify(req2.body));
  const rejected = await call('PUT', `/api/verifications/${req2.body.verification.id}/decide`, cons, { status: 'rejected', reason: 'Not measured yet' });
  assert.equal(rejected.status, 200, JSON.stringify(rejected.body));
  const h2 = (await hist(leader, '&status=rejected')).body.history.find((v) => v.id === req2.body.verification.id);
  assert.ok(h2.seen_at);
  assert.equal(h2.decision_reason, 'Not measured yet');

  // a withdrawn request that nobody opened says so
  const req3 = await call('POST', `/api/activities/${a.id}/verifications`, leader, { note: 'Third request' });
  assert.equal(req3.status, 201, JSON.stringify(req3.body));
  assert.equal((await call('PUT', `/api/verifications/${req3.body.verification.id}/withdraw`, leader, {})).status, 200);
  const h3 = (await hist(leader, '&status=withdrawn')).body.history.find((v) => v.id === req3.body.verification.id);
  assert.equal(h3.status, 'withdrawn');
  assert.equal(h3.seen_at, null);
});
