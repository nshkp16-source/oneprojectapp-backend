// Needs a THROWAWAY PostgreSQL database with the base schema and the three 2026-11 migrations applied.
// It inserts fixtures, so never point it at real data.
// Run:  TEST_DATABASE_URL=postgres://user:pass@localhost/scratch node --test verificationRoutes.test.js
// Needs the packages express, pg and multer (npm i -D express pg multer).
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import multer from 'multer';
import pg from 'pg';
import { registerActivityRoutes } from './activityRoutes.js';
import { registerReportRoutes } from './reportRoutes.js';
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
  await pool.query(`INSERT INTO milestones (id, schedule_id, project_id, title, planned_start, planned_end, quantity, unit) VALUES (1,1,'1','Foundation','2026-01-01','2026-03-01',400,'m3')`);
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
  const r = await call('POST', `/api/activities/${act.id}/verifications`, leader, { note: 'Block A excavated', signers: [{ role: 'TeamMember', user_id: 201, position: 'Inspector' }] });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  v1 = r.body.verification;
  assert.equal(Number(v1.claimed_progress_pct), 25);
  assert.equal(v1.claimed_figures.length, 2);
  assert.equal(v1.claimed_figures[0].approved_quantity, 100);
  assert.equal(String(v1.respond_by).slice(0, 10), today.d7);
  const n = notes.at(-1);
  assert.equal(n.entityType, 'activity_verification');
  assert.ok(n.recipients.some((x) => x.role === 'TeamMember' && x.id === 201));
  assert.equal((await call('POST', `/api/activities/${act.id}/verifications`, leader, {})).status, 409);   // one pending of this kind
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
  assert.equal((await call('GET', `/api/verifications/pending?projectId=1`, cons)).status, 200);
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
  const snag = await call('POST', `/api/activities/${act.id}/rework`, cons, { kind: 'snag', reason: 'Spoil heap not removed' });
  assert.equal(snag.status, 201);
  assert.equal((await call('POST', `/api/activities/${act.id}/rework`, leader, { kind: 'snag', reason: 'x' })).status, 403);
  assert.equal((await call('POST', `/api/activities/${act.id}/verifications`, leader, { kind: 'completion' })).status, 409);   // open snag
  await call('PUT', `/api/rework/${snag.body.item.id}/close`, cons, {});
  const req = await call('POST', `/api/activities/${act.id}/verifications`, leader, { kind: 'completion', note: 'All blocks done' });
  assert.equal(req.status, 201, JSON.stringify(req.body));
  assert.equal((await call('PUT', `/api/verifications/${req.body.verification.id}/decide`, cons, { status: 'verified_with_changes', certified_progress_pct: 90, reason: 'x' })).status, 400);   // not allowed for completion
  const d = await call('PUT', `/api/verifications/${req.body.verification.id}/decide`, cons, { status: 'verified', reason: 'Complete, one snag to clear', rework: [{ reason: 'Touch up edge protection' }] });
  assert.equal(d.status, 200, JSON.stringify(d.body));
  assert.equal(d.body.activity_closed, false);                        // a snag is open
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
});
