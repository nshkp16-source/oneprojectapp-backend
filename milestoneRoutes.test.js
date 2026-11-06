// Needs a THROWAWAY PostgreSQL database with the base schema and all dated migrations applied.
// It inserts fixtures, so never point it at real data.
// Run:  TEST_DATABASE_URL=postgres://user:pass@localhost/scratch node --test milestoneRoutes.test.js
// Needs the packages express, pg and multer (npm i -D express pg multer).
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import multer from 'multer';
import pg from 'pg';
import { registerActivityRoutes } from './activityRoutes.js';
import { registerReportRoutes } from './reportRoutes.js';
import { registerVerificationRoutes } from './verificationRoutes.js';
import { registerMilestoneRoutes, milestoneCompletionCheck, assertTypedProgressAllowed } from './milestoneRoutes.js';

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
registerActivityRoutes(app, deps); registerReportRoutes(app, deps); registerVerificationRoutes(app, deps); registerMilestoneRoutes(app, deps);
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
  await pool.query(`INSERT INTO milestones (id, schedule_id, project_id, title, planned_start, planned_end, quantity, unit) VALUES (1,1,'1','Foundation','2026-01-01','2026-05-01',400,'m3'),(2,1,'1','Walls','2026-03-02','2026-05-01',100,'m2')`);
  server = app.listen(0); base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { server.close(); await pool.end(); });


let act, task;
const ms = async (id = 1) => (await q(`SELECT progress_source, progress_pct, derived_progress_pct, override_pct FROM milestones WHERE id=$1`, [id]))[0];

test('fixture: one linked activity, fully reported and verified, so the milestone is derived at 100%', async () => {
  const r = await call('POST', '/api/planning-execution/create-with-tasks', leader, { ...common, title: 'Excavation', activity_type: 'quantity', planned_quantity: 400, unit: 'm3', baseline_milestone_id: 1,
    tasks: [{ title: 'All', assigned_members: [{ id: 101 }] }] });
  assert.equal(r.status, 201, JSON.stringify(r.body)); act = r.body.activity; task = r.body.tasks[0];
  await progressTo(task, m(101), '2026-03-10', 400);
  const v = await call('POST', `/api/activities/${act.id}/verifications`, leader, {});
  assert.equal((await call('PUT', `/api/verifications/${v.body.verification.id}/decide`, cons, { status: 'verified' })).status, 200);
  const x = await ms(); assert.equal(x.progress_source, 'activities'); assert.equal(Number(x.progress_pct), 100);
});

test('progress detail: contractor and consultant see claimed and certified, the client only certified', async () => {
  const c = await call('GET', '/api/milestones/baseline/1/progress-detail', cons);
  assert.equal(c.status, 200, JSON.stringify(c.body));
  assert.equal(c.body.coverage_pct, 100);
  assert.deepEqual(Object.keys(c.body.activities[0]).includes('claimed'), true);
  const cl = await call('GET', '/api/milestones/baseline/1/progress-detail', client);
  assert.equal(cl.status, 200);
  assert.equal(Object.keys(cl.body.activities[0]).includes('claimed'), false);
  assert.equal(cl.body.activities[0].certified, 100);
  assert.equal((await call('GET', '/api/milestones/sideways/1/progress-detail', cons)).status, 400);
});

test('completion check: blocked until the activity is closed, not applied to typed milestones', async () => {
  const c = await milestoneCompletionCheck(pool, 'baseline', 1);
  assert.equal(c.ok, false);
  assert.match(c.reasons.join(' '), /closed/);
  assert.equal((await milestoneCompletionCheck(pool, 'baseline', 2)).ok, true);
});

test('breakdown request: consultant only, caps at 99, one open at a time, withdrawing lifts the cap', async () => {
  assert.equal((await call('POST', '/api/milestones/baseline/1/breakdown-request', leader, { note: 'x' })).status, 403);
  assert.equal((await call('POST', '/api/milestones/baseline/1/breakdown-request', cons, {})).status, 400);
  assert.equal((await call('POST', '/api/milestones/baseline/2/breakdown-request', cons, { note: 'x' })).status, 409);   // typed milestone
  const r = await call('POST', '/api/milestones/baseline/1/breakdown-request', cons, { note: 'Split into excavation, blinding, rebar, pour' });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(r.body.milestone.progress_pct, 99);
  assert.equal(Number((await ms()).progress_pct), 99);
  assert.equal((await call('POST', '/api/milestones/baseline/1/breakdown-request', cons, { note: 'again' })).status, 409);
  assert.equal((await call('GET', '/api/milestones/baseline/1/progress-detail', cons)).body.breakdown_request.note.includes('Split'), true);
  assert.match((await milestoneCompletionCheck(pool, 'baseline', 1)).reasons.join(' '), /breakdown/);
  assert.equal(notes.at(-1).entityType, 'milestone_breakdown_request');
  const w = await call('PUT', '/api/milestones/baseline/1/breakdown-request/withdraw', cons, {});
  assert.equal(w.body.milestone.progress_pct, 100);
  assert.equal((await call('PUT', '/api/milestones/baseline/1/breakdown-request/withdraw', cons, {})).status, 409);
});

test('temporary value: consultant only, must lower and have a reason, replaces itself, can be withdrawn', async () => {
  assert.equal((await call('POST', '/api/milestones/baseline/1/override', leader, { value: 60, reason: 'x' })).status, 403);
  assert.equal((await call('POST', '/api/milestones/baseline/1/override', cons, { value: 100, reason: 'x' })).status, 400);
  assert.equal((await call('POST', '/api/milestones/baseline/1/override', cons, { value: 60 })).status, 400);
  assert.equal((await call('POST', '/api/milestones/baseline/2/override', cons, { value: 10, reason: 'x' })).status, 409);   // typed milestone
  const a = await call('POST', '/api/milestones/baseline/1/override', cons, { value: 60, reason: 'Cracks in certified slab' });
  assert.equal(a.status, 201, JSON.stringify(a.body));
  assert.equal(Number((await ms()).progress_pct), 60);
  assert.equal((await ms()).derived_progress_pct, '100.00');
  assert.match((await milestoneCompletionCheck(pool, 'baseline', 1)).reasons.join(' '), /temporary/);
  const b = await call('POST', '/api/milestones/baseline/1/override', cons, { value: 40, reason: 'More cracks found' });
  assert.equal(b.status, 201);
  assert.equal(Number((await ms()).progress_pct), 40);
  const hist = await q(`SELECT set_pct, ended_reason FROM milestone_progress_overrides WHERE baseline_milestone_id=1 ORDER BY id`);
  assert.deepEqual(hist.map((h) => [Number(h.set_pct), h.ended_reason]), [[60, 'replaced_by_new_value'], [40, null]]);
  assert.equal((await call('GET', '/api/milestones/baseline/1/progress-detail', client)).body.temporary_value.value, 40);   // the client sees the milestone value
  const w = await call('PUT', '/api/milestones/baseline/1/override/withdraw', cons, {});
  assert.equal(w.body.milestone.progress_pct, 100);
  assert.equal((await ms()).override_pct, null);
  assert.equal((await call('PUT', '/api/milestones/baseline/1/override/withdraw', cons, {})).status, 409);
});

test('typed entry is refused on a derived milestone and allowed on a typed one', async () => {
  await assert.rejects(assertTypedProgressAllowed(pool, 'baseline', 1), /takes its progress from its activities/);
  await assertTypedProgressAllowed(pool, 'baseline', 2);
});

test('contractor leaders can ask the consultant to record typed milestone progress once', async () => {
  const requested = await call('POST', '/api/milestones/baseline/2/progress-request', leader, { note: "Please enter today's measurement." });
  assert.equal(requested.status, 201, JSON.stringify(requested.body));
  assert.equal(requested.body.request.status, 'open');
  assert.equal(requested.body.request.note, "Please enter today's measurement.");
  assert.equal(notes.at(-1).entityType, 'milestone_progress_request');
  assert.equal((await call('POST', '/api/milestones/baseline/2/progress-request', leader, {})).status, 409);
  assert.equal((await call('POST', '/api/milestones/baseline/1/progress-request', leader, {})).status, 409);
});

test('project milestone list for the activity form: both kinds, typed and completed flags, members only', async () => {
  await pool.query(`INSERT INTO additional_milestones (id, schedule_id, project_id, title, planned_start, planned_end, quantity, unit, executed, progress_pct) VALUES (1,1,'1','Extra works','2026-04-01','2026-05-01',10,'nr',2,20)`);
  const r = await call('GET', '/api/project-milestones?projectId=1', leader);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const byTitle = Object.fromEntries(r.body.milestones.map((x) => [x.title, x]));
  assert.equal(byTitle.Foundation.kind, 'baseline');
  assert.equal(byTitle.Foundation.progress_source, 'activities');
  assert.equal(byTitle.Foundation.typed_progress, false);
  assert.equal(byTitle.Walls.typed_progress, false);
  assert.equal(byTitle['Extra works'].kind, 'additional');
  assert.equal(byTitle['Extra works'].typed_progress, true);
  assert.equal((await call('GET', '/api/project-milestones', leader)).status, 400);
});
