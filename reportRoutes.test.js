// Needs a THROWAWAY PostgreSQL database with the base schema and the three 2026-11 migrations applied.
// It inserts fixtures, so never point it at real data.
// Run:  TEST_DATABASE_URL=postgres://user:pass@localhost/scratch node --test reportRoutes.test.js
// Needs the packages express, pg and multer (npm i -D express pg multer).
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import multer from 'multer';
import pg from 'pg';
import { registerActivityRoutes } from './activityRoutes.js';
import { registerReportRoutes } from './reportRoutes.js';

const pool = new pg.Pool({ connectionString: process.env.TEST_DATABASE_URL });
const notes = [];
const app = express();
app.use(express.json());
const side = (r) => (r.startsWith('Contractor') ? 'Contractor' : r.startsWith('Consultant') ? 'Consultant' : null);
const deps = {
  pool, authenticateToken: (req, _res, next) => { req.user = JSON.parse(req.headers['x-user']); next(); },
  upload: multer({ storage: multer.memoryStorage() }), requireProjectLifecycleWrite: (_q, _s, n) => n(),
  scheduleCloudinaryUpload: async () => ({}), wcSide: side, isWCLeader: (r) => side(r) !== null,
  isProjectMember: async () => true, notify: async (n) => { notes.push(n); },
  flowKey: (role, id) => ({ role, id }), leadersOf: async () => [{ role: 'ContractorPM', id: 5 }],
};
registerActivityRoutes(app, deps);
registerReportRoutes(app, deps);
let server, base;
const leader = { user_id: 5, role: 'ContractorPM' };
const consultant = { user_id: 8, role: 'ConsultantPM' };
const m = (id) => ({ user_id: id, role: 'TeamMember' });
async function call(method, path, user, body) {
  const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json', 'x-user': JSON.stringify(user) }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}
const q = async (sql, params) => (await pool.query(sql, params)).rows;
const report = (user, o) => call('POST', '/api/work-center-progress', user, { projectId: 1, workDone: 'Work', ...o });
const decide = (user, id, status, reason = '') => call('PUT', `/api/work-center-progress/${id}/validate`, user, { projectId: 1, validation_status: status, validation_notes: reason });
const common = { projectId: 1, start_date: '2026-03-01', end_date: '2026-04-30' };

before(async () => {
  await pool.query(`INSERT INTO clients (id, company_name, company_email) VALUES (1,'Test client','client@test.local') ON CONFLICT DO NOTHING`);
  await pool.query(`INSERT INTO projects (id, name, client_id) VALUES (1,'Test project',1) ON CONFLICT DO NOTHING`);
  for (const t of ['workspace_work_center', 'planning_execution', 'workspace_work_center_progress'])
    await pool.query(`SELECT setval(pg_get_serial_sequence('${t}','id'), 1000)`);
  await pool.query(`INSERT INTO team_members (id, email) VALUES (101,'a@x'),(102,'b@x'),(103,'c@x')`);
  await pool.query(`INSERT INTO team_member_assignments (project_id, team_member_id, assigned_by, assigned_part) VALUES (1,101,5,'Contractor'),(1,102,5,'Contractor'),(1,103,5,'Contractor')`);
  server = app.listen(0); base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { server.close(); await pool.end(); });

let act, tA, tB, rA, rB;

test('fixture: quantity activity with two tasks', async () => {
  const r = await call('POST', '/api/planning-execution/create-with-tasks', leader, { ...common, title: 'Excavation', activity_type: 'quantity', planned_quantity: 400, unit: 'm3',
    tasks: [{ title: 'Block A', assigned_members: [{ id: 101 }] }, { title: 'Block B', assigned_members: [{ id: 102 }] }] });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  act = r.body.activity; [tA, tB] = r.body.tasks;
});

test('report checks: wrong member, missing quantity, future date, before task start', async () => {
  assert.equal((await report(m(103), { taskId: tA.id, reportDate: '2026-03-10', quantityDone: 5 })).status, 403);
  assert.equal((await report(m(101), { taskId: tA.id, reportDate: '2026-03-10' })).status, 400);
  assert.equal((await report(m(101), { taskId: tA.id, reportDate: '2099-01-01', quantityDone: 5 })).status, 400);
  assert.equal((await report(m(101), { taskId: tA.id, reportDate: '2026-02-01', quantityDone: 5 })).status, 400);
  assert.equal((await report(leader, { taskId: tA.id, reportDate: '2026-03-10', quantityDone: 5 })).status, 403);
});

test('a report waits as pending, leaders are told, nothing is counted yet', async () => {
  const r = await report(m(101), { taskId: tA.id, reportDate: '2026-03-10', quantityDone: 40, manpower: '6 workers', materials: 'none' });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  rA = r.body.entry;
  assert.equal(rA.validation_status, 'pending');
  assert.equal(Number(rA.progress_pct), 20);                         // what the task would show if approved
  assert.equal((await q(`SELECT COUNT(*)::int n FROM planning_execution_tracking WHERE activity_id=$1`, [act.id]))[0].n, 0);
  assert.equal(notes.at(-1).entityType, 'work_center_progress');
  assert.deepEqual(notes.at(-1).recipients, [{ role: 'ContractorPM', id: 5 }]);
});

test('decision checks: other side refused, rejection needs a reason', async () => {
  assert.equal((await decide(consultant, rA.id, 'approved')).status, 403);
  assert.equal((await decide(leader, rA.id, 'rejected')).status, 400);
  assert.equal((await decide(leader, rA.id, 'nonsense')).status, 400);
});

test('approval fills task, activity and the daily entry automatically', async () => {
  const r = await decide(leader, rA.id, 'approved', 'Good');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.task.progress_pct, 20);
  assert.equal(r.body.activity.progress_pct, 10);                    // 20% of a 50% task
  assert.equal(r.body.activity.status, 'ongoing');
  const [e] = await q(`SELECT actual_quantity, source, manpower_used, progress_pct, contributions FROM planning_execution_tracking WHERE activity_id=$1`, [act.id]);
  assert.equal(Number(e.actual_quantity), 40);
  assert.equal(e.source, 'work_center');
  assert.equal(e.manpower_used, '6 workers');
  assert.equal(Number(e.progress_pct), 10);
  assert.equal(e.contributions.length, 1);
  const [t] = await q(`SELECT to_char(actual_start,'YYYY-MM-DD') s FROM workspace_work_center WHERE id=$1`, [tA.id]);
  assert.equal(t.s, '2026-03-10');
  assert.equal(notes.at(-1).recipients[0].role, 'TeamMember');
});

test('a second member on the same day adds to the same entry, weighted by task share', async () => {
  const r = await report(m(102), { taskId: tB.id, reportDate: '2026-03-10', quantityDone: 30 });
  rB = r.body.entry;
  const d = await decide(leader, rB.id, 'approved');
  assert.equal(d.body.activity.progress_pct, 17.5);                  // 0.5 x 20 + 0.5 x 15
  const rows = await q(`SELECT actual_quantity, contributions FROM planning_execution_tracking WHERE activity_id=$1`, [act.id]);
  assert.equal(rows.length, 1);                                      // still one entry per date
  assert.equal(Number(rows[0].actual_quantity), 70);
  assert.equal(rows[0].contributions.length, 2);
});

test('a decided report cannot be decided again; approved cannot be rejected', async () => {
  assert.equal((await decide(leader, rA.id, 'approved')).status, 409);
  const rej = await decide(leader, rA.id, 'rejected', 'changed my mind');
  assert.equal(rej.status, 409);
  assert.match(rej.body.error, /void/);
});

test('a rejected report is not counted', async () => {
  const r = await report(m(102), { taskId: tB.id, reportDate: '2026-03-11', quantityDone: 100 });
  const d = await decide(leader, r.body.entry.id, 'rejected', 'Quantity not on site');
  assert.equal(d.status, 200);
  assert.equal(d.body.activity, null);
  assert.equal(Number((await q(`SELECT progress_pct FROM planning_execution WHERE id=$1`, [act.id]))[0].progress_pct), 17.5);
});

test('voiding needs a reason, removes the report from progress, and the report stays in the record', async () => {
  assert.equal((await decide(leader, rA.id, 'voided')).status, 400);
  assert.equal((await decide(leader, rB.id, 'voided', '')).status, 400);
  const v = await decide(leader, rA.id, 'voided', 'Measured wrongly, 40 m3 was 4');
  assert.equal(v.status, 200, JSON.stringify(v.body));
  assert.equal(v.body.activity.progress_pct, 7.5);
  assert.equal(Number((await q(`SELECT actual_quantity FROM planning_execution_tracking WHERE activity_id=$1`, [act.id]))[0].actual_quantity), 30);
  const [row] = await q(`SELECT validation_status, void_reason FROM workspace_work_center_progress WHERE id=$1`, [rA.id]);
  assert.equal(row.validation_status, 'voided');
  await assert.rejects(pool.query(`UPDATE workspace_work_center_progress SET work_done='edited' WHERE id=$1`, [rA.id]), /voided/);
  await assert.rejects(pool.query(`DELETE FROM workspace_work_center_progress WHERE id=$1`, [rA.id]), /cannot be changed or deleted/);
  assert.equal((await decide(leader, rA.id, 'voided', 'again')).status, 409);
});

test('a typed entry on the same date keeps its own figures', async () => {
  await pool.query(`INSERT INTO planning_execution_tracking (activity_id, report_date, actual_quantity, progress_pct, delay_days, status_change_to_closed, logged_by, logged_by_role, source)
                    VALUES ($1,'2026-03-12',5,1,0,false,5,'ContractorPM','manual')`, [act.id]);
  const r = await report(m(101), { taskId: tA.id, reportDate: '2026-03-12', quantityDone: 10 });
  await decide(leader, r.body.entry.id, 'approved');
  const [e] = await q(`SELECT actual_quantity, source, jsonb_array_length(contributions) n FROM planning_execution_tracking WHERE activity_id=$1 AND report_date='2026-03-12'`, [act.id]);
  assert.equal(Number(e.actual_quantity), 5);
  assert.equal(e.source, 'manual');
  assert.equal(e.n, 1);
});

test('reaching 100% completes the task and the activity, and voiding moves them back', async () => {
  const a = await report(m(101), { taskId: tA.id, reportDate: '2026-03-13', quantityDone: 190 });   // 10 + 190 = 200 of 200
  await decide(leader, a.body.entry.id, 'approved');
  const b = await report(m(102), { taskId: tB.id, reportDate: '2026-03-13', quantityDone: 170 });   // 30 + 170 = 200 of 200
  const d = await decide(leader, b.body.entry.id, 'approved');
  assert.equal(d.body.activity.progress_pct, 100);
  assert.equal(d.body.activity.status, 'completed');
  assert.equal((await q(`SELECT status FROM workspace_work_center WHERE id=$1`, [tB.id]))[0].status, 'completed');
  const v = await decide(leader, b.body.entry.id, 'voided', 'Overstated');
  assert.equal(v.body.activity.status, 'ongoing');
  assert.equal((await q(`SELECT status FROM workspace_work_center WHERE id=$1`, [tB.id]))[0].status, 'ongoing');
});

test('quantity above the target is accepted with a warning', async () => {
  const r = await report(m(102), { taskId: tB.id, reportDate: '2026-03-14', quantityDone: 500 });
  assert.equal(r.status, 201);
  assert.match(r.body.warning, /above the task target/);
});

test('percentage activity: cumulative, cannot go backwards', async () => {
  const c = await call('POST', '/api/planning-execution/create-with-tasks', leader, { ...common, title: 'Painting', activity_type: 'percentage', tasks: [{ title: 'Paint', assigned_members: [{ id: 101 }] }] });
  const t = c.body.tasks[0];
  const first = await report(m(101), { taskId: t.id, reportDate: '2026-03-10', progressPct: 40 });
  await decide(leader, first.body.entry.id, 'approved');
  const lower = await report(m(101), { taskId: t.id, reportDate: '2026-03-11', progressPct: 30 });
  assert.equal(lower.status, 400);
  assert.match(lower.body.error, /cumulative/);
  const higher = await report(m(101), { taskId: t.id, reportDate: '2026-03-11', progressPct: 60 });
  const d = await decide(leader, higher.body.entry.id, 'approved');
  assert.equal(d.body.activity.progress_pct, 60);
});

test('stages activity: hold point locks the next stage until verified, a stage completes once', async () => {
  const c = await call('POST', '/api/planning-execution/create-with-tasks', leader, { ...common, title: 'Slab', activity_type: 'stages',
    tasks: [{ title: 'Pour', assigned_members: [{ id: 101 }], stages: [{ title: 'Reinforcement', weight_pct: 40, is_hold_point: true }, { title: 'Pour', weight_pct: 60 }] }] });
  const t = c.body.tasks[0];
  const [s1, s2] = await q(`SELECT id FROM task_stages WHERE task_id=$1 ORDER BY seq`, [t.id]);
  const locked = await report(m(101), { taskId: t.id, reportDate: '2026-03-10', stageId: s2.id });
  assert.equal(locked.status, 409);
  assert.match(locked.body.error, /hold point/);
  const r1 = await report(m(101), { taskId: t.id, reportDate: '2026-03-10', stageId: s1.id });
  assert.equal((await report(m(101), { taskId: t.id, reportDate: '2026-03-10', stageId: s1.id })).status, 409);   // already pending
  const d = await decide(leader, r1.body.entry.id, 'approved');
  assert.equal(d.body.activity.progress_pct, 40);
  assert.ok((await q(`SELECT completed_at FROM task_stages WHERE id=$1`, [s1.id]))[0].completed_at);
  assert.equal((await report(m(101), { taskId: t.id, reportDate: '2026-03-11', stageId: s1.id })).status, 409);   // already completed
  assert.equal((await report(m(101), { taskId: t.id, reportDate: '2026-03-11', stageId: s2.id })).status, 409);   // hold point not verified
  await pool.query(`UPDATE task_stages SET hold_verified_at = NOW() WHERE id=$1`, [s1.id]);
  const r2 = await report(m(101), { taskId: t.id, reportDate: '2026-03-11', stageId: s2.id });
  assert.equal(r2.status, 201, JSON.stringify(r2.body));
  const d2 = await decide(leader, r2.body.entry.id, 'approved');
  assert.equal(d2.body.activity.progress_pct, 100);
});

test('count activity: passed items drive progress, failed cannot exceed done', async () => {
  const c = await call('POST', '/api/planning-execution/create-with-tasks', consultant, { ...common, title: 'Inspections', activity_type: 'count', planned_quantity: 12, unit: 'inspections',
    tasks: [{ title: 'Inspect', assigned_members: [{ id: 103 }] }] });
  assert.equal(c.status, 403, 'member 103 belongs to the contractor side');
  const own = await call('POST', '/api/planning-execution/create-with-tasks', leader, { ...common, title: 'Tests', activity_type: 'count', planned_quantity: 12, unit: 'tests',
    tasks: [{ title: 'Cube tests', assigned_members: [{ id: 103 }] }] });
  const t = own.body.tasks[0];
  assert.equal((await report(m(103), { taskId: t.id, reportDate: '2026-03-10', quantityDone: 5, quantityFailed: 6 })).status, 400);
  assert.equal((await report(m(103), { taskId: t.id, reportDate: '2026-03-10', quantityDone: 2.5 })).status, 400);
  const ok = await report(m(103), { taskId: t.id, reportDate: '2026-03-10', quantityDone: 5, quantityFailed: 1 });
  const d = await decide(leader, ok.body.entry.id, 'approved');
  assert.equal(d.body.activity.progress_pct, 33.33);                  // 4 passed of 12
});

test('standalone quantity task reports and approval update task progress without an activity', async () => {
  const [task] = await q(`
    INSERT INTO workspace_work_center
      (project_id, title, description, assigned_members, priority, status, start_date, end_date,
       creator_id, creator_role, side, activity_id, activity_type, target_quantity, standalone_unit, weight_pct)
    VALUES (1,'Standalone excavation','', '[{"id":101}]'::jsonb, 'normal', 'ongoing',
       '2026-03-01','2026-04-30',5,'ContractorPM','Contractor',NULL,'quantity',20,'m3',100)
    RETURNING id`);
  const submitted = await report(m(101), { taskId: task.id, reportDate: '2026-03-10', quantityDone: 10 });
  assert.equal(submitted.status, 201, JSON.stringify(submitted.body));
  const approved = await decide(leader, submitted.body.entry.id, 'approved');
  assert.equal(approved.status, 200, JSON.stringify(approved.body));
  assert.equal(approved.body.activity, null);
  assert.equal(approved.body.task.progress_pct, 50);
  const [stored] = await q(`SELECT activity_id, progress_pct FROM workspace_work_center WHERE id=$1`, [task.id]);
  assert.equal(stored.activity_id, null);
  assert.equal(Number(stored.progress_pct), 50);
});
