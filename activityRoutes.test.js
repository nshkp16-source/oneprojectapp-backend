// Needs a THROWAWAY PostgreSQL database with the base schema and migrations through
// 2026-11-14-standalone-tasks-after-activity-delete.sql applied.
// It inserts fixtures and switches the project-deletion guard off for its own sessions, so never point it at real data.
// Run:  TEST_DATABASE_URL=postgres://user:pass@localhost/scratch node --test activityRoutes.test.js
// Needs the packages express, pg and multer (npm i -D express pg multer).
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import multer from 'multer';
import pg from 'pg';
import { registerActivityRoutes, syncMilestone } from './planningRoutes.js';

const pool = new pg.Pool({ connectionString: process.env.TEST_DATABASE_URL });
const notes = [];
const app = express();
app.use(express.json());
const side = (role) => (role.startsWith('Contractor') ? 'Contractor' : role.startsWith('Consultant') ? 'Consultant' : role.startsWith('Client') ? 'Client' : null);
registerActivityRoutes(app, {
  pool,
  authenticateToken: (req, _res, next) => { req.user = JSON.parse(req.headers['x-user']); next(); },
  upload: multer({ storage: multer.memoryStorage() }),
  requireProjectLifecycleWrite: (_req, _res, next) => next(),
  scheduleCloudinaryUpload: async () => ({}),
  wcSide: side, isWCLeader: (r) => side(r) !== null,
  isProjectMember: async () => true,
  notify: async (n) => { notes.push(n); },
  flowKey: (role, id) => ({ role, id }),
});
let server, base;
const contractor = { user_id: 5, role: 'ContractorPM' };
const consultant = { user_id: 8, role: 'ConsultantPM' };
async function call(method, path, user, body) {
  const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json', 'x-user': JSON.stringify(user) }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}
const q = async (sql, params) => (await pool.query(sql, params)).rows;
const members = [{ id: 101 }, { id: 102 }];
const base1 = { projectId: 1, start_date: '2026-03-01', end_date: '2026-04-30', activity_type: 'quantity', planned_quantity: 400, unit: 'm3' };

before(async () => {
  await pool.query(`INSERT INTO clients (id, company_name, company_email) VALUES (1,'Test client','client@test.local') ON CONFLICT DO NOTHING`);
  await pool.query(`INSERT INTO projects (id, name, client_id) VALUES (1,'Test project',1) ON CONFLICT DO NOTHING`);
  await pool.query(`SELECT set_config('app.project_deletion_purge','on',false)`);
  for (const t of ['workspace_work_center','planning_execution','milestones','project_schedules'])
    await pool.query(`SELECT setval(pg_get_serial_sequence('${t}','id'), 1000)`);
  await pool.query(`INSERT INTO team_members (id, email) VALUES (101,'a@x'),(102,'b@x'),(103,'c@x'),(201,'k@x')`);
  await pool.query(`INSERT INTO team_member_assignments (project_id, team_member_id, assigned_by, assigned_part) VALUES (1,101,5,'Contractor'),(1,102,5,'Contractor'),(1,103,5,'Contractor'),(1,201,8,'Consultant')`);
  await pool.query(`INSERT INTO project_schedules (id, project_id, planned_start, planned_finish) VALUES (1,'1','2026-01-01','2026-12-31')`);
  await pool.query(`INSERT INTO milestones (id, schedule_id, project_id, title, planned_start, planned_end, quantity, unit, executed, progress_pct) VALUES
    (1,1,'1','Foundation','2026-01-01','2026-05-01',400,'m3',120,30),(2,1,'1','Walls','2026-03-02','2026-05-01',100,'m2',0,0)`);
  await pool.query(`INSERT INTO milestone_progress_entries (milestone_id, project_id, report_date, qty_executed, cumulative_after_entry, progress_pct_after_entry) VALUES (1,'1','2026-01-10',120,120,30)`);
  server = app.listen(0); base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { server.close(); await pool.end(); });

let actA, actB;

test('activity dates must stay inside the selected milestone period', async () => {
  const before = await call('POST', '/api/planning-execution/create-with-tasks', contractor, {
    ...base1, title: 'Too early', start_date: '2025-12-31', baseline_milestone_id: 1,
    tasks: [{ title: 'Work', assigned_members: members }],
  });
  assert.equal(before.status, 400);
  assert.match(before.body.error, /cannot start before its milestone/);
  const after = await call('POST', '/api/planning-execution/create-with-tasks', contractor, {
    ...base1, title: 'Too late', end_date: '2026-05-02', baseline_milestone_id: 1,
    tasks: [{ title: 'Work', assigned_members: members }],
  });
  assert.equal(after.status, 400);
  assert.match(after.body.error, /cannot end after its milestone/);
});

test('linking to a milestone with typed progress asks for confirmation and writes nothing', async () => {
  const before = (await q(`SELECT COUNT(*)::int n FROM planning_execution`))[0].n;
  const r = await call('POST', '/api/planning-execution/create-with-tasks', contractor, { ...base1, title: 'Excavation', baseline_milestone_id: 1,
    tasks: [{ title: 'Block A', assigned_members: members }, { title: 'Block B', assigned_members: [{ id: 103 }] }] });
  assert.equal(r.status, 409);
  assert.equal(r.body.code, 'CONFIRM_REPLACE_MANUAL');
  assert.equal(r.body.typed_progress_pct, 30);
  assert.equal(r.body.will_become, 0);
  assert.equal((await q(`SELECT COUNT(*)::int n FROM planning_execution`))[0].n, before);
  assert.equal((await q(`SELECT progress_source FROM milestones WHERE id=1`))[0].progress_source, 'manual');
});

test('confirmed: activity, two tasks with equal weights and targets, milestone switched to activities', async () => {
  const r = await call('POST', '/api/planning-execution/create-with-tasks', contractor, { ...base1, title: 'Excavation', baseline_milestone_id: 1, confirm_replace_manual: 'true', done_when: 'Levels confirmed',
    planned_resources: [{ type: 'material', name: 'Concrete', planned_quantity: 30, unit: 'm3', planned_hours: null }],
    tasks: [
      { title: 'Block A', priority: 'high', assigned_members: members,
        planned_resources: [{ type: 'equipment', name: 'Excavator', planned_quantity: 1, unit: 'machine', planned_hours: 16 }] },
      { title: 'Block B', priority: 'low', assigned_members: [{ id: 103 }] },
    ] });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  actA = r.body.activity;
  assert.equal(actA.milestone_weight_pct, '100.00');
  assert.equal(actA.milestone_name, 'Foundation');
  assert.deepEqual(r.body.tasks.map((t) => [Number(t.weight_pct), Number(t.target_quantity)]), [[50, 200], [50, 200]]);
  assert.deepEqual(r.body.tasks.map((t) => t.priority), ['high', 'low']);
  const [m] = await q(`SELECT progress_source, progress_pct, derived_progress_pct FROM milestones WHERE id=1`);
  assert.equal(m.progress_source, 'activities');
  assert.equal(Number(m.progress_pct), 0);
  assert.equal((await q(`SELECT COUNT(*)::int n FROM milestone_progress_entries WHERE milestone_id=1 AND superseded_at IS NOT NULL`))[0].n, 1);
  assert.equal((await q(`SELECT COUNT(*)::int n FROM milestone_activity_progress WHERE baseline_milestone_id=1`))[0].n, 1);
  const createdResources = await q(`SELECT task_id, resource_type, name, planned_quantity, unit, planned_hours
    FROM planned_resources WHERE activity_id=$1 ORDER BY task_id NULLS FIRST`, [actA.id]);
  assert.deepEqual(createdResources.map((row) => [
    row.task_id == null ? null : Number(row.task_id), row.resource_type, row.name,
    Number(row.planned_quantity), row.unit, row.planned_hours == null ? null : Number(row.planned_hours),
  ]), [
    [null, 'material', 'Concrete', 30, 'm3', null],
    [Number(r.body.tasks[0].id), 'equipment', 'Excavator', 1, 'machine', 16],
  ]);
  assert.equal(notes.length, 2);                                   // one notification per task
  assert.deepEqual(notes[0].recipients.map((x) => x.id), [101, 102]);
});

test('activity card returns weighted task details to its side and restricts other sides', async () => {
  const r = await call('GET', `/api/planning-execution/${actA.id}/activity-card?projectId=1`, contractor);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(Number(r.body.activity.claimed_progress_pct), 0);
  assert.equal(r.body.tasks.length, 2);
  assert.deepEqual(r.body.tasks.map((t) => Number(t.weight_pct)), [50, 50]);
  assert.equal(r.body.can_add_task, true);

  const denied = await call('GET', `/api/planning-execution/${actA.id}/activity-card?projectId=1`,
    { user_id: 8, role: 'ClientPM' });
  assert.equal(denied.status, 403);
});

test('activity plan creates and synchronizes activity-level planned resources', async () => {
  const plan = {
    projectId: 1, title: 'Excavation', description: '', done_when: 'Levels confirmed',
    start_date: '2026-03-01', end_date: '2026-04-30', activity_type: 'quantity',
    planned_quantity: 400, unit: 'm3',
    planned_resources: [
      { type: 'manpower', name: 'Crew', planned_quantity: 4, unit: 'workers', planned_hours: 32 },
      { type: 'equipment', name: 'Excavator', planned_quantity: 1, unit: 'machine', planned_hours: 16 },
    ],
  };
  const created = await call('PUT', `/api/planning-execution/${actA.id}/plan`, contractor, plan);
  assert.equal(created.status, 200, JSON.stringify(created.body));
  let resources = await q(`SELECT id, task_id, resource_type, name, planned_quantity, unit, planned_hours
    FROM planned_resources WHERE activity_id=$1 ORDER BY id`, [actA.id]);
  assert.deepEqual(resources.map((row) => [row.task_id, row.resource_type, row.name, Number(row.planned_quantity), row.unit, Number(row.planned_hours)]),
    [[null, 'manpower', 'Crew', 4, 'workers', 32], [null, 'equipment', 'Excavator', 1, 'machine', 16]]);

  const updated = await call('PUT', `/api/planning-execution/${actA.id}/plan`, contractor, {
    ...plan,
    planned_resources: [
      { id: resources[0].id, type: 'manpower', name: 'Updated crew', planned_quantity: 5, unit: 'workers', planned_hours: 40 },
      { type: 'material', name: 'Concrete', planned_quantity: 12, unit: 'm3', planned_hours: null },
    ],
  });
  assert.equal(updated.status, 200, JSON.stringify(updated.body));
  resources = await q(`SELECT task_id, resource_type, name, planned_quantity, unit, planned_hours
    FROM planned_resources WHERE activity_id=$1 ORDER BY id`, [actA.id]);
  assert.deepEqual(resources.map((row) => [row.task_id, row.resource_type, row.name, Number(row.planned_quantity), row.unit, row.planned_hours == null ? null : Number(row.planned_hours)]),
    [[null, 'manpower', 'Updated crew', 5, 'workers', 40], [null, 'material', 'Concrete', 12, 'm3', null]]);
});

test('client activity card exposes certified progress only', async () => {
  await pool.query(`INSERT INTO team_members (id, email) VALUES (301,'client-member@x') ON CONFLICT DO NOTHING`);
  await pool.query(`INSERT INTO team_member_assignments (project_id, team_member_id, assigned_by, assigned_part)
    VALUES (1,301,9,'Client') ON CONFLICT DO NOTHING`);
  const created = await call('POST', '/api/planning-execution/create-with-tasks',
    { user_id: 9, role: 'ClientPM' }, {
      projectId: 1, title: 'Client inspection', activity_type: 'stages',
      start_date: '2026-03-01', end_date: '2026-04-30',
      tasks: [{ title: 'Review', assigned_members: [{ id: 301 }], stages: [{ title: 'Review', weight_pct: 100 }] }],
    });
  assert.equal(created.status, 201, JSON.stringify(created.body));

  const card = await call('GET', `/api/planning-execution/${created.body.activity.id}/activity-card?projectId=1`,
    { user_id: 9, role: 'ClientPM' });
  assert.equal(card.status, 200, JSON.stringify(card.body));
  assert.equal(card.body.activity.claimed_progress_pct, null);
  assert.equal(card.body.activity.progress_pct, null);
  assert.equal(card.body.activity.status, null);
  assert.deepEqual(card.body.tasks, []);
});

test('a task with a member from another side rolls everything back', async () => {
  const r = await call('POST', '/api/planning-execution/create-with-tasks', contractor, { ...base1, title: 'Rollback me',
    tasks: [{ title: 'ok', assigned_members: members }, { title: 'bad', assigned_members: [{ id: 201 }] }] });
  assert.equal(r.status, 403);
  assert.equal((await q(`SELECT COUNT(*)::int n FROM planning_execution WHERE title='Rollback me'`))[0].n, 0);
  assert.equal((await q(`SELECT COUNT(*)::int n FROM workspace_work_center WHERE title IN ('ok','bad')`))[0].n, 0);
});

test('task targets must add up to the activity plan', async () => {
  const r = await call('POST', '/api/planning-execution/create-with-tasks', contractor, { ...base1, title: 'Bad targets',
    tasks: [{ title: 'a', assigned_members: members, target_quantity: 100 }, { title: 'b', assigned_members: members, target_quantity: 100 }] });
  assert.equal(r.status, 400);
  assert.match(r.body.error, /add up to 200/);
});

test('targets given for every task become weights', async () => {
  const r = await call('POST', '/api/planning-execution/create-with-tasks', contractor, { ...base1, title: 'By targets', planned_quantity: 400,
    tasks: [{ title: 't1', assigned_members: members, target_quantity: 300 }, { title: 't2', assigned_members: members, target_quantity: 100 }] });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.deepEqual(r.body.tasks.map((t) => Number(t.weight_pct)), [75, 25]);
});

test('stages activity needs stage weights that total 100 and stores hold points', async () => {
  const bad = await call('POST', '/api/planning-execution/create-with-tasks', contractor, { projectId: 1, title: 'Steps', activity_type: 'stages', start_date: '2026-03-01', end_date: '2026-04-30',
    tasks: [{ title: 's', assigned_members: members, stages: [{ title: 'one', weight_pct: 60 }, { title: 'two', weight_pct: 30 }] }] });
  assert.equal(bad.status, 400);
  const ok = await call('POST', '/api/planning-execution/create-with-tasks', contractor, { projectId: 1, title: 'Steps ok', activity_type: 'stages', start_date: '2026-03-01', end_date: '2026-04-30',
    tasks: [{ title: 's', assigned_members: members, stages: [{ title: 'Reinforcement', weight_pct: 40, is_hold_point: true }, { title: 'Pour', weight_pct: 60 }] }] });
  assert.equal(ok.status, 201, JSON.stringify(ok.body));
  const st = await q(`SELECT title, weight_pct, is_hold_point FROM task_stages WHERE task_id=$1 ORDER BY seq`, [ok.body.tasks[0].id]);
  assert.deepEqual(st.map((s) => [s.title, Number(s.weight_pct), s.is_hold_point]), [['Reinforcement', 40, true], ['Pour', 60, false]]);
});

test('second contractor activity rebalances milestone weights, keeps a history and resolves a breakdown request', async () => {
  await pool.query(`INSERT INTO milestone_breakdown_requests (project_id, baseline_milestone_id, note, requested_by_id, requested_by_role) VALUES (1,1,'Split it',8,'ConsultantPM')`);
  const r = await call('POST', '/api/planning-execution/create-with-tasks', contractor, { ...base1, title: 'Blinding', baseline_milestone_id: 1, planned_quantity: 100,
    tasks: [{ title: 'Whole', assigned_members: members }] });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  actB = r.body.activity;
  const w = await q(`SELECT id, milestone_weight_pct FROM planning_execution WHERE baseline_milestone_id=1 ORDER BY id`);
  assert.deepEqual(w.map((x) => Number(x.milestone_weight_pct)), [50, 50]);
  assert.equal((await q(`SELECT COUNT(*)::int n FROM activity_weight_changes WHERE activity_id=$1`, [actB.id]))[0].n, 1);
  assert.equal((await q(`SELECT status FROM milestone_breakdown_requests WHERE baseline_milestone_id=1`))[0].status, 'resolved');
});

test('a consultant activity can reference the milestone without changing it', async () => {
  const r = await call('POST', '/api/planning-execution/create-with-tasks', consultant, { projectId: 1, title: 'Inspections', activity_type: 'count', planned_quantity: 12, unit: 'inspections',
    start_date: '2026-03-01', end_date: '2026-04-30', baseline_milestone_id: 1, tasks: [{ title: 'Inspect', assigned_members: [{ id: 201 }] }] });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(Number(r.body.activity.milestone_weight_pct), 0);
  assert.equal(r.body.milestone, null);
  const w = await q(`SELECT milestone_weight_pct FROM planning_execution WHERE baseline_milestone_id=1 AND drives_milestone ORDER BY id`);
  assert.deepEqual(w.map((x) => Number(x.milestone_weight_pct)), [50, 50]);
});

test('adding a task: preview writes nothing, apply rebalances and keeps a history', async () => {
  const body = { task: { title: 'Block C', assigned_members: [{ id: 103 }],
    planned_resources: [{ type: 'equipment', name: 'Compactor', planned_quantity: 1, unit: 'machine', planned_hours: 8 }] }, preview: true };
  const p = await call('POST', `/api/planning-execution/${actA.id}/tasks`, contractor, body);
  assert.equal(p.status, 200, JSON.stringify(p.body));
  assert.deepEqual(p.body.weights.map((w) => w.after), [33.33, 33.33, 33.34]);
  assert.equal((await q(`SELECT COUNT(*)::int n FROM workspace_work_center WHERE activity_id=$1`, [actA.id]))[0].n, 2);
  assert.equal((await q(`SELECT COUNT(*)::int n FROM planned_resources WHERE activity_id=$1 AND task_id IS NOT NULL`, [actA.id]))[0].n, 0);
  const a = await call('POST', `/api/planning-execution/${actA.id}/tasks`, contractor, { ...body, preview: false, reason: 'Extra block' });
  assert.equal(a.status, 201, JSON.stringify(a.body));
  const tasks = await q(`SELECT weight_pct, target_quantity FROM workspace_work_center WHERE activity_id=$1 ORDER BY id`, [actA.id]);
  assert.deepEqual(tasks.map((t) => Number(t.weight_pct)), [33.33, 33.33, 33.34]);
  assert.deepEqual(tasks.map((t) => Number(t.target_quantity)), [133.32, 133.32, 133.36]);
  assert.equal((await q(`SELECT COUNT(*)::int n FROM activity_weight_changes WHERE activity_id=$1 AND reason='Extra block'`, [actA.id]))[0].n, 1);
  const addedTaskResources = await q(`SELECT resource_type, name, planned_quantity, unit, planned_hours
    FROM planned_resources WHERE activity_id=$1 AND task_id=$2`, [actA.id, a.body.task.id]);
  assert.deepEqual(addedTaskResources.map((row) => [
    row.resource_type, row.name, Number(row.planned_quantity), row.unit, Number(row.planned_hours),
  ]), [['equipment', 'Compactor', 1, 'machine', 8]]);
});

test('adding a task is refused on a closed activity and for another side', async () => {
  const other = await call('POST', `/api/planning-execution/${actA.id}/tasks`, consultant, { task: { title: 'x', assigned_members: [{ id: 201 }] }, preview: true });
  assert.equal(other.status, 404);
  await pool.query(`UPDATE planning_execution SET status='ongoing' WHERE id=$1`, [actB.id]);
  await pool.query(`SET LOCAL x.y = 1`).catch(() => {});
  await pool.query(`SELECT set_config('app.project_deletion_purge','on',false)`);
  await pool.query(`UPDATE planning_execution SET status='closed' WHERE id=$1`, [actB.id]);   // purge switch bypasses the certification rule for this fixture only
  const closed = await call('POST', `/api/planning-execution/${actB.id}/tasks`, contractor, { task: { title: 'x', assigned_members: members }, preview: true });
  assert.equal(closed.status, 409);
});

test('milestone follows certified progress, is capped by a breakdown request and lowered by a temporary value', async () => {
  const c = await pool.connect();
  try {
  const run = async (fn) => { await c.query('BEGIN'); try { const out = await fn(); await c.query('COMMIT'); return out; } catch (e) { await c.query('ROLLBACK'); throw e; } };
  await pool.query(`UPDATE planning_execution SET certified_progress_pct=50 WHERE id=$1`, [actA.id]);
  await pool.query(`UPDATE planning_execution SET certified_progress_pct=0 WHERE id=$1`, [actB.id]);
  let r = await run(() => syncMilestone(c, 'baseline', 1));
  assert.equal(r.progress_pct, 25);                                // 50% weight x 50% certified
  assert.equal(Number((await q(`SELECT executed FROM milestones WHERE id=1`))[0].executed), 100);   // 25% of 400 m3
  await pool.query(`UPDATE planning_execution SET certified_progress_pct=100 WHERE baseline_milestone_id=1 AND drives_milestone`);
  await pool.query(`INSERT INTO milestone_breakdown_requests (project_id, baseline_milestone_id, note, requested_by_id, requested_by_role) VALUES (1,1,'Again',8,'ConsultantPM')`);
  await pool.query(`UPDATE planning_execution SET milestone_weight_pct=100 WHERE id=$1`, [actA.id]);
  await pool.query(`UPDATE planning_execution SET milestone_weight_pct=0 WHERE id=$1`, [actB.id]);   // only one real activity, so the request stays open
  r = await run(() => syncMilestone(c, 'baseline', 1));
  assert.equal(r.progress_pct, 99);
  assert.equal(r.breakdown_open, true);
  await pool.query(`UPDATE milestone_breakdown_requests SET status='withdrawn', closed_at=now() WHERE baseline_milestone_id=1`);
  await pool.query(`UPDATE milestones SET override_pct=60, override_reason='Cracks', override_by_id=8, override_by_role='ConsultantPM', override_at=now() WHERE id=1`);
  r = await run(() => syncMilestone(c, 'baseline', 1));
  assert.equal(r.progress_pct, 60);
  assert.equal(r.derived, 100);
  } finally { c.release(); }
});

test('activity deletion keeps task data, rebalances the milestone and rejects a stale preview', async () => {
  const create = (title, resources) => call('POST', '/api/planning-execution/create-with-tasks', contractor, {
    projectId: 1, title, activity_type: 'quantity', planned_quantity: 100, unit: 'm2',
    start_date: '2026-03-02', end_date: '2026-05-01', baseline_milestone_id: 2,
    planned_resources: resources,
    tasks: [{
      title: `${title} task`, assigned_members: [{ id: 101 }],
      planned_resources: [{ type: 'equipment', name: `${title} equipment`, planned_quantity: 1, unit: 'machine' }],
    }],
  });
  const first = await create('Delete fixture A', [
    { type: 'material', name: 'Activity-only material', planned_quantity: 2, unit: 'bag' },
  ]);
  assert.equal(first.status, 201, JSON.stringify(first.body));
  const second = await create('Delete fixture B', []);
  assert.equal(second.status, 201, JSON.stringify(second.body));
  const activity = first.body.activity;
  const taskId = first.body.tasks[0].id;
  await pool.query(`UPDATE planning_execution SET certified_progress_pct=20 WHERE id=$1`, [activity.id]);
  await pool.query(`UPDATE planning_execution SET certified_progress_pct=60 WHERE id=$1`, [second.body.activity.id]);
  await pool.query(`INSERT INTO workspace_work_center_progress
    (task_id, report_date, member_id, member_role, work_done, progress_pct)
    VALUES ($1,'2026-03-10',101,'TeamMember','Kept report',10)`, [taskId]);

  const denied = await call('GET', `/api/planning-execution/${activity.id}/delete-preview?projectId=1`, consultant);
  assert.equal(denied.status, 403);
  const initial = await call('GET', `/api/planning-execution/${activity.id}/delete-preview?projectId=1`, contractor);
  assert.equal(initial.status, 200, JSON.stringify(initial.body));
  assert.equal(initial.body.preview.task_count, 1);
  await pool.query(`UPDATE planning_execution SET milestone_weight_pct=40 WHERE id=$1`, [activity.id]);
  await pool.query(`UPDATE planning_execution SET milestone_weight_pct=60 WHERE id=$1`, [second.body.activity.id]);
  const stale = await call('DELETE', `/api/planning-execution/${activity.id}`, contractor, {
    projectId: 1, expectedWeights: initial.body.preview.source_weights,
  });
  assert.equal(stale.status, 409);
  assert.equal(stale.body.code, 'DELETE_PREVIEW_STALE');

  const preview = await call('GET', `/api/planning-execution/${activity.id}/delete-preview?projectId=1`, contractor);
  assert.equal(preview.status, 200, JSON.stringify(preview.body));
  assert.equal(preview.body.preview.remaining_activities[0].after_weight_pct, 100);
  assert.equal(preview.body.preview.progress_after, 60);
  const deleted = await call('DELETE', `/api/planning-execution/${activity.id}`, contractor, {
    projectId: 1, expectedWeights: preview.body.preview.source_weights,
  });
  assert.equal(deleted.status, 200, JSON.stringify(deleted.body));
  assert.equal(deleted.body.unlinked_tasks, 1);
  assert.equal((await q(`SELECT COUNT(*)::int n FROM planning_execution WHERE id=$1`, [activity.id]))[0].n, 0);
  const [task] = await q(`SELECT activity_id, activity_type, standalone_unit FROM workspace_work_center WHERE id=$1`, [taskId]);
  assert.deepEqual(task, { activity_id: null, activity_type: 'quantity', standalone_unit: 'm2' });
  assert.equal((await q(`SELECT COUNT(*)::int n FROM workspace_work_center_progress WHERE task_id=$1`, [taskId]))[0].n, 1);
  const resources = await q(`SELECT activity_id, task_id, name FROM planned_resources WHERE task_id=$1`, [taskId]);
  assert.deepEqual(resources.map((row) => [row.activity_id, Number(row.task_id), row.name]), [[null, Number(taskId), 'Delete fixture A equipment']]);
  assert.equal((await q(`SELECT COUNT(*)::int n FROM planned_resources WHERE activity_id=$1`, [activity.id]))[0].n, 0);
  const history = await q(`SELECT action FROM work_center_task_history WHERE task_id=$1 ORDER BY id`, [taskId]);
  assert.deepEqual(history.map((row) => row.action), ['task_created', 'task_unlinked', 'activity_deleted']);
  assert.equal(Number((await q(`SELECT milestone_weight_pct FROM planning_execution WHERE id=$1`, [second.body.activity.id]))[0].milestone_weight_pct), 100);
  assert.equal(Number((await q(`SELECT progress_pct FROM milestones WHERE id=2`))[0].progress_pct), 60);
});
