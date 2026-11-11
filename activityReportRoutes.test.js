// Needs a THROWAWAY PostgreSQL database with the base schema and all dated migrations applied.
// It inserts fixtures, so never point it at real data.
// Run:  TEST_DATABASE_URL=postgres://user:pass@localhost/scratch node --test activityReportRoutes.test.js
// Needs the packages express, pg and multer (npm i -D express pg multer).
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import multer from 'multer';
import pg from 'pg';
import { registerActivityRoutes, registerMilestoneRoutes, milestoneCompletionCheck, assertTypedProgressAllowed } from './planningRoutes.js';
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



let act, task, vid;

test('fixture: report approved, then certify needs a note and gets a certificate number', async () => {
  const r = await call('POST', '/api/planning-execution/create-with-tasks', leader, { ...common, title: 'Excavation', activity_type: 'quantity', planned_quantity: 400, unit: 'm3', baseline_milestone_id: 1,
    tasks: [{ title: 'All', assigned_members: [{ id: 101 }] }] });
  assert.equal(r.status, 201, JSON.stringify(r.body)); act = r.body.activity; task = r.body.tasks[0];
  await progressTo(task, m(101), '2026-03-10', 150);
  const v = await call('POST', `/api/activities/${act.id}/verifications`, leader, {}); vid = v.body.verification.id;
  const noNote = await call('PUT', `/api/verifications/${vid}/decide`, cons, { status: 'verified' });
  assert.equal(noNote.status, 400, JSON.stringify(noNote.body));
  const ok = await call('PUT', `/api/verifications/${vid}/decide`, cons, { status: 'verified', certification_note: 'Measured on site.' });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  const [row] = await q(`SELECT certificate_no, certification_note, report_snapshot IS NOT NULL AS has_snapshot FROM activity_verifications WHERE id=$1`, [vid]);
  assert.equal(Number(row.certificate_no), 1);
  assert.equal(row.certification_note, 'Measured on site.');
  assert.equal(row.has_snapshot, true);
});

test('activity report: contractor, consultant and client each get their own view', async () => {
  const path = `/api/planning-execution/${act.id}/activity-report?projectId=1`;
  const c = await call('GET', path, leader); assert.equal(c.status, 200, JSON.stringify(c.body).slice(0, 400));
  console.log('contractor keys:', Object.keys(c.body).join(','));
  assert.equal(Number(c.body.quantities.claimed), 150);
  assert.equal(c.body.certificates.length, 1);
  assert.equal(c.body.certificates[0].note, 'Measured on site.');
  const k = await call('GET', path, cons); assert.equal(k.status, 200, JSON.stringify(k.body).slice(0, 400));
  assert.equal(Number(k.body.quantities.claimed), 150);
  const cl = await call('GET', path, client); assert.equal(cl.status, 200, JSON.stringify(cl.body).slice(0, 400));
  console.log('client keys:', Object.keys(cl.body).join(','));
  assert.equal(Object.keys(cl.body.quantities || {}).includes('claimed'), false, 'client must not see claimed');
  assert.equal(cl.body.daily_log === undefined || cl.body.daily_log.length === 0, true, 'client must not see the daily log');
});

test('milestone log carries the certificate note and id on the activity entry', async () => {
  const rows = await q(`SELECT contributions FROM milestone_activity_progress WHERE baseline_milestone_id=1`);
  const items = rows.flatMap((r) => r.contributions || []);
  const hit = items.find((i) => i.verification_id);
  assert.ok(hit, 'a contribution item should carry verification_id: ' + JSON.stringify(items).slice(0, 300));
  assert.equal(hit.note, 'Measured on site.');
  assert.equal(Number(hit.certificate_no), 1);
});
