// Needs a THROWAWAY PostgreSQL database with the base schema and migrations through 2026-11-07 applied.
// Run: TEST_DATABASE_URL=... node --test taskQueryRoutes.test.js
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import pg from 'pg';
import { registerTaskQueryRoutes } from './taskQueryRoutes.js';

const pool = new pg.Pool({ connectionString: process.env.TEST_DATABASE_URL });
const app = express();
app.use(express.json());
const side = (role) => role.startsWith('Contractor') ? 'Contractor' : null;
registerTaskQueryRoutes(app, {
  pool,
  authenticateToken: (req, _res, next) => { req.user = JSON.parse(req.headers['x-user']); next(); },
  requireProjectLifecycleWrite: (_req, _res, next) => next(),
  wcSide: side,
  isWCLeader: (role) => side(role) !== null,
  isProjectMember: async () => true,
});
let server, base;
let reportId, otherTaskReportId;
const leader = { user_id: 5, role: 'ContractorPM' };
const member = { user_id: 101, role: 'TeamMember' };
const otherMember = { user_id: 102, role: 'TeamMember' };

async function call(method, path, user, body) {
  const response = await fetch(base + path, {
    method,
    headers: { 'content-type': 'application/json', 'x-user': JSON.stringify(user) },
    body: body == null ? undefined : JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

before(async () => {
  await pool.query(`SELECT set_config('app.project_deletion_purge','on',false)`);
  await pool.query(`INSERT INTO clients (id, company_name, company_email)
    VALUES (1,'Query test client','queries@test.local') ON CONFLICT DO NOTHING`);
  await pool.query(`INSERT INTO projects (id, name, client_id)
    VALUES (1,'Query test project',1) ON CONFLICT DO NOTHING`);
  await pool.query(`INSERT INTO team_members (id, email)
    VALUES (101,'member@test.local'),(102,'other@test.local') ON CONFLICT DO NOTHING`);
  await pool.query(`INSERT INTO team_member_assignments
    (project_id, team_member_id, assigned_by, assigned_part)
    VALUES (1,101,5,'Contractor'),(1,102,5,'Contractor')
    ON CONFLICT (project_id, team_member_id) DO NOTHING`);
  await pool.query(`INSERT INTO workspace_work_center
    (id, project_id, title, assigned_members, priority, status, start_date, end_date,
     creator_id, creator_role, side, activity_id, activity_type)
    VALUES (7001,1,'Query test task','[{"id":101,"email":"member@test.local"}]'::jsonb,
      'normal','ongoing','2026-11-01','2026-11-30',5,'ContractorPM','Contractor',NULL,'percentage')
    ON CONFLICT (id) DO NOTHING`);
  reportId = (await pool.query(`INSERT INTO workspace_work_center_progress
    (task_id, report_date, member_id, member_role, work_done, progress_pct)
    VALUES (7001,'2026-11-03',101,'TeamMember','Measured the completed section.',10)
    RETURNING id`)).rows[0].id;
  await pool.query(`INSERT INTO workspace_work_center
    (id, project_id, title, assigned_members, priority, status, start_date, end_date,
     creator_id, creator_role, side, activity_id, activity_type)
    VALUES (7002,1,'Another query test task','[{"id":101,"email":"member@test.local"}]'::jsonb,
      'normal','ongoing','2026-11-01','2026-11-30',5,'ContractorPM','Contractor',NULL,'percentage')
    ON CONFLICT (id) DO NOTHING`);
  otherTaskReportId = (await pool.query(`INSERT INTO workspace_work_center_progress
    (task_id, report_date, member_id, member_role, work_done, progress_pct)
    VALUES (7002,'2026-11-03',101,'TeamMember','Measured another section.',10)
    RETURNING id`)).rows[0].id;
  await pool.query(`SELECT setval(pg_get_serial_sequence('workspace_work_center','id'),
    GREATEST((SELECT COALESCE(MAX(id),1) FROM workspace_work_center),1))`);
  server = app.listen(0);
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  server.close();
  await pool.end();
});

test('leader asks independently, assigned member answers, leader resolves', async () => {
  const asked = await call('POST', '/api/work-center/7001/queries', leader, {
    projectId: 1, reportId, question: 'Please explain the measurement.',
  });
  assert.equal(asked.status, 201, JSON.stringify(asked.body));
  assert.equal(asked.body.query.status, 'open');
  assert.equal(Number(asked.body.query.recipient_id), 101);
  assert.equal(Number(asked.body.query.report_id), Number(reportId));

  const memberList = await call('GET', '/api/work-center/7001/queries?projectId=1', member);
  assert.equal(memberList.status, 200);
  assert.equal(memberList.body.queries.length, 1);
  assert.equal(memberList.body.queries[0].question, 'Please explain the measurement.');
  assert.equal(memberList.body.queries[0].report_work_done, 'Measured the completed section.');

  const answer = await call('PUT', `/api/work-center/queries/${asked.body.query.id}/answer`, member, {
    projectId: 1, answer: 'I used the approved drawing and tape measure.',
  });
  assert.equal(answer.status, 200, JSON.stringify(answer.body));
  assert.equal(answer.body.query.status, 'answered');
  assert.equal(answer.body.query.answer, 'I used the approved drawing and tape measure.');

  const resolved = await call('PUT', `/api/work-center/queries/${asked.body.query.id}/resolve`, leader, { projectId: 1 });
  assert.equal(resolved.status, 200, JSON.stringify(resolved.body));
  assert.equal(resolved.body.query.status, 'resolved');
});

test('only the addressed team member can answer and only answered queries can be resolved', async () => {
  const asked = await call('POST', '/api/work-center/7001/queries', leader, {
    projectId: 1, reportId, question: 'Which area did you measure?',
  });
  assert.equal(asked.status, 201);

  const wrongMember = await call('PUT', `/api/work-center/queries/${asked.body.query.id}/answer`, otherMember, {
    projectId: 1, answer: 'Not my task.',
  });
  assert.equal(wrongMember.status, 403);

  const unresolved = await call('PUT', `/api/work-center/queries/${asked.body.query.id}/resolve`, leader, { projectId: 1 });
  assert.equal(unresolved.status, 409);
});

test('leader must select a report submitted for the requested task', async () => {
  const missing = await call('POST', '/api/work-center/7001/queries', leader, {
    projectId: 1, question: 'Which area did you measure?',
  });
  assert.equal(missing.status, 400);

  const wrongTask = await call('POST', '/api/work-center/7001/queries', leader, {
    projectId: 1, reportId: otherTaskReportId, question: 'Which area did you measure?',
  });
  assert.equal(wrongTask.status, 400);
});
