import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveNotificationTarget } from './notificationWorkflow.js';

function mockPool(results) {
  const calls = [];
  return {
    calls,
    async query(sql, values) {
      calls.push({ sql, values });
      const match = results.find((item) => sql.includes(item.sql));
      if (!match) throw new Error(`Unexpected query: ${sql}`);
      return { rows: match.rows };
    },
  };
}

test('work-center progress notification opens its assigned task', async () => {
  const pool = mockPool([{
    sql: 'FROM workspace_work_center_progress',
    rows: [{ task_id: 17, side: 'Contractor', assigned_members: [{ id: 8 }] }],
  }]);
  assert.deepEqual(await resolveNotificationTarget({
    pool, projectId: 2, entityType: 'work_center_progress', entityId: 31,
    userId: 8, role: 'TeamMember', viewerSide: 'Contractor',
  }), { tab: 'work-center', recordId: 17 });
});

test('work-center task notification opens the assigned task', async () => {
  const pool = mockPool([{
    sql: 'FROM workspace_work_center',
    rows: [{ id: 17, side: 'Contractor', assigned_members: [{ id: 8 }] }],
  }]);
  assert.deepEqual(await resolveNotificationTarget({
    pool, projectId: 2, entityType: 'work_center_task', entityId: 17,
    userId: 8, role: 'TeamMember', viewerSide: 'Contractor',
  }), { tab: 'work-center', recordId: 17 });
});

test('a team member cannot open another member work-center notification', async () => {
  const pool = mockPool([{
    sql: 'FROM workspace_work_center',
    rows: [{ id: 17, side: 'Contractor', assigned_members: [{ id: 9 }] }],
  }]);
  assert.equal(await resolveNotificationTarget({
    pool, projectId: 2, entityType: 'work_center_task', entityId: 17,
    userId: 8, role: 'TeamMember', viewerSide: 'Contractor',
  }), null);
});

test('a task query notification resolves to its addressed member task', async () => {
  const pool = mockPool([{
    sql: 'FROM work_center_queries',
    rows: [{ task_id: 17, recipient_id: 8, side: 'Contractor', assigned_members: [{ id: 8 }] }],
  }]);
  assert.deepEqual(await resolveNotificationTarget({
    pool, projectId: 2, entityType: 'work_center_query', entityId: 31,
    userId: 8, role: 'TeamMember', viewerSide: 'Contractor',
  }), { tab: 'work-center', recordId: 17, type: 'query' });
});

test('a pending consultant inspector opens the verification decision screen', async () => {
  const pool = mockPool([
    { sql: 'FROM activity_verifications', rows: [{ activity_id: 41, side: 'Contractor' }] },
    { sql: 'FROM verification_signers', rows: [{ '?column?': 1 }] },
  ]);
  assert.deepEqual(await resolveNotificationTarget({
    pool, projectId: 2, entityType: 'activity_verification', entityId: 13,
    userId: 8, role: 'TeamMember', viewerSide: 'Consultant',
  }), { tab: 'planning-execution', type: 'verification', recordId: 41, verificationId: 13 });
});

test('a consultant leader opens the verification decision screen', async () => {
  const pool = mockPool([
    { sql: 'FROM activity_verifications', rows: [{ activity_id: 41, side: 'Contractor' }] },
  ]);
  assert.deepEqual(await resolveNotificationTarget({
    pool, projectId: 2, entityType: 'activity_verification', entityId: 13,
    userId: 8, role: 'Consultant', viewerSide: 'Consultant',
  }), { tab: 'planning-execution', type: 'verification', recordId: 41, verificationId: 13 });
});

test('a contractor opens the activity for its verification notification', async () => {
  const pool = mockPool([
    { sql: 'FROM activity_verifications', rows: [{ activity_id: 41, side: 'Contractor' }] },
  ]);
  assert.deepEqual(await resolveNotificationTarget({
    pool, projectId: 2, entityType: 'activity_verification', entityId: 13,
    userId: 8, role: 'Contractor', viewerSide: 'Contractor',
  }), { tab: 'planning-execution', type: 'activity', recordId: 41 });
});

test('milestone breakdown notifications open the milestone detail', async () => {
  const pool = mockPool([
    { sql: 'FROM milestone_breakdown_requests', rows: [{ baseline_milestone_id: 12, additional_milestone_id: null }] },
    { sql: 'FROM milestones', rows: [{ title: 'Foundation' }] },
  ]);
  assert.deepEqual(await resolveNotificationTarget({
    pool, projectId: 2, entityType: 'milestone_breakdown_request', entityId: 31,
    userId: 8, role: 'Contractor', viewerSide: 'Contractor',
  }), {
    tab: 'planning-execution',
    type: 'milestone',
    milestone: { kind: 'baseline', id: 12, title: 'Foundation' },
  });
});

test('milestone override notifications open the additional milestone detail', async () => {
  const pool = mockPool([
    { sql: 'FROM milestone_progress_overrides', rows: [{ baseline_milestone_id: null, additional_milestone_id: 15 }] },
    { sql: 'FROM additional_milestones', rows: [{ title: 'Extension work' }] },
  ]);
  assert.deepEqual(await resolveNotificationTarget({
    pool, projectId: 2, entityType: 'milestone_override', entityId: 32,
    userId: 8, role: 'Consultant', viewerSide: 'Consultant',
  }), {
    tab: 'planning-execution',
    type: 'milestone',
    milestone: { kind: 'additional', id: 15, title: 'Extension work' },
  });
});

test('consultant milestone progress requests open the requested baseline milestone', async () => {
  const pool = mockPool([
    { sql: 'FROM milestone_progress_requests', rows: [{ baseline_milestone_id: 21, additional_milestone_id: null }] },
    { sql: 'FROM milestones', rows: [{ title: 'Roof slab' }] },
  ]);
  assert.deepEqual(await resolveNotificationTarget({
    pool, projectId: 2, entityType: 'milestone_progress_request', entityId: 44,
    userId: 8, role: 'ConsultantPM', viewerSide: 'Consultant',
  }), {
    tab: 'planning-execution',
    type: 'milestone',
    milestone: { kind: 'baseline', id: 21, title: 'Roof slab' },
  });
});

test('contractors cannot open consultant-only milestone progress request notifications', async () => {
  const pool = mockPool([]);
  assert.equal(await resolveNotificationTarget({
    pool, projectId: 2, entityType: 'milestone_progress_request', entityId: 44,
    userId: 5, role: 'ContractorPM', viewerSide: 'Contractor',
  }), null);
});
