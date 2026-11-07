import test from 'node:test';
import assert from 'node:assert/strict';
import { sendOverdueVerificationReminders, sendWorkCenterTaskReminders } from './notificationWorkflow.js';

function reminderFixture({ locked = true } = {}) {
  const calls = [];
  let released = false;
  const client = {
    async query(sql, values) {
      calls.push({ sql, values });
      if (sql.includes('pg_try_advisory_lock')) return { rows: [{ locked }] };
      if (sql.includes('SELECT v.id')) return { rows: [{
        id: 21, project_id: 3, activity_id: 4, requested_by_id: 5,
        requested_by_role: 'Contractor', title: 'Foundation', overdue_days: 2,
      }] };
      if (sql.includes('FROM assignments_view')) return { rows: [
        { role: 'Consultant', role_id: 12 },
        { role: 'ConsultantPM', role_id: 13 },
      ] };
      if (sql.includes('FROM verification_signers')) return { rows: [
        { signer_role: 'TeamMember', signer_user_id: 14 },
        { signer_role: 'Consultant', signer_user_id: 12 },
      ] };
      if (sql.includes('UPDATE activity_verifications')) return { rows: [] };
      if (sql.includes('pg_advisory_unlock')) return { rows: [{ pg_advisory_unlock: true }] };
      throw new Error(`Unexpected query: ${sql}`);
    },
    release() { released = true; },
  };
  const pool = { async connect() { return client; } };
  const notifications = [];
  const notifyRecordUsers = async (notification) => {
    notifications.push(notification);
    return 99;
  };
  const flowKey = (role, id) => ({ recipient_role: role, recipient_role_id: Number(id) });
  return { calls, client, notifications, notifyRecordUsers, pool, released: () => released, flowKey };
}

test('overdue verification reminders notify consultant leaders and pending signers once per day', async () => {
  const fixture = reminderFixture();
  await sendOverdueVerificationReminders({
    pool: fixture.pool,
    notifyRecordUsers: fixture.notifyRecordUsers,
    flowKey: fixture.flowKey,
    normalizeRole: (role) => role,
  });

  assert.equal(fixture.notifications.length, 1);
  assert.equal(fixture.notifications[0].table, 'activity_verification');
  assert.deepEqual(
    fixture.notifications[0].recipients.map((recipient) => recipient.recipient_role_id).sort(),
    [12, 13, 14],
  );
  assert.match(fixture.notifications[0].message, /overdue by 2 days/);
  assert.ok(fixture.calls.some(({ sql }) => sql.includes("INTERVAL '1 day'")));
  assert.ok(fixture.calls.some(({ sql }) => sql.includes('UPDATE activity_verifications')));
  assert.ok(fixture.calls.some(({ sql }) => sql.includes('pg_advisory_unlock')));
  assert.equal(fixture.released(), true);
});

test('only one server instance processes the overdue reminder job at a time', async () => {
  const fixture = reminderFixture({ locked: false });
  await sendOverdueVerificationReminders({
    pool: fixture.pool,
    notifyRecordUsers: fixture.notifyRecordUsers,
    flowKey: fixture.flowKey,
    normalizeRole: (role) => role,
  });

  assert.equal(fixture.notifications.length, 0);
  assert.equal(fixture.calls.length, 1);
  assert.equal(fixture.released(), true);
});

test('work-center task reminders include the assigned group and side leaders', async () => {
  const calls = [];
  const client = {
    async query(sql) {
      calls.push(sql);
      if (sql.includes('pg_try_advisory_lock')) return { rows: [{ locked: true }] };
      if (sql.includes('SELECT w.id')) return { rows: [{
        id: 33, project_id: 3, side: 'Contractor', title: 'Pour slab',
        assigned_members: [{ id: 14 }, { id: 15 }], created_by_id: 5,
        created_by_role: 'ContractorPM', overdue_days: 1,
      }] };
      if (sql.includes('FROM assignments_view')) return { rows: [
        { role: 'ContractorPM', role_id: 5 },
      ] };
      if (sql.includes('UPDATE workspace_work_center')) return { rows: [] };
      if (sql.includes('pg_advisory_unlock')) return { rows: [] };
      throw new Error(`Unexpected query: ${sql}`);
    },
    release() {},
  };
  const notifications = [];
  await sendWorkCenterTaskReminders({
    pool: { connect: async () => client },
    notifyRecordUsers: async (notification) => { notifications.push(notification); return 99; },
    flowKey: (role, id) => ({ role, id: Number(id) }),
    normalizeRole: (role) => role,
  });
  assert.equal(notifications.length, 1);
  assert.equal(notifications[0].table, 'work_center_task');
  assert.ok(calls.some((sql) => sql.includes('w.creator_id AS created_by_id')
    && sql.includes('w.creator_role AS created_by_role')));
  assert.deepEqual(notifications[0].recipients.map((recipient) => recipient.id).sort((a, b) => a - b), [5, 14, 15]);
  assert.match(notifications[0].message, /overdue by 1 day/);
  assert.ok(calls.some((sql) => sql.includes("INTERVAL '1 day'")));
});
