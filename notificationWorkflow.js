// Notification target authorization and overdue verification reminders.
const targetResolution = (function () {
function assignedMemberIds(value) {
  const members = typeof value === 'string' ? JSON.parse(value) : value;
  return Array.isArray(members) ? members.map((member) => String(member.id)) : [];
}

async function resolveNotificationTarget({ pool, projectId, entityType, entityId, userId, role, viewerSide }) {
  if (entityType === 'work_center_progress') {
    const row = (await pool.query(
      `SELECT w.id AS task_id, w.side, w.assigned_members
       FROM workspace_work_center_progress p
       JOIN workspace_work_center w ON w.id = p.task_id
       WHERE p.id = $1 AND w.project_id = $2`, [entityId, projectId],
    )).rows[0];
    const permitted = role === 'TeamMember'
      ? assignedMemberIds(row?.assigned_members).includes(String(userId))
      : row?.side === viewerSide;
    return row && permitted ? { tab: 'work-center', recordId: row.task_id } : null;
  }

  if (entityType === 'work_center_task') {
    const row = (await pool.query(
      `SELECT id, side, assigned_members FROM workspace_work_center
       WHERE id = $1 AND project_id = $2`, [entityId, projectId],
    )).rows[0];
    const permitted = role === 'TeamMember'
      ? assignedMemberIds(row?.assigned_members).includes(String(userId))
      : row?.side === viewerSide;
    return row && permitted ? { tab: 'work-center', recordId: row.id } : null;
  }

  if (entityType === 'work_center_query') {
    const row = (await pool.query(
      `SELECT q.task_id, q.recipient_id, w.side, w.assigned_members
       FROM work_center_queries q
       JOIN workspace_work_center w ON w.id = q.task_id
       WHERE q.id = $1 AND q.project_id = $2`, [entityId, projectId],
    )).rows[0];
    if (!row) return null;
    const permitted = role === 'TeamMember'
      ? String(row.recipient_id) === String(userId)
      : row.side === viewerSide;
    return permitted ? { tab: 'work-center', recordId: row.task_id, type: 'query' } : null;
  }

  if (entityType === 'activity_verification') {
    const row = (await pool.query(
      `SELECT v.activity_id, pe.side
       FROM activity_verifications v
       JOIN planning_execution pe ON pe.id = v.activity_id
       WHERE v.id = $1 AND v.project_id = $2`, [entityId, projectId],
    )).rows[0];
    if (!row) return null;
    if (role === 'TeamMember') {
      const signer = await pool.query(
        `SELECT 1 FROM verification_signers
         WHERE verification_id = $1 AND signer_role = $2 AND signer_user_id = $3
           AND status = 'pending' LIMIT 1`,
        [entityId, role, userId],
      );
      return signer.rows.length
        ? { tab: 'planning-execution', type: 'verification', recordId: row.activity_id, verificationId: Number(entityId) }
        : null;
    }
    if (viewerSide === 'Consultant')
      return row.side === 'Contractor'
        ? { tab: 'planning-execution', type: 'verification', recordId: row.activity_id, verificationId: Number(entityId) }
        : null;
    if (viewerSide === 'Contractor' && row.side === 'Contractor')
      return { tab: 'planning-execution', type: 'activity', recordId: row.activity_id };
    return null;
  }

  if (entityType === 'rework_item') {
    const row = (await pool.query(
      `SELECT activity_id FROM rework_items
       WHERE id = $1 AND project_id = $2`, [entityId, projectId],
    )).rows[0];
    return row && ['Contractor', 'Consultant'].includes(viewerSide)
      ? { tab: 'planning-execution', type: 'activity', recordId: row.activity_id }
      : null;
  }

  if (entityType === 'milestone_breakdown_request' || entityType === 'milestone_override'
    || entityType === 'milestone_progress_request') {
    if (entityType === 'milestone_progress_request' && viewerSide !== 'Consultant') return null;
    const table = entityType === 'milestone_override'
      ? 'milestone_progress_overrides'
      : entityType === 'milestone_progress_request'
        ? 'milestone_progress_requests'
        : 'milestone_breakdown_requests';
    const row = (await pool.query(
      `SELECT baseline_milestone_id, additional_milestone_id
       FROM ${table} WHERE id = $1 AND project_id = $2`,
      [entityId, projectId],
    )).rows[0];
    if (!row) return null;
    const kind = row.baseline_milestone_id ? 'baseline' : 'additional';
    const milestoneId = row.baseline_milestone_id || row.additional_milestone_id;
    const milestoneTable = kind === 'baseline' ? 'milestones' : 'additional_milestones';
    const milestone = (await pool.query(
      `SELECT title FROM ${milestoneTable} WHERE id = $1 AND project_id = $2`,
      [milestoneId, String(projectId)],
    )).rows[0];
    return milestone
      ? { tab: 'planning-execution', type: 'milestone', milestone: { kind, id: milestoneId, title: milestone.title } }
      : null;
  }

  return null;
}

return { resolveNotificationTarget };
})();
const reminderJob = (function () {
async function sendOverdueVerificationReminders({ pool, notifyRecordUsers, flowKey, normalizeRole }) {
  let client;
  let locked = false;
  try {
    client = await pool.connect();
    const lockResult = await client.query('SELECT pg_try_advisory_lock(71022, 1) AS locked');
    locked = lockResult.rows[0].locked;
    if (!locked) return;

    const { rows } = await client.query(
      `SELECT v.id, v.project_id, v.activity_id, v.requested_by_id, v.requested_by_role,
              v.respond_by, pe.title,
              CURRENT_DATE - v.respond_by AS overdue_days
       FROM activity_verifications v
       JOIN planning_execution pe ON pe.id = v.activity_id
       WHERE v.status = 'pending' AND v.respond_by < CURRENT_DATE
         AND (v.reminder_sent_at IS NULL OR v.reminder_sent_at <= NOW() - INTERVAL '1 day')
       ORDER BY v.respond_by, v.id LIMIT 100`
    );

    for (const verification of rows) {
      const recipientsByKey = new Map();
      const { rows: consultantLeaders } = await client.query(
        `SELECT role, role_id FROM assignments_view
         WHERE project_id = $1 AND role IN ('Consultant', 'ConsultantPM')`,
        [verification.project_id]
      );
      const { rows: pendingSigners } = await client.query(
        `SELECT signer_role, signer_user_id FROM verification_signers
         WHERE verification_id = $1 AND status = 'pending'`,
        [verification.id]
      );
      for (const recipient of [...consultantLeaders, ...pendingSigners.map((signer) => ({
        role: signer.signer_role,
        role_id: signer.signer_user_id,
      }))]) {
        const key = `${normalizeRole(recipient.role)}:${recipient.role_id}`;
        recipientsByKey.set(key, flowKey(recipient.role, recipient.role_id));
      }

      if (!recipientsByKey.size) continue;
      const notificationId = await notifyRecordUsers({
        projectId: verification.project_id,
        recordId: verification.id,
        table: 'activity_verification',
        message: `Verification for "${verification.title}" is overdue by ${verification.overdue_days} day${Number(verification.overdue_days) === 1 ? '' : 's'}. Please review it.`,
        actorId: verification.requested_by_id,
        actorRole: verification.requested_by_role,
        recipients: [...recipientsByKey.values()],
      });
      if (notificationId) {
        await client.query(
          `UPDATE activity_verifications SET reminder_sent_at = NOW()
           WHERE id = $1 AND status = 'pending'
             AND (reminder_sent_at IS NULL OR reminder_sent_at <= NOW() - INTERVAL '1 day')`,
          [verification.id]
        );
      }
    }
  } catch (error) {
    console.error('Overdue verification reminder job failed:', error);
  } finally {
    if (client && locked) {
      await client.query('SELECT pg_advisory_unlock(71022, 1)').catch((error) =>
        console.error('Unable to release verification reminder lock:', error));
    }
    if (client) client.release();
  }
}

return { sendOverdueVerificationReminders };
})();

const taskReminderJob = (function () {
async function sendWorkCenterTaskReminders({ pool, notifyRecordUsers, flowKey, normalizeRole }) {
  let client;
  let locked = false;
  try {
    client = await pool.connect();
    const lockResult = await client.query('SELECT pg_try_advisory_lock(71022, 2) AS locked');
    locked = lockResult.rows[0].locked;
    if (!locked) return;

    const { rows } = await client.query(
      `SELECT w.id, w.project_id, w.side, w.title, w.assigned_members,
              w.created_by_id, w.created_by_role, w.end_date,
              CURRENT_DATE - w.end_date AS overdue_days
       FROM workspace_work_center w
       WHERE w.status NOT IN ('closed', 'completed') AND w.progress_pct < 100 AND w.end_date IS NOT NULL
         AND (
           (w.end_date = CURRENT_DATE + 2 AND w.reminder_sent_at IS NULL)
           OR (w.end_date < CURRENT_DATE
               AND (w.reminder_sent_at IS NULL OR w.reminder_sent_at <= NOW() - INTERVAL '1 day'))
         )
       ORDER BY w.end_date, w.id LIMIT 100`
    );

    for (const task of rows) {
      const recipientsByKey = new Map();
      const assignees = typeof task.assigned_members === 'string'
        ? JSON.parse(task.assigned_members) : task.assigned_members;
      for (const member of Array.isArray(assignees) ? assignees : []) {
        const key = `TeamMember:${member.id}`;
        recipientsByKey.set(key, flowKey('TeamMember', member.id));
      }
      const leaderRoles = task.side === 'Contractor'
        ? ['Contractor', 'ContractorPM', 'Contractor Project Manager']
        : task.side === 'Consultant'
          ? ['Consultant', 'ConsultantPM', 'Consultant Project Manager']
          : ['Client', 'ClientPM', 'Client Project Manager'];
      const { rows: leaders } = await client.query(
        `SELECT role, role_id FROM assignments_view
         WHERE project_id = $1 AND role = ANY($2::text[])`,
        [task.project_id, leaderRoles]
      );
      for (const recipient of leaders) {
        const key = `${normalizeRole(recipient.role)}:${recipient.role_id}`;
        recipientsByKey.set(key, flowKey(recipient.role, recipient.role_id));
      }
      if (!recipientsByKey.size) continue;

      const isOverdue = Number(task.overdue_days) > 0;
      const message = isOverdue
        ? `"${task.title}" is overdue by ${task.overdue_days} day${Number(task.overdue_days) === 1 ? '' : 's'}. Please review the task.`
        : `"${task.title}" is due in two days. Please review the task.`;
      const notificationId = await notifyRecordUsers({
        projectId: task.project_id,
        recordId: task.id,
        table: 'work_center_task',
        message,
        actorId: task.created_by_id,
        actorRole: task.created_by_role,
        recipients: [...recipientsByKey.values()],
      });
      if (notificationId) {
        await client.query(
          `UPDATE workspace_work_center SET reminder_sent_at = NOW()
           WHERE id = $1 AND (
             (end_date = CURRENT_DATE + 2 AND reminder_sent_at IS NULL)
             OR (end_date < CURRENT_DATE
                 AND (reminder_sent_at IS NULL OR reminder_sent_at <= NOW() - INTERVAL '1 day'))
           )`,
          [task.id]
        );
      }
    }
  } catch (error) {
    console.error('Work Center task reminder job failed:', error);
  } finally {
    if (client && locked) {
      await client.query('SELECT pg_advisory_unlock(71022, 2)').catch((error) =>
        console.error('Unable to release task reminder lock:', error));
    }
    if (client) client.release();
  }
}
return { sendWorkCenterTaskReminders };
})();

export const { resolveNotificationTarget } = targetResolution;
export const { sendOverdueVerificationReminders } = reminderJob;
export const { sendWorkCenterTaskReminders } = taskReminderJob;
