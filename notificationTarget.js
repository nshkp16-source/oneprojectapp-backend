function assignedMemberIds(value) {
  const members = typeof value === 'string' ? JSON.parse(value) : value;
  return Array.isArray(members) ? members.map((member) => String(member.id)) : [];
}

export async function resolveNotificationTarget({ pool, projectId, entityType, entityId, userId, role, viewerSide }) {
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
