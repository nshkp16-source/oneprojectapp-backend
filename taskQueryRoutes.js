class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function fail(res, err, label) {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  console.error(label, err);
  return res.status(500).json({ error: 'Server error.' });
}

const validId = (value) => {
  const id = Number(value);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
};

async function isMember(deps, projectId, userId, role) {
  if (deps.isProjectMember) return deps.isProjectMember(projectId, userId, role);
  const result = await deps.pool.query(
    `SELECT 1 FROM assignments_view WHERE project_id = $1 AND role_id = $2 AND role = $3 LIMIT 1`,
    [projectId, userId, role]);
  return result.rows.length > 0;
}

export function registerTaskQueryRoutes(app, deps) {
  const { pool, authenticateToken, requireProjectLifecycleWrite, wcSide, isWCLeader } = deps;
  const leaderOn = (role, side) => isWCLeader(role) && wcSide(role) === side;
  const notify = async (args) => {
    if (!deps.notify || !args.recipients?.length) return;
    try { await deps.notify(args); }
    catch (err) { console.error('[task query] notification failed (non-fatal):', err.message); }
  };

  async function loadTask(taskId, projectId) {
    const result = await pool.query(
      `SELECT id, project_id, side, status, assigned_members
       FROM workspace_work_center WHERE id = $1 AND project_id = $2`,
      [taskId, projectId]);
    return result.rows[0] || null;
  }

  async function requireProjectMember(projectId, userId, role) {
    if (!(await isMember(deps, projectId, userId, role)))
      throw new HttpError(403, 'You are not a member of this project.');
  }

  function isAssigned(task, userId) {
    const assigned = Array.isArray(task.assigned_members) ? task.assigned_members : [];
    return assigned.some((member) => String(member.id) === String(userId));
  }

  async function requireLeader(task, projectId, userId, role) {
    await requireProjectMember(projectId, userId, role);
    if (!leaderOn(role, task.side))
      throw new HttpError(403, 'Only a leader on this task’s side can manage queries.');
  }

  async function requireAssignedMember(task, projectId, userId, role) {
    await requireProjectMember(projectId, userId, role);
    if (role !== 'TeamMember' || !isAssigned(task, userId))
      throw new HttpError(403, 'Only a team member assigned to this task can answer its queries.');
    const assignment = await pool.query(
      `SELECT 1 FROM team_member_assignments
       WHERE project_id = $1 AND team_member_id = $2 AND assigned_part = $3 LIMIT 1`,
      [projectId, userId, task.side]);
    if (!assignment.rows.length)
      throw new HttpError(403, 'You are no longer assigned to this task’s project side.');
  }

  app.get('/api/work-center/:taskId/queries', authenticateToken, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const taskId = validId(req.params.taskId);
      const projectId = validId(req.query.projectId);
      if (!taskId || !projectId) throw new HttpError(400, 'taskId and projectId are required.');
      const task = await loadTask(taskId, projectId);
      if (!task) throw new HttpError(404, 'Task not found.');
      if (leaderOn(role, task.side)) {
        await requireLeader(task, projectId, userId, role);
      } else {
        await requireAssignedMember(task, projectId, userId, role);
      }

      const params = [taskId, projectId];
      let memberFilter = '';
      if (role === 'TeamMember') {
        params.push(userId);
        memberFilter = 'AND q.recipient_id = $3';
      }
      const result = await pool.query(
        `SELECT q.id, q.task_id, q.project_id, q.asked_by_id, q.asked_by_role,
                q.recipient_id, recipient.email AS recipient_email,
                q.question, q.answer, q.status, q.created_at,
                q.answered_at, q.answered_by_id, q.resolved_at,
                q.resolved_by_id, q.resolved_by_role
         FROM work_center_queries q
         LEFT JOIN team_members recipient ON recipient.id = q.recipient_id
         WHERE q.task_id = $1 AND q.project_id = $2 ${memberFilter}
         ORDER BY q.created_at DESC, q.id DESC`,
        params);
      return res.json({ queries: result.rows });
    } catch (err) { return fail(res, err, 'GET /api/work-center/:taskId/queries:'); }
  });

  app.post('/api/work-center/:taskId/queries', authenticateToken,
    requireProjectLifecycleWrite, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const taskId = validId(req.params.taskId);
      const projectId = validId(req.body?.projectId);
      const recipientId = validId(req.body?.memberId);
      const question = String(req.body?.question || '').trim();
      if (!taskId || !projectId) throw new HttpError(400, 'taskId and projectId are required.');
      if (!recipientId) throw new HttpError(400, 'Choose a team member to ask.');
      if (!question) throw new HttpError(400, 'Enter a question.');
      if (question.length > 5000) throw new HttpError(400, 'The question cannot exceed 5000 characters.');
      const task = await loadTask(taskId, projectId);
      if (!task) throw new HttpError(404, 'Task not found.');
      await requireLeader(task, projectId, userId, role);
      if (!isAssigned(task, recipientId))
        throw new HttpError(400, 'Choose a team member assigned to this task.');
      const assignment = await pool.query(
        `SELECT 1 FROM team_member_assignments
         WHERE project_id = $1 AND team_member_id = $2 AND assigned_part = $3 LIMIT 1`,
        [projectId, recipientId, task.side]);
      if (!assignment.rows.length)
        throw new HttpError(400, 'The selected member is no longer assigned to this task’s side.');

      const result = await pool.query(
        `INSERT INTO work_center_queries
           (task_id, project_id, asked_by_id, asked_by_role, recipient_id, question)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, task_id, project_id, asked_by_id, asked_by_role,
                   recipient_id, question, answer, status, created_at,
                   answered_at, answered_by_id, resolved_at, resolved_by_id, resolved_by_role`,
        [taskId, projectId, userId, role, recipientId, question]);
      await notify({
        projectId, entityId: result.rows[0].id, entityType: 'work_center_query',
        message: 'A task leader has asked you a question. Open Queries to respond.',
        actorId: userId, actorRole: role,
        recipients: [deps.flowKey('TeamMember', recipientId)],
      });
      return res.status(201).json({ query: result.rows[0] });
    } catch (err) { return fail(res, err, 'POST /api/work-center/:taskId/queries:'); }
  });

  app.put('/api/work-center/queries/:queryId/answer', authenticateToken,
    requireProjectLifecycleWrite, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const queryId = validId(req.params.queryId);
      const projectId = validId(req.body?.projectId);
      const answer = String(req.body?.answer || '').trim();
      if (!queryId || !projectId) throw new HttpError(400, 'queryId and projectId are required.');
      if (!answer) throw new HttpError(400, 'Enter an answer.');
      if (answer.length > 5000) throw new HttpError(400, 'The answer cannot exceed 5000 characters.');
      const query = (await pool.query(
        `SELECT q.*, w.side, w.assigned_members
         FROM work_center_queries q
         JOIN workspace_work_center w ON w.id = q.task_id
         WHERE q.id = $1 AND q.project_id = $2`,
        [queryId, projectId])).rows[0];
      if (!query) throw new HttpError(404, 'Query not found.');
      await requireAssignedMember(query, projectId, userId, role);
      if (String(query.recipient_id) !== String(userId))
        throw new HttpError(403, 'This query was addressed to another team member.');
      if (query.status !== 'open') throw new HttpError(409, 'Only an unanswered query can be answered.');
      const result = await pool.query(
        `UPDATE work_center_queries
         SET answer = $2, status = 'answered', answered_at = NOW(), answered_by_id = $3
         WHERE id = $1 AND status = 'open'
         RETURNING id, task_id, project_id, asked_by_id, asked_by_role,
                   recipient_id, question, answer, status, created_at,
                   answered_at, answered_by_id, resolved_at, resolved_by_id, resolved_by_role`,
        [queryId, answer, userId]);
      if (!result.rows.length) throw new HttpError(409, 'This query has already been answered.');
      await notify({
        projectId, entityId: queryId, entityType: 'work_center_query',
        message: 'A team member answered your task question. Open Queries to review it.',
        actorId: userId, actorRole: role,
        recipients: [deps.flowKey(query.asked_by_role, query.asked_by_id)],
      });
      return res.json({ query: result.rows[0] });
    } catch (err) { return fail(res, err, 'PUT /api/work-center/queries/:queryId/answer:'); }
  });

  app.put('/api/work-center/queries/:queryId/resolve', authenticateToken,
    requireProjectLifecycleWrite, async (req, res) => {
    try {
      const { user_id: userId, role } = req.user;
      const queryId = validId(req.params.queryId);
      const projectId = validId(req.body?.projectId);
      if (!queryId || !projectId) throw new HttpError(400, 'queryId and projectId are required.');
      const query = (await pool.query(
        `SELECT q.*, w.side FROM work_center_queries q
         JOIN workspace_work_center w ON w.id = q.task_id
         WHERE q.id = $1 AND q.project_id = $2`,
        [queryId, projectId])).rows[0];
      if (!query) throw new HttpError(404, 'Query not found.');
      await requireLeader(query, projectId, userId, role);
      if (query.status !== 'answered') throw new HttpError(409, 'Only an answered query can be resolved.');
      const result = await pool.query(
        `UPDATE work_center_queries
         SET status = 'resolved', resolved_at = NOW(), resolved_by_id = $2, resolved_by_role = $3
         WHERE id = $1 AND status = 'answered'
         RETURNING id, task_id, project_id, asked_by_id, asked_by_role,
                   recipient_id, question, answer, status, created_at,
                   answered_at, answered_by_id, resolved_at, resolved_by_id, resolved_by_role`,
        [queryId, userId, role]);
      if (!result.rows.length) throw new HttpError(409, 'This query is no longer awaiting resolution.');
      await notify({
        projectId, entityId: queryId, entityType: 'work_center_query',
        message: 'Your task question has been marked as resolved.',
        actorId: userId, actorRole: role,
        recipients: [deps.flowKey('TeamMember', query.recipient_id)],
      });
      return res.json({ query: result.rows[0] });
    } catch (err) { return fail(res, err, 'PUT /api/work-center/queries/:queryId/resolve:'); }
  });
}
