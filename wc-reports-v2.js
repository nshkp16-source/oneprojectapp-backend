// ===== Work Center v2: reports per activity type, and the leader's decisions (approve, reject, void) =====
// Replaces _wcHandleSubmitProgress and _wcHandleValidate, and adds the helpers the member and leader views use.
// Uses the dashboard's own globals: API, _wcFetch, _wcLabel, escapeHtml, recordsCache, loadWCRecords,
// ensureActiveProjectId.

function _wcTypeOf(task) { return (task && task.activity_type) || 'percentage'; }   // tasks from before the redesign are percentage tasks
function _wcUnitText(task) { return task && task.activity_unit ? ` ${task.activity_unit}` : ''; }
function _wcStagesOf(task) { return Array.isArray(task && task.stages) ? task.stages : []; }

// "Share of activity 50%  |  Task progress 20%  |  Target 200 m3"
function _wcTaskShareHtml(task) {
  if (!task || task.weight_pct == null) return '';
  const type = _wcTypeOf(task);
  const target = (type === 'quantity' || type === 'count') && Number(task.target_quantity) > 0
    ? ` &nbsp;|&nbsp; Target <strong>${escapeHtml(String(Number(task.target_quantity)))}${escapeHtml(_wcUnitText(task))}</strong>` : '';
  return `
    <div style="padding:8px 12px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;font-size:12px;color:#374151;">
      Share of the activity <strong>${escapeHtml(String(Number(task.weight_pct)))}%</strong>
      &nbsp;|&nbsp; Task progress <strong>${escapeHtml(String(Number(task.progress_pct) || 0))}%</strong>${target}
    </div>`;
}

// What the member fills in for this task (goes in the second cell of the date and progress row).
function _wcReportFieldsHtml(task) {
  const id = task.id, type = _wcTypeOf(task);
  const box = 'width:100%;padding:9px 10px;border:1px solid #d1d5db;border-radius:8px;font-size:13px;box-sizing:border-box;';
  if (type === 'quantity') {
    return `${_wcLabel(`Quantity done${_wcUnitText(task) ? ' (' + task.activity_unit + ')' : ''} *`)}
      <input id="wc-pr-qty-${id}" type="number" min="0" step="any" style="${box}"/>`;
  }
  if (type === 'count') {
    return `${_wcLabel('Items completed *')}
      <input id="wc-pr-qty-${id}" type="number" min="0" step="1" style="${box}"/>
      <div style="margin-top:6px;">${_wcLabel('Of which failed')}
      <input id="wc-pr-failed-${id}" type="number" min="0" step="1" value="0" style="${box}"/></div>`;
  }
  if (type === 'stages') {
    const stages = _wcStagesOf(task);
    const open = stages.filter((s) => !s.completed_at);
    if (!open.length) return `${_wcLabel('Stage')}<div style="font-size:12px;color:#6b7280;padding-top:8px;">All stages are completed.</div>`;
    let holdOpen = false;
    const options = stages.map((s) => {
      if (s.completed_at) return '';
      const locked = holdOpen;
      if (s.is_hold_point && !s.hold_verified_at) holdOpen = true;
      const note = locked ? ' (locked: an earlier hold point is not verified yet)' : s.is_hold_point ? ' (hold point)' : '';
      return `<option value="${s.id}"${locked ? ' disabled' : ''}>${escapeHtml(s.title)}${note}</option>`;
    }).join('');
    return `${_wcLabel('Stage completed *')}
      <select id="wc-pr-stage-${id}" style="${box}background:#fff;"><option value="">Select stage</option>${options}</select>`;
  }
  return `${_wcLabel('Progress % (total so far)')}
    <input id="wc-pr-pct-${id}" type="number" min="0" max="100" value="0" style="${box}"/>
    <div style="font-size:11px;color:#6b7280;margin-top:3px;">The total completed so far, not only today. It cannot go below the last approved value.</div>`;
}

// One line describing what a report claims, for the member's history and the leader's list.
function _wcEntryFigure(task, e) {
  const type = _wcTypeOf(task);
  if (type === 'quantity') return `${Number(e.quantity_done) || 0}${_wcUnitText(task)}`;
  if (type === 'count') {
    const done = Number(e.quantity_done) || 0, failed = Number(e.quantity_failed) || 0;
    return `${done} done${failed ? `, ${failed} failed` : ''}`;
  }
  if (type === 'stages') {
    const s = _wcStagesOf(task).find((x) => String(x.id) === String(e.stage_id));
    return s ? s.title : 'Stage';
  }
  return `${Number(e.progress_pct) || 0}%`;
}

async function _wcHandleSubmitProgress(taskId, tabKey) {
  try {
    const g = (name) => document.getElementById(`wc-pr-${name}-${taskId}`);
    const task = (recordsCache['work-center'] || []).find((r) => String(r.id) === String(taskId)) || {};
    const type = _wcTypeOf(task);
    const reportDate = g('date')?.value;
    const workDone = g('work')?.value.trim();
    if (!workDone) return alert('Please describe the work done.');
    if (!reportDate) return alert('Report date is required.');

    const form = new FormData();
    if (type === 'quantity' || type === 'count') {
      const done = Number(g('qty')?.value);
      if (!(done > 0)) return alert(type === 'count' ? 'Enter how many items were completed.' : 'Enter the quantity done.');
      form.append('quantityDone', String(done));
      if (type === 'count') {
        const failed = Number(g('failed')?.value || 0);
        if (!Number.isInteger(done) || !Number.isInteger(failed) || failed < 0) return alert('Items completed and failed must be whole numbers.');
        if (failed > done) return alert('Failed items cannot be more than the items completed.');
        form.append('quantityFailed', String(failed));
      }
    } else if (type === 'stages') {
      const stageId = g('stage')?.value;
      if (!stageId) return alert('Choose the stage you completed.');
      form.append('stageId', stageId);
    } else {
      const pct = Number(g('pct')?.value);
      if (!Number.isFinite(pct) || pct < 0 || pct > 100) return alert('The percentage must be between 0 and 100.');
      form.append('progressPct', String(Math.round(pct)));
    }

    const projectId = await ensureActiveProjectId();
    if (!projectId) return;
    form.append('projectId', projectId);
    form.append('taskId', taskId);
    form.append('reportDate', reportDate);
    form.append('workDone', workDone);
    for (const [field, name] of [['manpower', 'manpower'], ['equipment', 'equipment'], ['materials', 'materials'], ['issues', 'issues'], ['notes', 'notes']])
      form.append(field, g(name)?.value.trim() || '');
    const file = g('file');
    if (file?.files?.[0]) form.append('attachment', file.files[0]);

    const res = await _wcFetch(`${API}/work-center-progress`, { method: 'POST', body: form });
    if (!res) return;
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || data.message || 'Failed to submit progress');
    alert('Report submitted. It counts toward progress once a leader approves it.' + (data.warning ? `\n\n${data.warning}` : ''));
    delete recordsCache['work-center'];
    loadWCRecords();
  } catch (err) { alert('Failed to submit progress: ' + err.message); }
}

async function _wcHandleValidate(tabKey, progressId, validateAction) {
  try {
    let notes = document.getElementById(`wc-val-notes-${progressId}`)?.value.trim() || '';
    if (validateAction === 'rejected' && !notes) return alert('Please write the reason for rejecting in the notes box.');
    if (validateAction === 'voided') {
      notes = (prompt('Why is this approved report being voided? The reason stays in the record.') || '').trim();
      if (!notes) return;
      if (!confirm('Voiding removes this report from progress. It stays in the record and cannot be changed again. Continue?')) return;
    }
    const projectId = await ensureActiveProjectId();
    if (!projectId) return;
    const body = { projectId, validation_notes: notes };
    if (validateAction !== 'comment_only') body.validation_status = validateAction;
    const res = await _wcFetch(`${API}/work-center-progress/${progressId}/validate`, { method: 'PUT', body: JSON.stringify(body) });
    if (!res) return;
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || data.message || 'Failed to validate');
    const a = data.activity;
    alert({
      approved: `Report approved.${a ? ` The activity is now at ${a.progress_pct}%.` : ''}`,
      rejected: 'Report rejected. The member was told why.',
      voided: `Report voided.${a ? ` The activity is now at ${a.progress_pct}%.` : ''}`,
      comment_only: 'Comment saved.',
    }[validateAction]);
    delete recordsCache['work-center'];
    delete recordsCache['planning-execution'];
    loadWCRecords();
  } catch (err) { alert('Failed to validate: ' + err.message); }
}
