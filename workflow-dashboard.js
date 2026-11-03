// Activity reports, review, verification and milestone controls for the dashboard.
// The server remains the source of truth for permissions and all progress calculations.

(() => {
  const esc = (value) => escapeHtml(value == null ? '' : String(value));
  const pct = (value) => Math.max(0, Math.min(100, Number(value) || 0));
  const inputStyle = 'width:100%;padding:9px 10px;border:1px solid #d1d5db;border-radius:8px;font-size:13px;box-sizing:border-box;';
  const panelStyle = 'background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:12px;';
  const originalMemberView = window._wcMemberView;
  const originalPMView = window._wcPMView;
  const originalWireDetail = window._wcWireDetailButtons;
  const originalPEStatus = window._peUpdateStatusBadge;
  const originalActivityHtml = window._peActivityCardHtml;
  const originalActivityWire = window._peWireActivityCard;
  const originalPELoadDetail = window._peLoadDetail;
  const originalRenderPEShell = window._renderPEShell;
  const originalOpenNotificationTarget = window._openNotificationTarget;

  function activityBaseHtml(card) {
    const activity = card.activity;
    const clientView = card.viewer_side === 'Client';
    const tasks = Array.isArray(card.tasks) ? card.tasks : [];
    const claimed = pct(activity.claimed_progress_pct);
    const certified = pct(activity.certified_progress_pct);
    const displayed = clientView ? certified : claimed;
    const typeNames = { quantity: 'Quantity', count: 'Count', stages: 'Stages', percentage: 'Percentage' };
    const taskRows = clientView ? '' : tasks.map((task) => {
      const progress = pct(task.progress_pct);
      const members = (task.assigned_members || []).map((member) =>
        member.title || member.name || member.email || `Member ${member.id}`).join(', ');
      const stages = (task.stages || []).length ? `<div style="font-size:11px;color:#6b7280;margin-top:8px;">
        ${task.stages.map((stage) => `${esc(stage.title)} (${pct(stage.weight_pct)}%)${stage.is_hold_point ? ' · hold point' : ''}${stage.completed_at ? ' · done' : ''}`).join(' → ')}
      </div>` : '';
      return `<article style="${panelStyle}">
        <div style="display:flex;justify-content:space-between;gap:12px;"><strong>${esc(task.title)}</strong><strong>${pct(task.weight_pct)}% share</strong></div>
        <div style="font-size:11px;color:#6b7280;margin-top:4px;">${esc(members || 'No assignee listed')}</div>
        <div style="font-size:11px;color:#6b7280;margin-top:6px;">Task progress <strong>${progress}%</strong>
          ${task.target_quantity == null ? '' : ` · Target <strong>${esc(task.target_quantity)} ${esc(activity.unit || '')}</strong>`}</div>
        <div style="height:6px;background:#e5e7eb;border-radius:999px;margin-top:6px;"><div style="height:6px;width:${progress}%;background:#0e7490;border-radius:999px;"></div></div>${stages}
      </article>`;
    }).join('');
    const progress = clientView
      ? `<div style="font-size:12px;color:#6b7280;margin-top:10px;">Certified progress <strong style="color:#047857;">${certified}%</strong></div>`
      : `<div style="display:flex;justify-content:space-between;font-size:12px;margin-top:10px;"><span>Claimed <strong>${claimed}%</strong></span><span>Certified <strong style="color:#047857;">${certified}%</strong></span></div>`;
    return `<section style="display:grid;gap:12px;">
      <div style="${panelStyle}">
        <h3 style="margin:0 0 8px;color:#1f2937;">${esc(activity.title || 'Activity')}</h3>
        <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;">
          <strong>${esc(typeNames[activity.activity_type] || 'Activity')} activity</strong>
          <span>${esc(String(activity.start_date || '—').slice(0, 10))} → ${esc(String(activity.end_date || '—').slice(0, 10))}</span>
        </div>
        ${activity.done_when ? `<div style="font-size:12px;margin-top:6px;"><strong>Done when:</strong> ${esc(activity.done_when)}</div>` : ''}
        ${activity.milestone_name ? `<div style="font-size:12px;color:#166534;margin-top:6px;">Milestone: ${esc(activity.milestone_name)}</div>` : ''}
        ${activity.description ? `<p style="font-size:12px;color:#4b5563;">${esc(activity.description)}</p>` : ''}
        <div style="height:8px;background:#e5e7eb;border-radius:999px;margin-top:12px;"><div style="height:8px;width:${displayed}%;background:#2563eb;border-radius:999px;"></div></div>${progress}
      </div>
      ${clientView ? '' : `<div style="display:flex;justify-content:space-between;align-items:center;">
        <strong>Tasks (${tasks.length})</strong>${card.can_add_task ? '<button type="button" data-wf-open-add-task>+ Add task</button>' : ''}
      </div><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px;">${taskRows}</div>
      <div data-wf-add-task-form style="display:none;${panelStyle}"></div>`}
    </section>`;
  }

  function reportFigure(task, entry) {
    const type = task.activity_type || 'percentage';
    if (type === 'quantity') return `${Number(entry.quantity_done) || 0} ${task.activity_unit || ''}`.trim();
    if (type === 'count') return `${Number(entry.quantity_done) || 0} completed${Number(entry.quantity_failed) ? `, ${Number(entry.quantity_failed)} failed` : ''}`;
    if (type === 'stages') return (task.stages || []).find((stage) => String(stage.id) === String(entry.stage_id))?.title || 'Stage';
    return `${Number(entry.progress_pct) || 0}%`;
  }

  function reportInput(task) {
    const id = esc(task.id);
    if (task.activity_type === 'quantity') {
      return `<label>Quantity done (${esc(task.activity_unit || 'unit')})<input id="wf-quantity-${id}" type="number" min="0.001" step="any" style="${inputStyle}" required></label>`;
    }
    if (task.activity_type === 'count') {
      return `<label>Items completed<input id="wf-quantity-${id}" type="number" min="1" step="1" style="${inputStyle}" required></label>
        <label>Failed items<input id="wf-failed-${id}" type="number" min="0" step="1" value="0" style="${inputStyle}"></label>`;
    }
    if (task.activity_type === 'stages') {
      let blockedByHold = false;
      const options = (task.stages || []).map((stage) => {
        const disabled = blockedByHold;
        if (stage.is_hold_point && !stage.hold_verified_at) blockedByHold = true;
        if (stage.completed_at) return '';
        return `<option value="${esc(stage.id)}"${disabled ? ' disabled' : ''}>${esc(stage.title)}${disabled ? ' (locked until earlier hold point is verified)' : stage.is_hold_point ? ' (hold point)' : ''}</option>`;
      }).join('');
      return `<label>Stage completed<select id="wf-stage-${id}" style="${inputStyle}" required><option value="">Select a stage</option>${options}</select></label>`;
    }
    return `<label>Total progress so far (%)<input id="wf-percentage-${id}" type="number" min="0" max="100" step="1" style="${inputStyle}" required></label>`;
  }

  function activityEditHtml(activity) {
    const date = (value) => esc(String(value || '').slice(0, 10));
    const milestoneStart = activity.baseline_milestone_start || activity.additional_milestone_start || '';
    const milestoneEnd = activity.baseline_milestone_end || activity.additional_milestone_end || '';
    const input = (label, name, value = '', type = 'text', bounds = '') => `<label>${label}<input name="${name}" type="${type}" value="${esc(value)}" style="${inputStyle}"${bounds}${['title', 'start_date', 'end_date'].includes(name) ? ' required' : ''}></label>`;
    const measured = ['quantity', 'count'].includes(activity.activity_type);
    return `<details data-wf-edit-plan style="${panelStyle};margin-top:12px;">
      <summary style="cursor:pointer;font-weight:700;">Edit activity plan</summary>
      <form data-wf-edit-form>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:9px;margin-top:10px;">
        ${input('Title', 'title', activity.title)}
        ${input('Start date', 'start_date', date(activity.start_date), 'date', `${milestoneStart ? ` min="${esc(date(milestoneStart))}"` : ''}${milestoneEnd ? ` max="${esc(date(milestoneEnd))}"` : ''}`)}
        ${input('End date', 'end_date', date(activity.end_date), 'date', `${milestoneStart ? ` min="${esc(date(milestoneStart))}"` : ''}${milestoneEnd ? ` max="${esc(date(milestoneEnd))}"` : ''}`)}
        <label>Activity type<select name="activity_type" style="${inputStyle}">
          ${['quantity', 'count', 'stages', 'percentage'].map((type) => `<option value="${type}"${activity.activity_type === type ? ' selected' : ''}>${type[0].toUpperCase()}${type.slice(1)}</option>`).join('')}
        </select></label>
        <label>Planned quantity<input name="planned_quantity" type="number" min="0.001" step="any" value="${esc(activity.planned_quantity ?? '')}" style="${inputStyle}"${measured ? ' required' : ''}></label>
        ${input('Unit', 'unit', activity.unit || '')}
        ${input('Done when', 'done_when', activity.done_when || '')}
        ${input('Planned work', 'planned_work', activity.planned_work || '')}
        ${input('Planned manpower', 'planned_manpower', activity.planned_manpower || '')}
        ${input('Planned equipment', 'planned_equipment', activity.planned_equipment || '')}
        ${input('Planned materials', 'planned_materials', activity.planned_materials || '')}
        <label style="grid-column:1/-1;">Description<textarea name="description" rows="2" style="${inputStyle}">${esc(activity.description || '')}</textarea></label>
        <label style="grid-column:1/-1;">Replace plan attachment<input name="linked_file" type="file"></label>
      </div>
      <p data-wf-edit-error style="color:#b91c1c;font-size:12px;margin:6px 0;"></p>
      <button type="button" data-wf-save-plan style="margin-top:8px;">Save activity plan</button>
      <p style="font-size:11px;color:#6b7280;">Activity type is locked after reports or execution entries exist. Quantity task targets are recalculated using their existing task shares.</p>
      </form>
    </details>`;
  }
  window._peActivityEditHtml = activityEditHtml;

  window._wcMemberView = function (task, entries) {
    const rows = entries.length ? [...entries].reverse().map((entry) => `
      <div style="${panelStyle};margin-top:8px;">
        <div style="display:flex;justify-content:space-between;gap:8px;font-size:12px;">
          <strong>${esc(String(entry.report_date || '').slice(0, 10))}</strong>
          <span>${esc(entry.validation_status || 'pending')}</span>
        </div>
        <div style="font-size:12px;margin-top:5px;">${esc(reportFigure(task, entry))} · ${esc(entry.work_done || '')}</div>
        ${entry.validation_notes ? `<div style="font-size:11px;color:#6b7280;margin-top:5px;">Review: ${esc(entry.validation_notes)}</div>` : ''}
        ${entry.void_reason ? `<div style="font-size:11px;color:#991b1b;margin-top:5px;">Voided: ${esc(entry.void_reason)}</div>` : ''}
          ${entry.attachment_name ? `<a data-action="wc-dl-progress" data-progress-id="${esc(entry.id)}" data-filename="${esc(entry.attachment_name)}" style="font-size:12px;">Download attachment: ${esc(entry.attachment_name)}</a>` : ''}
      </div>`).join('') : '<p style="font-size:12px;color:#6b7280;">No reports submitted yet.</p>';
    return `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;">
      <section style="${panelStyle}">
        <strong>${esc(task.title || 'Assigned task')}</strong>
        <div style="font-size:12px;color:#6b7280;margin-top:5px;">${esc(task.start_date || '—')} → ${esc(task.end_date || '—')}${task.work_package ? ` · ${esc(task.work_package)}` : ''}</div>
        ${task.description ? `<p style="font-size:12px;color:#4b5563;">${esc(task.description)}</p>` : ''}
      </section>
      <section style="${panelStyle}">
        <strong style="color:#0e7490;">Submit daily report</strong>
        <div style="display:grid;gap:9px;margin-top:10px;">
          <label>Report date<input id="wf-date-${esc(task.id)}" type="date" value="${new Date().toISOString().slice(0, 10)}" style="${inputStyle}" required></label>
          ${reportInput(task)}
          <label>Work done<textarea id="wf-work-${esc(task.id)}" rows="3" style="${inputStyle}" required></textarea></label>
          <label>Manpower<input id="wf-manpower-${esc(task.id)}" type="text" style="${inputStyle}"></label>
          <label>Equipment<input id="wf-equipment-${esc(task.id)}" type="text" style="${inputStyle}"></label>
          <label>Materials<input id="wf-materials-${esc(task.id)}" type="text" style="${inputStyle}"></label>
          <label>Issues<input id="wf-issues-${esc(task.id)}" type="text" style="${inputStyle}"></label>
          <label>Notes<textarea id="wf-notes-${esc(task.id)}" rows="2" style="${inputStyle}"></textarea></label>
          <label>Attachment<input id="wf-file-${esc(task.id)}" type="file"></label>
          <p id="wf-error-${esc(task.id)}" style="color:#b91c1c;font-size:12px;margin:0;"></p>
          <button type="button" data-wf-action="submit-report" data-task-id="${esc(task.id)}"
            style="padding:10px;background:#007b8a;color:#fff;border:0;border-radius:8px;font-weight:700;">Submit report</button>
        </div>
      </section>
      <section style="${panelStyle}">
        <strong>My report history</strong>${rows}
      </section>
    </div>`;
  };

  window._wcPMView = function (task, entries) {
    const approved = entries.filter((entry) => entry.validation_status === 'approved');
    const audit = approved.length ? `<section style="${panelStyle};margin-top:14px;">
      <strong>Correction audit</strong>
      <p style="font-size:12px;color:#6b7280;">Voiding removes an approved report from calculated progress but preserves it in the audit history.</p>
      ${approved.map((entry) => `<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;border-top:1px solid #e5e7eb;padding:8px 0;font-size:12px;">
        <span>${esc(entry.member_email || 'Team member')} · ${esc(String(entry.report_date || '').slice(0, 10))} · ${esc(reportFigure(task, entry))}</span>
        <button type="button" data-wf-action="void" data-progress-id="${esc(entry.id)}">Void report</button>
      </div>`).join('')}
    </section>` : '';
    const legacy = typeof originalPMView === 'function' ? originalPMView(task, entries) : '';
    return `${legacy}${audit}`;
  };

  window._wcWireDetailButtons = function (recordId, task, leader, entries) {
    if (typeof originalWireDetail === 'function') originalWireDetail(recordId, task, leader, entries);
    const container = document.getElementById(`wc-detail-${recordId}`);
    if (!container) return;
    container.querySelectorAll('[data-wf-action="submit-report"]').forEach((button) => {
      button.addEventListener('click', () => submitReport(task));
    });
    container.querySelectorAll('[data-wf-action="void"]').forEach((button) => {
      button.addEventListener('click', () => voidReport(button.dataset.progressId));
    });
  };

  async function responseData(response) {
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || data.message || `Request failed (HTTP ${response.status}).`);
    return data;
  }

  async function submitReport(task) {
    const id = task.id;
    const form = new FormData();
    const projectId = await ensureActiveProjectId();
    if (!projectId) return showError(`wf-error-${id}`, 'Select a project before submitting a report.');
    const reportDate = document.getElementById(`wf-date-${id}`)?.value;
    const workDone = document.getElementById(`wf-work-${id}`)?.value.trim();
    if (!reportDate || !workDone) return showError(`wf-error-${id}`, 'Report date and work description are required.');
    form.append('projectId', projectId);
    form.append('taskId', id);
    form.append('reportDate', reportDate);
    form.append('workDone', workDone);
    if (task.activity_type === 'quantity' || task.activity_type === 'count') {
      const quantity = Number(document.getElementById(`wf-quantity-${id}`)?.value);
      if (!(quantity > 0) || (task.activity_type === 'count' && !Number.isInteger(quantity)))
        return showError(`wf-error-${id}`, 'Enter a valid positive quantity.');
      form.append('quantityDone', String(quantity));
      if (task.activity_type === 'count') {
        const failed = Number(document.getElementById(`wf-failed-${id}`)?.value || 0);
        if (!Number.isInteger(failed) || failed < 0 || failed > quantity)
          return showError(`wf-error-${id}`, 'Failed items must be a whole number from zero to items completed.');
        form.append('quantityFailed', String(failed));
      }
    } else if (task.activity_type === 'stages') {
      const stageId = document.getElementById(`wf-stage-${id}`)?.value;
      if (!stageId) return showError(`wf-error-${id}`, 'Choose a completed stage.');
      form.append('stageId', stageId);
    } else {
      const progress = Number(document.getElementById(`wf-percentage-${id}`)?.value);
      if (!Number.isInteger(progress) || progress < 0 || progress > 100)
        return showError(`wf-error-${id}`, 'Progress must be a whole number from 0 to 100.');
      form.append('progressPct', String(progress));
    }
    for (const field of ['manpower', 'equipment', 'materials', 'issues', 'notes'])
      form.append(field, document.getElementById(`wf-${field}-${id}`)?.value.trim() || '');
    const file = document.getElementById(`wf-file-${id}`)?.files?.[0];
    if (file) form.append('attachment', file);
    try {
      const result = await responseData(await _wcFetch(`${API}/work-center-progress`, { method: 'POST', body: form }));
      alert(`Report submitted. It counts toward progress after leader approval.${result.warning ? `\n\n${result.warning}` : ''}`);
      delete recordsCache['work-center'];
      await loadWCRecords();
    } catch (error) { showError(`wf-error-${id}`, error.message); }
  }

  async function voidReport(progressId) {
    const notes = (prompt('Why is this approved report being voided?') || '').trim();
    if (!notes || !confirm('This removes the report from progress but keeps it in the audit record. Continue?')) return;
    try {
      await responseData(await _wcFetch(`${API}/work-center-progress/${progressId}/validate`, {
        method: 'PUT',
        body: JSON.stringify({ projectId: await ensureActiveProjectId(), validation_status: 'voided', validation_notes: notes }),
      }));
      delete recordsCache['work-center'];
      delete recordsCache['planning-execution'];
      await loadWCRecords();
    } catch (error) { alert(`Unable to void report: ${error.message}`); }
  }

  function showError(id, message) {
    const node = document.getElementById(id);
    if (node) node.textContent = message;
  }

  window._peActivityCardHtml = function (card) {
    const html = typeof originalActivityHtml === 'function'
      ? originalActivityHtml(card, { verifications: [], rework: [] }, 'overview')
      : activityBaseHtml(card);
    if (!card?.can_edit_activity || typeof originalActivityHtml !== 'function') return html;
    return html.replace(/<div data-pe-pane="overview"[^>]*>/,
      openingTag => `${openingTag}${activityEditHtml(card.activity)}`);
  };

  window._peUpdateStatusBadge = function (activity, entries) {
    if (activity.client_view && wcSide(window.currentUserRole) === 'Client') {
      const badge = document.getElementById(`pe-status-badge-${activity.id}`);
      if (badge) {
        const progress = pct(activity.certified_progress_pct);
        badge.style.background = '#ecfdf5';
        badge.style.color = '#047857';
        badge.style.border = '1px solid #6ee7b7';
        badge.textContent = `Certified ${progress}%`;
      }
      return;
    }
    if (typeof originalPEStatus === 'function') originalPEStatus(activity, entries);
  };

  window._peWireActivityCard = function (recordId, card) {
    if (typeof originalActivityWire === 'function') originalActivityWire(recordId, card);
    const detail = document.getElementById(`pe-detail-inner-${recordId}`);
    detail?.querySelector('[data-wf-save-plan]')?.addEventListener('click', () => saveActivityPlan(recordId, detail));
  };

  if (typeof originalRenderPEShell === 'function') {
    window._renderPEShell = function (...args) {
      originalRenderPEShell.apply(this, args);
      const header = document.querySelector('.bottom-fixed-header');
      if (!header || header.querySelector('[data-wf-shell-actions]')) return;
      const actions = document.createElement('div');
      actions.dataset.wfShellActions = 'true';
      actions.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;';
      const pending = document.createElement('button');
      pending.type = 'button';
      pending.className = 'rc-btn rc-btn--sm';
      pending.textContent = 'Pending verifications';
      pending.addEventListener('click', () => window.openPendingVerifications());
      actions.appendChild(pending);
      if (isWCLeader(window.currentUserRole) && ['Contractor', 'Consultant', 'Client'].includes(wcSide(window.currentUserRole))) {
        const closeout = document.createElement('button');
        closeout.type = 'button';
        closeout.className = 'rc-btn rc-btn--sm';
        closeout.textContent = 'Download close-out CSV';
        closeout.addEventListener('click', () => window.downloadCloseoutReport());
        actions.appendChild(closeout);
      }
      header.appendChild(actions);
    };
  }

  function wireAddTask(activityId, card, detail) {
    const button = detail?.querySelector('[data-wf-open-add-task]');
    const formContainer = detail?.querySelector('[data-wf-add-task-form]');
    if (!button || !formContainer) return;
    button.addEventListener('click', async () => {
      if (formContainer.style.display === 'block') return;
      formContainer.style.display = 'block';
      formContainer.innerHTML = '<p>Loading assigned team members…</p>';
      try {
        const projectId = await ensureActiveProjectId();
        if (!projectId) return;
        const membersData = await responseData(await _wcFetch(
          `${API}/work-center/team-members?projectId=${encodeURIComponent(projectId)}`,
        ));
        const memberOptions = (membersData.members || []).map((member) =>
          `<option value="${esc(member.id)}">${esc(member.title || member.email || `Member ${member.id}`)}</option>`).join('');
        const isStages = card.activity.activity_type === 'stages';
        formContainer.innerHTML = `<form data-wf-add-task>
          <strong>Add task</strong>
          <label style="display:block;margin-top:8px;">Title<input name="title" required maxlength="200" style="${inputStyle}"></label>
          <label style="display:block;margin-top:8px;">Description<textarea name="description" rows="2" style="${inputStyle}"></textarea></label>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px;">
            <label>Start date<input name="start_date" type="date" required value="${esc(String(card.activity.start_date).slice(0, 10))}" style="${inputStyle}"></label>
            <label>End date<input name="end_date" type="date" required value="${esc(String(card.activity.end_date).slice(0, 10))}" style="${inputStyle}"></label>
          </div>
          <label style="display:block;margin-top:8px;">Priority<select name="priority" style="${inputStyle}"><option>normal</option><option>low</option><option>high</option></select></label>
          <label style="display:block;margin-top:8px;">Assign team members<select name="members" multiple size="4" style="${inputStyle}">${memberOptions}</select></label>
          ${isStages ? `<div data-wf-stage-list style="margin-top:8px;"><strong>Stages (weights must total 100%)</strong>
            <div data-wf-stage-row style="display:flex;gap:6px;margin-top:5px;"><input data-stage-title placeholder="Stage title" style="${inputStyle}"><input data-stage-weight type="number" min="0.01" step="0.01" value="100" style="width:82px;"><label><input data-stage-hold type="checkbox"> Hold</label></div>
            <button type="button" data-wf-add-stage style="margin-top:6px;">Add stage</button></div>` : ''}
          <p data-wf-add-error style="color:#b91c1c;font-size:12px;"></p>
          <button type="submit">Preview and add task</button><button type="button" data-wf-cancel-add>Cancel</button>
        </form>`;
        const form = formContainer.querySelector('[data-wf-add-task]');
        formContainer.querySelector('[data-wf-cancel-add]').addEventListener('click', () => {
          formContainer.style.display = 'none';
          formContainer.innerHTML = '';
        });
        formContainer.querySelector('[data-wf-add-stage]')?.addEventListener('click', () => {
          const list = formContainer.querySelector('[data-wf-stage-list]');
          const current = list.querySelectorAll('[data-wf-stage-row]').length + 1;
          const weight = (100 / current).toFixed(2);
          list.querySelectorAll('[data-stage-weight]').forEach((input) => { input.value = weight; });
          const row = document.createElement('div');
          row.setAttribute('data-wf-stage-row', '');
          row.style.cssText = 'display:flex;gap:6px;margin-top:5px;';
          row.innerHTML = `<input data-stage-title placeholder="Stage title" style="${inputStyle}"><input data-stage-weight type="number" min="0.01" step="0.01" value="${(100 - Number(weight) * (current - 1)).toFixed(2)}" style="width:82px;"><label><input data-stage-hold type="checkbox"> Hold</label>`;
          list.insertBefore(row, list.querySelector('[data-wf-add-stage]'));
        });
        form.addEventListener('submit', async (event) => {
          event.preventDefault();
          const error = form.querySelector('[data-wf-add-error]');
          const task = {
            title: form.elements.title.value.trim(),
            description: form.elements.description.value.trim(),
            start_date: form.elements.start_date.value,
            end_date: form.elements.end_date.value,
            priority: form.elements.priority.value,
            assigned_members: [...form.elements.members.selectedOptions].map((option) => {
              const member = (membersData.members || []).find((item) => String(item.id) === option.value);
              return { id: member.id, title: member.title, email: member.email, position: member.position };
            }),
          };
          if (isStages) {
            task.stages = [...formContainer.querySelectorAll('[data-wf-stage-row]')].map((row, index) => ({
              title: row.querySelector('[data-stage-title]').value.trim(),
              weight_pct: Number(row.querySelector('[data-stage-weight]').value),
              is_hold_point: row.querySelector('[data-stage-hold]').checked,
              seq: index + 1,
            }));
            if (task.stages.some((stage) => !stage.title) || Math.round(task.stages.reduce((sum, stage) => sum + stage.weight_pct, 0) * 100) !== 10000) {
              error.textContent = 'Enter a title for every stage and make their weights add up to 100%.';
              return;
            }
          }
          try {
            const preview = await responseData(await _wcFetch(
              `${API}/planning-execution/${encodeURIComponent(activityId)}/tasks`,
              { method: 'POST', body: JSON.stringify({ projectId, task, preview: true }) },
            ));
            const weightSummary = (preview.weights || []).map((item) => `${item.title}: ${item.after}%`).join('\n');
            if (!confirm(`Add this task and apply the following shares?\n${weightSummary}\nActivity progress: ${preview.progress_before}% → ${preview.progress_after}%.`)) return;
            await responseData(await _wcFetch(
              `${API}/planning-execution/${encodeURIComponent(activityId)}/tasks`,
              { method: 'POST', body: JSON.stringify({ projectId, task }) },
            ));
            delete recordsCache['planning-execution'];
            delete recordsCache['work-center'];
            await loadPERecords();
          } catch (error) { form.querySelector('[data-wf-add-error]').textContent = error.message; }
        });
      } catch (error) {
        formContainer.innerHTML = `<p style="color:#b91c1c;">Could not load the add-task form: ${esc(error.message)}</p>`;
      }
    });
  }

  async function saveActivityPlan(activityId, container) {
    const formElement = container.querySelector('[data-wf-edit-plan]');
    const form = new FormData();
    const projectId = await ensureActiveProjectId();
    if (!projectId) return showErrorIn(formElement, 'Select a project before saving.');
    const data = Object.fromEntries(new FormData(formElement.querySelector('[data-wf-edit-form]')).entries());
    if (!String(data.title || '').trim()) return showErrorIn(formElement, 'Activity title is required.');
    if (!data.start_date || !data.end_date || data.end_date < data.start_date)
      return showErrorIn(formElement, 'Enter valid dates with the end date on or after the start date.');
    if (['quantity', 'count'].includes(data.activity_type) && (!(Number(data.planned_quantity) > 0) || !String(data.unit || '').trim()))
      return showErrorIn(formElement, 'Quantity and count activities need a planned amount above zero and a unit.');
    form.append('projectId', projectId);
    for (const [key, value] of Object.entries(data)) {
      if (key !== 'linked_file') form.append(key, value);
    }
    const file = formElement.querySelector('[name="linked_file"]')?.files?.[0];
    if (file) form.append('linked_file', file);
    try {
      await responseData(await _wcFetch(`${API}/planning-execution/${encodeURIComponent(activityId)}/plan`, { method: 'PUT', body: form }));
      alert('Activity plan updated.');
      delete recordsCache['planning-execution'];
      await loadPERecords();
    } catch (error) { showErrorIn(formElement, error.message); }
  }

  function showErrorIn(form, message) {
    const target = form?.querySelector('[data-wf-edit-error]');
    if (target) target.textContent = message;
  }

  async function loadActivityWorkflow(activityId, card) {
    const controls = document.getElementById(`wf-activity-controls-${activityId}`);
    if (!controls) return;
    try {
      const [verificationResponse, verificationData] = await (async () => {
        const res = await _wcFetch(`${API}/activities/${activityId}/verifications`);
        return [res, await responseData(res)];
      })();
      const list = controls.querySelector('[data-wf-verifications]');
      if (list) {
        const verifications = verificationData.verifications || [];
        const rework = verificationData.rework || [];
        list.innerHTML = `${verifications.length ? verifications.map((item) =>
          `<div style="padding:7px 0;border-top:1px solid #e5e7eb;">
            <strong>${esc(item.kind.replaceAll('_', ' '))}</strong> · ${esc(item.status)}
            ${item.overdue ? '<strong style="color:#b91c1c;"> · OVERDUE</strong>' : ''}
            ${item.respond_by ? `<div>Respond by ${esc(String(item.respond_by).slice(0, 10))}</div>` : ''}
            ${item.decision_reason ? `<div>${esc(item.decision_reason)}</div>` : ''}
            ${item.status === 'pending' && card.activity.side === 'Contractor' ? `<button type="button" data-wf-withdraw="${esc(item.id)}">Withdraw request</button>` : ''}
          </div>`).join('') : '<div>No verification requests yet.</div>'}
          ${rework.length ? `<div style="margin-top:8px;"><strong>Rework and snags</strong>${rework.map(item =>
            `<div style="padding:6px 0;border-top:1px solid #e5e7eb;">${esc(item.kind)} · ${esc(item.status)}: ${esc(item.reason)}
             ${item.status === 'open' && card.activity.side === 'Contractor' ? `<button type="button" data-wf-correct="${esc(item.id)}">Mark corrected</button>` : ''}
             ${item.status !== 'closed' && card.viewer_side === 'Consultant' ? `<button type="button" data-wf-close="${esc(item.id)}">Close item</button>` : ''}</div>`).join('')}</div>` : ''}`;
      }
      controls.querySelector('[data-wf-request-submit]')?.addEventListener('click', () => requestVerification(activityId, controls, card));
      if (controls.querySelector('[data-wf-inspectors]')) loadVerificationInspectors(controls);
      controls.querySelector('[data-wf-rework-submit]')?.addEventListener('click', async () => {
        const reason = controls.querySelector('[data-wf-rework-reason]')?.value.trim();
        if (!reason) return alert('A reason is required.');
        const kind = controls.querySelector('[data-wf-rework-kind]')?.value || 'rework';
        if (await workflowAction(`/activities/${activityId}/rework`, 'POST', { kind, reason }))
          await loadActivityWorkflow(activityId, card);
      });
      controls.querySelectorAll('[data-wf-withdraw]').forEach((button) =>
        button.addEventListener('click', async () => {
          if (await workflowAction(`/verifications/${button.dataset.wfWithdraw}/withdraw`, 'PUT', {})) await loadActivityWorkflow(activityId, card);
        }));
      controls.querySelectorAll('[data-wf-correct]').forEach((button) =>
        button.addEventListener('click', async () => {
          if (await workflowAction(`/rework/${button.dataset.wfCorrect}/correct`, 'PUT', {})) await loadActivityWorkflow(activityId, card);
        }));
      controls.querySelectorAll('[data-wf-close]').forEach((button) =>
        button.addEventListener('click', async () => {
          if (await workflowAction(`/rework/${button.dataset.wfClose}/close`, 'PUT', {})) await loadActivityWorkflow(activityId, card);
        }));
      if (verificationResponse.ok) await loadMilestoneWorkflow(controls, card);
    } catch (error) {
      const list = controls.querySelector('[data-wf-verifications]');
      if (list) list.textContent = `Unable to load verification history: ${error.message}`;
    }
  }

  async function requestVerification(activityId, controls, card) {
    const kind = controls.querySelector('[data-wf-request-kind]')?.value || 'progress';
    const form = new FormData();
    form.append('kind', kind);
    form.append('note', controls.querySelector('[data-wf-request-note]')?.value.trim() || '');
    if (kind === 'hold_point') {
      const stage = controls.querySelector('[data-wf-stage]')?.value;
      if (!stage) return alert('Choose a hold point stage.');
      form.append('stageId', stage);
    }
    const signers = [...(controls.querySelector('[data-wf-inspectors]')?.selectedOptions || [])]
      .map((option) => ({ role: 'TeamMember', user_id: option.value }));
    if (signers.length) form.append('signers', JSON.stringify(signers));
    const file = controls.querySelector('[data-wf-request-file]')?.files?.[0];
    if (file) form.append('attachment', file);
    try {
      await responseData(await _wcFetch(`${API}/activities/${activityId}/verifications`, { method: 'POST', body: form }));
      await loadActivityWorkflow(activityId, card);
    } catch (error) { alert(`Unable to request verification: ${error.message}`); }
  }

  async function loadVerificationInspectors(controls) {
    const select = controls.querySelector('[data-wf-inspectors]');
    if (!select) return;
    try {
      const projectId = await ensureActiveProjectId();
      const result = await responseData(await _wcFetch(
        `${API}/verification-inspectors?projectId=${encodeURIComponent(projectId)}`,
      ));
      select.innerHTML = result.inspectors.length
        ? result.inspectors.map((person) => `<option value="${esc(person.id)}">${esc(person.title || person.email)}${person.position ? ` — ${esc(person.position)}` : ''}</option>`).join('')
        : '<option disabled>No consultant team members are assigned.</option>';
    } catch (error) {
      select.innerHTML = `<option disabled>Unable to load inspectors: ${esc(error.message)}</option>`;
    }
  }

  async function loadMilestoneWorkflow(controls, card) {
    const detail = controls.querySelector('[data-wf-milestone]');
    const kind = controls.dataset.milestoneKind;
    const id = controls.dataset.milestoneId;
    if (!detail || !kind || !id) return;
    try {
      const result = await responseData(await _wcFetch(`${API}/milestones/${kind}/${id}/progress-detail`));
      const breakdown = result.breakdown_request
        ? `<p>Breakdown request: ${esc(result.breakdown_request.note)}</p><button type="button" data-wf-withdraw-breakdown>Withdraw breakdown request</button>`
        : '';
      const canManage = card.viewer_side === 'Consultant' && isWCLeader(window.currentUserRole);
      detail.innerHTML = `
        <div>Derived progress: <strong>${pct(result.derived_progress_pct)}%</strong></div>
        <div>Shown progress: <strong>${pct(result.progress_pct)}%</strong></div>
        <div>Activity coverage: <strong>${pct(result.coverage_pct)}%</strong></div>
        ${result.temporary_value ? `<p>Temporary consultant value: ${pct(result.temporary_value.value)}% — ${esc(result.temporary_value.reason)}</p><button type="button" data-wf-withdraw-override>Withdraw temporary value</button>` : ''}
        ${breakdown}
        ${result.activities.map((activity) => `<div style="border-top:1px solid #e5e7eb;padding-top:5px;margin-top:5px;">${esc(activity.title)} · ${Number(activity.weight_pct) || 0}% · ${pct(activity.certified_progress_pct ?? activity.progress_pct)}% certified</div>`).join('')}
        ${canManage ? `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px;">
          ${!result.breakdown_request ? '<button type="button" data-wf-breakdown>Request breakdown</button>' : ''}
          ${!result.temporary_value ? '<button type="button" data-wf-override>Set temporary value</button>' : ''}
        </div>` : ''}`;
      detail.querySelector('[data-wf-breakdown]')?.addEventListener('click', async () => {
        const note = (prompt('Describe the breakdown required:') || '').trim();
        if (!note) return;
        await workflowAction(`/milestones/${kind}/${id}/breakdown-request`, 'POST', { note });
        await loadMilestoneWorkflow(controls, card);
      });
      detail.querySelector('[data-wf-override]')?.addEventListener('click', async () => {
        const value = Number(prompt(`Enter a value from 0 to ${pct(result.derived_progress_pct)}%:`));
        if (!Number.isFinite(value)) return;
        const reason = (prompt('Reason for the temporary lower value:') || '').trim();
        if (!reason) return alert('A reason is required.');
        await workflowAction(`/milestones/${kind}/${id}/override`, 'POST', { value, reason });
        await loadMilestoneWorkflow(controls, card);
      });
      detail.querySelector('[data-wf-withdraw-breakdown]')?.addEventListener('click', async () => {
        await workflowAction(`/milestones/${kind}/${id}/breakdown-request/withdraw`, 'PUT', {});
        await loadMilestoneWorkflow(controls, card);
      });
      detail.querySelector('[data-wf-withdraw-override]')?.addEventListener('click', async () => {
        await workflowAction(`/milestones/${kind}/${id}/override/withdraw`, 'PUT', {});
        await loadMilestoneWorkflow(controls, card);
      });
    } catch (error) { detail.textContent = `Unable to load milestone details: ${error.message}`; }
  }

  async function workflowAction(path, method, body) {
    try {
      await responseData(await _wcFetch(`${API}${path}`, {
        method, body: JSON.stringify(body),
      }));
      alert('Saved.');
      return true;
    } catch (error) { alert(`Unable to complete action: ${error.message}`); }
    return false;
  }

  window.openPendingVerifications = async function (verificationId = null) {
    const projectId = await ensureActiveProjectId();
    if (!projectId) return;
    let rows;
    try {
      const result = await responseData(await _wcFetch(`${API}/verifications/pending?projectId=${encodeURIComponent(projectId)}`));
      rows = result.pending || [];
      if (verificationId) rows = rows.filter((item) => String(item.id) === String(verificationId));
    } catch (error) {
      expandGrayPart(`<section style="padding:18px;"><p style="color:#b91c1c;">Unable to load pending verifications: ${esc(error.message)}</p>
        <button class="btn" type="button" onclick="collapseGrayPart()">Close</button></section>`);
      return;
    }
    if (verificationId && window._openActivityVerificationNotification) {
      const opened = await window._openActivityVerificationNotification(verificationId);
      if (opened) return;
    }
    if (rows.length === 1 && window._openActivityVerificationNotification) {
      const opened = await window._openActivityVerificationNotification(rows[0].id);
      if (opened) return;
    }
    const body = rows.length ? rows.map((item) => `
      <button type="button" class="rc-btn" data-wf-open-verification="${esc(item.id)}"
        style="width:100%;text-align:left;margin:6px 0;padding:12px;">
        <strong>${esc(item.activity_title)}</strong> · ${esc(String(item.kind).replace(/_/g, ' '))}
        <span style="display:block;margin-top:4px;font-size:12px;color:${item.overdue ? '#b91c1c' : '#64748b'};">
          Respond by ${esc(String(item.respond_by).slice(0, 10))}${item.overdue ? ' · Overdue' : ''}</span>
      </button>`).join('') : '<p style="color:#64748b;">No pending verification requests.</p>';
    expandGrayPart(`<section style="padding:18px;overflow:auto;height:100%;box-sizing:border-box;">
      <button class="btn" type="button" onclick="collapseGrayPart()">← Back</button>
      <h3 style="margin:14px 0 8px;color:#0f172a;">Pending verifications</h3>${body}</section>`);
    document.getElementById('grayContent')?.querySelectorAll('[data-wf-open-verification]').forEach((button) =>
      button.addEventListener('click', async () => {
        collapseGrayPart();
        await window._openActivityVerificationNotification?.(button.dataset.wfOpenVerification);
      }));
  };

  window.downloadCloseoutReport = async function () {
    try {
      const projectId = await ensureActiveProjectId();
      if (!projectId) throw new Error('Select a project first.');
      const audience = wcSide(window.currentUserRole) === 'Client' ? 'client' : 'side';
      const response = await _wcFetch(
        `${API}/planning-execution/closeout-report?projectId=${encodeURIComponent(projectId)}&audience=${audience}`,
      );
      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.error || `Report download failed (HTTP ${response.status}).`);
      }
      const blob = await response.blob();
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = `oneproject-closeout-${audience}-${projectId}.csv`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(link.href);
    } catch (error) {
      alert(`Unable to download the close-out report: ${error.message}`);
    }
  };

  window.openMilestoneDeepLink = async function (milestone) {
    if (!milestone?.kind || !milestone?.id) return alert('Milestone details are missing from this notification.');
    try {
      const result = await responseData(await _wcFetch(
        `${API}/milestones/${encodeURIComponent(milestone.kind)}/${encodeURIComponent(milestone.id)}/progress-detail`,
      ));
      const clientView = wcSide(window.currentUserRole) === 'Client';
      const activities = result.activities.map((activity) => `
        <div style="padding:8px 0;border-top:1px solid #e5e7eb;">
          <strong>${esc(activity.title)}</strong> · ${Number(activity.weight_pct) || 0}% share ·
          ${clientView ? `${pct(activity.certified)}% certified` : `${pct(activity.claimed)}% claimed / ${pct(activity.certified)}% certified`}
        </div>`).join('') || '<p>No linked activities yet.</p>';
      expandGrayPart(`<section style="padding:16px;overflow:auto;height:100%;">
        <button class="btn" type="button" onclick="collapseGrayPart()">← Back</button>
        <h3>${esc(result.title || milestone.title || 'Milestone')}</h3>
        <div style="${panelStyle}">
          <div>Derived progress: <strong>${pct(result.derived_progress_pct)}%</strong></div>
          <div>Shown progress: <strong>${pct(result.progress_pct)}%</strong></div>
          <div>Activity coverage: <strong>${pct(result.coverage_pct)}%</strong></div>
          ${result.breakdown_request ? `<p>Open breakdown request: ${esc(result.breakdown_request.note)}</p>` : ''}
          ${result.temporary_value ? `<p>Temporary value: ${pct(result.temporary_value.value)}% — ${esc(result.temporary_value.reason)}</p>` : ''}
          ${activities}
        </div>
      </section>`);
    } catch (error) {
      alert(`Unable to open milestone: ${error.message}`);
    }
  };

  if (typeof originalOpenNotificationTarget === 'function') {
    window._openNotificationTarget = async function (target) {
      const workflowTypes = new Set([
        'work_center_progress', 'work_center_task', 'activity_verification',
        'rework_item', 'milestone_breakdown_request', 'milestone_override',
      ]);
      if (!workflowTypes.has(String(target?.entityType || ''))) {
        return originalOpenNotificationTarget(target);
      }
      try {
        const projectId = await ensureActiveProjectId();
        if (!projectId) return false;
        const query = new URLSearchParams({
          projectId,
          entityType: String(target.entityType),
          entityId: String(target.entityId),
        });
        const result = await responseData(await _wcFetch(`${API}/notifications/target?${query}`));
        if (result.target.tab === 'work-center') {
          return await _openRecordNotification('workspace_work_center', String(result.target.recordId));
        }
        if (result.target.type === 'activity' && target.entityType === 'activity_verification') {
          return await window._openActivityVerificationNotification(target.entityId, result.target);
        }
        if (result.target.type === 'activity' && target.entityType === 'rework_item') {
          const activityId = String(result.target.recordId);
          sessionStorage.setItem(`pe-activity-tab-${activityId}`, 'certification');
          collapseGrayPart();
          const opened = await _openRecordNotification('planning_execution', activityId);
          if (!opened) return false;
          const tab = await _waitForElement(`#pe-detail-inner-${CSS.escape(activityId)} [data-pe-tab="certification"]`);
          tab?.click();
          const item = await _waitForElement(`#pe-rework-${CSS.escape(String(target.entityId))}`);
          item?.scrollIntoView({ behavior: 'smooth', block: 'center' });
          return Boolean(item);
        }
        if (result.target.type === 'activity') {
          return await _openRecordNotification('planning_execution', String(result.target.recordId));
        }
        if (result.target.type === 'verification') {
          return await window._openActivityVerificationNotification(target.entityId, result.target);
        }
        if (result.target.type === 'milestone') {
          await window.openMilestoneDeepLink(result.target.milestone);
          return true;
        }
        throw new Error('The notification target is not supported.');
      } catch (error) {
        console.error('Unable to open workflow notification:', error);
        if (typeof _showNotificationOpenError === 'function') _showNotificationOpenError();
        else alert(`Unable to open notification: ${error.message}`);
        return false;
      }
    };
  }
})();
