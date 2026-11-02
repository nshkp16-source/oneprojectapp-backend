// ===== Activity form v2: an activity with its tasks, weights, stages and a real milestone link =====
// Replaces the "Add Activity" form. It posts to POST /api/planning-execution/create-with-tasks.
// Uses the dashboard's own globals: API, _wcFetch, expandGrayPart, collapseGrayPart, escapeHtml, wcSide,
// isWCLeader, PE_UNITS, _peUnitOptions, _peLabelStyle, _peInputStyle, recordsCache, loadPERecords.
// The weight rules mirror progressRules.js on the server (the server checks them again).

const PE2_TYPES = {
  quantity:   { label: 'Quantity',   hint: 'Progress = amount done / planned amount. For measurable work such as m3, m2 or kg.' },
  count:      { label: 'Count',      hint: 'Progress = passed items / planned items. For inspections, tests and reviews.' },
  stages:     { label: 'Stages',     hint: 'Progress = weight of the stages completed. For steps, approvals or supervision periods. A stage can be a hold point.' },
  percentage: { label: 'Percentage', hint: 'Progress = the latest approved cumulative percentage. For work that cannot be measured.' },
};

let _pe2 = null;   // form state

// ── weights (hundredths, so totals are exact) ────────────────────────────────
function _pe2Cents(w) { return Math.round(Number(w) * 100); }
function _pe2SplitEqual(n) {
  if (n <= 0) return [];
  const base = Math.round(10000 / n);
  const out = Array(n).fill(base / 100);
  out[n - 1] = (10000 - base * (n - 1)) / 100;
  return out;
}
function _pe2WeightTotal(list) { return list.reduce((t, w) => t + _pe2Cents(w || 0), 0) / 100; }
// add one item: the others are scaled down in proportion (equal in, equal out)
function _pe2RebalanceForNew(existing) {
  if (!existing.length) return [100];
  const oldC = existing.map(_pe2Cents);
  if (Math.max(...oldC) - Math.min(...oldC) <= 1) return _pe2SplitEqual(existing.length + 1);
  const newC = Math.round(10000 / (existing.length + 1));
  const room = 10000 - newC, sum = oldC.reduce((t, c) => t + c, 0);
  const scaled = oldC.map((c) => Math.max(1, Math.round((c * room) / sum)));
  scaled[scaled.indexOf(Math.max(...scaled))] += room - scaled.reduce((t, c) => t + c, 0);
  return [...scaled.map((c) => c / 100), newC / 100];
}
// remove one item: the rest are scaled back up to 100
function _pe2RebalanceAfterRemove(remaining) {
  if (!remaining.length) return [];
  const oldC = remaining.map(_pe2Cents), sum = oldC.reduce((t, c) => t + c, 0);
  if (Math.max(...oldC) - Math.min(...oldC) <= 1) return _pe2SplitEqual(remaining.length);
  const scaled = oldC.map((c) => Math.max(1, Math.round((c * 10000) / sum)));
  scaled[scaled.indexOf(Math.max(...scaled))] += 10000 - scaled.reduce((t, c) => t + c, 0);
  return scaled.map((c) => c / 100);
}

function _pe2DefaultType() {
  const s = wcSide(window.currentUserRole);
  return s === 'Consultant' ? 'count' : s === 'Client' ? 'stages' : 'quantity';
}
function _pe2NewTask() { return { title: '', members: [], weight: 100, stages: [_pe2NewStage(100)] }; }
function _pe2NewStage(weight) { return { title: '', weight, hold: false }; }
function _pe2Measured() { return _pe2.type === 'quantity' || _pe2.type === 'count'; }

// ── data ─────────────────────────────────────────────────────────────────────
async function _pe2Fetch(path) {
  try {
    const res = await _wcFetch(`${API}${path}`);
    if (res && res.ok) return await res.json();
  } catch (e) { /* non-fatal: the form still works without the list */ }
  return null;
}

async function _peOpenAddForm() {
  if (projectLifecycleReadOnly) { showProjectLifecycleNotice(projectLifecycleReadOnlyReason); return; }
  if (!isWCLeader(window.currentUserRole)) { alert('Only side leaders can add activities.'); return; }
  const projectId = typeof ensureActiveProjectId === 'function' ? await ensureActiveProjectId() : localStorage.getItem('activeProjectId');
  if (!projectId) return;
  const [ms, tm] = await Promise.all([
    _pe2Fetch(`/project-milestones?projectId=${encodeURIComponent(projectId)}`),
    _pe2Fetch(`/work-center/team-members?projectId=${encodeURIComponent(projectId)}`),
  ]);
  _pe2 = { projectId, type: _pe2DefaultType(), milestones: (ms && ms.milestones) || [], members: (tm && tm.members) || [],
           tasks: [_pe2NewTask()], weightsEdited: false };
  expandGrayPart(_pe2FormHtml());
  _pe2Wire();
}
window.openPlanningExecutionForm = _peOpenAddForm;
window._peOpenForm = _peOpenAddForm;

// ── html ─────────────────────────────────────────────────────────────────────
function _pe2FormHtml() {
  const contractor = wcSide(window.currentUserRole) === 'Contractor';
  const msOption = (m) => {
    const note = m.completed ? ' (completed)' : m.typed_progress ? ` (typed progress ${m.progress_pct}%)` : m.progress_source === 'activities' ? ' (driven by activities)' : '';
    return `<option value="${m.kind === 'baseline' ? 'b' : 'a'}:${m.id}"${m.completed ? ' disabled' : ''}>${escapeHtml(m.title)}${note}</option>`;
  };
  const base = _pe2.milestones.filter((m) => m.kind === 'baseline'), add = _pe2.milestones.filter((m) => m.kind === 'additional');
  return `
  <div style="width:100%;height:100%;display:flex;flex-direction:column;overflow:hidden;">
    <div style="padding:16px 20px 12px;border-bottom:2px solid #007B8A;flex-shrink:0;background:#fff;">
      <h3 style="margin:0;color:#1f2937;font-size:18px;font-weight:700;">Add Activity</h3>
      <p style="margin:4px 0 0;font-size:12px;color:#6b7280;">Plan the activity and hand it to your team in one step. Each task carries a share of the activity.</p>
    </div>
    <div id="pe2-body" style="flex:1;overflow-y:auto;padding:16px 20px;display:flex;flex-direction:column;gap:14px;">

      <div>
        <label style="${_peLabelStyle()}">Milestone</label>
        <select id="pe2-milestone" style="${_peInputStyle()}">
          <option value="">No milestone</option>
          ${base.length ? `<optgroup label="Schedule milestones">${base.map(msOption).join('')}</optgroup>` : ''}
          ${add.length ? `<optgroup label="Additional milestones">${add.map(msOption).join('')}</optgroup>` : ''}
          <option value="new">Type a standalone milestone...</option>
        </select>
        <input id="pe2-milestone-text" type="text" placeholder="Standalone milestone name" style="${_peInputStyle()}margin-top:6px;display:none;"/>
        <p id="pe2-milestone-note" style="font-size:11px;color:#6b7280;margin:4px 0 0;min-height:14px;"></p>
      </div>

      <div>
        <label style="${_peLabelStyle()}">Activity title *</label>
        <input id="pe2-title" type="text" placeholder="e.g. Excavation of grid B foundation" style="${_peInputStyle()}padding:10px 12px;font-size:14px;"/>
      </div>
      <div>
        <label style="${_peLabelStyle()}">Scope</label>
        <textarea id="pe2-desc" placeholder="Scope and objectives" style="width:100%;min-height:64px;padding:10px 12px;border:1px solid #d1d5db;border-radius:8px;font-size:14px;resize:vertical;box-sizing:border-box;"></textarea>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div><label style="${_peLabelStyle()}">Start date *</label><input id="pe2-start" type="date" style="${_peInputStyle()}"/></div>
        <div><label style="${_peLabelStyle()}">End date *</label><input id="pe2-end" type="date" style="${_peInputStyle()}"/></div>
      </div>

      <div>
        <label style="${_peLabelStyle()}">How is progress measured? *</label>
        <select id="pe2-type" style="${_peInputStyle()}">
          ${Object.entries(PE2_TYPES).map(([k, t]) => `<option value="${k}"${k === _pe2.type ? ' selected' : ''}>${t.label}</option>`).join('')}
        </select>
        <p id="pe2-type-hint" style="font-size:11px;color:#6b7280;margin:4px 0 0;">${PE2_TYPES[_pe2.type].hint}</p>
      </div>
      <div id="pe2-measure" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div><label style="${_peLabelStyle()}">Planned amount *</label><input id="pe2-qty" type="number" min="0" step="any" style="${_peInputStyle()}"/></div>
        <div id="pe2-unit-wrap"></div>
      </div>

      <div>
        <label style="${_peLabelStyle()}">Done when</label>
        <input id="pe2-donewhen" type="text" placeholder="The agreed finish condition, e.g. levels confirmed within tolerance" style="${_peInputStyle()}"/>
      </div>

      <details>
        <summary style="cursor:pointer;font-size:12px;font-weight:600;color:#374151;">Resource plan (optional)</summary>
        <div style="display:flex;flex-direction:column;gap:10px;margin-top:10px;">
          <textarea id="pe2-work" placeholder="Planned work" style="width:100%;min-height:50px;padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;font-size:13px;box-sizing:border-box;"></textarea>
          <input id="pe2-manpower" type="text" placeholder="Planned manpower" style="${_peInputStyle()}"/>
          <input id="pe2-equipment" type="text" placeholder="Planned equipment" style="${_peInputStyle()}"/>
          <input id="pe2-materials" type="text" placeholder="Planned materials" style="${_peInputStyle()}"/>
        </div>
      </details>
      <div><label style="${_peLabelStyle()}">Plan file</label><input id="pe2-file" type="file" style="font-size:13px;color:#374151;"/></div>

      <div style="border-top:1px solid #e5e7eb;padding-top:12px;">
        <div style="display:flex;align-items:center;justify-content:space-between;">
          <label style="${_peLabelStyle()}margin:0;">Tasks</label>
          <span id="pe2-total" style="font-size:12px;font-weight:600;"></span>
        </div>
        <p style="font-size:11px;color:#6b7280;margin:4px 0 8px;">Each task is handed to team members in Work Center. Weights show how much of the activity each task is worth.</p>
        <div id="pe2-tasks" style="display:flex;flex-direction:column;gap:10px;"></div>
        <div style="display:flex;gap:8px;margin-top:10px;">
          <button type="button" id="pe2-add-task" style="padding:8px 12px;font-size:13px;border:1px solid #d1d5db;border-radius:8px;background:#fff;cursor:pointer;">+ Add task</button>
          <button type="button" id="pe2-equal" style="padding:8px 12px;font-size:13px;border:1px solid #d1d5db;border-radius:8px;background:#fff;cursor:pointer;">Split weights equally</button>
        </div>
      </div>
    </div>
    <div style="flex-shrink:0;padding:16px 20px;border-top:1px solid #e5e7eb;background:#fff;display:flex;gap:12px;">
      <button type="button" id="pe2-save" style="flex:1;padding:12px;font-size:14px;font-weight:700;background:#007B8A;color:#fff;border:none;border-radius:8px;cursor:pointer;">Create activity</button>
      <button type="button" onclick="collapseGrayPart()" style="flex:1;padding:12px;font-size:14px;font-weight:700;background:#f5f5f5;color:#333;border:1px solid #ddd;border-radius:8px;cursor:pointer;">Cancel</button>
    </div>
  </div>`;
}

function _pe2TasksHtml() {
  const measured = _pe2Measured();
  const unit = (document.getElementById('pe2-unit')?.value || '').trim();
  const qty = Number(document.getElementById('pe2-qty')?.value) || 0;
  const many = _pe2.tasks.length > 1;
  return _pe2.tasks.map((t, i) => {
    const target = measured && qty > 0 ? Math.round(((qty * (t.weight || 0)) / 100) * 1000) / 1000 : null;
    const members = _pe2.members.length
      ? _pe2.members.map((m) => `
          <label style="display:inline-flex;align-items:center;gap:4px;font-size:12px;border:1px solid #d1d5db;border-radius:14px;padding:3px 9px;margin:2px;cursor:pointer;background:${t.members.includes(m.id) ? '#e5e7eb' : '#fff'};">
            <input type="checkbox" data-task="${i}" data-member="${m.id}" ${t.members.includes(m.id) ? 'checked' : ''}/>
            ${escapeHtml(m.title || m.email)}${m.position ? ` <span style="color:#6b7280;">(${escapeHtml(m.position)})</span>` : ''}
          </label>`).join('')
      : '<span style="font-size:12px;color:#9ca3af;">No team members are assigned to your side yet (Assign Team).</span>';
    const stages = _pe2.type === 'stages' ? `
      <div style="margin-top:8px;border-top:1px dashed #e5e7eb;padding-top:8px;">
        <div style="font-size:11px;font-weight:600;color:#6b7280;text-transform:uppercase;margin-bottom:4px;">Stages (weights add up to 100)
          <span data-stage-total="${i}" style="text-transform:none;margin-left:6px;"></span></div>
        ${t.stages.map((s, j) => `
          <div style="display:grid;grid-template-columns:1fr 70px auto auto;gap:6px;align-items:center;margin-bottom:4px;">
            <input data-stage-title="${i}:${j}" type="text" value="${escapeHtml(s.title)}" placeholder="Stage ${j + 1}" style="${_peInputStyle()}"/>
            <input data-stage-weight="${i}:${j}" type="number" min="0" step="any" value="${s.weight}" style="${_peInputStyle()}"/>
            <label style="font-size:11px;white-space:nowrap;"><input data-stage-hold="${i}:${j}" type="checkbox" ${s.hold ? 'checked' : ''}/> hold point</label>
            <button type="button" data-stage-del="${i}:${j}" ${t.stages.length < 2 ? 'disabled' : ''} style="border:none;background:none;cursor:pointer;color:#6b7280;">x</button>
          </div>`).join('')}
        <button type="button" data-stage-add="${i}" style="font-size:12px;border:1px solid #d1d5db;border-radius:8px;background:#fff;padding:4px 8px;cursor:pointer;">+ Add stage</button>
      </div>` : '';
    return `
      <div style="border:1px solid #e5e7eb;border-radius:10px;padding:10px;background:#fafafa;">
        <div style="display:grid;grid-template-columns:1fr ${many ? '90px' : ''} auto;gap:8px;align-items:end;">
          <div><label style="${_peLabelStyle()}">Task ${i + 1} title *</label>
            <input data-task-title="${i}" type="text" value="${escapeHtml(t.title)}" style="${_peInputStyle()}"/></div>
          ${many ? `<div><label style="${_peLabelStyle()}">Weight %</label>
            <input data-task-weight="${i}" type="number" min="0" step="any" value="${t.weight}" style="${_peInputStyle()}"/></div>` : ''}
          <button type="button" data-task-del="${i}" ${many ? '' : 'disabled'} title="Remove task" style="border:none;background:none;cursor:pointer;color:#6b7280;font-size:16px;">x</button>
        </div>
        ${measured ? `<div data-task-target="${i}" style="font-size:12px;color:#6b7280;margin-top:4px;">${target != null ? `Target: ${target} ${escapeHtml(unit)}` : 'Target follows the planned amount.'}</div>` : ''}
        <div style="margin-top:6px;"><label style="${_peLabelStyle()}">Assigned to *</label>${members}</div>
        ${stages}
      </div>`;
  }).join('');
}

// ── wiring ───────────────────────────────────────────────────────────────────
function _pe2UpdateTotals() {
  const total = _pe2WeightTotal(_pe2.tasks.map((t) => t.weight));
  const el = document.getElementById('pe2-total');
  if (el) {
    const ok = _pe2.tasks.length < 2 || total === 100;
    el.textContent = _pe2.tasks.length < 2 ? '' : `Weights total ${total}%${ok ? '' : ' (must be 100)'}`;
    el.style.color = ok ? '#374151' : '#b91c1c';
  }
  if (_pe2.type === 'stages') {
    _pe2.tasks.forEach((t, i) => {
      const s = document.querySelector(`[data-stage-total="${i}"]`);
      if (!s) return;
      const st = _pe2WeightTotal(t.stages.map((x) => x.weight));
      s.textContent = `total ${st}%${st === 100 ? '' : ' (must be 100)'}`;
      s.style.color = st === 100 ? '#374151' : '#b91c1c';
    });
  }
  if (_pe2Measured()) {
    const qty = Number(document.getElementById('pe2-qty')?.value) || 0;
    const unit = document.getElementById('pe2-unit')?.value || '';
    _pe2.tasks.forEach((t, i) => {
      const el2 = document.querySelector(`[data-task-target="${i}"]`);
      if (el2) el2.textContent = qty > 0 ? `Target: ${Math.round(((qty * (t.weight || 0)) / 100) * 1000) / 1000} ${unit}` : 'Target follows the planned amount.';
    });
  }
}

function _pe2RenderTasks() {
  const box = document.getElementById('pe2-tasks');
  if (box) box.innerHTML = _pe2TasksHtml();
  _pe2UpdateTotals();
}

function _pe2RenderMeasure() {
  const measured = _pe2Measured();
  const measure = document.getElementById('pe2-measure');
  if (measure) measure.style.display = measured ? 'grid' : 'none';
  const wrap = document.getElementById('pe2-unit-wrap');
  if (wrap) {
    wrap.innerHTML = _pe2.type === 'count'
      ? `<label style="${_peLabelStyle()}">What is counted *</label><input id="pe2-unit" type="text" placeholder="e.g. inspections" style="${_peInputStyle()}"/>`
      : `<label style="${_peLabelStyle()}">Unit *</label><select id="pe2-unit" style="${_peInputStyle()}"><option value="">Select unit</option>${_peUnitOptions('')}</select>`;
    document.getElementById('pe2-unit')?.addEventListener('input', _pe2UpdateTotals);
    document.getElementById('pe2-unit')?.addEventListener('change', _pe2UpdateTotals);
  }
  const hint = document.getElementById('pe2-type-hint');
  if (hint) hint.textContent = PE2_TYPES[_pe2.type].hint;
}

function _pe2MilestoneNote() {
  const sel = document.getElementById('pe2-milestone')?.value || '';
  const note = document.getElementById('pe2-milestone-note');
  const text = document.getElementById('pe2-milestone-text');
  if (text) text.style.display = sel === 'new' ? 'block' : 'none';
  if (!note) return;
  const m = _pe2.milestones.find((x) => `${x.kind === 'baseline' ? 'b' : 'a'}:${x.id}` === sel);
  const drives = wcSide(window.currentUserRole) === 'Contractor';
  if (!m) { note.textContent = sel === 'new' ? 'A standalone milestone is a label of your side. It is not linked to the schedule.' : ''; return; }
  note.textContent = !drives
    ? 'Reference only: this activity does not change the milestone percentage.'
    : m.typed_progress
      ? `This milestone has typed progress (${m.progress_pct}%). Linking replaces it with progress from activities, which starts at 0% until the consultant certifies work. You will be asked to confirm.`
      : 'The milestone percentage will follow the consultant-certified progress of this activity and the other contractor activities linked to it.';
}

function _pe2Wire() {
  const $ = (id) => document.getElementById(id);
  _pe2RenderMeasure();
  _pe2RenderTasks();
  _pe2MilestoneNote();

  $('pe2-milestone').addEventListener('change', _pe2MilestoneNote);
  $('pe2-type').addEventListener('change', (e) => {
    _pe2.type = e.target.value;
    _pe2.tasks.forEach((t) => { if (!t.stages.length) t.stages = [_pe2NewStage(100)]; });
    _pe2RenderMeasure();
    _pe2RenderTasks();
  });
  $('pe2-qty').addEventListener('input', _pe2UpdateTotals);

  $('pe2-add-task').addEventListener('click', () => {
    const w = _pe2.tasks.length ? _pe2RebalanceForNew(_pe2.tasks.map((t) => t.weight)) : [100];
    _pe2.tasks.forEach((t, i) => { t.weight = w[i]; });
    const nt = _pe2NewTask(); nt.weight = w[w.length - 1];
    _pe2.tasks.push(nt);
    _pe2RenderTasks();
  });
  $('pe2-equal').addEventListener('click', () => {
    const w = _pe2SplitEqual(_pe2.tasks.length);
    _pe2.tasks.forEach((t, i) => { t.weight = w[i]; });
    _pe2RenderTasks();
  });

  const box = $('pe2-tasks');
  box.addEventListener('input', (e) => {
    const d = e.target.dataset;
    if (d.taskTitle != null) _pe2.tasks[+d.taskTitle].title = e.target.value;
    else if (d.taskWeight != null) { _pe2.tasks[+d.taskWeight].weight = e.target.value === '' ? 0 : Number(e.target.value); _pe2.weightsEdited = true; _pe2UpdateTotals(); }
    else if (d.stageTitle != null) { const [i, j] = d.stageTitle.split(':').map(Number); _pe2.tasks[i].stages[j].title = e.target.value; }
    else if (d.stageWeight != null) { const [i, j] = d.stageWeight.split(':').map(Number); _pe2.tasks[i].stages[j].weight = e.target.value === '' ? 0 : Number(e.target.value); _pe2UpdateTotals(); }
  });
  box.addEventListener('change', (e) => {
    const d = e.target.dataset;
    if (d.member != null) {
      const t = _pe2.tasks[+d.task], id = Number(d.member);
      t.members = e.target.checked ? [...new Set([...t.members, id])] : t.members.filter((x) => x !== id);
    } else if (d.stageHold != null) { const [i, j] = d.stageHold.split(':').map(Number); _pe2.tasks[i].stages[j].hold = e.target.checked; }
  });
  box.addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b) return;
    const d = b.dataset;
    if (d.taskDel != null) {
      _pe2.tasks.splice(+d.taskDel, 1);
      const w = _pe2RebalanceAfterRemove(_pe2.tasks.map((t) => t.weight));
      _pe2.tasks.forEach((t, i) => { t.weight = w[i]; });
      _pe2RenderTasks();
    } else if (d.stageAdd != null) {
      const t = _pe2.tasks[+d.stageAdd];
      const w = _pe2RebalanceForNew(t.stages.map((s) => s.weight));
      t.stages.forEach((s, k) => { s.weight = w[k]; });
      t.stages.push(_pe2NewStage(w[w.length - 1]));
      _pe2RenderTasks();
    } else if (d.stageDel != null) {
      const [i, j] = d.stageDel.split(':').map(Number);
      const t = _pe2.tasks[i]; t.stages.splice(j, 1);
      const w = _pe2RebalanceAfterRemove(t.stages.map((s) => s.weight));
      t.stages.forEach((s, k) => { s.weight = w[k]; });
      _pe2RenderTasks();
    }
  });

  $('pe2-save').addEventListener('click', () => _pe2Submit(false));
}

// ── submit ───────────────────────────────────────────────────────────────────
function _pe2Problem() {
  const v = (id) => (document.getElementById(id)?.value || '').trim();
  if (!v('pe2-title')) return 'Activity title is required.';
  if (!v('pe2-start') || !v('pe2-end')) return 'Start and end dates are required.';
  if (v('pe2-end') < v('pe2-start')) return 'The end date cannot be before the start date.';
  if (document.getElementById('pe2-milestone')?.value === 'new' && !v('pe2-milestone-text')) return 'Type the standalone milestone name, or choose another option.';
  if (_pe2Measured()) {
    if (!(Number(v('pe2-qty')) > 0)) return 'The planned amount must be above 0.';
    if (!v('pe2-unit')) return _pe2.type === 'count' ? 'Say what is counted.' : 'Please select a unit.';
  }
  if (_pe2.tasks.length > 1 && _pe2WeightTotal(_pe2.tasks.map((t) => t.weight)) !== 100) return 'Task weights must add up to 100%.';
  for (const [i, t] of _pe2.tasks.entries()) {
    if (!t.title.trim()) return `Task ${i + 1} needs a title.`;
    if (!t.members.length) return `Task ${i + 1} needs at least one assigned team member.`;
    if (_pe2.type === 'stages') {
      if (t.stages.some((s) => !s.title.trim())) return `Every stage of task ${i + 1} needs a title.`;
      if (_pe2WeightTotal(t.stages.map((s) => s.weight)) !== 100) return `Stage weights of task ${i + 1} must add up to 100%.`;
    }
  }
  return null;
}

function _pe2Payload(confirmReplace) {
  const v = (id) => (document.getElementById(id)?.value || '').trim();
  const form = new FormData();
  form.append('projectId', _pe2.projectId);
  form.append('title', v('pe2-title'));
  form.append('description', v('pe2-desc'));
  form.append('start_date', v('pe2-start'));
  form.append('end_date', v('pe2-end'));
  form.append('activity_type', _pe2.type);
  if (_pe2Measured()) { form.append('planned_quantity', v('pe2-qty')); form.append('unit', v('pe2-unit')); }
  form.append('done_when', v('pe2-donewhen'));
  form.append('planned_work', v('pe2-work'));
  form.append('planned_manpower', v('pe2-manpower'));
  form.append('planned_equipment', v('pe2-equipment'));
  form.append('planned_materials', v('pe2-materials'));
  const sel = document.getElementById('pe2-milestone')?.value || '';
  if (sel.startsWith('b:')) form.append('baseline_milestone_id', sel.slice(2));
  else if (sel.startsWith('a:')) form.append('additional_milestone_id', sel.slice(2));
  else if (sel === 'new') form.append('milestone_name', v('pe2-milestone-text'));
  const many = _pe2.tasks.length > 1;
  form.append('tasks', JSON.stringify(_pe2.tasks.map((t) => ({
    title: t.title.trim(),
    assigned_members: t.members.map((id) => ({ id })),
    ...(many ? { weight_pct: t.weight } : {}),
    ...(_pe2.type === 'stages' ? { stages: t.stages.map((s) => ({ title: s.title.trim(), weight_pct: s.weight, is_hold_point: !!s.hold })) } : {}),
  }))));
  const file = document.getElementById('pe2-file')?.files?.[0];
  if (file) form.append('linked_file', file);
  if (confirmReplace) form.append('confirm_replace_manual', 'true');
  return form;
}

async function _pe2Submit(confirmReplace) {
  const btn = document.getElementById('pe2-save');
  try {
    const problem = _pe2Problem();
    if (problem) return alert(problem);
    if (btn) { btn.disabled = true; btn.textContent = 'Saving...'; }
    const res = await _wcFetch(`${API}/planning-execution/create-with-tasks`, { method: 'POST', body: _pe2Payload(confirmReplace) });
    const data = await res.json().catch(() => ({}));
    if (res.status === 409 && data.code === 'CONFIRM_REPLACE_MANUAL') {
      const unit = data.unit ? ` ${data.unit}` : '';
      const yes = confirm(
        `This milestone has typed progress: ${data.typed_progress_pct}%` +
        `${data.quantity ? ` (${data.typed_executed} of ${data.quantity}${unit})` : ''}.\n\n` +
        `Linking replaces it with progress from activities, which starts at ${data.will_become}% until the consultant certifies work. ` +
        `The typed entries are kept as history.\n\nContinue?`);
      if (btn) { btn.disabled = false; btn.textContent = 'Create activity'; }
      if (yes) return _pe2Submit(true);
      return;
    }
    if (!res.ok) throw new Error(data.error || data.message || `HTTP ${res.status}`);
    const n = (data.tasks || []).length;
    alert(`Activity created${n ? ` with ${n} task${n > 1 ? 's' : ''}` : ''}.`);
    delete recordsCache['planning-execution'];
    delete recordsCache['work-center'];
    collapseGrayPart();
    loadPERecords();
  } catch (err) {
    console.error('Create activity error:', err);
    alert('Failed to save: ' + err.message);
    if (btn) { btn.disabled = false; btn.textContent = 'Create activity'; }
  }
}
