// Renders the patched dashboard's real member and leader task views (extracted from dashboard.html with a JS parser)
// and checks what a user would see: fields per activity type, figures, void button, voided reports.
// Run: node --test wc-views.test.js   (needs: npm i -D jsdom acorn)
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { JSDOM } from 'jsdom';
import * as acorn from 'acorn';

const html = fs.readFileSync(new URL('../frontend/dashboard.html', import.meta.url), 'utf8');
const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
function extract(names) {
  const found = {};
  for (const src of scripts) {
    const ast = acorn.parse(src, { ecmaVersion: 'latest', sourceType: 'script' });
    for (const n of ast.body) if (n.type === 'FunctionDeclaration' && names.includes(n.id.name)) found[n.id.name] = src.slice(n.start, n.end);
  }
  for (const n of names) assert.ok(found[n], `${n} not found in dashboard.html`);
  return names.map((n) => found[n]).join('\n');
}

const HELPERS = ['_wcFmtDate', '_wcReportDelayDays', '_uiLabelStyle', '_wcReadField', '_wcLabel', '_wcInput', '_wcStatusBadgeHtml', '_wcDeriveStatus', '_wcActivityStatusBadge',
  'wcPriorityBadge', '_wcMemberView', '_wcPMView', '_wcTypeOf', '_wcUnitText', '_wcStagesOf', '_wcTaskShareHtml',
  '_wcReportFieldsHtml', '_wcEntryFigure', '_wcReportExtraHtml', '_wcTaskSummaryHtml', '_wcActivityPlanHtml', '_wcPlanRow',
  '_supportingAttachmentTypeOptions', '_supportingAttachmentTypeLabel', '_wcUpdateSupportingAttachmentGroup', '_wcSupportingAttachmentGroupHtml',
  '_wcReportSupportingAttachmentsHtml', '_wcFilesHtml', '_wcQueryPanelHtml', '_wcTabifyDetail',
  '_wcCardHeaderHtml', '_wcCardTilesHtml',
  '_safeHttpsUrl', '_fileDisplayName', '_thumbUrl', '_evidenceFileAttrs', '_evidenceFileRowHtml', '_evidencePhotosHtml', '_evidenceFilesHtml'];

function views() {
  const dom = new JSDOM('<!doctype html><body></body>', { runScripts: 'outside-only', url: 'http://localhost/' });
  const ctx = dom.getInternalVMContext();
  vm.runInContext(`function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }`, ctx);
  vm.runInContext(extract(HELPERS), ctx);
  vm.runInContext(`function tabbed(task, entries, queries, leader) {
    document.body.innerHTML = leader ? _wcPMView(task, entries) : _wcMemberView(task, entries);
    _wcTabifyDetail(document.body, task, entries, queries, leader, true);
    return document;
  }
  function saveReportFilter(taskId, filter) {
    sessionStorage.setItem(\`wc-report-filter-\${taskId}\`, filter);
  }`, ctx);
  const render = (fn, task, entries) => { dom.window.__t = task; dom.window.__e = entries; dom.window.document.body.innerHTML = vm.runInContext(`${fn}(window.__t, window.__e)`, ctx); return dom.window.document; };
  return {
    formatDate: (value) => { dom.window.__date = value; return vm.runInContext('_wcFmtDate(window.__date)', ctx); },
    reportDelayDays: (reportDate, plannedEndDate) => {
      dom.window.__reportDate = reportDate; dom.window.__plannedEndDate = plannedEndDate;
      return vm.runInContext('_wcReportDelayDays(window.__reportDate, window.__plannedEndDate)', ctx);
    },
    member: (t, e) => render('_wcMemberView', t, e),
    leader: (t, e) => render('_wcPMView', t, e),
    updateSupportingGroup: (group, type) => {
      dom.window.__group = group;
      dom.window.__type = type;
      vm.runInContext(`window.__group.querySelector('[data-supporting-type]').value = window.__type;
        _wcUpdateSupportingAttachmentGroup(window.__group)`, ctx);
    },
    cardTiles: (t, e, c = []) => {
      dom.window.__t = t; dom.window.__e = e; dom.window.__c = c;
      dom.window.document.body.innerHTML = vm.runInContext('_wcCardTilesHtml(window.__t, window.__e, window.__c)', ctx);
      return dom.window.document;
    },
    cardHeader: (t, location) => {
      dom.window.__t = t; dom.window.__location = location;
      dom.window.document.body.innerHTML = vm.runInContext('_wcCardHeaderHtml(window.__t, window.__location)', ctx);
      return dom.window.document;
    },
    attachments: (t, e, files, leader) => {
      dom.window.__t = t; dom.window.__e = e; dom.window.__files = files;
      dom.window.document.body.innerHTML = vm.runInContext('_wcFilesHtml(window.__t, window.__e, window.__files, ' + leader + ')', ctx);
      return dom.window.document;
    },
    tabbed: (t, e, q, leader) => { dom.window.__t = t; dom.window.__e = e; dom.window.__q = q; return vm.runInContext(`tabbed(window.__t, window.__e, window.__q, ${leader})`, ctx); },
    saveReportFilter: (taskId, filter) => { dom.window.__taskId = taskId; dom.window.__filter = filter; vm.runInContext('saveReportFilter(window.__taskId, window.__filter)', ctx); },
  };
}

const task = { id: 5, title: 'Block A', assigned_members: [{ id: 101, email: 'a@x' }], activity_id: 3, activity_title: 'Excavation', activity_status: 'ongoing',
  activity_progress: 10, activity_type: 'quantity', activity_unit: 'm3', target_quantity: '200.000', weight_pct: '50.00', progress_pct: '20.00',
  start_date: '2026-03-01', end_date: '2026-04-30', status: 'ongoing' };
const entries = [
  { id: 1, report_date: '2026-03-10', member_id: 101, member_email: 'a@x', work_done: 'Dug', quantity_done: '40.000', progress_pct: 20, validation_status: 'pending', materials: 'Marker paint', notes: 'North trench completed' },
  { id: 2, report_date: '2026-03-11', member_id: 101, member_email: 'a@x', work_done: 'Dug more', quantity_done: '30.000', progress_pct: 35, validation_status: 'approved', validation_notes: 'Good', materials: 'Survey stakes', notes: 'Levels checked' },
  { id: 3, report_date: '2026-03-12', member_id: 101, member_email: 'a@x', work_done: 'Overstated', quantity_done: '99.000', progress_pct: 99, validation_status: 'voided', void_reason: 'Measured wrongly' },
];

test('member view: quantity field instead of a bare percentage, share line, figures and the void reason', () => {
  const d = views().member(task, entries);
  assert.ok(d.getElementById('wc-pr-qty-5')); assert.equal(d.getElementById('wc-pr-pct-5'), null);
  assert.match(d.body.textContent, /Quantity done \(m3\)/);
  assert.match(d.body.textContent, /Share of the activity 50%/);
  assert.match(d.body.textContent, /Target 200 m3/);
  assert.match(d.body.textContent, /40 m3/); assert.match(d.body.textContent, /30 m3/);
  assert.match(d.body.textContent, /Voided/); assert.match(d.body.textContent, /Measured wrongly/);
});

test('report delay days count dates after the planned task end only', () => {
  const view = views();
  assert.equal(view.reportDelayDays('2026-03-10', '2026-03-09'), 1);
  assert.equal(view.reportDelayDays('2026-03-09', '2026-03-09'), 0);
  assert.equal(view.reportDelayDays('2026-03-08', '2026-03-09'), 0);
  assert.equal(view.reportDelayDays('invalid', '2026-03-09'), 0);
});

test('report cards render photo, structured resources and delay details safely', () => {
  const d = views().member(task, [{
    id: 21, report_date: '2026-03-10', member_id: 101, work_done: 'Poured',
    quantity_done: 12, validation_status: 'pending', delay_cause: 'weather',
    delay_days: 2, delay_note: 'Rain stopped the work.',
    photos: [{ file_name: 'pour.jpg', file_url: 'https://images.example.test/pour.jpg' }],
    resources: [{ resource_type: 'equipment', name: 'Pump', quantity: 1, unit: 'unit', hours: 3 }],
  }]);
  assert.equal(d.querySelectorAll('img[alt="pour.jpg"]').length, 1);
  const photoButton = d.querySelector('button[data-ev-preview][data-ev-name="pour.jpg"]');
  assert.ok(photoButton, 'the photo opens in the preview window');
  assert.equal(photoButton.dataset.evUrl, 'https://images.example.test/pour.jpg');
  assert.equal(d.querySelectorAll('a[href="https://images.example.test/pour.jpg"]').length, 0);   // no direct link to the storage file
  assert.match(d.body.textContent, /equipment: Pump · 1 unit · 3 hours/);
  assert.match(d.body.textContent.replace(/\s+/g, ' '), /Delay: weather · 2 day\(s\) past planned end/);
  assert.match(d.body.textContent, /Rain stopped the work\./);
});

test('member view of an old task (no activity type) still shows the percentage box', () => {
  const d = views().member({ ...task, activity_type: undefined, weight_pct: undefined }, []);
  assert.ok(d.getElementById('wc-pr-pct-5')); assert.equal(d.getElementById('wc-pr-qty-5'), null);
  assert.doesNotMatch(d.body.textContent, /Share of the activity/);
});

test('member view for a stages task offers a stage list', () => {
  const t = { ...task, activity_type: 'stages', target_quantity: null, stages: [{ id: 1, seq: 1, title: 'Reinforcement', is_hold_point: true }, { id: 2, seq: 2, title: 'Pour' }] };
  const d = views().member(t, []);
  const opts = [...d.getElementById('wc-pr-stage-5').options].map((o) => o.textContent.trim());
  assert.deepEqual(opts, ['Select stage', 'Reinforcement (hold point)', 'Pour (locked: an earlier hold point is not verified yet)']);
});

test('task dates use one readable format and invalid values have a safe fallback', () => {
  const view = views();
  assert.equal(view.formatDate('2026-11-03'), '3 Nov 2026');
  assert.equal(view.formatDate('not-a-date'), '—');
});

test('leader view: validate buttons only on pending reports, void button only on approved ones', () => {
  const d = views().leader(task, entries);
  const actions = (id) => [...d.querySelectorAll(`[data-progress-id="${id}"]`)].map((b) => b.dataset.validateAction).filter(Boolean);
  assert.deepEqual(actions(1), ['approved', 'rejected', 'comment_only']);
  assert.deepEqual(actions(2), ['voided']);
  assert.deepEqual(actions(3), []);                                                      // a voided report offers nothing
  assert.match(d.body.textContent, /Void this report/);
  assert.ok(d.getElementById('wc-val-notes-2'));
  assert.match(d.querySelector('label[for="wc-val-notes-2"]').textContent, /Reason for voiding \*/);
  assert.doesNotMatch(d.body.textContent, /Correction audit/);
  assert.match(d.body.textContent, /Measured wrongly/);
  assert.match(d.body.textContent, /40 m3/);
  assert.match(d.body.textContent, /Share of the activity 50%/);
});

test('leader view: no void button once the task is closed', () => {
  const d = views().leader({ ...task, status: 'closed' }, entries);
  assert.equal([...d.querySelectorAll('[data-validate-action="voided"]')].length, 0);
});

test('expanded leader task uses Details and Reports tabs, with queries inside their report', () => {
  const t = { ...task, title: 'Excavate trenches', priority: 'high', description: 'Dig to the levels on drawing S-04.',
    activity_description: 'Excavate grid B foundation.', activity_done_when: 'Formation levels confirmed.',
    activity_planned_quantity: 200, activity_planned_work: 'Excavate and remove spoil.',
    activity_planned_manpower: '6 workers', activity_planned_equipment: '1 excavator',
    activity_planned_materials: 'Not required', activity_milestone_title: 'Foundation',
    activity_milestone_start: '2026-03-01', activity_milestone_end: '2026-04-30',
    activity_start_date: '2026-03-05', activity_end_date: '2026-04-20' };
  const queries = [{ id: 21, asked_by_role: 'ContractorPM', recipient_email: 'a@x',
    report_id: 2, report_date: '2026-03-11', report_work_done: 'Dug more',
    question: 'Please explain the measurement.', answer: 'Measured from the drawing.', status: 'answered',
    created_at: '2026-03-10' }];
  const d = views().tabbed(t, entries, queries, true);
  const tabs = [...d.querySelectorAll('[role="tab"]')];
  assert.ok(tabs.every((tab) => tab.classList.contains('detail-tab')));
  assert.deepEqual(tabs.map((tab) => tab.textContent.trim().replace(/\s+\d+$/, '')),
    ['Details', 'Reports']);
  const summary = d.querySelector('[data-wc-card-summary]');
  assert.doesNotMatch(summary.textContent, /Progress|30 m3 completed|200 m3/);
  assert.doesNotMatch(summary.textContent, /Excavate trenches|Created by|High|Ongoing|Start Date/);
  const details = d.querySelector('#wc-read-5').textContent;
  assert.doesNotMatch(details, /Start Date|End Date|Required priority|Excavate trenches/);
  assert.doesNotMatch(d.body.textContent, /Required priorityHigh/);
  assert.doesNotMatch(d.body.textContent, /How to read this task/);
  assert.match(d.body.textContent, /All 3/);
  assert.match(d.body.textContent, /Pending 1/);
  assert.match(d.body.textContent, /Materials/);
  assert.match(d.body.textContent, /Marker paint/);
  assert.match(d.body.textContent, /North trench completed/);
  assert.match(d.body.textContent, /Foundation/);
  assert.match(d.body.textContent, /Formation levels confirmed/);
  assert.match(d.body.textContent, /Planned manpower6 workers/);
  assert.match(d.body.textContent, /Please explain the measurement/);
  assert.match(d.body.textContent, /Progress report/);
  assert.match(d.body.textContent, /Ask about this report/);
  assert.equal(d.querySelector('#wc-query-question-5'), null);
  assert.ok(d.querySelector('#wc-query-question-2'));
  assert.match(d.querySelector('[data-wc-report-queries="2"]').textContent, /Please explain the measurement/);
  assert.match(d.body.textContent, /Dug more/);
  assert.ok(d.querySelector('[data-wc-pane="reports"]'));
  assert.equal(d.querySelector('[data-wc-pane="queries"]'), null);
  assert.equal(d.querySelector('[data-wc-report-card][data-report-status="approved"]').hidden, true);
  d.querySelector('[data-report-filter="all"]').click();
  assert.equal(d.querySelector('[data-wc-report-card][data-report-status="approved"]').hidden, false);
});

test('task card tiles show team-wide totals, pending reports and task progress', () => {
  const taskTotals = {
    ...task, progress_pct: 35, pending_report_count: 2, total_report_count: 5,
    approved_quantity_done: 70,
  };
  const d = views().cardTiles(taskTotals, [
    { validation_status: 'approved', quantity_done: 30 },
    { validation_status: 'pending', quantity_done: 40 },
  ]);
  const text = d.body.textContent.replace(/\s+/g, ' ');
  assert.match(text, /Task progress 35%/);
  assert.match(text, /Quantity done 70 of 200 m3/);
  assert.match(text, /Share of activity 50%/);
  assert.match(text, /Reports 5 2 pending/);
  assert.doesNotMatch(text, /Checklist/);
});

test('card hierarchy chips show activity, location, dates and drawing', () => {
  const d = views().cardHeader(task, {
    block: 'Block A', floor: '2', grid: 'C-4', drawing: 'S-04',
  });
  assert.match(d.body.textContent, /Activity Excavation/);
  assert.match(d.body.textContent, /Location Block A · 2 · C-4/);
  assert.match(d.body.textContent, /Dates 1 Mar 2026 to 30 Apr 2026/);
  assert.match(d.body.textContent, /Drawing S-04/);
});

test('task attachment tab lists legacy and multiple files and offers upload/removal to leaders', () => {
  const d = views().attachments(
    { ...task, linked_file_name: 'legacy.pdf' },
    [{ id: 2, attachment_name: 'report.jpg', report_date: '2026-03-10' }],
    [{ id: 9, file_name: 'drawing.dwg', file_url: 'https://files.test/drawing.dwg' }],
    true,
  );
  assert.match(d.body.textContent, /legacy\.pdf/);
  assert.match(d.body.textContent, /drawing\.dwg/);
  assert.match(d.body.textContent, /report\.jpg/);
  const download = d.querySelector('[data-ev-download][data-ev-name="drawing.dwg"]');
  assert.ok(download, 'each task file has a Download control that saves it under its real name');
  assert.equal(download.dataset.evUrl, 'https://files.test/drawing.dwg');
  assert.ok(d.querySelector('[data-wc-attachment-input][multiple]'));
  assert.ok(d.querySelector('[data-wc-attachment-delete="9"]'));
});

test('progress report has exactly Photos and type-first Supporting attachments', () => {
  const view = views();
  const d = view.member(task, entries);
  assert.equal(d.querySelectorAll('input[type="file"]').length, 2);
  assert.ok(d.querySelector(`#wc-pr-photos-${task.id}[multiple][accept="image/*"]`));
  const supportingFiles = [...d.querySelectorAll('input[type="file"]')]
    .find((input) => input.hasAttribute('data-supporting-files'));
  assert.ok(supportingFiles);
  assert.equal(supportingFiles.multiple, true);
  assert.equal(supportingFiles.disabled, true);
  assert.equal(d.querySelector(`#wc-pr-file-${task.id}`), null);
  const group = d.querySelector('[data-wc-supporting-group]');
  assert.ok(group.querySelector('[data-supporting-type]'));
  const customWrap = group.querySelector('[data-supporting-custom-wrap]');
  assert.equal(customWrap.hidden, true);
  assert.equal(customWrap.style.display, 'none');
  assert.ok(customWrap.querySelector('[data-supporting-custom][disabled]'));
  assert.match(group.textContent, /Evidence title/);
  assert.match(customWrap.textContent, /Custom title \(required for Other\)/);
  view.updateSupportingGroup(group, 'other');
  assert.equal(customWrap.hidden, false);
  assert.equal(customWrap.style.display, 'block');
  assert.equal(customWrap.querySelector('[data-supporting-custom]').disabled, false);
  assert.equal(customWrap.querySelector('[data-supporting-custom]').required, true);
  view.updateSupportingGroup(group, 'daily_progress');
  assert.equal(customWrap.hidden, true);
  assert.equal(customWrap.style.display, 'none');
});

test('progress submission pairs each supporting file with its chosen title', async () => {
  const dom = new JSDOM('<!doctype html><body></body>', { runScripts: 'outside-only', url: 'http://localhost/' });
  const ctx = dom.getInternalVMContext();
  dom.window.__form = null;
  vm.runInContext(`
    const API = '/api';
    const recordsCache = { 'work-center': [{ id: 5, activity_type: 'percentage', end_date: '2026-03-10' }] };
    async function ensureActiveProjectId() { return '1'; }
    function _wcTypeOf(task) { return task.activity_type; }
    function _wcReportDelayDays() { return 0; }
    async function _wcReadPhotoMetadata() { return {}; }
    async function _wcFetch(_url, options) { window.__form = options.body; return { ok: true, json: async () => ({}) }; }
    async function _wcRefreshTaskCard() {}
    window._wcReportLocationByTask = {};
    window.alert = (message) => { throw new Error(message); };
  `, ctx);
  vm.runInContext(extract(['_wcHandleSubmitProgress']), ctx);
  const d = dom.window.document;
  d.body.innerHTML = `
    <input id="wc-pr-date-5" value="2026-03-10"/><input id="wc-pr-pct-5" value="20"/>
    <textarea id="wc-pr-work-5">Installed pipes</textarea>
    <input id="wc-pr-manpower-5"/><input id="wc-pr-equipment-5"/><input id="wc-pr-materials-5"/>
    <input id="wc-pr-issues-5"/><textarea id="wc-pr-notes-5"></textarea>
    <select id="wc-pr-delay-cause-5"><option value=""></option></select><textarea id="wc-pr-delay-note-5"></textarea>
    <input id="wc-pr-photos-5" type="file" multiple/>
    <div data-wc-supporting-groups data-task-id="5">
      <div data-wc-supporting-group><select data-supporting-type><option value="daily_progress" selected></option></select>
        <input data-supporting-custom/><input data-supporting-files type="file" multiple/></div>
      <div data-wc-supporting-group><select data-supporting-type><option value="other" selected></option></select>
        <input data-supporting-custom value="Calibration records"/><input data-supporting-files type="file" multiple/></div>
    </div>`;
  const inputs = d.querySelectorAll('[data-supporting-files]');
  Object.defineProperty(inputs[0], 'files', { configurable: true, value: [
    new dom.window.File(['a'], 'daily-1.pdf', { type: 'application/pdf' }),
    new dom.window.File(['b'], 'daily-2.pdf', { type: 'application/pdf' }),
  ] });
  Object.defineProperty(inputs[1], 'files', { configurable: true, value: [
    new dom.window.File(['c'], 'calibration.pdf', { type: 'application/pdf' }),
  ] });

  await vm.runInContext(`_wcHandleSubmitProgress(5, 'work-center')`, ctx);
  const body = dom.window.__form;
  assert.deepEqual(body.getAll('supporting_attachments').map((file) => file.name), [
    'daily-1.pdf', 'daily-2.pdf', 'calibration.pdf',
  ]);
  assert.deepEqual(JSON.parse(body.get('supportingAttachmentMetadata')), [
    { attachmentType: 'daily_progress', customAttachmentType: '' },
    { attachmentType: 'daily_progress', customAttachmentType: '' },
    { attachmentType: 'other', customAttachmentType: 'Calibration records' },
  ]);
});

test('task creation forms keep ordinary multiple-file inputs without evidence type selectors', () => {
  assert.match(html, /id="wc-cr-attachments" type="file" multiple/);
  assert.match(html, /id="pe2-attachments" type="file" multiple/);
  assert.doesNotMatch(html, /wc-create-attachment-type|wc-card-attachment-type|_appendCardAttachmentType/);
});

test('internal task-card links are buttons and leader choices are selected from project items', async () => {
  const dom = new JSDOM('<!doctype html><body><div id="wc-detail-5"><div id="card"><div role="tablist"></div><div data-wc-pane="details"></div></div></div></body>',
    { runScripts: 'outside-only', url: 'http://localhost/' });
  const ctx = dom.getInternalVMContext();
  const cardData = {
    location: {},
    comments: [], history: [], checklists: [],
    links: [
      { id: 1, link_type: 'task', target_id: '22', title: 'Block B' },
      { id: 2, link_type: 'query', target_id: '5:31', title: 'Block A: Confirm the depth' },
      { id: 3, link_type: 'record', target_id: 'operational_records:42', title: 'Drawing S-04' },
      { id: 4, link_type: 'url', target_id: null, title: 'External spec', url: 'https://example.test/spec' },
    ],
  };
  dom.window.__cardData = cardData;
  vm.runInContext(`function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
    const API = '/api'; const recordsCache = { 'work-center': [] };
    const CSS = { escape: (value) => String(value) };
    async function _openRecordNotification(type, id) { window.__navigation.push([type, String(id)]); return true; }
    async function _waitForElement(selector) { return document.querySelector(selector); }
    function isWCLeader() { return true; }
    window.HTMLElement.prototype.scrollIntoView = function() {};
    async function _wcFetch(url) {
      if (url.includes('/link-options?')) return { ok: true, json: async () => ({
        tasks: [{ targetId: '22', title: 'Block B' }],
        queries: [{ targetId: '5:31', title: 'Block A: Confirm the depth' }],
        records: [{ targetId: 'operational_records:42', title: 'Operational: Drawing S-04' }],
        drawings: [{ targetId: 'operational_records:42', title: 'Drawing S-04' }],
      }) };
      return { ok: true, json: async () => window.__cardData };
    }`, ctx);
  vm.runInContext(extract([
    '_wcFmtDate', '_wcTypeOf', '_wcUnitText', '_wcStagesOf', '_wcHistoryText',
    '_wcCardHeaderHtml', '_wcCardTilesHtml', '_wcFilesHtml', '_wcRenderTaskCardExtras', '_wcOpenInternalTaskLink',
  ]), ctx);
  dom.window.__navigation = [];
  dom.window.__task = { ...task, activity_title: 'Excavation' };
  await vm.runInContext(`_wcRenderTaskCardExtras(window.__task, document.getElementById('card'), true, [])`, ctx);
  const d = dom.window.document;
  assert.equal(d.querySelectorAll('[data-card-operation="link-open"]').length, 3);
  assert.ok(d.querySelector('[data-wc-tab="attachments"]'));
  assert.ok(d.querySelector('[data-wc-pane="attachments"] input[type="file"][multiple]'));
  assert.equal(d.querySelector('a[href="https://example.test/spec"]')?.textContent, 'External spec');
  const typeSelect = d.querySelector('[data-card-field="link-type"]');
  const targetSelect = d.querySelector('[data-card-field="link-target"]');
  assert.equal(targetSelect.options[1].value, '22');
  typeSelect.value = 'query';
  typeSelect.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
  assert.equal(targetSelect.options[1].value, '5:31');
  typeSelect.value = 'drawing';
  typeSelect.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
  assert.equal(targetSelect.options[1].value, 'operational_records:42');
  const report = d.createElement('details');
  report.setAttribute('data-wc-report-card', '');
  const queryCard = d.createElement('article');
  queryCard.id = 'wc-query-31';
  report.appendChild(queryCard);
  d.getElementById('wc-detail-5').appendChild(report);
  const reportsTab = d.createElement('button');
  reportsTab.setAttribute('data-wc-tab', 'reports');
  d.getElementById('wc-detail-5').appendChild(reportsTab);
  assert.equal(await vm.runInContext(`_wcOpenInternalTaskLink('task', '22')`, ctx), true);
  assert.equal(await vm.runInContext(`_wcOpenInternalTaskLink('record', 'operational_records:42')`, ctx), true);
  assert.equal(await vm.runInContext(`_wcOpenInternalTaskLink('query', '5:31')`, ctx), true);
  assert.deepEqual(JSON.parse(JSON.stringify(dom.window.__navigation)), [
    ['work_center_task', '22'], ['operational_records', '42'], ['work_center_task', '5'],
  ]);
});

test('expanded standalone task does not show a task-level query tab', () => {
  const d = views().tabbed({ ...task, activity_id: null, activity_title: null }, [], [], false);
  assert.equal(d.querySelector('[data-wc-pane="queries"]'), null);
  assert.match(d.body.textContent, /Task plan/);
});

test('leader reports default to All when there are no pending reports', () => {
  const stalePending = views();
  stalePending.saveReportFilter(task.id, 'pending');
  const d = stalePending.tabbed(task, [{ ...entries[1], validation_status: 'approved' }], [], true);
  assert.equal(d.querySelector('[data-report-filter="all"]').getAttribute('aria-pressed'), 'true');
  assert.equal(d.querySelector('[data-report-filter="pending"]').getAttribute('aria-pressed'), 'false');
  assert.equal(d.querySelector('[data-wc-report-card][data-report-status="approved"]').hidden, false);

  const withPending = views().tabbed(task, entries, [], true);
  assert.equal(withPending.querySelector('[data-report-filter="pending"]').getAttribute('aria-pressed'), 'true');
  assert.equal(withPending.querySelector('[data-wc-report-card][data-report-status="approved"]').hidden, true);
});

test('questions without a matching report appear in Other questions for leaders and members', () => {
  const questions = [
    { id: 31, report_id: null, question: 'Unlinked question', status: 'open', created_at: '2026-03-10' },
    { id: 32, report_id: 999, question: 'Question for a deleted report', status: 'answered', created_at: '2026-03-11' },
    { id: 33, report_id: 2, question: 'Question about a visible report', status: 'answered', created_at: '2026-03-12' },
  ];
  for (const leader of [true, false]) {
    const d = views().tabbed(task, [entries[1]], questions, leader);
    const paneKey = leader ? 'reports' : 'my-reports';
    const orphanPanel = d.querySelector(`[data-wc-pane="${paneKey}"] [data-wc-orphan-queries]`);
    assert.ok(orphanPanel);
    assert.match(orphanPanel.textContent, /Other questions \(2\)/);
    assert.match(orphanPanel.textContent, /Unlinked question/);
    assert.match(orphanPanel.textContent, /Question for a deleted report/);
    assert.equal(orphanPanel.querySelector('#wc-query-33'), null);
    assert.ok(d.querySelector('[data-wc-report-queries="2"] #wc-query-33'));
    assert.equal(orphanPanel.querySelector('[data-action="wc-query-create"]'), null);
  }
});

test('expanded member task separates progress and reports; closed task hides progress', () => {
  const d = views().tabbed(task, entries.filter((entry) => entry.member_id === 101), [], false);
  const tabs = [...d.querySelectorAll('[role="tab"]')].map((tab) => tab.getAttribute('data-wc-tab'));
  assert.deepEqual(tabs, ['details', 'progress', 'my-reports']);
  assert.ok(d.querySelector('[data-wc-pane="my-reports"]')?.textContent.includes('My Previous Submissions'));
  assert.equal(d.querySelector('[data-wc-pane="queries"]'), null);
  assert.equal(d.querySelectorAll('[data-wc-report-queries]').length, entries.length);
  assert.match(d.body.textContent, /leader must approve the report before it changes task or activity progress/);
  assert.match(d.body.textContent, /Pending reports are waiting for review/);
  assert.match(d.body.textContent, /Survey stakes/);
  assert.match(d.body.textContent, /Levels checked/);
  assert.ok(d.querySelector('[data-wc-pane="progress"]'));

  const closed = views().tabbed({ ...task, status: 'closed' }, [], [], false);
  assert.deepEqual([...closed.querySelectorAll('[role="tab"]')].map((tab) => tab.getAttribute('data-wc-tab')),
    ['details', 'my-reports']);
  assert.equal(closed.querySelector('[data-wc-pane="progress"]'), null);
});
