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
'wcPriorityBadge', '_wcMemberView', '_wcPMView', '_wcTypeOf', '_wcTodayDate', '_wcUnitText', '_wcStagesOf', '_wcTaskShareHtml',
  '_wcReportFieldsHtml', '_wcEntryFigure', '_wcReportExtraHtml', '_wcTaskSummaryHtml', '_wcActivityPlanHtml', '_wcPlanRow',
  '_wcInitReportWizard',
  '_wcEnhanceReports', '_wcOpenReportPanel', '_wcBeginReportEdit', '_wcResetReportEdit', '_wcDeleteReport',
  '_wcHandleSubmitProgress',
  '_supportingAttachmentTypeOptions', '_supportingAttachmentTypeLabel', '_wcUpdateSupportingAttachmentGroup', '_wcSupportingAttachmentGroupHtml',
  '_wcReportSupportingAttachmentsHtml', '_wcFilesHtml', '_wcQueryPanelHtml', '_wcTabifyDetail',
  '_wcCollectTaskFiles', '_wcInitTaskFiles', '_wcOpenTaskFilesViewer',
  '_wcOpenOfflineReportDb', '_wcQueueOfflineTaskAttachments',
  '_wcDownloadTaskPdf',
  '_wcCardHeaderHtml', '_wcCardTilesHtml',
  '_wcHistoryText',
  '_safeHttpsUrl', '_fileDisplayName', '_thumbUrl', '_evidenceFileAttrs', '_evidenceFileRowHtml', '_evidencePhotosHtml', '_evidenceFilesHtml'];

function views() {
  const dom = new JSDOM('<!doctype html><body></body>', { runScripts: 'outside-only', url: 'http://localhost/' });
  const ctx = dom.getInternalVMContext();
  vm.runInContext(`const CSS = { escape: (value) => String(value) };
  const API = '/api';
  var recordsCache = {};
  window.__wcFetches = [];
  window.__wcAlerts = [];
  window._wcReportLocationByTask = {};
  async function ensureActiveProjectId() { return '9'; }
  async function _wcFetch(url, options) {
    window.__wcFetches.push({ url, options });
    return { ok: true, json: async () => ({}) };
  }
  async function _wcReadPhotoMetadata() { return {}; }
  async function _wcRefreshTaskCard() {}
  function _wcSetTaskCardMessage() {}
  async function _wcQueueOfflineReport() {}
  window.alert = (message) => window.__wcAlerts.push(message);
  function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }`, ctx);
  vm.runInContext(`function expandGrayPart(html) {
    const panel = document.createElement('div'); panel.id = 'grayContent'; panel.innerHTML = html;
    document.body.appendChild(panel);
  }
  function collapseGrayPart() { document.getElementById('grayContent')?.remove(); }
  HTMLElement.prototype.scrollIntoView = function() {};`, ctx);
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
    w: dom.window,
    formatDate: (value) => { dom.window.__date = value; return vm.runInContext('_wcFmtDate(window.__date)', ctx); },
    history: (item) => {
      dom.window.__historyItem = item;
      return vm.runInContext('_wcHistoryText(window.__historyItem)', ctx);
    },
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
    openFilesViewer: (files, index, taskId) => {
      dom.window.__files = files; dom.window.__fileIndex = index; dom.window.__taskId = taskId;
      vm.runInContext('_wcOpenTaskFilesViewer(window.__files, window.__fileIndex, window.__taskId)', ctx);
      return dom.window.document;
    },
    tabbed: (t, e, q, leader) => { dom.window.__t = t; dom.window.__e = e; dom.window.__q = q; return vm.runInContext(`tabbed(window.__t, window.__e, window.__q, ${leader})`, ctx); },
    saveReportFilter: (taskId, filter) => { dom.window.__taskId = taskId; dom.window.__filter = filter; vm.runInContext('saveReportFilter(window.__taskId, window.__filter)', ctx); },
    submitProgress: (taskId) => {
      dom.window.__submitTaskId = taskId;
      return vm.runInContext('_wcHandleSubmitProgress(window.__submitTaskId, "reports")', ctx);
    },
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

test('report edit and delete history shows only the short summary', () => {
  const view = views();
  for (const action of ['report_edited', 'report_deleted']) {
    const text = view.history({
      action, detail: { summary: '2 m3 on 11 Mar, rejected: photo was unclear.' },
    });
    assert.match(text, /2 m3 on 11 Mar/);
    assert.match(text, /Summary only/);
    assert.doesNotMatch(text, /work done|file name/i);
  }
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
  assert.deepEqual(actions(1), ['approved', 'rejected']);
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

test('expanded leader task uses Overview and Reports tabs, with summary first and queries inside their report', () => {
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
    ['Overview', 'Reports']);
  const summary = d.querySelector('[data-wc-card-summary]');
  assert.ok(summary);
  assert.equal(summary.parentElement.getAttribute('data-wc-pane'), 'overview');
  assert.equal(summary.parentElement.firstElementChild, summary);
  assert.match(summary.textContent, /Approved/);
  assert.match(summary.textContent, /Pending/);
  assert.match(summary.textContent, /Quantity/);
  const details = d.querySelector('#wc-read-5').textContent;
  assert.doesNotMatch(details, /Start Date|End Date|Required priority|Excavate trenches/);
  assert.doesNotMatch(d.body.textContent, /Required priorityHigh/);
  assert.doesNotMatch(d.body.textContent, /How to read this task/);
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
  assert.equal(d.querySelector('[data-wc-report-card][data-report-status="pending"]').hidden, false);
  assert.equal(d.querySelector('[data-wc-report-card][data-report-status="approved"]').hidden, true);
  assert.ok(d.querySelector('[data-wc-report-row][data-report-id="2"]'));
  assert.equal(d.querySelector('[data-report-filter]'), null);
});

test('Reports tab keeps pending cards open and turns other reports into newest-first rows', () => {
  const d = views().tabbed(task, entries, [], true);
  const pendingCard = d.querySelector('[data-wc-report-card][data-report-status="pending"]');
  assert.equal(pendingCard.hidden, false);
  const rejectionReason = pendingCard.querySelector('#wc-val-notes-1');
  assert.equal(rejectionReason.hidden, true);
  const reject = pendingCard.querySelector('[data-validate-action="rejected"]');
  reject.click();
  assert.equal(rejectionReason.hidden, false);
  assert.equal(reject.textContent, 'Confirm rejection');
  assert.equal(d.querySelector('[data-wc-report-row][data-report-id="2"]').hidden, false);
  assert.equal(d.querySelector('[data-wc-report-row][data-report-id="3"]').hidden, false);
  assert.deepEqual([...d.querySelectorAll('[data-wc-report-row]')].map((row) => row.dataset.reportId), ['2', '3']);
  assert.match(d.querySelector('[data-wc-report-row][data-report-id="2"]').textContent, /Running total: 30 m3/);
  assert.match(d.querySelector('[data-wc-report-row][data-report-id="3"]').textContent, /Running total: 30 m3/);
  assert.equal(d.querySelector('[data-wc-report-row][data-report-id="3"]').style.opacity, '0.75');
});

test('member sees edit and delete only on open pending or rejected reports, with the locked note on approved', () => {
  const memberEntries = [
    { ...entries[0], validation_status: 'pending' },
    { ...entries[1], id: 4, validation_status: 'rejected', validation_notes: 'Add a clear photo.' },
    { ...entries[1], id: 5, validation_status: 'approved' },
    { ...entries[2], id: 6, validation_status: 'voided' },
  ];
  const d = views().tabbed(task, memberEntries, [], false);
  for (const id of ['1', '4']) {
    const card = d.querySelector(`[data-wc-report-card][data-report-id="${id}"]`);
    assert.equal(card.hidden, false);
    assert.ok(card.querySelector(`[data-action="wc-edit-progress"][data-progress-id="${id}"]`));
    assert.ok(card.querySelector(`[data-action="wc-delete-progress"][data-progress-id="${id}"]`));
  }
  for (const id of ['5', '6']) {
    const card = d.querySelector(`[data-wc-report-card][data-report-id="${id}"]`);
    assert.equal(card.hidden, true);
    assert.equal(card.querySelector('[data-action="wc-edit-progress"]'), null);
    assert.equal(card.querySelector('[data-action="wc-delete-progress"]'), null);
  }
  assert.match(d.querySelector('[data-wc-report-card][data-report-id="5"]').textContent,
    /Approved reports are locked\. If one is wrong, ask your leader to void it\./);
  assert.deepEqual([...d.querySelectorAll('[data-wc-report-row]')].map((row) => row.dataset.reportId), ['5', '6']);
});

test('member report form assigns the report date automatically instead of asking for a date', () => {
  const d = views().tabbed(task, [], [], false);
  assert.equal(d.querySelector('[data-wc-pane="record-progress"] input[id^="wc-pr-date-"]'), null);
  assert.match(d.querySelector('[data-wc-pane="record-progress"]').textContent,
    /Report date is recorded automatically when you submit/);
});

test('rejected edit pre-fills the wizard and shows its leader note and exact history notice', () => {
  const rejected = { ...entries[1], id: 4, validation_status: 'rejected', validation_notes: 'Add a clear photo.' };
  const d = views().tabbed(task, [rejected], [], false);
  d.querySelector('[data-action="wc-edit-progress"][data-progress-id="4"]').click();
  const wizard = d.querySelector('[aria-label="Add progress report"]');
  const notice = wizard.querySelector('[data-wc-report-edit-notice]');
  assert.equal(notice.hidden, false);
  assert.match(notice.textContent, /Leader note: Add a clear photo\./);
  assert.match(notice.textContent, /Saving replaces the rejected report completely\. The old version is kept in History as a short summary only\./);
  assert.equal(d.querySelector('[data-action="wc-submit-progress"]').textContent, 'Save and resubmit');
  assert.equal(d.getElementById('wc-pr-work-5').value, 'Dug more');
});

test('saving an edited report PATCHes it and sends the selected existing-file IDs', async () => {
  const s = views();
  const d = s.tabbed(task, [{ ...entries[0], id: 8, validation_status: 'rejected' }], [], false);
  d.body.id = 'wc-detail-5';
  s.w.recordsCache['work-center'] = [task];
  s.w._wcEditingReportByTask = { 5: { id: '8', status: 'rejected', reportDate: '2026-03-10' } };
  d.getElementById('wc-pr-work-5').value = 'Revised work';
  d.getElementById('wc-pr-qty-5').value = '8';
  const files = d.querySelector('[data-wc-existing-report-files]');
  files.innerHTML = `<input type="checkbox" data-wc-keep-photo="31" checked>
    <input type="checkbox" data-wc-keep-supporting="41" checked>
    <input type="checkbox" data-wc-keep-attachment>`;

  await s.submitProgress(5);

  assert.deepEqual([...s.w.__wcAlerts], []);
  assert.equal(s.w.__wcFetches.length, 1);
  const request = s.w.__wcFetches[0];
  assert.equal(request.url, '/api/work-center-progress/8');
  assert.equal(request.options.method, 'PATCH');
  assert.equal(request.options.body.get('reportDate'), '2026-03-10');
  assert.equal(request.options.body.get('workDone'), 'Revised work');
  assert.equal(request.options.body.get('keepPhotoIds'), '[\"31\"]');
  assert.equal(request.options.body.get('keepSupportingAttachmentIds'), '[\"41\"]');
  assert.equal(request.options.body.get('removeAttachment'), 'true');
});

test('Reports tab pages ten rows and opens a full report in the existing side panel', () => {
  const many = Array.from({ length: 12 }, (_, index) => ({
    ...entries[1], id: index + 10, report_date: `2026-03-${String(index + 1).padStart(2, '0')}`,
    validation_status: 'approved', quantity_done: String(index + 1), work_done: `Approved work ${index + 1}`,
  }));
  const d = views().tabbed(task, many, [], true);
  const rows = [...d.querySelectorAll('[data-wc-report-row]')];
  assert.equal(rows.filter((row) => !row.hidden).length, 10);
  const loadMore = [...d.querySelectorAll('button')].find((button) => button.textContent === 'Load more reports');
  assert.ok(loadMore);
  loadMore.click();
  assert.equal(rows.filter((row) => !row.hidden).length, 12);
  rows[0].click();
  const panel = d.querySelector('#grayContent');
  assert.ok(panel);
  assert.equal(panel.querySelector('[data-wc-report-card]').hidden, false);
  assert.match(panel.textContent, /Approved work 12/);
});

test('task card has the three-cell Progress, Planned today and Due strip', () => {
  const taskTotals = {
    ...task, progress_pct: 35, pending_report_count: 2, total_report_count: 5,
    approved_quantity_done: 70,
  };
  const d = views().cardTiles(taskTotals, [
    { validation_status: 'approved', quantity_done: 30 },
    { validation_status: 'pending', quantity_done: 40 },
  ]);
  const text = d.body.textContent.replace(/\s+/g, ' ');
  assert.match(text, /Progress 35\.0%/);
  assert.match(text, /70 of 200 m3 approved/);
  assert.match(text, /Planned today/);
  assert.match(text, /Ahead by|Behind by|On plan/);
  assert.match(text, /Due/);
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

test('Files tab shows task and report files in one grid and offers upload controls to leaders', () => {
  const d = views().attachments(
    { ...task, linked_file_name: 'legacy.pdf' },
    [{ id: 2, attachment_name: 'report.jpg', report_date: '2026-03-10' }],
    [{ id: 9, file_name: 'drawing.dwg', file_url: 'https://files.test/drawing.dwg' }],
    true,
  );
  assert.match(d.body.textContent, /legacy\.pdf/);
  assert.match(d.body.textContent, /drawing\.dwg/);
  assert.match(d.body.textContent, /report\.jpg/);
  assert.equal(d.querySelectorAll('[data-wc-file-index]').length, 3);
  assert.ok(d.querySelector('[data-wc-attachment-input][multiple]'));
  assert.ok(d.querySelector('[data-wc-attachment-choose]'));
  assert.match(d.body.textContent, /Upload size limit is unavailable/);
});

test('task file viewer navigates between files and previews PDFs inline', () => {
  const d = views().openFilesViewer([
    { id: 1, name: 'photo.jpg', file_url: 'https://files.test/photo.jpg', mime_type: 'image/jpeg', source: 'Uploaded here', date: '2026-03-10' },
    { id: 2, name: 'plan.pdf', file_url: 'https://files.test/plan.pdf', mime_type: 'application/pdf', source: 'From report 11 Mar', date: '2026-03-11' },
  ], 0, 5);
  const modal = d.getElementById('wc-task-file-viewer');
  assert.equal(modal.querySelector('[data-wc-viewer-count]').textContent, '1 of 2');
  modal.querySelector('[data-wc-viewer-next]').click();
  assert.equal(modal.querySelector('[data-wc-viewer-count]').textContent, '2 of 2');
  assert.equal(modal.querySelector('[data-wc-viewer-content] iframe').title, 'plan.pdf');
  modal.querySelector('[data-wc-viewer-prev]').click();
  assert.equal(modal.querySelector('[data-wc-viewer-count]').textContent, '1 of 2');
});

test('task files are persisted in the existing offline database', async () => {
  const d = views();
  const stores = new Set();
  const records = new Map();
  let openedVersion;
  const db = {
    objectStoreNames: { contains: (name) => stores.has(name) },
    createObjectStore: (name) => stores.add(name),
    transaction: (name) => ({
      objectStore: () => ({
        put: (record) => {
          assert.equal(name, 'attachments');
          records.set(record.key, record);
          const request = {};
          queueMicrotask(() => request.onsuccess?.());
          return request;
        },
      }),
    }),
    close() {},
  };
  Object.defineProperty(d.w, 'indexedDB', {
    configurable: true,
    value: {
      open: (_name, version) => {
        openedVersion = version;
        const request = { result: db };
        queueMicrotask(() => {
          request.onupgradeneeded?.();
          request.onsuccess?.();
        });
        return request;
      },
    },
  });
  const file = new d.w.Blob(['image-data'], { type: 'image/jpeg' });
  Object.defineProperty(file, 'name', { value: 'site.jpg' });
  await d.w._wcQueueOfflineTaskAttachments(12, 9, [file]);
  assert.equal(openedVersion, 2);
  assert.ok(stores.has('reports'));
  assert.ok(stores.has('attachments'));
  const [record] = records.values();
  assert.equal(record.taskId, '12');
  assert.equal(record.projectId, '9');
  assert.equal(record.files[0].fileName, 'site.jpg');
  assert.equal(record.files[0].fileType, 'image/jpeg');
  assert.equal(record.files[0].blob, file);
});

test('task summary PDF is one page and pending reports do not count', async () => {
  const d = views();
  const pdfText = [];
  let pageCount = 0;
  const font = { widthOfTextAtSize: (text, size) => String(text).length * size * 0.5 };
  const page = {
    drawText: (text) => pdfText.push(String(text)),
    drawLine() {},
    drawRectangle() {},
    drawImage() {},
  };
  d.w.PDFLib = {
    PDFDocument: {
      create: async () => ({
        addPage: () => { pageCount++; return page; },
        embedFont: async () => font,
        save: async () => new Uint8Array([1, 2, 3]),
      }),
    },
    StandardFonts: { Helvetica: 'Helvetica', HelveticaBold: 'HelveticaBold' },
    rgb: (...values) => values,
  };
  d.w.URL.createObjectURL = () => 'blob:task-pdf';
  d.w.URL.revokeObjectURL = () => {};
  d.w.setTimeout = () => 0;
  d.w.HTMLAnchorElement.prototype.click = function () {};
  d.w.__task = {
    id: 21, title: 'Excavation', activity_type: 'quantity', activity_unit: 'm3',
    activity_id: 3, activity_title: 'Foundation', activity_milestone_title: 'Structure',
    start_date: '2026-03-01', end_date: '2026-04-30', status: 'open',
    progress_pct: 25, target_quantity: 80, approved_quantity_done: 20,
    assigned_members: [{ id: 4, name: 'Taylor' }],
  };
  d.w.__entries = [
    { id: 1, report_date: '2026-03-10', member_title: 'Taylor', quantity_done: 20, validation_status: 'approved' },
    { id: 2, report_date: '2026-03-11', member_title: 'Jordan', quantity_done: 10, validation_status: 'pending' },
  ];
  await d.w._wcDownloadTaskPdf(d.w.__task, d.w.__entries, []);
  assert.equal(pageCount, 1);
  assert.ok(pdfText.includes('Only approved reports count toward progress'));
  assert.ok(pdfText.includes('Not counted'));
  assert.ok(pdfText.includes('Pending review'));
  assert.ok(pdfText.some((text) => text.includes('20 m3')));
});

test('progress report has Photos and optional-type Supporting attachments', () => {
  const view = views();
  const d = view.member(task, entries);
  assert.equal(d.querySelectorAll('input[type="file"]').length, 2);
  assert.ok(d.querySelector(`#wc-pr-photos-${task.id}[multiple][accept="image/*"]`));
  const supportingFiles = [...d.querySelectorAll('input[type="file"]')]
    .find((input) => input.hasAttribute('data-supporting-files'));
  assert.ok(supportingFiles);
  assert.equal(supportingFiles.multiple, true);
  assert.equal(supportingFiles.disabled, false);
  assert.equal(d.querySelector(`#wc-pr-file-${task.id}`), null);
  const group = d.querySelector('[data-wc-supporting-group]');
  assert.ok(group.querySelector('[data-supporting-type]'));
  const customWrap = group.querySelector('[data-supporting-custom-wrap]');
  assert.equal(customWrap.hidden, true);
  assert.equal(customWrap.style.display, 'none');
  assert.ok(customWrap.querySelector('[data-supporting-custom][disabled]'));
  assert.match(group.textContent, /Evidence type \(optional\)/);
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

test('progress submission defaults missing supporting types to General and preserves selected titles', async () => {
  const dom = new JSDOM('<!doctype html><body></body>', { runScripts: 'outside-only', url: 'http://localhost/' });
  const ctx = dom.getInternalVMContext();
  dom.window.__form = null;
  vm.runInContext(`
    const API = '/api';
    const recordsCache = { 'work-center': [{ id: 5, activity_type: 'percentage', end_date: '2026-03-10' }] };
    async function ensureActiveProjectId() { return '1'; }
    function _wcTypeOf(task) { return task.activity_type; }
    function _wcTodayDate() { return '2026-03-12'; }
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
    <input id="wc-pr-pct-5" value="20"/>
    <textarea id="wc-pr-work-5">Installed pipes</textarea>
    <input id="wc-pr-manpower-5"/><input id="wc-pr-equipment-5"/><input id="wc-pr-materials-5"/>
    <input id="wc-pr-issues-5"/><textarea id="wc-pr-notes-5"></textarea>
    <select id="wc-pr-delay-cause-5"><option value=""></option></select><textarea id="wc-pr-delay-note-5"></textarea>
    <input id="wc-pr-photos-5" type="file" multiple/>
    <div data-wc-supporting-groups data-task-id="5">
      <div data-wc-supporting-group><select data-supporting-type><option value="" selected></option></select>
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
    { attachmentType: 'general', customAttachmentType: '' },
    { attachmentType: 'general', customAttachmentType: '' },
    { attachmentType: 'other', customAttachmentType: 'Calibration records' },
  ]);
  assert.equal(body.get('reportDate'), '2026-03-12');
});

test('task creation forms keep ordinary multiple-file inputs without evidence type selectors', () => {
  assert.match(html, /id="wc-cr-attachments" type="file" multiple/);
  assert.match(html, /id="pe2-attachments" type="file" multiple/);
  assert.doesNotMatch(html, /wc-create-attachment-type|wc-card-attachment-type|_appendCardAttachmentType/);
});

test('internal task-card links are buttons and leader choices are selected from project items', async () => {
  const dom = new JSDOM('<!doctype html><body><div id="wc-detail-5"><div id="card"><div role="tablist"></div><div data-wc-pane="overview"></div></div></div></body>',
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
    '_wcCardHeaderHtml', '_wcCardTilesHtml', '_wcCollectTaskFiles', '_wcFilesHtml',
    '_wcInitTaskFiles', '_wcOpenTaskFilesViewer', '_wcRenderTaskCardExtras', '_wcOpenInternalTaskLink',
  ]), ctx);
  dom.window.__navigation = [];
  dom.window.__task = { ...task, activity_title: 'Excavation' };
  await vm.runInContext(`_wcRenderTaskCardExtras(window.__task, document.getElementById('card'), true, [])`, ctx);
  const d = dom.window.document;
  assert.equal(d.querySelectorAll('[data-card-operation="link-open"]').length, 3);
  assert.ok(d.querySelector('[data-wc-tab="files"]'));
  assert.ok(d.querySelector('[data-wc-pane="files"] input[type="file"][multiple]'));
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

test('expanded standalone task uses the new tab set and does not show a task-level query tab', () => {
  const d = views().tabbed({ ...task, activity_id: null, activity_title: null }, [], [], false);
  assert.equal(d.querySelector('[data-wc-pane="queries"]'), null);
  assert.match(d.body.textContent, /Task plan/);
  assert.deepEqual([...d.querySelectorAll('[role="tab"]')].map((tab) => tab.dataset.wcTab),
    ['overview', 'record-progress', 'my-submissions']);
  assert.ok(d.querySelector('[data-wc-pane="record-progress"] [data-action="wc-submit-progress"]'));
  assert.ok(d.querySelector('[data-wc-pane="my-submissions"]'));
});

test('leader reports do not render obsolete status filter chips', () => {
  const stalePending = views();
  stalePending.saveReportFilter(task.id, 'pending');
  const d = stalePending.tabbed(task, [{ ...entries[1], validation_status: 'approved' }], [], true);
  assert.equal(d.querySelector('[data-report-filter]'), null);
  assert.equal(d.querySelector('[data-wc-report-card][data-report-status="approved"]').hidden, true);
  assert.ok(d.querySelector('[data-wc-report-row][data-report-status="approved"]'));

  const withPending = views().tabbed(task, entries, [], true);
  assert.equal(withPending.querySelector('[data-report-filter]'), null);
  assert.equal(withPending.querySelector('[data-wc-report-card][data-report-status="pending"]').hidden, false);
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
    const paneKey = leader ? 'reports' : 'my-submissions';
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

test('expanded member task separates progress recording and submissions; closed task hides progress', () => {
  const d = views().tabbed(task, entries.filter((entry) => entry.member_id === 101), [], false);
  const tabs = [...d.querySelectorAll('[role="tab"]')].map((tab) => tab.getAttribute('data-wc-tab'));
  assert.deepEqual(tabs, ['overview', 'record-progress', 'my-submissions']);
  assert.ok(d.querySelector('[data-wc-pane="record-progress"] [data-action="wc-submit-progress"]'));
  assert.equal(d.querySelector('[data-wc-pane="record-progress"] [data-wc-report-card]'), null);
  assert.ok(d.querySelector('[data-wc-pane="my-submissions"]')?.textContent.includes('My Previous Submissions'));
  assert.equal(d.querySelector('[data-wc-pane="my-submissions"] [data-action="wc-submit-progress"]'), null);
  assert.equal(d.querySelector('[data-wc-pane="queries"]'), null);
  assert.equal(d.querySelectorAll('[data-wc-report-queries]').length, entries.length);
  assert.match(d.body.textContent, /leader must approve the report before it changes task or activity progress/);
  assert.match(d.body.textContent, /Pending reports are waiting for review/);
  assert.match(d.body.textContent, /Survey stakes/);
  assert.match(d.body.textContent, /Levels checked/);
  assert.ok(d.querySelector('[data-wc-pane="my-submissions"]'));

  const closed = views().tabbed({ ...task, status: 'closed' }, [], [], false);
  assert.deepEqual([...closed.querySelectorAll('[role="tab"]')].map((tab) => tab.getAttribute('data-wc-tab')),
    ['overview', 'my-submissions']);
  assert.ok(closed.querySelector('[data-wc-pane="my-submissions"]'));
  assert.equal(closed.querySelector('[data-action="wc-submit-progress"]'), null);
});
