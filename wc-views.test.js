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

const HELPERS = ['_wcFmtDate', '_uiLabelStyle', '_wcReadField', '_wcLabel', '_wcInput', '_wcStatusBadgeHtml', '_wcDeriveStatus', '_wcActivityStatusBadge',
  'wcPriorityBadge', '_wcMemberView', '_wcPMView', '_wcTypeOf', '_wcUnitText', '_wcStagesOf', '_wcTaskShareHtml',
  '_wcReportFieldsHtml', '_wcEntryFigure', '_wcTaskSummaryHtml', '_wcActivityPlanHtml', '_wcPlanRow', '_wcQueryPanelHtml', '_wcTabifyDetail'];

function views() {
  const dom = new JSDOM('<!doctype html><body></body>', { runScripts: 'outside-only', url: 'http://localhost/' });
  const ctx = dom.getInternalVMContext();
  vm.runInContext(`function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }`, ctx);
  vm.runInContext(extract(HELPERS), ctx);
  vm.runInContext(`function tabbed(task, entries, queries, leader) {
    document.body.innerHTML = leader ? _wcPMView(task, entries) : _wcMemberView(task, entries);
    _wcTabifyDetail(document.body, task, entries, queries, leader, true);
    return document;
  }`, ctx);
  const render = (fn, task, entries) => { dom.window.__t = task; dom.window.__e = entries; dom.window.document.body.innerHTML = vm.runInContext(`${fn}(window.__t, window.__e)`, ctx); return dom.window.document; };
  return {
    formatDate: (value) => { dom.window.__date = value; return vm.runInContext('_wcFmtDate(window.__date)', ctx); },
    member: (t, e) => render('_wcMemberView', t, e),
    leader: (t, e) => render('_wcPMView', t, e),
    tabbed: (t, e, q, leader) => { dom.window.__t = t; dom.window.__e = e; dom.window.__q = q; return vm.runInContext(`tabbed(window.__t, window.__e, window.__q, ${leader})`, ctx); },
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
  assert.match(d.body.textContent, /Measured wrongly/);
  assert.match(d.body.textContent, /40 m3/);
  assert.match(d.body.textContent, /Share of the activity 50%/);
});

test('leader view: no void button once the task is closed', () => {
  const d = views().leader({ ...task, status: 'closed' }, entries);
  assert.equal([...d.querySelectorAll('[data-validate-action="voided"]')].length, 0);
});

test('expanded leader task uses summary and Details, Reports, Queries tabs with the activity plan', () => {
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
    ['Details', 'Reports', 'Queries']);
  const summary = d.querySelector('[data-wc-card-summary]');
  assert.match(summary.textContent, /Progress/);
  assert.doesNotMatch(summary.textContent, /Excavate trenches|Created by|High|Ongoing|Start Date/);
  const details = d.querySelector('#wc-read-5').textContent;
  assert.doesNotMatch(details, /Start Date|End Date|Required priority|Excavate trenches/);
  assert.match(d.body.textContent, /20%/);
  assert.doesNotMatch(d.body.textContent, /Required priorityHigh/);
  assert.match(d.body.textContent, /How to read this task/);
  assert.match(d.body.textContent, /approved reports measured as quantity/);
  assert.match(d.body.textContent, /Review each submission’s work description/);
  assert.match(d.body.textContent, /Materials/);
  assert.match(d.body.textContent, /Marker paint/);
  assert.match(d.body.textContent, /North trench completed/);
  assert.match(d.body.textContent, /Foundation/);
  assert.match(d.body.textContent, /Formation levels confirmed/);
  assert.match(d.body.textContent, /Planned manpower6 workers/);
  assert.match(d.body.textContent, /Please explain the measurement/);
  assert.match(d.body.textContent, /Progress report/);
  assert.match(d.body.textContent, /Choose a report/);
  assert.match(d.querySelector('#wc-query-report-5').textContent, /a@x/);
  assert.equal(d.querySelector('#wc-query-member-5'), null);
  assert.match(d.body.textContent, /Dug more/);
  assert.match(d.body.textContent, /A query and its answer are kept with the task/);
  assert.ok(d.querySelector('[data-wc-pane="reports"]'));
  assert.ok(d.querySelector('[data-wc-pane="queries"]'));
});

test('expanded standalone task explains its progress source without implying an activity link', () => {
  const d = views().tabbed({ ...task, activity_id: null, activity_title: null }, [], [], false);
  assert.match(d.body.textContent, /This is a standalone task and is not included in an activity/);
  assert.match(d.body.textContent, /approved reports measured as quantity/);
});

test('expanded member task separates progress, previous reports and queries; closed task hides progress', () => {
  const d = views().tabbed(task, entries.filter((entry) => entry.member_id === 101), [], false);
  const tabs = [...d.querySelectorAll('[role="tab"]')].map((tab) => tab.getAttribute('data-wc-tab'));
  assert.deepEqual(tabs, ['details', 'progress', 'my-reports', 'queries']);
  assert.ok(d.querySelector('[data-wc-pane="my-reports"]')?.textContent.includes('My Previous Submissions'));
  assert.match(d.body.textContent, /leader must approve the report before it changes task or activity progress/);
  assert.match(d.body.textContent, /Pending reports are waiting for review/);
  assert.match(d.body.textContent, /Survey stakes/);
  assert.match(d.body.textContent, /Levels checked/);
  assert.ok(d.querySelector('[data-wc-pane="progress"]'));

  const closed = views().tabbed({ ...task, status: 'closed' }, [], [], false);
  assert.deepEqual([...closed.querySelectorAll('[role="tab"]')].map((tab) => tab.getAttribute('data-wc-tab')),
    ['details', 'my-reports', 'queries']);
  assert.equal(closed.querySelector('[data-wc-pane="progress"]'), null);
});
