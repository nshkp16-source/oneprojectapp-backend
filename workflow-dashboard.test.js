import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const html = fs.readFileSync(new URL('../frontend/dashboard.html', import.meta.url), 'utf8');
const marker = '// Activity reports, review, verification and milestone controls for the dashboard.';
const sourceStart = html.indexOf(marker);
assert.notEqual(sourceStart, -1, 'integrated workflow script not found in dashboard.html');
const sourceEnd = html.indexOf('</script>', sourceStart);
assert.notEqual(sourceEnd, -1, 'integrated workflow script is not closed');
const source = html.slice(sourceStart, sourceEnd);
const queryHandlerStart = html.indexOf('async function _openTaskQueryNotification');
const queryHandlerEnd = html.indexOf('async function _openActivityVerificationNotification', queryHandlerStart);
assert.ok(queryHandlerStart >= 0 && queryHandlerEnd > queryHandlerStart, 'task-query notification handler not found');
const queryHandler = html.slice(queryHandlerStart, queryHandlerEnd);

function setup({ legacyActivityCard = true, queryNotification = null } = {}) {
  const window = {
    _wcMemberView: () => '<div>legacy member</div>',
    _wcPMView: () => '<div>legacy leader</div>',
    _wcWireDetailButtons: () => {},
  };
  window.__activityCalls = {};
  if (legacyActivityCard) {
    window._peActivityCardHtml = (_card, verificationData = { verifications: [], rework: [] }, selectedTab = 'overview') => {
      if (!verificationData || !Array.isArray(verificationData.verifications))
        throw new TypeError('verification data is required');
      window.__activityCalls.html = [_card, verificationData, selectedTab];
      return '<main><div data-pe-pane="overview"></div></main>';
    };
    window._peWireActivityCard = (...args) => { window.__activityCalls.wire = args; };
  }
  const context = {
    window,
    document: { getElementById: () => null },
    escapeHtml: (value) => String(value).replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[char]),
  };
  if (queryNotification) {
    const report = queryNotification.query.report_id
      ? { open: false }
      : null;
    const queryCard = {
      closest: (selector) => selector === '[data-wc-report-card]' ? report : null,
      scrollIntoView: () => { window.__queryNotificationLog.scrolled = true; },
    };
    window.__queryNotificationLog = { report, selectedTab: null, scrolled: false };
    Object.assign(context, {
      API: '/api',
      URLSearchParams,
      localStorage: { getItem: () => '7' },
      sessionStorage: { setItem: (key, value) => { window.__queryNotificationLog[key] = value; } },
      CSS: { escape: (value) => String(value) },
      isWCLeader: () => queryNotification.leader,
      authFetch: async (url) => ({
        ok: true,
        json: async () => url.includes('/notifications/target')
          ? { target: { recordId: 5 } }
          : { queries: [queryNotification.query] },
      }),
      _openRecordNotification: async () => true,
      _waitForElement: async (selector) => selector.includes(`#wc-query-${queryNotification.query.id}`) ? queryCard : null,
    });
    context.document.querySelector = (selector) => ({
      click: () => { window.__queryNotificationLog.selectedTab = selector; },
    });
    window.__runTaskQueryNotification = () =>
      vm.runInContext(`_openTaskQueryNotification(${JSON.stringify(queryNotification.query.id)})`, context);
  }
  vm.createContext(context);
  vm.runInContext(source, context);
  if (queryNotification) vm.runInContext(queryHandler, context);
  return window;
}

test('merged workflow leaves task view rendering to dashboard.html', () => {
  const window = setup();
  assert.equal(window._wcMemberView(), '<div>legacy member</div>');
});

test('integrated workflow does not replace task views or add a correction audit', () => {
  const window = setup();
  assert.equal(window._wcPMView(), '<div>legacy leader</div>');
  assert.doesNotMatch(source, /Correction audit/);
  assert.doesNotMatch(source, /window\._wcMemberView\s*=/);
  assert.doesNotMatch(source, /window\._wcPMView\s*=/);
  assert.doesNotMatch(source, /window\._wcWireDetailButtons\s*=/);
});

test('workflow code is inline and dashboards do not load a script from the backend folder', () => {
  assert.match(html, /window\.downloadCloseoutReport/);
  assert.doesNotMatch(html, /<script src=["']\.\/backend\/workflow-dashboard\.js/);
});

test('task-query notifications open the linked report instead of a removed Queries tab', () => {
  const start = html.indexOf('async function _openTaskQueryNotification');
  const end = html.indexOf('async function _openActivityVerificationNotification', start);
  assert.ok(start >= 0 && end > start);
  const handler = html.slice(start, end);
  assert.match(handler, /#wc-query-\$\{CSS\.escape\(String\(queryId\)\)\}/);
  assert.match(handler, /queryCard\.closest\('\[data-wc-report-card\]'\)/);
  assert.doesNotMatch(handler, /if \(!query\?\.report_id\) return false/);
  assert.doesNotMatch(handler, /data-wc-tab="queries"|setItem\([^;]*'queries'/);
});

test('task-query notifications open both linked and unlinked questions', async () => {
  for (const reportId of [42, null]) {
    const window = setup({
      queryNotification: {
        leader: true,
        query: { id: 31, report_id: reportId },
      },
    });
    assert.equal(await window.__runTaskQueryNotification(), true);
    assert.match(window.__queryNotificationLog.selectedTab, /data-wc-tab="reports"/);
    assert.equal(window.__queryNotificationLog.scrolled, true);
    assert.equal(window.__queryNotificationLog.report?.open ?? false, Boolean(reportId));
  }
});

test('voiding uses the reason field in the expanded report instead of a prompt', () => {
  const start = html.indexOf('async function _wcHandleValidate');
  const end = html.indexOf('async function _wcHandleDelete', start);
  assert.ok(start >= 0 && end > start);
  const handler = html.slice(start, end);
  assert.match(handler, /validateAction === 'voided'/);
  assert.match(handler, /Enter a reason for voiding this report/);
  assert.doesNotMatch(handler, /prompt\(/);
});

test('activity workflow does not append duplicate verification controls to the tabbed card', () => {
  const window = setup();
  const client = window._peActivityCardHtml({
    viewer_side: 'Client',
    activity: { id: 1, side: 'Contractor' },
    tasks: [],
  });
  assert.equal(client, '<main><div data-pe-pane="overview"></div></main>');

  const html = window._peActivityCardHtml({
    viewer_side: 'Contractor',
    can_add_task: true,
    activity: { id: 2, side: 'Contractor', baseline_milestone_id: 3 },
    tasks: [{ stages: [{ id: 7, title: 'Inspection', is_hold_point: true }] }],
  });
  assert.equal(html, '<main><div data-pe-pane="overview"></div></main>');
  assert.doesNotMatch(html, /wf-activity-controls|Request verification/);
});

test('activity workflow preserves verification data and card arguments', () => {
  const window = setup();
  const card = { can_edit_activity: false, activity: { id: 8 } };
  const verificationData = { verifications: [{ id: 21 }], rework: [{ id: 22 }] };
  const cachedRecord = { id: 8, side: 'Contractor' };
  const html = window._peActivityCardHtml(card, verificationData, 'certification');
  assert.equal(html, '<main><div data-pe-pane="overview"></div></main>');
  assert.deepEqual(window.__activityCalls.html, [card, verificationData, 'certification']);

  window._peWireActivityCard(8, card, cachedRecord, verificationData);
  assert.deepEqual(window.__activityCalls.wire, [8, card, cachedRecord, verificationData]);
});

test('activity plan editing stays inside the Overview tab for its creator', () => {
  const window = setup();
  const html = window._peActivityCardHtml({
    can_edit_activity: true,
    activity: { id: 2, title: 'Excavate', start_date: '2026-03-01', end_date: '2026-03-15', activity_type: 'quantity' },
  });
  assert.match(html, /data-pe-pane="overview"/);
  assert.match(html, /Edit activity plan/);
  assert.doesNotMatch(window._peActivityCardHtml({
    can_edit_activity: false,
    activity: { id: 2 },
  }), /Edit activity plan/);
});

test('pending verification navigation uses the activity card instead of a modal', () => {
  const start = source.indexOf('window.openPendingVerifications =');
  const end = source.indexOf('window.downloadCloseoutReport =', start);
  assert.ok(start >= 0 && end > start);
  const pendingWorkflow = source.slice(start, end);
  assert.match(pendingWorkflow, /_openActivityVerificationNotification/);
  assert.match(pendingWorkflow, /expandGrayPart/);
  assert.doesNotMatch(pendingWorkflow, /position:fixed|document\.createElement\('div'\)/);
});

test('close-out download is limited to project-side leaders and PMs and names the selected side', () => {
  assert.match(source, /\['Contractor', 'Consultant', 'Client', 'ContractorPM', 'ConsultantPM', 'ClientPM',\s*'Contractor Project Manager', 'Consultant Project Manager', 'Client Project Manager'\]\.includes\(window\.currentUserRole\)/);
  assert.match(source, /only project-side leaders and project managers can download this report/i);
  assert.match(source, /oneproject-closeout-\$\{side\}-\$\{projectId\}\.csv/);
  assert.doesNotMatch(source, /audience = wcSide\(window\.currentUserRole\) === 'Client'/);
});

test('activity cards also render when the deployed dashboard has no legacy card renderer', () => {
  const window = setup({ legacyActivityCard: false });
  const contractorCard = window._peActivityCardHtml({
    viewer_side: 'Contractor',
    can_add_task: true,
    activity: {
      id: 3,
      side: 'Contractor',
      title: 'Excavation',
      activity_type: 'quantity',
      claimed_progress_pct: 35,
      certified_progress_pct: 20,
      start_date: '2026-03-01',
      end_date: '2026-03-30',
    },
    tasks: [{ title: 'Block A', weight_pct: 100, progress_pct: 35, target_quantity: 400 }],
  });
  assert.match(contractorCard, /Excavation/);
  assert.match(contractorCard, /Block A/);
  assert.match(contractorCard, /35%/);
  assert.match(contractorCard, /Certified <strong/);
  assert.match(contractorCard, /Add task/);

  const clientCard = window._peActivityCardHtml({
    viewer_side: 'Client',
    activity: { id: 3, title: 'Excavation', side: 'Contractor', certified_progress_pct: 20, claimed_progress_pct: 35 },
    tasks: [{ title: 'Private task', weight_pct: 100 }],
  });
  assert.match(clientCard, /Certified progress/);
  assert.doesNotMatch(clientCard, /Private task|Claimed/);
});
