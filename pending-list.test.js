// Runs the Pending verifications list (tabs, search, unread markers, read receipts, history) in a simulated browser.
// Run: node --test pending-list.test.js   (needs: npm i -D jsdom; reads ../frontend/dashboard.html)
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { JSDOM } from 'jsdom';

const html = fs.readFileSync(new URL('../frontend/dashboard.html', import.meta.url), 'utf8');
const start = html.indexOf('// Read receipts: a consultant-side reader');
const end = html.indexOf('window.downloadCloseoutReport = async function');
assert.ok(start > 0 && end > start, 'pending verification list code not found in dashboard.html');
const code = html.slice(start, end);
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const pendingRows = () => [
  { id: 11, activity_title: 'Excavation', kind: 'progress', claimed_progress_pct: 25, activity_certified_progress_pct: 0, respond_by: '2026-11-15',
    days_left: 3, overdue: false, requested_at: '2026-11-08T08:00:00Z', requested_by_role: 'ContractorPM', cut_off_date: '2026-11-08', is_unread: true,
    seen_at: null, activity_summary: { task_count: 2, approved_report_count: 1, approved_quantity: 100, planned_quantity: 400 }, activity_unit: 'm3' },
  { id: 12, activity_title: 'Slab reinforcement', kind: 'hold_point', stage_title: 'Reinforcement', claimed_progress_pct: 60, activity_certified_progress_pct: 40,
    respond_by: '2026-11-06', days_left: -2, overdue: true, requested_at: '2026-11-01T08:00:00Z', requested_by_role: 'ContractorPM', cut_off_date: '2026-11-01',
    is_unread: false, seen_at: '2026-11-03T09:00:00Z', activity_summary: { task_count: 1, approved_report_count: 3, approved_quantity: 40, planned_quantity: 200 } },
];
const historyRows = (n, from = 0) => Array.from({ length: n }, (_, i) => ({
  id: 100 + from + i, activity_title: `Done activity ${from + i}`, kind: 'progress', status: i % 2 ? 'rejected' : 'verified_with_changes',
  claimed_progress_pct: 25, certified_progress_pct: i % 2 ? null : 20, decided_at: '2026-11-07T10:00:00Z', decided_by_role: 'ConsultantPM',
  decision_reason: 'Measured 80 m3 on site', requested_at: '2026-11-05T08:00:00Z', requested_by_role: 'ContractorPM', cut_off_date: '2026-11-05',
  seen_at: i === 0 ? '2026-11-06T09:00:00Z' : null,
}));

function setup(role, { pending = pendingRows(), history = historyRows(2), hasMore = false } = {}) {
  const dom = new JSDOM('<!doctype html><body></body>', { runScripts: 'outside-only', url: 'http://localhost/' });
  const ctx = dom.getInternalVMContext();
  const log = { fetches: [], alerts: [], collapsed: 0, opened: [] };
  dom.window.__log = log; dom.window.__pending = pending; dom.window.__history = history; dom.window.__hasMore = hasMore;
  dom.window.localStorage.setItem('activeProjectId', '1');
  vm.runInContext(`
    const API = 'http://api/api';
    window.currentUserRole = ${JSON.stringify(role)};
    function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
    function wcSide(r) { return r.startsWith('Consultant') ? 'Consultant' : r.startsWith('Contractor') ? 'Contractor' : r.startsWith('Client') ? 'Client' : null; }
    async function ensureActiveProjectId() { return '1'; }
    function expandGrayPart(h) { document.body.innerHTML = '<div id="grayContent">' + h + '</div>'; }
    function collapseGrayPart() { window.__log.collapsed++; }
    window.alert = (m) => window.__log.alerts.push(m);
    window._openActivityVerificationNotification = async (id) => { window.__log.opened.push(String(id)); return true; };
    async function responseData(res) { const body = await res.json(); if (!res.ok) throw new Error(body.error || 'failed'); return body; }
    async function _wcFetch(url, opts) {
      window.__log.fetches.push({ url, opts });
      const u = new URL(url);
      if (u.pathname.endsWith('/verifications/pending')) return { ok: true, status: 200, json: async () => ({ pending: window.__pending }) };
      if (u.pathname.endsWith('/verifications/history')) return { ok: true, status: 200, json: async () => ({ history: window.__history, has_more: window.__hasMore }) };
      if (u.pathname.endsWith('/read')) return { ok: true, status: 200, json: async () => ({ success: true }) };
      return { ok: false, status: 404, json: async () => ({ error: 'unexpected ' + url }) };
    }
  `, ctx);
  vm.runInContext(code, ctx);
  const d = dom.window.document;
  const q = (sel) => d.querySelector(sel);
  const tab = (key) => q(`[data-wf-vtab="${key}"]`);
  const reads = () => log.fetches.filter((f) => f.url.endsWith('/read'));
  const histories = () => log.fetches.filter((f) => f.url.includes('/verifications/history'));
  return { dom, d, q, tab, log, reads, histories, open: () => dom.window.openPendingVerifications() };
}

test('consultant: unread requests are marked New, and opening one records the read once', async () => {
  const t = setup('ConsultantPM');
  await t.open();
  assert.match(t.tab('pending').textContent, /Pending \(2, 1 new\)/);
  const rows = [...t.d.querySelectorAll('[data-wf-vtoggle]')];
  assert.equal(rows.length, 2);
  assert.ok(rows[0].querySelector('[data-wf-new]'));                          // Excavation is unread
  assert.equal(rows[1].querySelector('[data-wf-new]'), null);                 // Slab reinforcement was opened before
  assert.match(rows[1].textContent, /Overdue by 2 days/);
  assert.equal(t.d.querySelector('[data-wf-vbody]').hidden, true);            // collapsed until opened
  rows[0].click();
  await wait(20);
  assert.equal(rows[0].parentElement.querySelector('[data-wf-vbody]').hidden, false);
  assert.equal(t.reads().length, 1);
  assert.ok(t.reads()[0].url.endsWith('/verifications/11/read'));
  assert.equal(t.reads()[0].opts.method, 'POST');
  assert.equal(rows[0].querySelector('[data-wf-new]'), null);
  assert.match(t.tab('pending').textContent, /Pending \(2\)/);
  rows[0].click(); rows[0].click();                                           // closing and opening again does not post again
  await wait(20);
  assert.equal(t.reads().length, 1);
  rows[1].click(); await wait(20);                                            // already read: no post
  assert.equal(t.reads().length, 1);
});

test('consultant: a failed read keeps the request marked New', async () => {
  const t = setup('ConsultantPM');
  await t.open();
  vm.runInContext(`_wcFetch = async (url, opts) => { window.__log.fetches.push({ url, opts }); return url.endsWith('/read') ? { ok: false, status: 500, json: async () => ({}) } : { ok: true, json: async () => ({ pending: window.__pending }) }; };`, t.dom.getInternalVMContext());
  const first = t.d.querySelector('[data-wf-vtoggle]');
  first.click(); await wait(20);
  assert.ok(first.querySelector('[data-wf-new]'));
  assert.equal(first.dataset.wfUnread, 'true');
});

test('search filters the pending list by activity, review type or note', async () => {
  const t = setup('ConsultantPM');
  await t.open();
  const search = t.q('[data-wf-vsearch]');
  search.value = 'slab'; search.dispatchEvent(new t.dom.window.Event('input'));
  assert.equal(t.d.querySelectorAll('[data-wf-vtoggle]').length, 1);
  assert.match(t.q('[data-wf-vlist]').textContent, /Slab reinforcement/);
  search.value = 'hold point'; search.dispatchEvent(new t.dom.window.Event('input'));
  assert.equal(t.d.querySelectorAll('[data-wf-vtoggle]').length, 1);
  search.value = 'nothing like this'; search.dispatchEvent(new t.dom.window.Event('input'));
  assert.match(t.q('[data-wf-vlist]').textContent, /No pending request matches your search/);
  assert.equal(t.histories().length, 0);                                      // pending search never asks the server for history
});

test('history: opens from its tab, shows outcomes, filters by outcome and searches on the server', async () => {
  const t = setup('ConsultantPM');
  await t.open();
  assert.equal(t.q('[data-wf-vstatus]').hidden, true);
  t.tab('history').click();
  await wait(30);
  assert.equal(t.q('[data-wf-vstatus]').hidden, false);
  assert.equal(t.histories().length, 1);
  assert.match(t.histories()[0].url, /projectId=1/);
  assert.doesNotMatch(t.histories()[0].url, /q=|status=/);
  const text = t.q('[data-wf-vlist]').textContent;
  assert.match(text, /Done activity 0/); assert.match(text, /Verified with changes/); assert.match(text, /Rejected/);
  assert.match(text, /Claimed 25% . Certified 20%/);
  assert.match(text, /Measured 80 m3 on site/);
  assert.equal(t.d.querySelectorAll('[data-wf-vtoggle][data-wf-unread="true"]').length, 0);   // decided requests are never "new"

  const status = t.q('[data-wf-vstatus]');
  status.value = 'rejected'; status.dispatchEvent(new t.dom.window.Event('change'));
  await wait(30);
  assert.match(t.histories().at(-1).url, /status=rejected/);

  const search = t.q('[data-wf-vsearch]');
  search.value = 'slab'; search.dispatchEvent(new t.dom.window.Event('input'));
  search.value = 'slab 2'; search.dispatchEvent(new t.dom.window.Event('input'));
  await wait(400);
  const last = t.histories().at(-1).url;
  assert.match(last, /q=slab\+2/); assert.match(last, /status=rejected/);
  assert.equal(t.histories().length, 3);                                      // typing twice made one request, not two

  t.q('[data-wf-open-verification]').click();
  await wait(20);
  assert.equal(t.log.collapsed, 0);                                           // the reviewer stays in the panel, which is not closed and reopened
  assert.deepEqual(t.log.opened, ['100']);
});

test('history: load more adds the next page and empty results say so', async () => {
  const t = setup('ConsultantPM', { history: historyRows(25), hasMore: true });
  await t.open();
  t.tab('history').click(); await wait(30);
  assert.equal(t.d.querySelectorAll('[data-wf-vtoggle]').length, 25);
  t.dom.window.__history = historyRows(3, 25); t.dom.window.__hasMore = false;
  t.q('[data-wf-load-more]').click(); await wait(30);
  assert.match(t.histories().at(-1).url, /offset=25/);
  assert.equal(t.d.querySelectorAll('[data-wf-vtoggle]').length, 28);
  assert.equal(t.q('[data-wf-load-more]'), null);

  t.dom.window.__history = [];
  const search = t.q('[data-wf-vsearch]');
  search.value = 'zzz'; search.dispatchEvent(new t.dom.window.Event('input')); await wait(400);
  assert.match(t.q('[data-wf-vlist]').textContent, /No earlier request matches your search/);
});

test('contractor: sees whether the consultant opened each request, never a New marker, and posts no read', async () => {
  const t = setup('ContractorPM');
  await t.open();
  const text = t.q('[data-wf-vlist]').textContent;
  assert.match(text, /Not opened by the consultant yet/);                      // Excavation
  assert.match(text, /Opened by the consultant 2026-11-03, no decision yet/);  // Slab reinforcement
  assert.equal(t.d.querySelectorAll('[data-wf-new]').length, 0);
  assert.doesNotMatch(t.tab('pending').textContent, /new/);
  assert.match(t.d.querySelector('h3').textContent, /Verification requests/);
  t.d.querySelector('[data-wf-vtoggle]').click(); await wait(20);
  assert.equal(t.reads().length, 0);

  t.tab('history').click(); await wait(30);
  const history = t.q('[data-wf-vlist]').textContent;
  assert.match(history, /Opened by the consultant 2026-11-06/);                // decided and opened
  assert.match(history, /Decided 2026-11-07 by ConsultantPM/);
});

test('contractor: a withdrawn request says whether it was ever opened', async () => {
  const withdrawn = { ...historyRows(1)[0], status: 'withdrawn', seen_at: null, decided_at: null, decided_by_role: null, certified_progress_pct: null, decision_reason: null };
  const t = setup('ContractorPM', { history: [withdrawn] });
  await t.open();
  t.tab('history').click(); await wait(30);
  assert.match(t.q('[data-wf-vlist]').textContent, /Not opened by the consultant before it was withdrawn/);
  assert.match(t.q('[data-wf-vlist]').textContent, /Withdrawn/);
});

test('an empty pending list points to History, and a server error is shown', async () => {
  const t = setup('ConsultantPM', { pending: [] });
  await t.open();
  assert.match(t.q('[data-wf-vlist]').textContent, /No pending verification requests. Earlier requests are under History/);
  vm.runInContext(`_wcFetch = async () => ({ ok: false, status: 500, json: async () => ({ error: 'Server error.' }) });`, t.dom.getInternalVMContext());
  t.tab('history').click(); await wait(30);
  assert.match(t.q('[data-wf-vlist]').textContent, /Unable to load earlier requests: Server error/);
});
