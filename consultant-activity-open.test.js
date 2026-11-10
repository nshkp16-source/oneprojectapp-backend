// Opening a contractor activity from a verification request, as a consultant, must stay inside the side panel:
// no wait on the Planning and Execution list, no panel collapse, the card and verifications requested together,
// and a specific message (not one generic "check your connection" alert) when something goes wrong.
// Run: node --test consultant-activity-open.test.js   (needs: npm i -D jsdom acorn; reads ../frontend/dashboard.html)
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import * as acorn from 'acorn';
import { JSDOM } from 'jsdom';

const html = fs.readFileSync(new URL('../frontend/dashboard.html', import.meta.url), 'utf8');
const names = ['_peClassifyLoadError', '_peHttpError', '_peLoadDetail', '_peShowPanelNotice', '_waitForElement',
  '_openActivityCardInPanel', '_openActivityVerificationNotification'];
const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map((match) => match[1]);
const source = scripts.map((script) => acorn.parse(script, { ecmaVersion: 'latest', sourceType: 'script' }).body
  .filter((node) => node.type === 'FunctionDeclaration' && names.includes(node.id.name))
  .map((node) => script.slice(node.start, node.end)).join('\n')).join('\n');
for (const name of names) assert.match(source, new RegExp(`function ${name}\\(`), `${name} was not found`);

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const CARD = { viewer_side: 'Consultant', activity: { id: 7, title: 'Excavate', side: 'Contractor', drives_milestone: true }, tasks: [], progress_reports: [] };

function setup(role, { cardStatus = 200, verificationStatus = 200, listed = true, delay = 120, rejectWith = null, targetStatus = 200 } = {}) {
  const dom = new JSDOM('<!doctype html><body></body>', { runScripts: 'outside-only', url: 'http://localhost/' });
  const ctx = dom.getInternalVMContext();
  const log = { calls: [], starts: [], alerts: [], collapsed: 0, listLookups: 0, tabSelects: 0 };
  dom.window.__log = log;
  dom.window.localStorage.setItem('activeProjectId', '1');
  dom.window.CSS = { escape: (value) => String(value) };
  dom.window.Element.prototype.scrollIntoView = () => {};   // jsdom does not implement it; browsers do
  vm.runInContext(`
    const API = 'http://api/api';
    window.currentUserRole = ${JSON.stringify(role)};
    const recordsCache = {};
    function wcSide(r) { return r.startsWith('Consultant') ? 'Consultant' : r.startsWith('Contractor') ? 'Contractor' : r.startsWith('Client') ? 'Client' : null; }
    function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
    function expandGrayPart(h) { document.body.innerHTML = h; }
    function collapseGrayPart() { window.__log.collapsed++; }
    async function _openRecordNotification() { window.__log.listLookups++; await new Promise(r => setTimeout(r, 2500)); return false; }
    function _selectNotificationTab() { window.__log.tabSelects++; }
    function _peActivityCardHtml(card, data) {
      return '<div data-pe-tab="certification"></div>' + (${listed ? 'true' : 'false'} ? '<div id="pe-verification-91"></div>' : '');
    }
    function _peWireActivityCard() {} function _peUpdateStatusBadge() {}
    window.alert = (m) => window.__log.alerts.push(m);
    async function authFetch(url) {
      window.__log.calls.push(url);
      return { ok: ${targetStatus} < 400, status: ${targetStatus}, json: async () => ({ target: { recordId: 7 } }) };
    }
    async function _wcFetch(url) {
      const kind = url.includes('/activity-card') ? 'card' : 'verifications';
      window.__log.starts.push({ kind, at: Date.now() });
      ${rejectWith ? `throw new TypeError(${JSON.stringify(rejectWith)});` : ''}
      await new Promise(r => setTimeout(r, ${delay}));
      const status = kind === 'card' ? ${cardStatus} : ${verificationStatus};
      return { ok: status < 400, status, json: async () => (kind === 'card' ? ${JSON.stringify(CARD)} : { verifications: [], rework: [] }) };
    }
  `, ctx);
  vm.runInContext(source, ctx);
  return { dom, log, doc: dom.window.document, open: (id = 91) => vm.runInContext(`_openActivityVerificationNotification(${id})`, ctx) };
}

test('a consultant opens the activity in the panel without waiting on, or switching to, the list', async () => {
  const t = setup('ConsultantPM');
  const started = Date.now();
  const opened = await t.open();
  const elapsed = Date.now() - started;
  assert.equal(opened, true);
  assert.equal(t.log.listLookups, 0);          // never looked for the activity in the consultant's own list
  assert.equal(t.log.tabSelects, 0);           // never switched to the Planning and Execution tab
  assert.equal(t.log.collapsed, 0);            // the side panel was not closed and reopened
  assert.equal(t.log.alerts.length, 0);
  assert.ok(elapsed < 1500, `took ${elapsed} ms; the old 2.5 s list wait is still there`);
  assert.ok(t.doc.getElementById('pe-verification-91'));
});

test('the card and the verification list are requested together, not one after the other', async () => {
  const t = setup('ConsultantPM', { delay: 150 });
  const started = Date.now();
  await t.open();
  const kinds = t.log.starts.map((entry) => entry.kind).sort();
  assert.deepEqual(kinds, ['card', 'verifications']);
  const gap = Math.abs(t.log.starts[0].at - t.log.starts[1].at);
  assert.ok(gap < 100, `second request started ${gap} ms after the first`);
  assert.ok(Date.now() - started < 600);
});

test('the panel shows a loading message immediately', async () => {
  const t = setup('ConsultantPM', { delay: 200 });
  const pending = t.open();
  await wait(30);
  assert.match(t.doc.body.textContent, /Loading the activity/);
  await pending;
});

test('a request that is no longer listed opens the activity with a notice and no alert', async () => {
  const t = setup('ConsultantPM', { listed: false });
  assert.equal(await t.open(), true);
  assert.match(t.doc.body.textContent, /Activity opened, but this request is no longer listed/);
  assert.equal(t.log.alerts.length, 0);
});

test('a connection failure shows a connection message with Try again, not a server message', async () => {
  const t = setup('ConsultantPM', { rejectWith: 'Failed to fetch' });
  assert.equal(await t.open(), true);                       // the panel is open and explains the problem itself
  assert.match(t.doc.body.textContent, /could not be reached/);
  assert.ok(t.doc.querySelector('[data-pe-retry]'));
  assert.equal(t.log.alerts.length, 0);
});

test('a server error shows the server message, and a missing request is reported as such', async () => {
  const server = setup('ConsultantPM', { cardStatus: 500 });
  await server.open();
  assert.match(server.doc.body.textContent, /server error 500/);
  assert.doesNotMatch(server.doc.body.textContent, /Check your connection/);

  const missing = setup('ConsultantPM', { targetStatus: 404 });
  assert.equal(await missing.open(), false);
  assert.match(vm.runInContext('window._activityOpenIssue.message', missing.dom.getInternalVMContext()), /no longer available/);
  const broken = setup('ConsultantPM', { targetStatus: 500 });
  assert.equal(await broken.open(), false);
  assert.match(vm.runInContext('window._activityOpenIssue.message', broken.dom.getInternalVMContext()), /error 500/);
});

test('the contractor still opens their own activity through the list', async () => {
  const t = setup('ContractorPM');
  const pending = t.open();
  await wait(50);
  assert.equal(t.log.listLookups, 1);
  assert.equal(t.log.collapsed, 1);
  pending.catch(() => {});
});
