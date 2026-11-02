// Runs the Work Center report and decision code inside a simulated browser (jsdom).
// Run: node --test wc-reports-v2.test.js   (needs: npm i -D jsdom)
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { JSDOM } from 'jsdom';

const same = (actual, expected) => assert.deepStrictEqual(JSON.parse(JSON.stringify(actual)), expected);
const code = fs.readFileSync(new URL('./wc-reports-v2.js', import.meta.url), 'utf8');

function setup(task, extra = {}) {
  const dom = new JSDOM('<!doctype html><body></body>', { runScripts: 'outside-only', url: 'http://localhost/' });
  const ctx = dom.getInternalVMContext();
  const log = { alerts: [], confirms: [], prompts: [], fetches: [], reloaded: 0 };
  dom.window.__log = log; dom.window.__responses = []; dom.window.__task = task;
  dom.window.__promptAnswer = extra.prompt ?? 'Measured wrongly';
  vm.runInContext(`
    const API = 'http://api/api';
    const recordsCache = { 'work-center': [window.__task], 'planning-execution': [1] };
    function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
    function _wcLabel(t) { return '<label>' + t + '</label>'; }
    function loadWCRecords() { window.__log.reloaded++; }
    async function ensureActiveProjectId() { return '1'; }
    window.alert = (m) => window.__log.alerts.push(m);
    window.confirm = (m) => { window.__log.confirms.push(m); return true; };
    window.prompt = (m) => { window.__log.prompts.push(m); return window.__promptAnswer; };
    async function _wcFetch(url, opts) {
      window.__log.fetches.push({ url, opts });
      const r = window.__responses.shift() || { status: 200, body: {} };
      return { ok: r.status < 400, status: r.status, json: async () => r.body };
    }
  `, ctx);
  vm.runInContext(code, ctx);
  const w = dom.window, d = w.document;
  const render = () => {
    d.body.innerHTML = `
      <input id="wc-pr-date-${task.id}" value="2026-03-10"/><textarea id="wc-pr-work-${task.id}">Excavated</textarea>
      <div id="fields">${vm.runInContext(`_wcReportFieldsHtml(window.__task)`, ctx)}</div>
      <input id="wc-pr-manpower-${task.id}" value="6 workers"/><input id="wc-pr-equipment-${task.id}"/><input id="wc-pr-materials-${task.id}"/>
      <input id="wc-pr-issues-${task.id}"/><textarea id="wc-pr-notes-${task.id}"></textarea><input id="wc-pr-file-${task.id}" type="file"/>`;
  };
  const set = (name, value) => { d.getElementById(`wc-pr-${name}-${task.id}`).value = value; };
  const submit = async () => { await vm.runInContext(`_wcHandleSubmitProgress(${task.id}, 'work-center')`, ctx); };
  const posts = () => log.fetches.filter((f) => f.url.endsWith('/work-center-progress'));
  const validate = async (id, action) => { await vm.runInContext(`_wcHandleValidate('work-center', ${id}, '${action}')`, ctx); };
  return { w, d, log, render, set, submit, posts, validate, ctx, call: (expr) => vm.runInContext(expr, ctx) };
}

const quantityTask = { id: 5, activity_type: 'quantity', activity_unit: 'm3', target_quantity: '200.000', weight_pct: '50.00', progress_pct: '20.00' };
const stagesTask = { id: 6, activity_type: 'stages', stages: [
  { id: 61, seq: 1, title: 'Reinforcement', is_hold_point: true, completed_at: '2026-03-10', hold_verified_at: null },
  { id: 62, seq: 2, title: 'Pour', is_hold_point: false, completed_at: null, hold_verified_at: null },
  { id: 63, seq: 3, title: 'Cure', is_hold_point: false, completed_at: null, hold_verified_at: null }] };

test('the share line shows weight, task progress and target', () => {
  const s = setup(quantityTask);
  const html = s.call('_wcTaskShareHtml(window.__task)');
  assert.match(html, /Share of the activity <strong>50%/);
  assert.match(html, /Task progress <strong>20%/);
  assert.match(html, /Target <strong>200 m3/);
  assert.equal(s.call('_wcTaskShareHtml({ id: 1 })'), '');                              // old task without a weight: nothing to show
});

test('report fields follow the activity type, and old tasks stay percentage tasks', () => {
  let s = setup(quantityTask); s.render();
  assert.ok(s.d.getElementById('wc-pr-qty-5')); assert.equal(s.d.getElementById('wc-pr-pct-5'), null);
  assert.match(s.d.getElementById('fields').innerHTML, /Quantity done \(m3\)/);
  s = setup({ id: 7, activity_type: 'count' }); s.render();
  assert.ok(s.d.getElementById('wc-pr-qty-7')); assert.ok(s.d.getElementById('wc-pr-failed-7'));
  s = setup({ id: 8 }); s.render();                                                      // no activity_type: legacy
  assert.ok(s.d.getElementById('wc-pr-pct-8'));
  s = setup({ id: 9, activity_type: 'percentage' }); s.render();
  assert.match(s.d.getElementById('fields').innerHTML, /cannot go below the last approved/);
});

test('stages: only open stages are offered and the one after a hold point is locked', () => {
  const s = setup(stagesTask); s.render();
  const opts = [...s.d.getElementById('wc-pr-stage-6').options].map((o) => [o.textContent.trim(), o.disabled]);
  same(opts, [['Select stage', false], ['Pour', false], ['Cure', false]]);              // Reinforcement is done; its hold point is closed above Pour
  const locked = setup({ id: 10, activity_type: 'stages', stages: [
    { id: 1, seq: 1, title: 'Steel', is_hold_point: true, completed_at: null }, { id: 2, seq: 2, title: 'Pour', completed_at: null }] });
  locked.render();
  const o2 = [...locked.d.getElementById('wc-pr-stage-10').options];
  assert.match(o2[1].textContent, /\(hold point\)/); assert.equal(o2[1].disabled, false);
  assert.equal(o2[2].disabled, true); assert.match(o2[2].textContent, /locked/);
  const done = setup({ id: 11, activity_type: 'stages', stages: [{ id: 1, seq: 1, title: 'A', completed_at: 'x' }] }); done.render();
  assert.match(done.d.getElementById('fields').innerHTML, /All stages are completed/);
});

test('entry figure per type', () => {
  const s = setup(quantityTask);
  assert.equal(s.call(`_wcEntryFigure(window.__task, { quantity_done: '40.000' })`), '40 m3');
  assert.equal(s.call(`_wcEntryFigure({ activity_type: 'count' }, { quantity_done: 5, quantity_failed: 1 })`), '5 done, 1 failed');
  assert.equal(s.call(`_wcEntryFigure({ activity_type: 'count' }, { quantity_done: 3, quantity_failed: 0 })`), '3 done');
  assert.equal(s.call(`_wcEntryFigure(${JSON.stringify(stagesTask)}, { stage_id: 62 })`), 'Pour');
  assert.equal(s.call(`_wcEntryFigure({}, { progress_pct: 60 })`), '60%');
});

test('quantity report: validation, then the request carries quantityDone', async () => {
  const s = setup(quantityTask); s.render();
  await s.submit(); assert.match(s.log.alerts.at(-1), /Enter the quantity done/);
  s.set('qty', '40');
  s.w.__responses.push({ status: 201, body: { entry: { id: 1 }, warning: 'With this report the total is 240, above the task target of 200.' } });
  await s.submit();
  assert.equal(s.posts().length, 1);
  const b = s.posts()[0].opts.body;
  assert.equal(b.get('quantityDone'), '40'); assert.equal(b.get('progressPct'), null); assert.equal(b.get('stageId'), null);
  assert.equal(b.get('taskId'), '5'); assert.equal(b.get('projectId'), '1'); assert.equal(b.get('reportDate'), '2026-03-10');
  assert.equal(b.get('workDone'), 'Excavated'); assert.equal(b.get('manpower'), '6 workers');
  assert.match(s.log.alerts.at(-1), /counts toward progress once a leader approves/);
  assert.match(s.log.alerts.at(-1), /above the task target/);
  assert.equal(s.log.reloaded, 1);
});

test('count report: whole numbers and failed not above completed', async () => {
  const s = setup({ id: 7, activity_type: 'count' }); s.render();
  s.set('qty', '5'); s.set('failed', '6'); await s.submit(); assert.match(s.log.alerts.at(-1), /cannot be more than/);
  s.set('qty', '2.5'); s.set('failed', '0'); await s.submit(); assert.match(s.log.alerts.at(-1), /whole numbers/);
  s.set('qty', '5'); s.set('failed', '1'); await s.submit();
  const b = s.posts().at(-1).opts.body;
  assert.equal(b.get('quantityDone'), '5'); assert.equal(b.get('quantityFailed'), '1');
});

test('stage report and percentage report send the right field', async () => {
  const st = setup(stagesTask); st.render();
  await st.submit(); assert.match(st.log.alerts.at(-1), /Choose the stage/);
  st.set('stage', '62'); await st.submit();
  assert.equal(st.posts()[0].opts.body.get('stageId'), '62');
  const p = setup({ id: 8 }); p.render();
  p.set('pct', '150'); await p.submit(); assert.match(p.log.alerts.at(-1), /between 0 and 100/);
  p.set('pct', '60'); await p.submit();
  const b = p.posts()[0].opts.body;
  assert.equal(b.get('progressPct'), '60'); assert.equal(b.get('quantityDone'), null);
});

test('the server message is shown, not a generic one', async () => {
  const s = setup(quantityTask); s.render(); s.set('qty', '5');
  s.w.__responses.push({ status: 409, body: { error: 'This task is closed. Reports can no longer be added.' } });
  await s.submit();
  assert.match(s.log.alerts.at(-1), /This task is closed/);
  assert.equal(s.log.reloaded, 0);
});

test('leader decisions: reject needs a reason, void asks for one and confirms, approve reports the new progress', async () => {
  const s = setup(quantityTask);
  s.d.body.innerHTML = '<textarea id="wc-val-notes-12"></textarea>';
  await s.validate(12, 'rejected');
  assert.match(s.log.alerts.at(-1), /reason for rejecting/); assert.equal(s.log.fetches.length, 0);

  s.d.getElementById('wc-val-notes-12').value = 'Not on site';
  s.w.__responses.push({ status: 200, body: { success: true } });
  await s.validate(12, 'rejected');
  const rej = s.log.fetches[0];
  assert.equal(rej.url, 'http://api/api/work-center-progress/12/validate'); assert.equal(rej.opts.method, 'PUT');
  same(JSON.parse(rej.opts.body), { projectId: '1', validation_notes: 'Not on site', validation_status: 'rejected' });

  s.w.__responses.push({ status: 200, body: { activity: { progress_pct: 17.5, status: 'ongoing' } } });
  await s.validate(13, 'approved');
  assert.match(s.log.alerts.at(-1), /Report approved\. The activity is now at 17\.5%/);

  s.w.__promptAnswer = 'Measured 40 m3 instead of 4';
  s.w.__responses.push({ status: 200, body: { activity: { progress_pct: 7.5 } } });
  await s.validate(13, 'voided');
  assert.match(s.log.prompts[0], /voided/); assert.match(s.log.confirms[0], /stays in the record/);
  const v = JSON.parse(s.log.fetches.at(-1).opts.body);
  assert.equal(v.validation_status, 'voided'); assert.equal(v.validation_notes, 'Measured 40 m3 instead of 4');
  assert.match(s.log.alerts.at(-1), /Report voided.*7\.5%/);
  assert.equal(s.log.reloaded, 3);                                                       // reject, approve and void each refresh the list
});

test('voiding is cancelled when no reason is given, and server refusals are shown', async () => {
  const s = setup(quantityTask, { prompt: '   ' });
  await s.validate(14, 'voided');
  assert.equal(s.log.fetches.length, 0);
  s.d.body.innerHTML = '';
  s.w.__responses.push({ status: 409, body: { error: 'This report is already approved. To correct it, void it with a reason.' } });
  await s.validate(15, 'approved');
  assert.match(s.log.alerts.at(-1), /void it with a reason/);
});
