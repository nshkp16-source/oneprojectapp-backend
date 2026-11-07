// Runs the new activity form inside a simulated browser (jsdom) with the dashboard's globals stubbed.
// Run: node --test activity-form-v2.test.js   (needs: npm i -D jsdom)
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { JSDOM } from 'jsdom';

// arrays made inside the simulated browser have another prototype, so compare plain copies
const same = (actual, expected) => assert.deepStrictEqual(JSON.parse(JSON.stringify(actual)), expected);
const html = fs.readFileSync(new URL('../frontend/dashboard.html', import.meta.url), 'utf8');
const startMarker = '// ===== Activity form v2:';
const codeStart = html.indexOf(startMarker);
const codeEnd = html.indexOf('</script>', codeStart);
assert.ok(codeStart >= 0 && codeEnd > codeStart, 'inline activity form was not found in dashboard.html');
const code = html.slice(codeStart, codeEnd);
const MILESTONES = { milestones: [
  { id: 1, kind: 'baseline', title: 'Foundation', progress_source: 'manual', progress_pct: 30, executed: 120, quantity: 400, unit: 'm3', typed_progress: true, completed: false },
  { id: 2, kind: 'baseline', title: 'Walls', progress_source: 'manual', progress_pct: 0, typed_progress: false, completed: false },
  { id: 3, kind: 'baseline', title: 'Old', progress_source: 'activities', progress_pct: 100, typed_progress: false, completed: true },
  { id: 1, kind: 'additional', title: 'Extra', progress_source: 'manual', progress_pct: 0, typed_progress: false, completed: false },
] };
const MEMBERS = { members: [{ id: 101, email: 'a@x', title: 'Amina', position: 'Engineer' }, { id: 102, email: 'b@x', title: 'Beno', position: 'Foreman' }] };

function setup(role = 'ContractorPM') {
  const dom = new JSDOM('<!doctype html><body></body>', { runScripts: 'outside-only', url: 'http://localhost/' });
  const ctx = dom.getInternalVMContext();
  const log = { alerts: [], confirms: [], fetches: [], closed: 0, reloaded: 0 };
  dom.window.__log = log;
  dom.window.__responses = [];
  vm.runInContext(`
    window.currentUserRole = ${JSON.stringify(role)};
    const API = 'http://api/api';
    const PE_UNITS = ['m3', 'm2', 'kg'];
    let projectLifecycleReadOnly = false; function showProjectLifecycleNotice() {}
    const recordsCache = { 'planning-execution': [1], 'work-center': [1] };
    function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
    function _wcFmtDate(value) { return value ? String(value).slice(0, 10) : '—'; }
    function wcSide(r) { return r.startsWith('Contractor') ? 'Contractor' : r.startsWith('Consultant') ? 'Consultant' : r.startsWith('Client') ? 'Client' : null; }
    function isWCLeader(r) { return wcSide(r) !== null; }
    function _peUnitOptions(sel) { return PE_UNITS.map(u => '<option value="' + u + '">' + u + '</option>').join(''); }
    function _peLabelStyle() { return ''; } function _peInputStyle() { return ''; }
    function expandGrayPart(html) { document.body.innerHTML = html; }
    function collapseGrayPart() { window.__log.closed++; }
    function loadPERecords() { window.__log.reloaded++; }
    async function ensureActiveProjectId() { return '1'; }
    window.alert = (m) => window.__log.alerts.push(m);
    window.confirm = (m) => { window.__log.confirms.push(m); return window.__confirmAnswer !== false; };
    async function _wcFetch(url, opts) {
      window.__log.fetches.push({ url, opts });
      if (url.includes('/project-milestones')) return { ok: true, status: 200, json: async () => (${JSON.stringify(MILESTONES)}) };
      if (url.includes('/team-members')) return { ok: true, status: 200, json: async () => (${JSON.stringify(MEMBERS)}) };
      const r = window.__responses.shift() || { status: 201, body: { tasks: [{}, {}] } };
      return { ok: r.status < 400, status: r.status, json: async () => r.body };
    }
  `, ctx);
  vm.runInContext(code, ctx);
  const w = dom.window, d = w.document;
  const $ = (id) => d.getElementById(id);
  const set = (id, value, ev = 'input') => { $(id).value = value; $(id).dispatchEvent(new w.Event(ev, { bubbles: true })); };
  const click = (el) => el.dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  const check = (el, on = true) => { el.checked = on; el.dispatchEvent(new w.Event('change', { bubbles: true })); };
  const state = () => vm.runInContext('_pe2', ctx);
  const open = () => vm.runInContext('_peOpenAddForm()', ctx);
  const fill = () => { set('pe2-title', 'Excavation'); set('pe2-start', '2026-03-01'); set('pe2-end', '2026-04-30'); set('pe2-qty', '400'); set('pe2-unit', 'm3', 'change'); };
  return { w, d, $, set, click, check, state, open, log, fill, ctx };
}

test('opens with a milestone list, a default type per side, and one task at 100%', async () => {
  const s = setup(); await s.open();
  assert.equal(s.$('pe2-type').value, 'quantity');
  assert.equal(s.state().tasks.length, 1);
  assert.equal(s.d.querySelector('[data-task-weight]').readOnly, true);               // one task is fixed at 100%
  const opts = [...s.$('pe2-milestone').options].map((o) => o.textContent.trim());
  assert.ok(opts.some((t) => t.includes('Foundation') && t.includes('typed progress 30%')));
  assert.ok(opts.some((t) => t.includes('Old') && t.includes('completed')));
  assert.equal([...s.$('pe2-milestone').options].find((o) => o.textContent.includes('Old')).disabled, true);
  const c = setup('ConsultantPM'); await c.open(); assert.equal(c.$('pe2-type').value, 'count');
  const k = setup('ClientPM'); await k.open(); assert.equal(k.$('pe2-type').value, 'stages');
});

test('adding tasks splits weights equally and shows targets from the planned amount', async () => {
  const s = setup(); await s.open(); s.fill();
  s.click(s.$('pe2-add-task'));
  same(s.state().tasks.map((t) => t.weight), [50, 50]);
  s.click(s.$('pe2-add-task'));
  same(s.state().tasks.map((t) => t.weight), [33.33, 33.33, 33.34]);
  assert.match(s.d.querySelector('[data-task-target="0"]').textContent, /Target: 133\.32 m3/);
  assert.equal(s.$('pe2-total').textContent, 'Weights total 100%');
});

test('editing a weight is kept, shows an invalid total, and a later task scales the others in proportion', async () => {
  const s = setup(); await s.open(); s.fill();
  s.click(s.$('pe2-add-task'));
  const w0 = s.d.querySelector('[data-task-weight="0"]'); w0.value = '60'; w0.dispatchEvent(new s.w.Event('input', { bubbles: true }));
  same(s.state().tasks.map((t) => t.weight), [60, 50]);
  assert.match(s.$('pe2-total').textContent, /110% \(must be 100\)/);
  const w1 = s.d.querySelector('[data-task-weight="1"]'); w1.value = '40'; w1.dispatchEvent(new s.w.Event('input', { bubbles: true }));
  assert.equal(s.$('pe2-total').textContent, 'Weights total 100%');
  s.click(s.$('pe2-add-task'));
  const w = s.state().tasks.map((t) => t.weight);
  assert.equal(w.length, 3);
  assert.equal(Math.round(w.reduce((a, b) => a + b, 0) * 100), 10000);
  assert.ok(w[0] > w[1] && Math.abs(w[0] / w[1] - 1.5) < 0.02);                    // 60:40 is kept
  s.click(s.d.querySelector('[data-task-del="2"]'));
  same(s.state().tasks.map((t) => t.weight), [60, 40]);                // scaled back
});

test('type switch: measure fields appear for quantity and count only, stages get a stage editor', async () => {
  const s = setup(); await s.open();
  assert.equal(s.$('pe2-measure').style.display, 'grid');
  s.set('pe2-type', 'percentage', 'change');
  assert.equal(s.$('pe2-measure').style.display, 'none');
  assert.equal(s.d.querySelector('[data-stage-title]'), null);
  s.set('pe2-type', 'stages', 'change');
  assert.ok(s.d.querySelector('[data-stage-title="0:0"]'));
  s.click(s.d.querySelector('[data-stage-add="0"]'));
  same(s.state().tasks[0].stages.map((x) => x.weight), [50, 50]);
  s.set('pe2-type', 'count', 'change');
  assert.equal(s.$('pe2-unit').tagName, 'INPUT');                                  // free text for what is counted
});

test('validation messages', async () => {
  const s = setup(); await s.open();
  s.click(s.$('pe2-save')); assert.match(s.log.alerts.at(-1), /title is required/);
  s.set('pe2-title', 'A'); s.click(s.$('pe2-save')); assert.match(s.log.alerts.at(-1), /dates are required/);
  s.set('pe2-start', '2026-05-01'); s.set('pe2-end', '2026-04-01'); s.click(s.$('pe2-save')); assert.match(s.log.alerts.at(-1), /cannot be before/);
  s.set('pe2-end', '2026-06-01'); s.click(s.$('pe2-save')); assert.match(s.log.alerts.at(-1), /planned amount/);
  s.set('pe2-qty', '10'); s.click(s.$('pe2-save')); assert.match(s.log.alerts.at(-1), /select a unit/);
  s.set('pe2-unit', 'm3', 'change'); s.click(s.$('pe2-save')); assert.match(s.log.alerts.at(-1), /Task 1 needs a title/);
  assert.equal([...s.$('pe2-milestone').options].some((option) => option.value === 'new'), false);
  assert.equal(s.$('pe2-milestone-text'), null);
  s.d.querySelector('[data-task-title="0"]').value = 'T'; s.d.querySelector('[data-task-title="0"]').dispatchEvent(new s.w.Event('input', { bubbles: true }));
  s.click(s.$('pe2-save')); assert.match(s.log.alerts.at(-1), /assigned team member/);
  assert.equal(s.log.fetches.filter((f) => f.url.includes('create-with-tasks')).length, 0);   // nothing was sent
});

test('milestone choice sends the right field, and the note explains the effect', async () => {
  const s = setup(); await s.open();
  s.set('pe2-milestone', 'b:1', 'change');
  assert.match(s.$('pe2-milestone-note').textContent, /typed progress \(30%\).*replaces it/);
  s.set('pe2-milestone', 'a:1', 'change');
  assert.match(s.$('pe2-milestone-note').textContent, /follow the consultant-certified/);
  const c = setup('ConsultantPM'); await c.open(); c.set('pe2-milestone', 'b:2', 'change');
  assert.match(c.$('pe2-milestone-note').textContent, /Reference only/);
  assert.equal([...s.$('pe2-milestone').options].some((option) => option.value === 'new'), false);
});

test('submit builds the request, asks to confirm replacing typed progress, and refreshes the lists', async () => {
  const s = setup(); await s.open(); s.fill();
  s.click(s.$('pe2-add-task'));
  s.d.querySelectorAll('[data-task-title]').forEach((el, i) => { el.value = `Block ${'AB'[i]}`; el.dispatchEvent(new s.w.Event('input', { bubbles: true })); });
  s.check(s.d.querySelector('[data-task="0"][data-member="101"]'));
  s.check(s.d.querySelector('[data-task="1"][data-member="102"]'));
  s.set('pe2-milestone', 'b:1', 'change'); s.set('pe2-donewhen', 'Levels confirmed');
  s.w.__responses.push({ status: 409, body: { code: 'CONFIRM_REPLACE_MANUAL', typed_progress_pct: 30, typed_executed: 120, quantity: 400, unit: 'm3', will_become: 0 } });
  s.w.__responses.push({ status: 201, body: { tasks: [{}, {}] } });
  s.click(s.$('pe2-save'));
  await new Promise((r) => setTimeout(r, 50));
  const posts = s.log.fetches.filter((f) => f.url.includes('create-with-tasks'));
  assert.equal(posts.length, 2);
  const first = posts[0].opts.body, second = posts[1].opts.body;
  assert.equal(first.get('projectId'), '1');
  assert.equal(first.get('activity_type'), 'quantity');
  assert.equal(first.get('planned_quantity'), '400');
  assert.equal(first.get('unit'), 'm3');
  assert.equal(first.get('baseline_milestone_id'), '1');
  assert.equal(first.get('milestone_name'), null);
  assert.equal(first.get('done_when'), 'Levels confirmed');
  assert.equal(first.get('confirm_replace_manual'), null);
  assert.deepEqual(JSON.parse(first.get('tasks')), [
    { title: 'Block A', description: '', start_date: '2026-03-01', end_date: '2026-04-30', priority: 'normal', assigned_members: [{ id: 101 }], weight_pct: 50 },
    { title: 'Block B', description: '', start_date: '2026-03-01', end_date: '2026-04-30', priority: 'normal', assigned_members: [{ id: 102 }], weight_pct: 50 }]);
  assert.match(s.log.confirms[0], /typed progress: 30%.*120 of 400 m3.*0%/s);
  assert.equal(second.get('confirm_replace_manual'), 'true');
  assert.match(s.log.alerts.at(-1), /Activity created with 2 tasks/);
  assert.equal(s.log.closed, 1); assert.equal(s.log.reloaded, 1);
  assert.equal(vm.runInContext("recordsCache['planning-execution']", s.ctx), undefined);
  assert.equal(vm.runInContext("recordsCache['work-center']", s.ctx), undefined);
});

test('declining the confirmation sends nothing more; a server error is shown and the button comes back', async () => {
  const s = setup(); await s.open(); s.fill();
  s.d.querySelector('[data-task-title="0"]').value = 'T'; s.d.querySelector('[data-task-title="0"]').dispatchEvent(new s.w.Event('input', { bubbles: true }));
  s.check(s.d.querySelector('[data-task="0"][data-member="101"]'));
  s.set('pe2-milestone', 'b:1', 'change');
  s.w.__confirmAnswer = false;
  s.w.__responses.push({ status: 409, body: { code: 'CONFIRM_REPLACE_MANUAL', typed_progress_pct: 30, typed_executed: 120, quantity: 400, unit: 'm3', will_become: 0 } });
  s.click(s.$('pe2-save')); await new Promise((r) => setTimeout(r, 30));
  assert.equal(s.log.fetches.filter((f) => f.url.includes('create-with-tasks')).length, 1);
  assert.equal(s.$('pe2-save').disabled, false);
  s.w.__responses.push({ status: 403, body: { error: 'One or more assigned members do not belong to your side.' } });
  s.click(s.$('pe2-save')); await new Promise((r) => setTimeout(r, 30));
  assert.match(s.log.alerts.at(-1), /do not belong to your side/);
  assert.equal(s.$('pe2-save').disabled, false);
});

test('stages activity sends stages with hold points and refuses stage weights that do not total 100', async () => {
  const s = setup('ClientPM'); await s.open();
  s.set('pe2-title', 'Valuation'); s.set('pe2-start', '2026-03-01'); s.set('pe2-end', '2026-04-30');
  s.d.querySelector('[data-task-title="0"]').value = 'Certify'; s.d.querySelector('[data-task-title="0"]').dispatchEvent(new s.w.Event('input', { bubbles: true }));
  s.check(s.d.querySelector('[data-task="0"][data-member="101"]'));
  s.set('pe2-donewhen', 'Paid');
  s.click(s.d.querySelector('[data-stage-add="0"]'));
  const t0 = s.d.querySelector('[data-stage-title="0:0"]'); t0.value = 'Review'; t0.dispatchEvent(new s.w.Event('input', { bubbles: true }));
  const t1 = s.d.querySelector('[data-stage-title="0:1"]'); t1.value = 'Approve'; t1.dispatchEvent(new s.w.Event('input', { bubbles: true }));
  s.check(s.d.querySelector('[data-stage-hold="0:1"]'));
  const sw = s.d.querySelector('[data-stage-weight="0:0"]'); sw.value = '70'; sw.dispatchEvent(new s.w.Event('input', { bubbles: true }));
  s.click(s.$('pe2-save')); assert.match(s.log.alerts.at(-1), /Stage weights of task 1 must add up to 100/);
  const sw1 = s.d.querySelector('[data-stage-weight="0:1"]'); sw1.value = '30'; sw1.dispatchEvent(new s.w.Event('input', { bubbles: true }));
  s.click(s.$('pe2-save')); await new Promise((r) => setTimeout(r, 30));
  const body = s.log.fetches.find((f) => f.url.includes('create-with-tasks')).opts.body;
  assert.equal(body.get('activity_type'), 'stages');
  assert.equal(body.get('planned_quantity'), null);
  assert.deepEqual(JSON.parse(body.get('tasks'))[0].stages, [
    { title: 'Review', weight_pct: 70, is_hold_point: false }, { title: 'Approve', weight_pct: 30, is_hold_point: true }]);
});
