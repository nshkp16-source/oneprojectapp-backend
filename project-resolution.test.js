// Tests ensureActiveProjectId (the fix for "No Project Selected") by extracting it from the patched dashboard.html.
// Run: node --test project-resolution.test.js
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const html = fs.readFileSync(new URL('../frontend/dashboard.html', import.meta.url), 'utf8');
const start = html.indexOf('async function ensureActiveProjectId');
const end = html.indexOf('// Project selector toggle', start);
const fn = html.slice(start, end);
assert.ok(start > 0 && end > start, 'ensureActiveProjectId was not found in dashboard.html');

function run({ saved = null, ready = null, projects = [], failures = 0 }) {
  const placeholder = { style: {}, innerHTML: '' };
  const store = { id: saved, name: null };
  let calls = 0;
  const ctx = vm.createContext({
    ProjectContext: { getId: () => store.id, set: (p) => { store.id = String(p.id); store.name = p.name; } },
    document: { querySelector: () => placeholder },
    API_PREFIX: '/contractor',
    apiRequest: async () => { calls++; if (calls <= failures) throw new Error('offline'); return { projects }; },
    setTimeout: (f) => { f(); return 0; },                                  // no real waiting in tests
    window: { __projectsReady: ready },
    Promise, String,
  });
  vm.runInContext(fn, ctx);
  return { call: () => vm.runInContext('ensureActiveProjectId()', ctx), placeholder, store, calls: () => calls };
}

test('a saved project is used without asking anyone', async () => {
  const t = run({ saved: '7' });
  assert.equal(await t.call(), '7');
  assert.equal(t.calls(), 0);
});

test('waits for the startup project load, then uses the project it selected', async () => {
  let release; const ready = new Promise((r) => { release = r; });
  const t = run({ ready });
  const pending = t.call();
  t.store.id = '3'; release();                                                  // the startup loader sets the project and settles
  assert.equal(await pending, '3');
  assert.equal(t.calls(), 0);
});

test('when the startup load missed, it asks again and selects the first project', async () => {
  const t = run({ ready: Promise.resolve(), projects: [{ id: 5, name: 'Simbi Heights' }, { id: 6, name: 'Other' }] });
  assert.equal(await t.call(), '5');
  assert.equal(t.store.name, 'Simbi Heights');
});

test('a sleeping server is retried: two failures, then it works', async () => {
  const t = run({ ready: Promise.resolve(), projects: [{ id: 9, name: 'P' }], failures: 2 });
  assert.equal(await t.call(), '9');
  assert.equal(t.calls(), 3);
});

test('no project assigned: a calm message, not an error', async () => {
  const t = run({ ready: Promise.resolve(), projects: [] });
  assert.equal(await t.call(), null);
  assert.match(t.placeholder.innerHTML, /not assigned to a project yet/);
  assert.doesNotMatch(t.placeholder.innerHTML, /No Project Selected|⚠/);
});

test('server unreachable after retries: says so and offers to try again', async () => {
  const t = run({ ready: Promise.resolve(), failures: 99 });
  assert.equal(await t.call(), null);
  assert.equal(t.calls(), 3);
  assert.match(t.placeholder.innerHTML, /could not be reached/);
  assert.match(t.placeholder.innerHTML, /Try again/);
});

test('the three old "No Project Selected" messages are gone from the tab loaders', () => {
  assert.equal((html.match(/No Project Selected/g) || []).length, 0);
});
