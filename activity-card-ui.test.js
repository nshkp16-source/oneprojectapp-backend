import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import * as acorn from 'acorn';

const html = fs.readFileSync(new URL('../frontend/dashboard.html', import.meta.url), 'utf8');
const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map((match) => match[1]);
const names = ['_peDeriveStatus', '_peInfoCell', '_peCertificationPanel', '_peActivityCardHtml'];
const source = scripts.map((script) => {
  const ast = acorn.parse(script, { ecmaVersion: 'latest', sourceType: 'script' });
  return ast.body.filter((node) => node.type === 'FunctionDeclaration' && names.includes(node.id.name))
    .map((node) => script.slice(node.start, node.end)).join('\n');
}).join('\n');
for (const name of names) assert.match(source, new RegExp(`function ${name}\\(`), `${name} was not found`);

function render(card, viewerRole = 'ConsultantPM') {
  const context = {
    window: { currentUserRole: viewerRole, currentUserId: 8 },
    isWCLeader: () => true,
    escapeHtml: (value) => String(value).replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[char]),
  };
  vm.createContext(context);
  vm.runInContext(source, context);
  return vm.runInContext(
    `_peActivityCardHtml(__card, __verificationData, 'overview')`,
    Object.assign(context, { __card: card, __verificationData: { verifications: [], rework: [] } }),
  );
}

test('activity tabs expose Certification only for milestone-driving activity', () => {
  const linked = render({
    viewer_side: 'Consultant',
    activity: { id: 1, title: 'Foundation', side: 'Contractor', drives_milestone: true, activity_type: 'quantity', planned_quantity: 200, unit: 'm3' },
    tasks: [],
    progress_reports: [],
  });
  assert.match(linked, /data-pe-tab="certification"/);
  assert.match(linked, /data-pe-tab="overview"/);
  assert.match(linked, /data-pe-tab="tasks"/);
  assert.match(linked, /data-pe-tab="progress"/);
  assert.doesNotMatch(linked, /Save Execution Entry|pe-save-actual/);

  const standalone = render({
    viewer_side: 'Contractor',
    activity: { id: 2, title: 'Standalone work', side: 'Contractor', drives_milestone: false, activity_type: 'percentage' },
    tasks: [],
    progress_reports: [],
  }, 'ContractorPM');
  assert.doesNotMatch(standalone, /data-pe-tab="certification"/);

  const client = render({
    viewer_side: 'Client',
    activity: {
      id: 3, title: 'Client view', side: 'Contractor', drives_milestone: true,
      progress_pct: 65, claimed_progress_pct: 65, certified_progress_pct: 40,
      activity_type: 'quantity', planned_quantity: 200, unit: 'm3',
    },
    tasks: [{ title: 'Private task' }],
    progress_reports: [{ work_done: 'Private report' }],
  }, 'ClientPM');
  assert.match(client, /Certified progress/);
  assert.doesNotMatch(client, /Claimed 65%|Private task|Private report|data-pe-tab="tasks"/);
});

test('consultant certification tab includes approved-work review evidence and existing decision flow', () => {
  const card = {
    viewer_side: 'Consultant',
    activity: {
      id: 7, title: 'Excavate foundation', side: 'Contractor', drives_milestone: true,
      baseline_milestone_title: 'Foundation', milestone_weight_pct: 65,
      activity_type: 'quantity', planned_quantity: 200, unit: 'm3',
      progress_pct: 55, claimed_progress_pct: 55, certified_progress_pct: 30,
    },
    tasks: [{ id: 12, title: 'Block A', weight_pct: 100, progress_pct: 55, target_quantity: 200, assigned_members: [], stages: [] }],
    progress_reports: [{
      id: 31, task_id: 12, task_title: 'Block A', report_date: '2026-05-04',
      member_email: 'engineer@example.test', work_done: 'Excavated to formation level',
      quantity_done: 50, manpower: '5 workers', equipment: 'Excavator',
    }],
  };
  const verification = {
    id: 91, kind: 'progress', status: 'pending', cut_off_date: '2026-05-04',
    respond_by: '2026-05-11', claimed_progress_pct: 55,
    claimed_figures: [{ title: 'Block A', weight_pct: 100, progress_pct: 55, target_quantity: 200, approved_quantity: 110 }],
    signers: [], request_note: 'Please review this period.',
  };
  const context = {
    window: { currentUserRole: 'ConsultantPM', currentUserId: 8 },
    isWCLeader: () => true,
    escapeHtml: (value) => String(value).replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[char]),
  };
  vm.createContext(context);
  vm.runInContext(source, context);
  const content = vm.runInContext(
    `_peCertificationPanel(__activity, __tasks, __reports, [__verification], [], 'Consultant')`,
    Object.assign(context, { __activity: card.activity, __tasks: card.tasks, __reports: card.progress_reports, __verification: verification }),
  );
  assert.match(content, /Foundation/);
  assert.match(content, /Block A/);
  assert.match(content, /Excavated to formation level/);
  assert.match(content, /5 workers/);
  assert.match(content, /data-pe-form="decision"/);
  assert.match(content, /data-pe-decision-status/);
  assert.doesNotMatch(content, /data-action="certify"/);
});

test('an activity is delayed only after its end date while still incomplete', () => {
  const today = new Date();
  const endDate = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1);
  const futureDate = new Date(today.getFullYear(), today.getMonth(), today.getDate() + 1);
  const iso = (date) => `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
  const context = { window: {}, isWCLeader: () => true, escapeHtml: String };
  vm.createContext(context);
  vm.runInContext(source, context);
  assert.equal(vm.runInContext(`_peDeriveStatus({ status: 'ongoing', progress_pct: 0, end_date: '${iso(endDate)}' }).label`, context), 'Delayed');
  assert.equal(vm.runInContext(`_peDeriveStatus({ status: 'ongoing', progress_pct: 0, end_date: '${iso(futureDate)}' }).label`, context), 'Ongoing');
  assert.equal(vm.runInContext(`_peDeriveStatus({ status: 'ongoing', progress_pct: 100, end_date: '${iso(endDate)}' }).label`, context), 'Completed');
});
