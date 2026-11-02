import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('./workflow-dashboard.js', import.meta.url), 'utf8');

function setup({ legacyActivityCard = true } = {}) {
  const window = {
    _wcMemberView: () => '<div>legacy member</div>',
    _wcPMView: () => '<div>legacy leader</div>',
    _wcWireDetailButtons: () => {},
  };
  if (legacyActivityCard) {
    window._peActivityCardHtml = () => '<main>activity card</main>';
    window._peWireActivityCard = () => {};
  }
  const context = {
    window,
    escapeHtml: (value) => String(value).replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[char]),
  };
  vm.createContext(context);
  vm.runInContext(source, context);
  return window;
}

test('member report form renders controls according to activity type', () => {
  const window = setup();
  const quantity = window._wcMemberView(
    { id: 5, title: 'Excavation', activity_type: 'quantity', activity_unit: 'm3' }, [],
  );
  assert.match(quantity, /Quantity done \(m3\)/);
  assert.match(quantity, /wf-quantity-5/);
  assert.doesNotMatch(quantity, /wf-percentage-5/);

  const count = window._wcMemberView({ id: 6, activity_type: 'count' }, []);
  assert.match(count, /Items completed/);
  assert.match(count, /wf-failed-6/);

  const stages = window._wcMemberView({
    id: 7,
    activity_type: 'stages',
    stages: [
      { id: 1, title: 'Steel', seq: 1, is_hold_point: true },
      { id: 2, title: 'Pour', seq: 2 },
    ],
  }, []);
  assert.match(stages, /Steel \(hold point\)/);
  assert.match(stages, /Pour \(locked until earlier hold point is verified\)/);
});

test('leader view retains existing task controls and adds audited void controls', () => {
  const window = setup();
  const html = window._wcPMView(
    { id: 9, activity_type: 'count', stages: [] },
    [{ id: 22, member_email: 'member@example.test', report_date: '2026-03-10', validation_status: 'approved', quantity_done: 4, quantity_failed: 1 }],
  );
  assert.match(html, /legacy leader/);
  assert.match(html, /Correction audit/);
  assert.match(html, /Void report/);
  assert.match(html, /4 completed, 1 failed/);
});

test('activity workflow controls are hidden for clients and rendered for activities', () => {
  const window = setup();
  const client = window._peActivityCardHtml({
    viewer_side: 'Client',
    activity: { id: 1, side: 'Contractor' },
    tasks: [],
  });
  assert.equal(client, '<main>activity card</main>');

  const html = window._peActivityCardHtml({
    viewer_side: 'Contractor',
    can_add_task: true,
    activity: { id: 2, side: 'Contractor', baseline_milestone_id: 3 },
    tasks: [{ stages: [{ id: 7, title: 'Inspection', is_hold_point: true }] }],
  });
  assert.match(html, /Progress verification/);
  assert.match(html, /Hold point inspection/);
  assert.match(html, /Completion certification/);
  assert.match(html, /Inspection/);
  assert.match(html, /Linked milestone/);
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
