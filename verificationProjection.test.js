// The consultant's view of a verification request: task names and approved figures are always included,
// member identity, task ids and report details never are, and the history list stays slim.
import test from 'node:test';
import assert from 'node:assert/strict';
import { consultantProjection } from './verificationRoutes.js';

const request = {
  id: 91, status: 'pending', claimed_progress_pct: 55,
  claimed_figures: [
    { task_id: 12, title: 'Block A', weight_pct: '60', progress_pct: '50', target_quantity: '120', approved_report_count: 2, approved_quantity: '60', last_approved_date: '2026-11-05', member_email: 'a@x.test' },
    { task_id: 13, title: 'Block B', weight_pct: 40, progress_pct: 0, target_quantity: null, approved_report_count: 0, approved_quantity: 0 },
  ],
  share_evidence: false, shared_evidence: null, share_activity_summary: false, shared_activity_summary: null,
};

test('with tasks: titles, shares and approved figures are listed, without ids or member data', () => {
  const view = consultantProjection(request, { withTasks: true });
  assert.deepEqual(view.work_by_task, [
    { title: 'Block A', weight_pct: 60, progress_pct: 50, target_quantity: 120, approved_report_count: 2, approved_quantity: 60, last_approved_date: '2026-11-05' },
    { title: 'Block B', weight_pct: 40, progress_pct: 0, target_quantity: null, approved_report_count: 0, approved_quantity: 0, last_approved_date: null },
  ]);
  assert.doesNotMatch(JSON.stringify(view), /task_id|member_email|a@x\.test/);
  assert.deepEqual(view.claimed_figures, []);
  assert.equal(view.activity_summary.task_count, 2);
  assert.equal(view.activity_summary.approved_report_count, 2);
});

test('lists that do not need the breakdown stay slim', () => {
  const view = consultantProjection(request);
  assert.equal(view.work_by_task, undefined);
  assert.equal('work_by_task' in JSON.parse(JSON.stringify(view)), false);
  assert.deepEqual(view.claimed_figures, []);
});

test('older requests with no stored figures give an empty breakdown, not an error', () => {
  assert.deepEqual(consultantProjection({ ...request, claimed_figures: null }, { withTasks: true }).work_by_task, []);
});

test('report details are still shared only when the contractor shares them', () => {
  const view = consultantProjection({ ...request, share_evidence: false,
    shared_evidence: { reports: [{ work_done: 'secret' }], supporting_attachments: [], selected_evidence: [] } }, { withTasks: true });
  assert.equal(view.shared_evidence, null);
});
