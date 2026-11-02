import test from 'node:test';
import assert from 'node:assert/strict';
import * as R from './progressRules.js';

const rep = (o) => ({ validation_status: 'approved', ...o });

test('equal split always adds up to 100 and the last item takes the remainder', () => {
  assert.deepEqual(R.splitEqual(1), [100]);
  assert.deepEqual(R.splitEqual(2), [50, 50]);
  assert.deepEqual(R.splitEqual(3), [33.33, 33.33, 33.34]);
  for (let n = 1; n <= 40; n++) assert.ok(R.weightsValid(R.splitEqual(n)), `n=${n}`);
});

test('weights must be above 0 and total exactly 100', () => {
  assert.ok(R.weightsValid([60, 40]));
  assert.ok(!R.weightsValid([60, 39.99]));
  assert.ok(!R.weightsValid([100, 0]));
  assert.ok(!R.weightsValid([]));
  assert.ok(R.weightsValid([33.33, 33.33, 33.34]));
});

test('adding a task rebalances proportionally and keeps the ratios', () => {
  const out = R.rebalanceForNew([60, 40]);               // new task takes an equal third
  assert.ok(R.weightsValid(out));
  assert.equal(out.length, 3);
  assert.equal(out[2], 33.33);
  assert.ok(out[0] > out[1]);                           // 60:40 order is kept
  assert.ok(Math.abs(out[0] / out[1] - 1.5) < 0.01);
  assert.deepEqual(R.rebalanceForNew([50, 50]), [33.33, 33.33, 33.34]);                 // equal in, equal out
  assert.deepEqual(R.rebalanceForNew([33.33, 33.33, 33.34]), [25, 25, 25, 25]);
  assert.deepEqual(R.rebalanceForNew([100], 30), [70, 30]);
  assert.deepEqual(R.rebalanceForNew([]), [100]);
  assert.throws(() => R.rebalanceForNew([100], 100));
});

test('default milestone weights follow quantities only when every unit matches', () => {
  const m = { unit: 'm3' };
  assert.deepEqual(R.defaultMilestoneWeights(m, [{ planned_quantity: 300, unit: 'm3' }, { planned_quantity: 100, unit: 'M3' }]), [75, 25]);
  assert.deepEqual(R.defaultMilestoneWeights(m, [{ planned_quantity: 300, unit: 'm3' }, { planned_quantity: 100, unit: 'm2' }]), [50, 50]);
  assert.ok(R.weightsValid(R.defaultMilestoneWeights(m, [1, 1, 1].map((q) => ({ planned_quantity: q, unit: 'm3' })))));
});

test('quantity type counts approved quantity only', () => {
  const reports = [rep({ quantity_done: 40 }), { validation_status: 'rejected', quantity_done: 500 }, { validation_status: 'pending', quantity_done: 500 }];
  assert.equal(R.taskProgress('quantity', { target_quantity: 150 }, reports), 26.67);
  assert.equal(R.taskProgress('quantity', { target_quantity: 0 }, reports), 0);
  assert.equal(R.taskProgress('quantity', { target_quantity: 10 }, [rep({ quantity_done: 99 })]), 100);   // stops at 100
});

test('count type uses passed items, not failed ones', () => {
  const reports = [rep({ quantity_done: 5, quantity_failed: 1 }), rep({ quantity_done: 3, quantity_failed: 0 })];
  assert.equal(R.taskProgress('count', { target_quantity: 12 }, reports), 58.33);   // 7 passed of 12
});

test('stages type adds the weight of completed stages', () => {
  const stages = [{ id: 1, weight_pct: 20 }, { id: 2, weight_pct: 30 }, { id: 3, weight_pct: 50 }];
  assert.equal(R.taskProgress('stages', {}, [rep({ stage_id: 1 }), rep({ stage_id: 3 }), rep({ stage_id: 3 })], stages), 70);
});

test('percentage type takes the latest approved value and refuses to go backwards', () => {
  const reports = [rep({ id: 1, report_date: '2026-01-05', progress_pct: 40 }), rep({ id: 2, report_date: '2026-01-10', progress_pct: 60 }),
    { id: 3, validation_status: 'rejected', report_date: '2026-01-12', progress_pct: 95 }];
  assert.equal(R.taskProgress('percentage', {}, reports), 60);
  assert.equal(R.checkPercentageReport(55, reports) !== null, true);
  assert.equal(R.checkPercentageReport(60, reports), null);
  assert.equal(R.checkPercentageReport(101, reports) !== null, true);
});

test('hold point keeps later stages locked until it is verified', () => {
  const stages = [{ id: 1, seq: 1 }, { id: 2, seq: 2, is_hold_point: true }, { id: 3, seq: 3 }];
  assert.ok(R.stageUnlocked(stages, 2, []));
  assert.ok(!R.stageUnlocked(stages, 3, []));
  assert.ok(R.stageUnlocked(stages, 3, [2]));
});

test('activity progress is a weighted sum, not an average', () => {
  // A = 60% weight at 50% done, B = 40% weight at 25% done  ->  40
  assert.equal(R.activityProgress([{ weight_pct: 60, progress_pct: 50 }, { weight_pct: 40, progress_pct: 25 }]), 40);
  // the old average of the two would have said 37.5
  assert.equal(R.activityProgress([{ weight_pct: 100, progress_pct: 70 }]), 70);
  assert.equal(R.activityProgress([]), 0);
  assert.equal(R.activityProgressWithoutTasks({ planned_quantity: 200 }, [{ actual_quantity: 50 }]), 25);
});

test('daily entry sums approved reports and lists who contributed', () => {
  const e = R.buildDailyEntry([rep({ id: 1, task_id: 1, member_id: 9, quantity_done: 10, work_done: 'Excavated block A' }),
    rep({ id: 2, task_id: 2, member_id: 10, quantity_done: 5.5, work_done: 'Excavated block B' }),
    { id: 3, validation_status: 'rejected', task_id: 2, quantity_done: 99 }]);
  assert.equal(e.actual_quantity, 15.5);
  assert.equal(e.day_remark, 'Excavated block A; Excavated block B');
  assert.equal(e.contributions.length, 2);
});

test('certified progress only moves on a verified answer', () => {
  assert.equal(R.certifiedAfterDecision(20, { status: 'verified', claimed_progress_pct: 45 }), 45);
  assert.equal(R.certifiedAfterDecision(20, { status: 'verified_with_changes', certified_progress_pct: 35 }), 35);
  assert.equal(R.certifiedAfterDecision(20, { status: 'rejected' }), 20);
  assert.equal(R.certifiedAfterDecision(20, null), 20);
});

test('the client sees certified progress only', () => {
  const c = R.visibleProgress('Client', { claimed: 60, certified: 45, lastVerifiedAt: '2026-01-20', pendingRequests: 0 });
  assert.deepEqual(Object.keys(c).sort(), ['certified', 'lastVerifiedAt', 'verificationPending']);
  assert.equal(c.verificationPending, true);             // claimed is ahead, but the number itself is not shown
  const k = R.visibleProgress('Contractor', { claimed: 60, certified: 45 });
  assert.equal(k.gap, 15);
  assert.equal(R.visibleProgress('Consultant', { claimed: 60, certified: 45 }).claimed, 60);
});

test('milestone progress comes from certified progress of contractor activities only', () => {
  const acts = [
    { drives_milestone: true, milestone_weight_pct: 60, certified_progress_pct: 50, status: 'ongoing' },
    { drives_milestone: true, milestone_weight_pct: 40, certified_progress_pct: 100, status: 'closed' },
    { drives_milestone: false, milestone_weight_pct: 0, certified_progress_pct: 100, status: 'closed' },   // consultant activity
  ];
  assert.equal(R.milestoneCoverage(acts), 100);
  assert.equal(R.milestoneDerivedProgress(acts), 70);
});

test('one activity at 100% weight: its completion is the whole milestone', () => {
  const one = [{ drives_milestone: true, milestone_weight_pct: 100, certified_progress_pct: 100, status: 'closed' }];
  assert.equal(R.milestoneDerivedProgress(one), 100);
  assert.ok(R.canCompleteMilestone({ activities: one }).ok);
});

test('a breakdown request caps the milestone at 99 and blocks completion', () => {
  const one = [{ drives_milestone: true, milestone_weight_pct: 100, certified_progress_pct: 100, status: 'closed' }];
  assert.equal(R.effectiveMilestoneProgress({ derived: 100, breakdownOpen: true }), 99);
  assert.equal(R.effectiveMilestoneProgress({ derived: 40, breakdownOpen: true }), 40);
  const r = R.canCompleteMilestone({ activities: one, breakdownOpen: true });
  assert.ok(!r.ok);
  assert.match(r.reasons.join(' '), /breakdown/);
});

test('the consultant temporary value can only lower progress and needs a reason', () => {
  assert.equal(R.effectiveMilestoneProgress({ derived: 70, override: 40 }), 40);
  assert.equal(R.effectiveMilestoneProgress({ derived: 70, override: 90 }), 70);   // never raises
  assert.equal(R.checkOverride({ value: 40, derived: 70, reason: 'Cracks in certified slab' }), null);
  assert.notEqual(R.checkOverride({ value: 80, derived: 70, reason: 'x' }), null);
  assert.notEqual(R.checkOverride({ value: 40, derived: 70, reason: '  ' }), null);
});

test('milestone completion needs full coverage, closed activities and no open hold', () => {
  const partial = [{ drives_milestone: true, milestone_weight_pct: 60, certified_progress_pct: 100, status: 'closed' }];
  assert.ok(!R.canCompleteMilestone({ activities: partial }).ok);
  const open = [{ drives_milestone: true, milestone_weight_pct: 100, certified_progress_pct: 100, status: 'completed' }];
  assert.match(R.canCompleteMilestone({ activities: open }).reasons.join(' '), /closed/);
  const ok = [{ drives_milestone: true, milestone_weight_pct: 100, certified_progress_pct: 100, status: 'closed' }];
  assert.ok(!R.canCompleteMilestone({ activities: ok, overrideActive: true }).ok);
  assert.ok(!R.canCompleteMilestone({ activities: [] }).ok);
});

test('delay is calculated from planned and actual dates', () => {
  assert.equal(R.delayDays({ plannedEnd: '2026-02-01', actualEnd: '2026-02-06' }), 5);
  assert.equal(R.delayDays({ plannedEnd: '2026-02-01', actualEnd: '2026-01-28' }), 0);
  assert.equal(R.delayDays({ plannedEnd: '2026-02-01', status: 'ongoing', today: new Date(2026, 1, 4) }), 3);
  assert.equal(R.delayDays({ plannedEnd: '2026-02-01', status: 'completed', today: new Date(2026, 1, 4) }), 3);   // claimed only, still counting
  assert.equal(R.delayDays({ plannedEnd: '2026-02-01', status: 'closed', today: new Date(2026, 1, 4) }), 0);
  assert.equal(R.delayDays({ plannedEnd: null }), 0);
});

test('respond-by date adds the project response days', () => {
  assert.equal(R.respondByDate('2026-01-25', 7), '2026-02-01');
  assert.equal(R.respondByDate('2026-12-28', 7), '2027-01-04');
  assert.equal(R.respondByDate('bad'), null);
});
