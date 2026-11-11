// Pure rules for activities, tasks, weights, claimed and certified progress, and milestone derivation.
// No database or Express code here, so every rule can be tested on its own (same idea as docRules.js).
//
// Vocabulary
//   claimed   = progress approved by a leader of the contractor side
//   certified = progress verified by the consultant (this is what milestones and the client use)
//   weights   = percentages that add up to exactly 100 (task weights inside an activity,
//               activity weights inside a milestone)

export const ACTIVITY_TYPES = ['quantity', 'count', 'stages', 'percentage'];

const round2 = (x) => Math.round((Number(x) + Number.EPSILON) * 100) / 100;
const clampPct = (x) => Math.min(100, Math.max(0, Number(x) || 0));
const cents = (w) => Math.round(Number(w) * 100);
const fromCents = (c) => c / 100;

// ── weights ──────────────────────────────────────────────────────────────────

/** Equal split that always adds up to 100. The last item takes the rounding remainder (3 -> 33.33, 33.33, 33.34). */
export function splitEqual(n) {
  const count = Math.floor(Number(n) || 0);
  if (count <= 0) return [];
  const base = Math.round(10000 / count);
  const out = Array(count).fill(fromCents(base));
  out[count - 1] = fromCents(10000 - base * (count - 1));
  return out;
}

/** True when every weight is above 0 and the total is exactly 100 (checked in hundredths, so no float noise). */
export function weightsValid(weights) {
  if (!Array.isArray(weights) || !weights.length) return false;
  if (weights.some((w) => !(Number(w) > 0) || Number(w) > 100)) return false;
  return weights.reduce((t, w) => t + cents(w), 0) === 10000;
}

/**
 * Add one item to an existing set. The new item takes `newWeight` (default: an equal share) and the
 * existing items are scaled down in proportion, so their ratios are kept. Returns the full list with
 * the new item last. Rounding leftovers go to the largest existing weight.
 */
export function rebalanceForNew(existing, newWeight) {
  const list = (existing || []).map(Number);
  if (!list.length) return [100];
  const oldCents = list.map(cents);
  // all existing weights equal (within a cent) and no explicit new weight: this is an equal split again
  if (newWeight == null && Math.max(...oldCents) - Math.min(...oldCents) <= 1) return splitEqual(list.length + 1);
  const newC = newWeight == null ? Math.round(10000 / (list.length + 1)) : cents(newWeight);
  if (!(newC > 0) || newC >= 10000) throw new Error('The new weight must be above 0 and below 100.');
  const room = 10000 - newC;
  const oldC = oldCents;
  const oldSum = oldC.reduce((t, c) => t + c, 0);
  const scaled = oldC.map((c) => Math.max(1, Math.round((c * room) / oldSum)));
  const diff = room - scaled.reduce((t, c) => t + c, 0);
  const biggest = scaled.indexOf(Math.max(...scaled));
  scaled[biggest] += diff;
  return [...scaled.map(fromCents), fromCents(newC)];
}

/** Reallocate the remaining positive weights to 100 after an item is removed. */
export function rebalanceAfterRemoval(remaining) {
  if (!Array.isArray(remaining)) throw new Error('Remaining weights must be a list.');
  if (!remaining.length) return [];
  const weights = remaining.map(Number);
  if (weights.some((weight) => !Number.isFinite(weight) || weight <= 0 || weight > 100))
    throw new Error('Remaining weights must be above 0 and no greater than 100.');
  const total = weights.reduce((sum, weight) => sum + cents(weight), 0);
  if (!(total > 0)) throw new Error('Remaining weights must have a positive total.');
  const scaled = weights.map((weight) => Math.max(1, Math.round((cents(weight) * 10000) / total)));
  const difference = 10000 - scaled.reduce((sum, weight) => sum + weight, 0);
  const largest = scaled.indexOf(Math.max(...scaled));
  scaled[largest] += difference;
  return scaled.map(fromCents);
}

/**
 * Default activity weights inside a milestone. When every activity uses the same unit as the milestone,
 * weights follow the planned quantities. Otherwise they are split equally.
 * activities: [{ planned_quantity, unit }], milestone: { unit }
 */
export function defaultMilestoneWeights(milestone, activities) {
  const n = (activities || []).length;
  if (!n) return [];
  const unit = String(milestone?.unit || '').trim().toLowerCase();
  const same = unit && activities.every((a) => String(a.unit || '').trim().toLowerCase() === unit && Number(a.planned_quantity) > 0);
  if (!same) return splitEqual(n);
  const total = activities.reduce((t, a) => t + Number(a.planned_quantity), 0);
  const raw = activities.map((a) => Math.max(1, Math.round((Number(a.planned_quantity) / total) * 10000)));
  const diff = 10000 - raw.reduce((t, c) => t + c, 0);
  raw[raw.indexOf(Math.max(...raw))] += diff;
  return raw.map(fromCents);
}

// ── task progress, one rule per activity type ────────────────────────────────

const approvedOnly = (reports) => (reports || []).filter((r) => r && r.validation_status === 'approved');

/**
 * Progress of one task, from its approved reports only.
 *  quantity   : quantity done / task target
 *  count      : passed items (done minus failed) / task target
 *  stages     : total weight of the stages that an approved report marks as done
 *  percentage : the latest approved cumulative percentage
 */
export function taskProgress(type, task, reports, stages = []) {
  const ok = approvedOnly(reports);
  if (type === 'quantity' || type === 'count') {
    const target = Number(task?.target_quantity);
    if (!(target > 0)) return 0;
    const done = ok.reduce((t, r) => {
      const d = Number(r.quantity_done) || 0;
      return t + (type === 'count' ? Math.max(0, d - (Number(r.quantity_failed) || 0)) : d);
    }, 0);
    return round2(clampPct((done / target) * 100));
  }
  if (type === 'stages') {
    const done = new Set(ok.map((r) => r.stage_id).filter((id) => id != null));
    const total = (stages || []).reduce((t, s) => t + (done.has(s.id) ? Number(s.weight_pct) || 0 : 0), 0);
    return round2(clampPct(total));
  }
  if (type === 'percentage') {
    if (!ok.length) return 0;
    const latest = [...ok].sort((a, b) =>
      String(a.report_date).localeCompare(String(b.report_date)) || (Number(a.id) || 0) - (Number(b.id) || 0)).pop();
    return round2(clampPct(latest.progress_pct));
  }
  throw new Error(`Unknown activity type: ${type}`);
}

/** A percentage report may not go backwards. Returns an error message, or null when it is fine. */
export function checkPercentageReport(newPct, reports) {
  const pct = Number(newPct);
  if (!Number.isFinite(pct) || pct < 0 || pct > 100) return 'The percentage must be between 0 and 100.';
  const last = taskProgress('percentage', null, reports);
  if (pct < last) return `The percentage is cumulative and cannot be lower than the last approved value (${last}%).`;
  return null;
}

/** A stage after a hold point stays locked until the hold point is verified. stages are in order (seq). */
export function stageUnlocked(stages, stageId, verifiedHoldStageIds = []) {
  const ordered = [...(stages || [])].sort((a, b) => a.seq - b.seq);
  const index = ordered.findIndex((s) => s.id === stageId);
  if (index < 0) return false;
  const verified = new Set(verifiedHoldStageIds);
  return ordered.slice(0, index).every((s) => !s.is_hold_point || verified.has(s.id));
}

// ── activity progress ────────────────────────────────────────────────────────

/** Weighted sum of task progress. tasks: [{ weight_pct, progress_pct }]. Never an average. */
export function activityProgress(tasks) {
  if (!tasks?.length) return 0;
  const sum = tasks.reduce((t, k) => t + (Number(k.weight_pct) || 0) * clampPct(k.progress_pct), 0);
  return round2(clampPct(sum / 100));
}

/** An activity with no tasks (leader works directly): quantity done / planned quantity. */
export function activityProgressWithoutTasks(activity, entries) {
  const planned = Number(activity?.planned_quantity);
  if (!(planned > 0)) return 0;
  const done = (entries || []).reduce((t, e) => t + (Number(e.actual_quantity) || 0), 0);
  return round2(clampPct((done / planned) * 100));
}

/** The daily execution entry built from the approved reports of one activity on one date. */
export function buildDailyEntry(reports) {
  const ok = approvedOnly(reports);
  return {
    actual_quantity: round2(ok.reduce((t, r) => t + (Number(r.quantity_done) || 0), 0)),
    day_remark: ok.map((r) => String(r.work_done || '').trim()).filter(Boolean).join('; '),
    contributions: ok.map((r) => ({
      report_id: r.id, task_id: r.task_id, member_id: r.member_id,
      quantity_done: r.quantity_done == null ? null : Number(r.quantity_done),
      progress_pct: r.progress_pct == null ? null : Number(r.progress_pct),
    })),
  };
}

// ── claimed and certified ────────────────────────────────────────────────────

/** Certified progress after a consultant answer. Rejected and pending requests change nothing. */
export function certifiedAfterDecision(previousCertified, decision) {
  if (!decision) return round2(clampPct(previousCertified));
  if (decision.status === 'verified') return round2(clampPct(decision.claimed_progress_pct));
  if (decision.status === 'verified_with_changes') return round2(clampPct(decision.certified_progress_pct));
  return round2(clampPct(previousCertified));
}

/** What a viewer may see. The client side only ever sees certified progress. */
export function visibleProgress(viewerSide, { claimed, certified, lastVerifiedAt = null, pendingRequests = 0 }) {
  const cert = round2(clampPct(certified));
  if (viewerSide === 'Contractor' || viewerSide === 'Consultant') {
    const cl = round2(clampPct(claimed));
    return { claimed: cl, certified: cert, gap: round2(Math.max(0, cl - cert)), lastVerifiedAt, verificationPending: pendingRequests > 0 };
  }
  return { certified: cert, lastVerifiedAt, verificationPending: pendingRequests > 0 || round2(clampPct(claimed)) > cert };
}

// ── milestones ───────────────────────────────────────────────────────────────

/** Share of the milestone covered by contractor activities (weights of the activities that drive it). */
export function milestoneCoverage(activities) {
  return round2((activities || []).filter((a) => a.drives_milestone).reduce((t, a) => t + (Number(a.milestone_weight_pct) || 0), 0));
}

/** Derived milestone progress: weighted sum of certified activity progress, contractor activities only. */
export function milestoneDerivedProgress(activities) {
  const sum = (activities || []).filter((a) => a.drives_milestone)
    .reduce((t, a) => t + (Number(a.milestone_weight_pct) || 0) * clampPct(a.certified_progress_pct), 0);
  return round2(clampPct(sum / 100));
}

/**
 * The figure the schedule reads (milestones.progress_pct) for a derived milestone.
 *  - the consultant's temporary value applies only when it lowers the derived value
 *  - while a breakdown request is open the milestone is capped at 99
 */
export function effectiveMilestoneProgress({ derived, override = null, breakdownOpen = false }) {
  let value = round2(clampPct(derived));
  if (override != null && Number(override) < value) value = round2(clampPct(override));
  return breakdownOpen ? Math.min(value, 99) : value;
}

/** A temporary value must be lower than the derived progress and come with a reason. Returns an error or null. */
export function checkOverride({ value, derived, reason }) {
  const v = Number(value);
  if (!Number.isFinite(v) || v < 0 || v > 100) return 'The value must be between 0 and 100.';
  if (!String(reason || '').trim()) return 'A reason is required.';
  if (v >= round2(clampPct(derived))) return 'A temporary value can only lower the progress that the activities give.';
  return null;
}

/** Can the milestone be completed? Returns { ok, reasons }. */
export function canCompleteMilestone({ activities, breakdownOpen = false, overrideActive = false }) {
  const reasons = [];
  const drivers = (activities || []).filter((a) => a.drives_milestone);
  if (!drivers.length) reasons.push('No contractor activity is linked to this milestone.');
  if (milestoneCoverage(activities) !== 100) reasons.push('Activity weights must add up to 100.');
  if (drivers.some((a) => a.status !== 'closed')) reasons.push('Every linked activity must be closed (completion certified).');
  if (breakdownOpen) reasons.push('A breakdown request is open.');
  if (overrideActive) reasons.push('A temporary value set by the consultant is still active.');
  return { ok: reasons.length === 0, reasons };
}

// ── delay ────────────────────────────────────────────────────────────────────

const dayNumber = (value) => {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(value || ''));
  return m ? Date.UTC(+m[1], +m[2] - 1, +m[3]) / 86400000 : null;
};

/** Delay in whole days, calculated: actual finish (or today, while still open) against the planned end. */
export function delayDays({ plannedEnd, actualEnd = null, status = 'ongoing', today = new Date() }) {
  const planned = dayNumber(plannedEnd);
  if (planned == null) return 0;
  if (actualEnd) return Math.max(0, Math.round(dayNumber(actualEnd) - planned));
  if (status === 'closed') return 0;   // 'completed' is only claimed, so the delay keeps counting until it is certified
  const t = Date.UTC(today.getFullYear(), today.getMonth(), today.getDate()) / 86400000;
  return Math.max(0, Math.round(t - planned));
}

/** Response date of a verification request: requested date plus the project's response days. */
export function respondByDate(requestedOn, days = 7) {
  const base = dayNumber(requestedOn);
  if (base == null) return null;
  return new Date((base + Math.max(1, Math.floor(Number(days) || 7))) * 86400000).toISOString().slice(0, 10);
}
