import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import * as acorn from 'acorn';

const html = fs.readFileSync(new URL('../frontend/dashboard.html', import.meta.url), 'utf8');
const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map((match) => match[1]);
const names = ['_wcFmtDate', '_peDeriveStatus', '_peCertificationPanel', '_peActivityCardHtml',
  '_supportingAttachmentTypeOptions', '_supportingAttachmentTypeLabel', '_safeHttpsUrl', '_fileDisplayName', '_thumbUrl',
  '_evidenceFileAttrs', '_evidenceFileRowHtml', '_evidencePhotosHtml', '_evidenceFilesHtml', '_peRequestEvidencePickerHtml',
  '_peWorkByTaskHtml'];
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
  const linkedCard = {
    viewer_side: 'Consultant',
    activity: { id: 1, title: 'Foundation', side: 'Contractor', drives_milestone: true, activity_type: 'quantity', planned_quantity: 200, unit: 'm3' },
    tasks: [],
    progress_reports: [],
  };
  const linked = render(linkedCard);
  assert.match(linked, /data-pe-tab="certification"/);
  assert.match(linked, /data-pe-tab="overview"/);
  assert.doesNotMatch(linked, /data-pe-tab="tasks"/);   // a consultant does not get the contractor's internal task breakdown
  assert.match(linked, /data-pe-tab="progress"/);
  assert.match(linked, /data-pe-tab="attachments"/);
  assert.match(linked, /class="detail-tab"/);
  assert.doesNotMatch(linked, /rc-btn--approve/);
  assert.doesNotMatch(linked, /Activity dates|Created by|>Title</);
  assert.doesNotMatch(linked, /Foundation/);
  assert.doesNotMatch(linked, /Save Execution Entry|pe-save-actual/);
  const consultantProgress = render({
    ...linkedCard,
    activity_summary: { approved_report_count: 3, approved_quantity: 42 },
  });
  assert.match(consultantProgress, /3 approved reports/);
  assert.match(consultantProgress, /42 m3 reported/);
  assert.match(consultantProgress, /details and files are private here/);
  assert.doesNotMatch(consultantProgress, /No approved task reports have been recorded/);
  const withTasks = render({
    ...linkedCard,
    activity_summary: { approved_report_count: 3, approved_quantity: 42 },
    work_by_task: [
      { title: 'Block A', weight_pct: 60, progress_pct: 50, target_quantity: 120, approved_report_count: 2, approved_quantity: 60, last_approved_date: '2026-11-05' },
      { title: 'Block B', weight_pct: 40, progress_pct: 0, target_quantity: 80, approved_report_count: 0, approved_quantity: 0, last_approved_date: null },
    ],
  });
  assert.match(withTasks, /Approved work by task/);
  assert.match(withTasks, />Block A</);
  assert.match(withTasks, /60 of 120 m3/);
  assert.match(withTasks, />Block B</);                       // a task with no approved work is still listed, so the shares add up
  assert.match(withTasks, /No approved work yet/);
  assert.match(withTasks, /2026-11-05/);
  assert.match(withTasks, /Claimed activity progress[^<]*<\/td><td[^>]*>30%/);   // 60% x 50% = 30% (weighted, never an average)
  assert.doesNotMatch(withTasks, /@|member|Reported by/i);   // no member identity
  const wrapperContext = {
    window: { currentUserRole: 'ConsultantPM', currentUserId: 8 },
    isWCLeader: () => true,
    escapeHtml: String,
    __card: linkedCard,
  };
  vm.createContext(wrapperContext);
  vm.runInContext(source, wrapperContext);
  assert.doesNotThrow(() => vm.runInContext(`_peActivityCardHtml(__card)`, wrapperContext));
  const withAttachments = render({
    ...linkedCard, can_edit_activity: true,
    attachments: [{ id: 5, file_name: 'foundation.dwg', file_url: 'https://files.test/foundation.dwg' }],
  }, 'ContractorPM');
  assert.match(withAttachments, /foundation\.dwg/);
  assert.match(withAttachments, /data-pe-attachment-upload/);
  assert.match(withAttachments, /data-pe-attachment-delete="5"/);

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
    activity_summary: { task_count: 1, approved_report_count: 1, approved_quantity: 50, planned_quantity: 200 },
    signers: [], request_note: 'Please review this period.',
    work_by_task: [{ title: 'Block A', weight_pct: 100, progress_pct: 55, target_quantity: 200, approved_report_count: 1, approved_quantity: 110, last_approved_date: '2026-05-04' }],
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
  assert.match(content, /Activity tasks/);
  assert.match(content, /Approved reports/);
  assert.match(content, /Work covered by this request/);
  assert.match(content, />Block A</);                         // the approved task and its figures are shown
  assert.match(content, /110 of 200 m3/);
  assert.doesNotMatch(content, /Excavated to formation level|5 workers|engineer@example\.test|Excavator/);   // report details stay private unless shared
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

const STORAGE_ID = 'work_center/progress/k3j2h1g0f9e8d7c6b5a4';
const evidenceCard = {
  viewer_side: 'Contractor', can_edit_activity: true,
  activity: { id: 9, title: 'Slab', side: 'Contractor', drives_milestone: false, activity_type: 'quantity', planned_quantity: 100, unit: 'm3' },
  tasks: [{ id: 1, title: 'Pour', weight_pct: 100, progress_pct: 40, target_quantity: 100, assigned_members: [], stages: [] }],
  progress_reports: [{
    id: 5, task_id: 1, task_title: 'Pour', report_date: '2026-11-02', member_email: 'a@x.test', work_done: 'Poured bay 1', quantity_done: 40,
    photos: [{ id: 1, file_name: 'bay-1-front.jpg', file_url: `https://res.cloudinary.com/demo/image/upload/v1/${STORAGE_ID}-1.jpg` }],
    supporting_attachments: [
      { id: 7, file_name: 'Cube test results.pdf', file_url: `https://res.cloudinary.com/demo/raw/upload/v1/${STORAGE_ID}-2.pdf`, mime_type: 'application/pdf', attachment_type: 'quality_test', custom_attachment_type: null },
      { id: 8, file_name: 'Delivery note 14.pdf', file_url: `https://res.cloudinary.com/demo/raw/upload/v1/${STORAGE_ID}-3.pdf`, mime_type: 'application/pdf', attachment_type: 'other', custom_attachment_type: 'Concrete tickets' },
    ],
  }],
};

test('Progress tab shows each report\'s photos and documents by their real names, with preview and download', () => {
  const html = render(evidenceCard, 'ContractorPM');
  assert.match(html, />Evidence</);
  assert.match(html, /1 photo · 2 files/);
  assert.match(html, /bay-1-front\.jpg/);
  assert.match(html, /Cube test results\.pdf/);
  assert.match(html, /Delivery note 14\.pdf/);
  assert.match(html, /Other: Concrete tickets/);
  assert.equal((html.match(/data-ev-preview/g) || []).length, 3);     // one photo thumbnail and two documents
  assert.equal((html.match(/data-ev-download/g) || []).length, 2);    // a click target to download each document
  assert.match(html, /c_fill,w_220,h_165/);                           // photos are shown as thumbnails
  assert.doesNotMatch(html, />[^<]*k3j2h1g0f9e8d7c6b5a4[^<]*</);     // the storage name is never shown as text
  assert.doesNotMatch(html, /<a [^>]*href="https:\/\/res\.cloudinary/); // no direct links that would save under the storage name
});

test('a report without evidence shows None and unsafe links are not clickable', () => {
  const html = render({
    ...evidenceCard,
    progress_reports: [{ ...evidenceCard.progress_reports[0], photos: [], supporting_attachments: [
      { id: 9, file_name: 'x.pdf', file_url: 'javascript:alert(1)', attachment_type: 'other', custom_attachment_type: 'T' }] },
    { ...evidenceCard.progress_reports[0], id: 6, photos: [], supporting_attachments: [] }],
  }, 'ContractorPM');
  assert.match(html, />None</);
  assert.doesNotMatch(html, /javascript:/);
});

test('evidence rows use the original name even when only a storage URL is known', () => {
  const context = { escapeHtml: String };
  vm.createContext(context);
  vm.runInContext(source, context);
  assert.equal(vm.runInContext(`_fileDisplayName({ file_url: 'https://x.test/${STORAGE_ID}.pdf' })`, context), 'Attachment');
  assert.equal(vm.runInContext(`_fileDisplayName({ attachment_name: 'Site plan.dwg' })`, context), 'Site plan.dwg');
});

test('verification evidence picker offers individual files and photo previews', () => {
  const context = {
    escapeHtml: (value) => String(value).replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[char]),
  };
  vm.createContext(context);
  vm.runInContext(source, context);
  const reports = [{
    id: 21, task_title: 'Pour slab', report_date: '2026-11-02',
    attachment_name: 'Legacy ticket.pdf', attachment_url: 'https://files.test/legacy.pdf',
    photos: [{ id: 31, file_name: 'Pour photo.jpg', file_url: 'https://res.cloudinary.com/demo/image/upload/v1/pour.jpg' }],
    supporting_attachments: [{
      id: 41, file_name: 'Test certificate.pdf', file_url: 'https://files.test/test.pdf',
      mime_type: 'application/pdf', attachment_type: 'quality_test',
    }],
  }];
  const html = vm.runInContext(`_peRequestEvidencePickerHtml(__reports)`, Object.assign(context, { __reports: reports }));
  assert.match(html, /Choose evidence to share/);
  assert.match(html, /Pour photo\.jpg/);
  assert.match(html, /c_fill,w_220,h_165/);
  assert.match(html, /<img /);
  assert.match(html, /Legacy ticket\.pdf/);
  assert.match(html, /Test certificate\.pdf/);
  assert.match(html, /name="selectedEvidence"/);
  assert.match(html, /legacy_attachment/);
  assert.match(html, /supporting_attachment/);
  assert.match(html, /type&quot;:&quot;photo/);
});
