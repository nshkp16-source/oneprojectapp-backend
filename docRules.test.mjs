import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeFolderName, canonicalFolder, folderCode, projectCode, formatDocNumber, revisionLetter, validDate, daysOverdue, contentTypeFor } from './docRules.js';

test('folder names are tidied and "Draft" is reserved', () => {
  assert.equal(normalizeFolderName('  Site   Photos  '), 'Site Photos');
  assert.equal(normalizeFolderName(''), '');
  assert.equal(normalizeFolderName(null), '');
  assert.throws(() => normalizeFolderName('draft'), e => e.code === 'RESERVED');
  assert.throws(() => normalizeFolderName(' Drafts '), e => e.code === 'RESERVED');
  assert.equal(normalizeFolderName('x'.repeat(100)).length, 60);
});

test('a typed folder reuses an existing spelling instead of creating a near-duplicate', () => {
  const existing = ['Drawing', 'Progress Report'];
  assert.equal(canonicalFolder('drawings', existing), 'Drawing');
  assert.equal(canonicalFolder('DRAWING', existing), 'Drawing');
  assert.equal(canonicalFolder('progress  report', existing), 'Progress Report');
  assert.equal(canonicalFolder('Site Photos', existing), 'Site Photos');
  assert.equal(canonicalFolder('class', ['Clas']), 'class'); // "ss" is not treated as a plural
});

test('document numbers', () => {
  assert.equal(folderCode('Drawing'), 'DWG');
  assert.equal(folderCode('Progress Report'), 'PR');
  assert.equal(folderCode('Request for Information (RFI)'), 'RFI');
  assert.equal(folderCode('Site Photos'), 'SP');
  assert.equal(folderCode('Photos'), 'PHO');
  assert.equal(folderCode(''), 'DOC');
  assert.equal(projectCode('Simbi Heights Phase 2'), 'SHP2');
  assert.equal(projectCode('Kigali'), 'KIGA');
  assert.equal(projectCode(''), 'PRJ');
  assert.equal(formatDocNumber('SH', 'Drawing', 7), 'SH-DWG-007');
  assert.equal(formatDocNumber('SH', 'Drawing', 1234), 'SH-DWG-1234');
});

test('revision letters', () => {
  assert.deepEqual([0, 1, 2, 25, 26, 27].map(revisionLetter), ['A', 'B', 'C', 'Z', 'AA', 'AB']);
  assert.equal(revisionLetter(-3), 'A');
  assert.equal(revisionLetter('x'), 'A');
});

test('dates', () => {
  assert.equal(validDate('2026-11-05'), '2026-11-05');
  assert.equal(validDate('2026-02-30'), null);
  assert.equal(validDate('05/11/2026'), null);
  assert.equal(validDate(''), null);
  const today = new Date(2026, 10, 5);                       // 5 Nov 2026 (local)
  assert.equal(daysOverdue('2026-11-05', today), null);       // due today is not late yet
  assert.equal(daysOverdue('2026-11-06', today), null);
  assert.equal(daysOverdue('2026-11-02', today), 3);
  assert.equal(daysOverdue('2026-11-02T10:00:00.000Z', today), 3);
  assert.equal(daysOverdue(null, today), null);
});

test('content types', () => {
  assert.equal(contentTypeFor('a.PDF'), 'application/pdf');
  assert.equal(contentTypeFor('plan.dwg'), 'application/acad');
  assert.equal(contentTypeFor('noext'), 'application/octet-stream');
});
