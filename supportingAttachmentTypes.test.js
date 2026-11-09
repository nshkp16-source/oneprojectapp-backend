import test from 'node:test';
import assert from 'node:assert/strict';
import { parseSupportingAttachmentType } from './supportingAttachmentTypes.js';

test('accepts a predefined supporting attachment title', () => {
  assert.deepEqual(parseSupportingAttachmentType({
    attachmentType: 'daily_progress',
    customAttachmentType: '',
  }), { attachmentType: 'daily_progress', customAttachmentType: null });
});

test('requires a valid predefined type or bounded custom title for Other', () => {
  assert.deepEqual(parseSupportingAttachmentType({
    attachmentType: 'other',
    customAttachmentType: 'Calibration records',
  }), { attachmentType: 'other', customAttachmentType: 'Calibration records' });
  assert.match(parseSupportingAttachmentType({ attachmentType: 'other' }).error, /custom title/);
  assert.match(parseSupportingAttachmentType({
    attachmentType: 'other',
    customAttachmentType: 'x'.repeat(121),
  }).error, /120 characters/);
  assert.match(parseSupportingAttachmentType({}).error, /valid supporting attachment title/);
});

test('rejects document-management categories from supporting evidence', () => {
  assert.match(parseSupportingAttachmentType({ attachmentType: 'method_statement' }).error, /valid supporting attachment title/);
});
