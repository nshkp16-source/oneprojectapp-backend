import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCardAttachmentType } from './cardAttachmentTypes.js';

test('accepts a predefined card attachment type', () => {
  assert.deepEqual(parseCardAttachmentType({ attachmentType: 'daily_progress', customAttachmentType: '' }), {
    attachmentType: 'daily_progress',
    customAttachmentType: null,
  });
});

test('requires a bounded custom label for Other', () => {
  assert.deepEqual(parseCardAttachmentType({ attachmentType: 'other', customAttachmentType: 'Calibration certificates' }), {
    attachmentType: 'other',
    customAttachmentType: 'Calibration certificates',
  });
  assert.match(parseCardAttachmentType({ attachmentType: 'other' }).error, /Enter a custom/);
  assert.match(parseCardAttachmentType({ attachmentType: 'other', customAttachmentType: 'x'.repeat(121) }).error, /120 characters/);
});

test('keeps older clients compatible by classifying untyped attachments as Other', () => {
  assert.deepEqual(parseCardAttachmentType({}), {
    attachmentType: 'other',
    customAttachmentType: null,
  });
});

test('rejects document-management categories in execution attachments', () => {
  assert.match(parseCardAttachmentType({ attachmentType: 'method_statement' }).error, /valid attachment type/);
  assert.match(parseCardAttachmentType({ attachmentType: 'monthly_progress_report' }).error, /valid attachment type/);
});
