import test from 'node:test';
import assert from 'node:assert/strict';
import { createCloudinaryUploadTracker } from './cloudinaryUploadTracker.js';

function setup({ failOn = null, destroyFails = false } = {}) {
  const stored = new Set();
  let uploads = 0;
  const tracker = createCloudinaryUploadTracker({
    scheduleCloudinaryUpload: async () => {
      uploads += 1;
      if (uploads === failOn) throw new Error('Storage unavailable.');
      const result = { public_id: `file-${uploads}`, resource_type: 'image' };
      stored.add(result.public_id);
      return result;
    },
    cloudinary: {
      uploader: {
        destroy: async (id) => {
          if (destroyFails) throw new Error('Storage unavailable.');
          stored.delete(id);
          return { result: 'ok' };
        },
      },
    },
  });
  return { stored, tracker };
}

test('discard removes uploaded files that have no committed database row', async () => {
  const { stored, tracker } = setup();
  await tracker.upload(Buffer.from('one'), 'one.jpg', 'test');
  await tracker.upload(Buffer.from('two'), 'two.jpg', 'test');
  await tracker.discard();
  assert.equal(stored.size, 0);
});

test('kept files survive cleanup when a later operation fails', async () => {
  const { stored, tracker } = setup();
  const saved = await tracker.upload(Buffer.from('one'), 'one.jpg', 'test');
  tracker.keep(saved);
  await tracker.upload(Buffer.from('two'), 'two.jpg', 'test');
  await tracker.discard();
  assert.deepEqual([...stored], [saved.public_id]);
});

test('all uploaded files can be retained once their transaction commits', async () => {
  const { stored, tracker } = setup();
  await tracker.upload(Buffer.from('one'), 'one.jpg', 'test');
  tracker.keepAll();
  await tracker.discard();
  assert.equal(stored.size, 1);
});

test('a later upload failure leaves earlier uploads available for cleanup', async () => {
  const { stored, tracker } = setup({ failOn: 2 });
  await tracker.upload(Buffer.from('one'), 'one.jpg', 'test');
  await assert.rejects(tracker.upload(Buffer.from('two'), 'two.jpg', 'test'));
  await tracker.discard();
  assert.equal(stored.size, 0);
});

test('cleanup logs storage failures without hiding the route error', async () => {
  const { tracker } = setup({ destroyFails: true });
  await tracker.upload(Buffer.from('one'), 'one.jpg', 'test');
  await assert.doesNotReject(tracker.discard());
});
