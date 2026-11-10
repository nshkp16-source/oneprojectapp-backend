export function createCloudinaryUploadTracker({ scheduleCloudinaryUpload, cloudinary }) {
  let pending = [];

  return {
    async upload(buffer, name, folder) {
      const result = await scheduleCloudinaryUpload(buffer, name, folder);
      if (result?.public_id) {
        pending.push({
          id: result.public_id,
          resourceType: result.resource_type || 'raw',
        });
      }
      return result;
    },
    keep(uploaded) {
      if (!uploaded?.public_id) return;
      pending = pending.filter((file) => file.id !== uploaded.public_id);
    },
    keepAll() {
      pending = [];
    },
    async discard() {
      const files = pending;
      pending = [];
      if (!files.length) return;
      if (!cloudinary?.uploader) {
        console.error(`[upload cleanup] storage unavailable for ${files.length} uploaded file(s).`);
        return;
      }
      await Promise.all(files.map(async ({ id, resourceType }) => {
        try {
          const result = await cloudinary.uploader.destroy(id, { resource_type: resourceType });
          if (!['ok', 'not found'].includes(result?.result))
            console.error('[upload cleanup] could not delete', id, result?.result || 'unknown result');
        } catch (err) {
          console.error('[upload cleanup] could not delete', id, err.message);
        }
      }));
    },
  };
}
