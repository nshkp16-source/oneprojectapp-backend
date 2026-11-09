export const SUPPORTING_ATTACHMENT_TYPES = Object.freeze([
  'site_photos',
  'daily_progress',
  'materials_delivery',
  'equipment',
  'manpower',
  'quality_test',
  'inspection_hold_point',
  'issue_delay',
  'other',
]);

export function parseSupportingAttachmentType(metadata) {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata))
    return { error: 'Choose a valid supporting attachment title.' };

  const attachmentType = metadata.attachmentType;
  if (typeof attachmentType !== 'string' || !SUPPORTING_ATTACHMENT_TYPES.includes(attachmentType))
    return { error: 'Choose a valid supporting attachment title.' };

  const customAttachmentType = String(metadata.customAttachmentType || '').trim();
  if (attachmentType === 'other') {
    if (!customAttachmentType) return { error: 'Enter a custom title for Other.' };
    if (customAttachmentType.length > 120)
      return { error: 'A custom supporting attachment title cannot exceed 120 characters.' };
    return { attachmentType, customAttachmentType };
  }

  if (customAttachmentType)
    return { error: 'A custom title can only be used with Other.' };
  return { attachmentType, customAttachmentType: null };
}
