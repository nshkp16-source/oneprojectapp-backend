export const CARD_ATTACHMENT_TYPES = Object.freeze([
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

export function parseCardAttachmentType(body = {}) {
  const rawType = body.attachmentType;
  const rawCustomType = body.customAttachmentType;
  if (rawType == null && rawCustomType == null)
    return { attachmentType: 'other', customAttachmentType: null };

  if (typeof rawType !== 'string' || !CARD_ATTACHMENT_TYPES.includes(rawType))
    return { error: 'Choose a valid attachment type.' };

  const customAttachmentType = String(rawCustomType || '').trim();
  if (rawType === 'other') {
    if (!customAttachmentType) return { error: 'Enter a custom attachment type for Other.' };
    if (customAttachmentType.length > 120)
      return { error: 'The custom attachment type cannot exceed 120 characters.' };
    return { attachmentType: rawType, customAttachmentType };
  }

  if (customAttachmentType)
    return { error: 'A custom attachment type can only be used with Other.' };
  return { attachmentType: rawType, customAttachmentType: null };
}
