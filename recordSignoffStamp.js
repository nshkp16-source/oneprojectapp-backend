import { clampStampScale } from './stamp-renderer.js';

export function parseRecordSignoffPlacement(value, pageCount) {
  let placement = value;
  if (typeof placement === 'string') {
    try {
      placement = JSON.parse(placement);
    } catch {
      throw new Error('Choose a valid signature position on the record.');
    }
  }

  if (!placement || typeof placement !== 'object' || Array.isArray(placement)) {
    throw new Error('Choose where your signature should be placed on the record.');
  }

  const page = Number(placement.page);
  const x = Number(placement.x);
  const y = Number(placement.y);
  if (!Number.isInteger(page) || page < 1 || page > pageCount
      || !Number.isFinite(x) || x < 0 || x > 1
      || !Number.isFinite(y) || y < 0 || y > 1) {
    throw new Error('Choose a valid page and signature position on the record.');
  }

  return { page, x, y, scale: clampStampScale(placement.scale) };
}
