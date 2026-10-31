// Pure rules for the document flow (folders, numbering, revisions, due dates).
// No database or Express code here, so every rule can be tested on its own.

const KNOWN_CODES = {
  'daily report': 'DR', 'weekly report': 'WR', 'monthly report': 'MR', 'progress report': 'PR',
  'inspection report': 'IR', 'method statement': 'MS', 'risk assessment': 'RA',
  'quality control report': 'QC', 'safety report': 'SR', 'request for information (rfi)': 'RFI',
  'submittal': 'SUB', 'technical note': 'TN', 'correspondence': 'COR', 'meeting summary': 'MIN',
  'claim document': 'CLM', 'drawing': 'DWG',
};

export const RESERVED_FOLDER = /^drafts?$/i;

/** Tidy a typed folder name. Returns '' when empty. Throws { code: 'RESERVED' } for "Draft". */
export function normalizeFolderName(raw) {
  const name = String(raw ?? '').replace(/\s+/g, ' ').trim().slice(0, 60);
  if (!name) return '';
  if (RESERVED_FOLDER.test(name)) { const e = new Error('Draft is reserved for private drafts. Choose another folder name.'); e.code = 'RESERVED'; throw e; }
  return name;
}

const folderKey = n => String(n || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().replace(/(?<!s)s$/, '');

/** If a folder with the same name (ignoring case, spacing, a trailing "s") exists, reuse its spelling. */
export function canonicalFolder(name, existingNames = []) {
  const clean = normalizeFolderName(name);
  if (!clean) return '';
  const key = folderKey(clean);
  const hit = existingNames.find(n => folderKey(n) === key);
  return hit || clean;
}

/** Short code used inside document numbers: "Progress Report" -> PR, "Drawing" -> DWG. */
export function folderCode(name) {
  const clean = String(name || '').replace(/\s+/g, ' ').trim();
  if (!clean) return 'DOC';
  const known = KNOWN_CODES[clean.toLowerCase()];
  if (known) return known;
  const words = clean.replace(/[^A-Za-z0-9 ]/g, ' ').split(' ').filter(Boolean);
  if (words.length >= 2) return words.slice(0, 4).map(w => w[0]).join('').toUpperCase();
  return (words[0] || 'DOC').slice(0, 3).toUpperCase();
}

/** "Simbi Heights Phase 2" -> SHP2 (max 4 characters). */
export function projectCode(name) {
  const words = String(name || '').replace(/[^A-Za-z0-9 ]/g, ' ').split(' ').filter(Boolean);
  if (!words.length) return 'PRJ';
  if (words.length === 1) return words[0].slice(0, 4).toUpperCase();
  return words.slice(0, 4).map(w => w[0]).join('').toUpperCase();
}

export function formatDocNumber(projCode, folder, n) {
  return `${projCode}-${folderCode(folder)}-${String(n).padStart(3, '0')}`;
}

/** 0 -> A, 1 -> B ... 25 -> Z, 26 -> AA */
export function revisionLetter(n) {
  let x = Math.max(0, Math.floor(Number(n) || 0)), out = '';
  do { out = String.fromCharCode(65 + (x % 26)) + out; x = Math.floor(x / 26) - 1; } while (x >= 0);
  return out;
}

/** Accepts YYYY-MM-DD only (a real calendar date), else null. */
export function validDate(value) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value || '').trim());
  if (!m) return null;
  const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
  return d.getUTCFullYear() === +m[1] && d.getUTCMonth() === +m[2] - 1 && d.getUTCDate() === +m[3] ? m[0] : null;
}

/** Whole days late (>0), due today (0) or days left (<0 means not yet due is NOT used: returns null when not overdue). */
export function daysOverdue(dueDate, today = new Date()) {
  const due = validDate(String(dueDate || '').slice(0, 10));
  if (!due) return null;
  const t = Date.UTC(today.getFullYear(), today.getMonth(), today.getDate());
  const [y, m, d] = due.split('-').map(Number);
  const diff = Math.round((t - Date.UTC(y, m - 1, d)) / 86400000);
  return diff > 0 ? diff : null;
}

/** Content type from a file name, so previews and downloads are not all labelled PDF. */
export function contentTypeFor(fileName) {
  const ext = String(fileName || '').toLowerCase().split('.').pop();
  return ({
    pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp', gif: 'image/gif',
    doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    csv: 'text/csv', zip: 'application/zip', dwg: 'application/acad', dxf: 'application/dxf',
  })[ext] || 'application/octet-stream';
}
