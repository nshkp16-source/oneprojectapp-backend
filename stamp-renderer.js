// stamp-renderer.js
// ONE stamp, drawn in ONE place. Used by add-record, review-record, the decision sign-off
// page, the verification page and the live preview in "My Signature Setup".
//
// Design rules (from the agreed decisions):
//  * Two parts only:  [ mark ] | [ details ]
//      mark    = one image: a drawn signature, a signature image, a stamp image,
//                or a single image that already contains stamp + signature.
//      details = Digitally signed/approved by, name, position, company, date/time + timezone.
//  * Official look: thin header with the label, a Stamp ID footer and an optional QR code.
//  * Watermark behaviour: nothing is filled. Every mark uses the Multiply blend mode, so white
//    pixels vanish and the document text underneath stays fully readable.
//  * Layout is measured, never hard-coded: text shrinks to a minimum size, then wraps, and a
//    running cursor places each line, so long names and positions cannot overlap or overflow.

import { PDFDocument, StandardFonts, rgb, BlendMode } from 'pdf-lib';
import crypto from 'crypto';

export const STAMP_BOX_W = 300;          // preferred stamp width in PDF points
export const STAMP_MAX_PAGE_FRACTION = 0.52;

const MULTIPLY = { blendMode: BlendMode.Multiply };
const INK = rgb(0.11, 0.14, 0.18);
const MUTED = rgb(0.38, 0.42, 0.47);
const RULE = rgb(0.55, 0.59, 0.64);
const ACCENT = rgb(0.1, 0.17, 0.3);      // neutral navy

// ── helpers ──────────────────────────────────────────────────────────────────
const safeFor = (font) => (text) => Array.from(String(text ?? '').normalize('NFC')).map((ch) => {
  try { font.encodeText(ch); return ch; } catch (_) { return '?'; }
}).join('');

function wrapToWidth(text, font, size, maxWidth) {
  const out = [];
  let line = '';
  const pushWord = (word) => {
    const candidate = line ? `${line} ${word}` : word;
    if (!line || font.widthOfTextAtSize(candidate, size) <= maxWidth) { line = candidate; return; }
    out.push(line);
    line = word;
  };
  for (const word of String(text).split(/\s+/).filter(Boolean)) {
    if (font.widthOfTextAtSize(word, size) <= maxWidth) { pushWord(word); continue; }
    // a single word wider than the column: break it by characters
    let chunk = '';
    for (const ch of word) {
      if (chunk && font.widthOfTextAtSize(chunk + ch, size) > maxWidth) { pushWord(chunk); chunk = ch; }
      else chunk += ch;
    }
    if (chunk) pushWord(chunk);
  }
  if (line) out.push(line);
  return out.length ? out : [''];
}

// Shrink first (down to minSize), then wrap. Returns the lines and the size used.
function fitText(text, font, size, minSize, maxWidth, maxLines = 3) {
  let s = size;
  while (s > minSize && font.widthOfTextAtSize(text, s) > maxWidth) s -= 0.2;
  if (font.widthOfTextAtSize(text, s) <= maxWidth) return { lines: [text], size: s };
  let lines = wrapToWidth(text, font, s, maxWidth);
  if (lines.length > maxLines) {
    lines = lines.slice(0, maxLines);
    let last = lines[maxLines - 1];
    while (last.length > 1 && font.widthOfTextAtSize(`${last}...`, s) > maxWidth) last = last.slice(0, -1);
    lines[maxLines - 1] = `${last}...`;
  }
  return { lines, size: s };
}

export function formatStampDate(value, tz) {
  const d = value ? new Date(value) : new Date();
  const opts = { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' };
  try { return d.toLocaleString('en-GB', { ...opts, timeZone: tz || 'UTC' }); }
  catch (_) { return d.toLocaleString('en-GB', { ...opts, timeZone: 'UTC' }); }
}

// OP-7F3A-92C1: short, printable, derived from SHA-256 of whatever uniquely identifies the signing event.
export function deriveStampId(parts) {
  const hex = crypto.createHash('sha256').update(JSON.stringify(parts)).digest('hex').toUpperCase();
  return `OP-${hex.slice(0, 4)}-${hex.slice(4, 8)}`;
}

// Which single image is "the mark" for this saved profile.
export function pickMark(profile) {
  if (!profile) return null;
  const t = profile.mark_type;
  if (t === 'stamp_image' || t === 'combined') return profile.stamp_image_url || profile.signature_image || null;
  return profile.signature_image || profile.stamp_image_url || null;
}

async function embedImage(pdfDoc, source) {
  if (!source) return null;
  try {
    const value = String(source);
    const m = value.match(/^data:image\/(png|jpeg|jpg);base64,(.+)$/i);
    let bytes, isPng;
    if (m) { isPng = m[1].toLowerCase() === 'png'; bytes = Buffer.from(m[2], 'base64'); }
    else {
      const r = await fetch(value);
      if (!r.ok) return null;
      bytes = Buffer.from(await r.arrayBuffer());
      isPng = (r.headers.get('content-type') || '').includes('png') || value.toLowerCase().includes('.png');
    }
    return isPng ? await pdfDoc.embedPng(bytes) : await pdfDoc.embedJpg(bytes);
  } catch (err) {
    console.warn('[stamp] could not embed mark image:', err.message);
    return null;
  }
}

let qrLib;   // optional dependency: `npm i qrcode`. Without it the stamp simply prints the ID.
async function qrMatrix(text) {
  if (qrLib === undefined) {
    try { const mod = await import('qrcode'); qrLib = mod.default || mod; }
    catch (err) { qrLib = null; console.warn('[stamp] QR codes are OFF because the qrcode package could not be loaded (' + err.message + '). Run "npm i qrcode" in the folder that contains stamp-renderer.js, then restart the server.'); }
  }
  if (!qrLib) return null;
  if (!text) { console.warn('[stamp] QR skipped: no verify URL was given.'); return null; }
  try { return qrLib.create(text, { errorCorrectionLevel: 'M' }).modules; } catch (_) { return null; }
}

function roundedPath(w, h, r) {
  const k = r * 0.55228475;
  return [
    `M ${r} 0`, `L ${w - r} 0`,
    `C ${w - r + k} 0 ${w} ${r - k} ${w} ${r}`, `L ${w} ${h - r}`,
    `C ${w} ${h - r + k} ${w - r + k} ${h} ${w - r} ${h}`, `L ${r} ${h}`,
    `C ${r - k} ${h} 0 ${h - r + k} 0 ${h - r}`, `L 0 ${r}`,
    `C 0 ${r - k} ${r - k} 0 ${r} 0`, 'Z',
  ].join(' ');
}

// -- layout (measures everything, draws nothing) ----------------------------
// spec: { markSource, name, secondary, company, signedAt, tz, stampId, label, verifyUrl }
// scale: 0.8 to 1.2. Everything (text, lines, margins, QR) is scaled together, so the look never changes.
export const clampStampScale = (v) => Math.min(1.2, Math.max(0.8, Number(v) || 1));

export async function layoutStamp(pdfDoc, spec, { width = STAMP_BOX_W, scale = 1 } = {}) {
  const k = clampStampScale(scale);
  const bold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const reg = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const safe = safeFor(reg);
  const mark = await embedImage(pdfDoc, spec.markSource);
  const qr = await qrMatrix(spec.verifyUrl);

  const PAD = 8 * k, GAP = 7 * k, HEAD = 16 * k;
  const FOOT = (qr ? 34 : 15) * k;
  const W = width * k;
  const markW = mark ? Math.round((W - PAD * 2 - GAP) * 0.38) : 0;
  const detailsW = W - PAD * 2 - (mark ? markW + GAP : 0);

  const label = String(spec.label || 'SIGNED').toUpperCase();
  const verb = label === 'SIGNED' ? 'signed' : label.toLowerCase();
  const rows = [
    { text: `Digitally ${verb} by`, font: reg, size: 7.2 * k, min: 5.6 * k, color: MUTED },
    { text: spec.name || 'Signer', font: bold, size: 10 * k, min: 6.4 * k, color: ACCENT, maxLines: 2 },
    { text: spec.secondary || '', font: reg, size: 7.6 * k, min: 5.6 * k, color: INK, maxLines: 2 },
    { text: spec.company || '', font: reg, size: 7.6 * k, min: 5.6 * k, color: INK, maxLines: 2 },
    { text: formatStampDate(spec.signedAt, spec.tz), font: reg, size: 6.8 * k, min: 5.2 * k, color: MUTED, maxLines: 2 },
  ].filter((r) => String(r.text).trim()).map((r) => {
    const fit = fitText(safe(r.text), r.font, r.size, r.min, detailsW, r.maxLines || 2);
    return { ...r, ...fit, leading: fit.size * 1.25, gap: 1.8 * k };
  });

  const textH = rows.reduce((t, r) => t + r.lines.length * r.leading + r.gap, 0);
  const H = Math.max(PAD + HEAD + 4 * k + textH + 4 * k + FOOT, 92 * k);
  const bodyTop = H - HEAD;                // y (from box bottom) where the header ends
  const bodyBottom = FOOT;                 // y where the footer begins
  const thin = 0.6 * k;

  const paint = (page, x, y) => {
    // outline only: no fill, so the page text beneath stays visible
    page.drawSvgPath(roundedPath(W, H, 6 * k), { x, y: y + H, borderColor: INK, borderWidth: 1 * k, borderOpacity: 0.9, ...MULTIPLY });
    // header: label on the left, thin rule below
    page.drawText(safe(label), { x: x + PAD, y: y + H - HEAD + 5 * k, size: 7 * k, font: bold, color: ACCENT, ...MULTIPLY });
    page.drawLine({ start: { x: x + PAD, y: y + bodyTop }, end: { x: x + W - PAD, y: y + bodyTop }, thickness: thin, color: RULE, ...MULTIPLY });
    // footer rule + stamp id (+ QR)
    page.drawLine({ start: { x: x + PAD, y: y + bodyBottom }, end: { x: x + W - PAD, y: y + bodyBottom }, thickness: thin, color: RULE, ...MULTIPLY });
    const idText = safe(`Stamp ID ${spec.stampId || ''}`.trim());
    page.drawText(idText, { x: x + PAD, y: y + (qr ? FOOT - 12 * k : 5 * k), size: 6.4 * k, font: bold, color: MUTED, ...MULTIPLY });
    if (qr) {
      page.drawText('Scan to verify', { x: x + PAD, y: y + FOOT - 21 * k, size: 5.6 * k, font: reg, color: MUTED, ...MULTIPLY });
      const qs = 26 * k, cell = qs / qr.size, qx = x + W - PAD - qs, qy = y + (FOOT - qs) / 2 - 0.5 * k;
      for (let r = 0; r < qr.size; r++) {
        for (let c = 0; c < qr.size; c++) {
          if (!qr.get(r, c)) continue;
          page.drawRectangle({ x: qx + c * cell, y: qy + (qr.size - 1 - r) * cell, width: cell + 0.05, height: cell + 0.05, color: INK, ...MULTIPLY });
        }
      }
    }
    // mark column
    const areaH = bodyTop - bodyBottom - 6 * k;
    if (mark) {
      const fit = Math.min(markW / mark.width, areaH / mark.height);
      const w = mark.width * fit, h = mark.height * fit;
      page.drawImage(mark, { x: x + PAD + (markW - w) / 2, y: y + bodyBottom + 3 * k + (areaH - h) / 2, width: w, height: h, ...MULTIPLY });
      const dx = x + PAD + markW + GAP / 2;
      page.drawLine({ start: { x: dx, y: y + bodyBottom + 4 * k }, end: { x: dx, y: y + bodyTop - 4 * k }, thickness: 0.5 * k, color: RULE, ...MULTIPLY });
    }
    // details column from a running cursor (never fixed offsets)
    const tx = x + PAD + (mark ? markW + GAP : 0);
    let cursor = y + bodyTop - 5 * k;
    for (const r of rows) {
      for (const line of r.lines) {
        cursor -= r.leading;
        if (cursor < y + bodyBottom + 2 * k) break;
        page.drawText(line, { x: tx, y: cursor + r.leading * 0.22, size: r.size, font: r.font, color: r.color, ...MULTIPLY });
      }
      cursor -= r.gap;
    }
  };
  return { width: W, height: H, paint };
}

// Draw on an existing page. xRatio / yRatio are the CENTRE of the stamp, as fractions of the
// page measured from the bottom-left (the same convention as the placement preview).
export async function drawStampOnPage(pdfDoc, page, spec, { xRatio = 0.8, yRatio = 0.08, width, scale = 1 } = {}) {
  const { width: pw, height: ph } = page.getSize();
  const W = width || Math.min(STAMP_BOX_W, pw * STAMP_MAX_PAGE_FRACTION);
  const lay = await layoutStamp(pdfDoc, spec, { width: W, scale });
  const m = 12;
  const x = Math.min(Math.max(xRatio * pw - lay.width / 2, m), Math.max(m, pw - lay.width - m));
  const y = Math.min(Math.max(yRatio * ph - lay.height / 2, m), Math.max(m, ph - lay.height - m));
  lay.paint(page, x, y);
  return { x, y, width: lay.width, height: lay.height, xRatio: (x + lay.width / 2) / pw, yRatio: (y + lay.height / 2) / ph };
}

// Stamp a PDF buffer. placement = { page: number | 'append', x, y }.
export async function stampPdfBuffer(buffer, spec, placement) {
  const doc = await PDFDocument.load(buffer, { ignoreEncryption: true });
  let page, pageNo;
  if (placement.page === 'append') {
    const last = doc.getPage(doc.getPageCount() - 1).getSize();
    page = doc.addPage([last.width, last.height]);
    pageNo = doc.getPageCount();
  } else {
    pageNo = Math.min(Math.max(parseInt(placement.page, 10) || 1, 1), doc.getPageCount());
    page = doc.getPage(pageNo - 1);
  }
  const box = await drawStampOnPage(doc, page, spec, { xRatio: placement.x, yRatio: placement.y, scale: placement.scale });
  return { bytes: Buffer.from(await doc.save()), box, page: pageNo };
}

// One-page PDF sized to the stamp, for the live preview (same code path as the real stamp).
export async function buildStampPreviewPdf(spec) {
  const doc = await PDFDocument.create();
  const lay = await layoutStamp(doc, spec, { width: STAMP_BOX_W });
  const page = doc.addPage([lay.width + 4, lay.height + 4]);
  lay.paint(page, 2, 2);
  return { bytes: Buffer.from(await doc.save()), width: lay.width + 4, height: lay.height + 4 };
}
