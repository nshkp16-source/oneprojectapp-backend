// server.js
import express from 'express';
import multer from 'multer';
import { Pool } from 'pg';
import nodemailer from 'nodemailer';
import cors from 'cors';
import nodemailerSendgrid from 'nodemailer-sendgrid';
import pkg from 'uuid';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { v2 as cloudinary } from 'cloudinary';
import { PDFDocument, rgb, StandardFonts } from 'pdf-lib';
import { Readable } from 'stream';
import { layoutStamp, drawStampOnPage, stampPdfBuffer, buildStampPreviewPdf, deriveStampId, pickMark, formatStampDate } from './stamp-renderer.js';

const { v4: uuidv4 } = pkg;
const app = express();
app.use(express.json());
app.use(cors());

// Simple request logger for API routes
app.use((req, _res, next) => {
  if (req.originalUrl && req.originalUrl.startsWith('/api')) {
    console.log(`[API] ${new Date().toISOString()} ${req.method} ${req.originalUrl}`);
  }
  next();
});

// ─── Cloudinary ───────────────────────────────────────────────────────────────
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ─── Multer ───────────────────────────────────────────────────────────────────
const upload = multer({
  limits: { fileSize: 200 * 1024 * 1024 }, // 200 MB — supports video attachments
  storage: multer.memoryStorage(),
  fileFilter: (_req, _file, cb) => cb(null, true),
});

const photoUpload = multer({
  limits:     { fileSize: 10 * 1024 * 1024 },
  storage:    multer.memoryStorage(),
  fileFilter: (_req, file, cb) => {
    const ok = file.mimetype.startsWith('image/');
    cb(ok ? null : new Error('Images only'), ok);
  },
});

const meetingMinutePdfUpload = multer({
  limits: { fileSize: 50 * 1024 * 1024, files: 1 },
  storage: multer.memoryStorage(),
  fileFilter: (_req, file, cb) => {
    const isPdf = file.mimetype === 'application/pdf' || /\.pdf$/i.test(file.originalname || '');
    cb(isPdf ? null : new Error('Meeting report must be a PDF'), isPdf);
  },
});

// ─── Cloudinary helpers ───────────────────────────────────────────────────────
function uploadToCloudinary(buffer, folder, resourceType = 'auto') {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder, resource_type: resourceType },
      (err, result) => (err ? reject(err) : resolve(result))
    );
    Readable.from(buffer).pipe(stream);
  });
}

function scheduleCloudinaryUpload(buffer, originalName, folder) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder, resource_type: 'auto', public_id: `${Date.now()}_${originalName}` },
      (err, result) => (err ? reject(err) : resolve(result))
    );
    Readable.from(buffer).pipe(stream);
  });
}

// ─── JWT middleware ───────────────────────────────────────────────────────────
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = {
      user_id: parseInt(decoded.sub, 10),
      role:    normalizeRole(decoded.role),
      email:   decoded.companyEmail || decoded.email,
    };
    next();
  });
}

// ─── DB ───────────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function ensureStampStatusColumns() {
  const recordTables = [
    'contractual_records',
    'administrative_records',
    'safety_records',
    'operational_records',
    'financial_records',
  ];

  for (const table of recordTables) {
    try {
      await pool.query(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS stamp_status TEXT`);
      console.log(`[schema] ensured stamp_status on ${table}`);
    } catch (err) {
      console.warn(`[schema] unable to ensure stamp_status on ${table}:`, err.message);
    }
  }
}

await ensureStampStatusColumns();

// One shared stamp: registry of every stamp the server has drawn (powers /verify/:id).
async function ensureStampTables() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS stamp_registry (
      stamp_id TEXT PRIMARY KEY,
      project_id INTEGER,
      record_table TEXT,
      record_id INTEGER,
      kind TEXT,
      signer_user_id INTEGER,
      signer_role TEXT,
      signer_name TEXT,
      signer_position TEXT,
      company_name TEXT,
      label TEXT,
      tz TEXT,
      file_hash TEXT,
      signed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await pool.query(`CREATE INDEX IF NOT EXISTS stamp_registry_record_idx ON stamp_registry (record_table, record_id)`);
    await pool.query(`ALTER TABLE user_stamps ADD COLUMN IF NOT EXISTS mark_type TEXT`);
  } catch (err) {
    console.warn('[schema] stamp tables not ensured:', err.message);
  }
}
await ensureStampTables();

const publicBaseUrl = (req) => (process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get('host')}`).replace(/\/+$/, '');

async function registerStamp(db, row) {
  try {
    await db.query(
      `INSERT INTO stamp_registry (stamp_id, project_id, record_table, record_id, kind, signer_user_id, signer_role,
         signer_name, signer_position, company_name, label, tz, file_hash, signed_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
       ON CONFLICT (stamp_id) DO NOTHING`,
      [row.stampId, row.projectId, row.table, row.recordId, row.kind, row.userId, row.role,
       row.name || null, row.position || null, row.company || null, row.label || null, row.tz || null,
       row.fileHash || null, row.signedAt || new Date()]
    );
  } catch (err) { console.warn('[stamp] registry write failed:', err.message); }
}

// Builds the renderer input from a signer profile. Name, position and company come from the database.
function stampSpecFromProfile(profile, { label, signedAt, tz, stampId, baseUrl }) {
  const sideText = profile.side ? `${flowSideLabel(profile.side)} side` : '';
  return {
    markSource: pickMark(profile),
    name: profile.name,
    secondary: [profile.position, sideText].filter(Boolean).join(', '),
    company: profile.company || '',
    signedAt, tz, stampId, label,
    verifyUrl: stampId && baseUrl ? `${baseUrl}/verify/${stampId}` : null,
  };
}

async function ensureDisplayNameColumns() {
  const userTables = [
    'clients',
    'contractors',
    'consultants',
    'team_members',
    'contractor_project_managers',
    'consultant_project_managers',
    'client_project_managers',
  ];

  for (const t of userTables) {
    try {
      await pool.query(`ALTER TABLE ${t} ADD COLUMN IF NOT EXISTS display_name TEXT`);
      console.log(`[schema] ensured display_name on ${t}`);
    } catch (err) {
      console.warn(`[schema] unable to ensure display_name on ${t}:`, err.message);
    }
  }
}

await ensureDisplayNameColumns();

// ─── SendGrid ─────────────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport(
  nodemailerSendgrid({ apiKey: process.env.SENDGRID_API_KEY })
);

// =============================================================================
//  CORE HELPERS
// =============================================================================

const VALID_RECORD_TABLES = new Set([
  'contractual_records',
  'administrative_records',
  'safety_records',
  'operational_records',
  'financial_records',
]);

function resolveTable(recordType) {
  if (!recordType || !VALID_RECORD_TABLES.has(recordType)) return null;
  return recordType;
}

// ─────────────────────────────────────────────────────────────────────────────
//  RECORD FLOW: signers, decisions with signed notices, queries, revisions
//  A decision (approve, accept, reject) is only issued together with a signed
//  notice. The notice is a record of its own, tied to the first record, and it
//  needs no approval: it is final once the deciding leader has signed.
// ─────────────────────────────────────────────────────────────────────────────
const SIDE_NAMES = ['contractor', 'consultant', 'client'];

// Who reviews a record, in order, depending on which side added it.
const FLOW_STEP_MAP = {
  contractor: [
    { side: 'consultant', step: 1, label: 'Consultant Approval',  action: 'approved' },
    { side: 'client',     step: 2, label: 'Client Acceptance',    action: 'accepted' },
  ],
  consultant: [
    { side: 'client',     step: 1, label: 'Client Approval',      action: 'approved' },
    { side: 'contractor', step: 2, label: 'Contractor Acceptance', action: 'accepted' },
  ],
  client: [
    { side: 'consultant', step: 1, label: 'Consultant Approval',  action: 'approved' },
    { side: 'contractor', step: 2, label: 'Contractor Acceptance', action: 'accepted' },
  ],
};
const FLOW_NOTICE_KIND  = { approved: 'notice', accepted: 'acceptance_notice', rejected: 'rejection_notice' };
const FLOW_NOTICE_TITLE = {
  notice: 'NOTICE OF DETERMINATION (APPROVAL)',
  acceptance_notice: 'NOTICE OF ACCEPTANCE',
  rejection_notice: 'NOTICE OF REJECTION',
};
const FLOW_DECISION_WORD = { approved: 'APPROVED', accepted: 'ACCEPTED', rejected: 'REJECTED' };
const FLOW_TABLE_LABELS = {
  contractual_records: 'Contractual & Legal',
  administrative_records: 'Administrative & Instructional',
  safety_records: 'Safety & Compliance',
  operational_records: 'Operational & Performance',
  financial_records: 'Financial',
};
const FLOW_MAX_QUERIES = 200;
const FLOW_REMIND_COOLDOWN_HOURS = 24;

function flowSideLabel(side) { return side ? side.charAt(0).toUpperCase() + side.slice(1) : ''; }
function flowRoleLabel(role) { return String(role || '').replace(/([a-z])([A-Z])/g, '$1 $2').trim(); }

async function ensureRecordFlowSchema() {
  const columns = [
    'revision_of_id INTEGER',
    'revision_no INTEGER NOT NULL DEFAULT 0',
    'superseded_by_id INTEGER',
    'notice_source TEXT',
    'respond_by DATE',
    'stamped_doc_public_id TEXT',
  ];
  for (const table of VALID_RECORD_TABLES) {
    for (const column of columns) {
      try { await pool.query(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${column}`); }
      catch (err) { console.warn(`[schema] unable to add (${column}) to ${table}:`, err.message); }
    }
  }
  const statements = [
    `CREATE TABLE IF NOT EXISTS record_signers (
       id SERIAL PRIMARY KEY,
       record_table TEXT NOT NULL,
       record_id INTEGER NOT NULL,
       project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
       stage INTEGER NOT NULL,
       side TEXT NOT NULL,
       signer_role TEXT NOT NULL,
       signer_user_id INTEGER NOT NULL,
       signer_position TEXT,
       is_team_member BOOLEAN NOT NULL DEFAULT FALSE,
       is_decider BOOLEAN NOT NULL DEFAULT FALSE,
       order_no INTEGER NOT NULL DEFAULT 0,
       status TEXT NOT NULL DEFAULT 'pending',
       outcome TEXT,
       findings JSONB,
       signed_at TIMESTAMPTZ,
       notice_id INTEGER,
       first_viewed_at TIMESTAMPTZ,
       last_viewed_at TIMESTAMPTZ,
       replaced_by_signer_id INTEGER,
       replaced_at TIMESTAMPTZ,
       replaced_by_user_id INTEGER,
       replaced_by_role TEXT,
       reminder_sent_at TIMESTAMPTZ,
       created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
     )`,
    `CREATE INDEX IF NOT EXISTS record_signers_record_idx ON record_signers (record_table, record_id, stage)`,
    `CREATE INDEX IF NOT EXISTS record_signers_user_idx ON record_signers (signer_role, signer_user_id, status)`,
    `CREATE TABLE IF NOT EXISTS record_queries (
       id SERIAL PRIMARY KEY,
       record_table TEXT NOT NULL,
       record_id INTEGER NOT NULL,
       notice_id INTEGER NOT NULL,
       project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
       seq INTEGER NOT NULL,
       ref TEXT,
       query TEXT NOT NULL,
       required_action TEXT,
       issuer_role TEXT,
       issuer_side TEXT,
       status TEXT NOT NULL DEFAULT 'open',
       response TEXT,
       responded_at TIMESTAMPTZ,
       responded_in_record_id INTEGER,
       responded_by_role TEXT,
       responded_by_id INTEGER,
       resolved_at TIMESTAMPTZ,
       resolved_by_role TEXT,
       resolved_by_id INTEGER,
       created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
     )`,
    `CREATE INDEX IF NOT EXISTS record_queries_record_idx ON record_queries (record_table, record_id)`,
    `ALTER TABLE record_queries ADD COLUMN IF NOT EXISTS raised_by TEXT`,
    // One live row per person per stage: stops duplicates and double-clicks racing each other
    `CREATE UNIQUE INDEX IF NOT EXISTS record_signers_one_active ON record_signers (record_table, record_id, stage, signer_role, signer_user_id) WHERE status <> 'replaced'`,
  ];
  for (const sql of statements) {
    try { await pool.query(sql); }
    catch (err) { console.warn('[schema] record flow statement failed:', err.message); }
  }
  console.log('[schema] record flow tables ensured');
}
await ensureRecordFlowSchema();

// ── People who can be named as signers ───────────────────────────────────────
function flowTeamSide(part) {
  const p = String(part || '').toLowerCase();
  return SIDE_NAMES.find(s => p.includes(s)) || null;
}
function flowMemberSide(m) { return m.role === 'TeamMember' ? flowTeamSide(m.assigned_part) : getSide(m.role); }
function flowMemberPosition(m) {
  if (m.role === 'TeamMember') return m.position || 'Team member';
  return m.title_position || flowRoleLabel(m.role);
}

async function getSignerCandidates(projectId, side) {
  const members = await getProjectMembers(projectId);
  const seen = new Set();
  const out = [];
  for (const m of members) {
    if (flowMemberSide(m) !== side) continue;
    const role = normalizeRole(m.role);
    const key = `${role}:${m.role_id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      role,
      user_id: Number(m.role_id),
      name: m.display_name,
      position: flowMemberPosition(m),
      side,
      is_team_member: role === 'TeamMember',
    });
  }
  return out;
}

// Checks a chosen list of signers: everyone belongs to the side, exactly one
// deciding leader, team members and other leaders sign first, the decider last.
async function validateSignerPlan(projectId, side, rawSigners) {
  let list = rawSigners;
  if (typeof list === 'string') {
    try { list = JSON.parse(list); } catch { return { error: 'The list of signers is not valid.' }; }
  }
  if (!Array.isArray(list) || !list.length) return { error: 'Choose who must sign. At least the deciding leader is required.' };
  if (list.length > 8) return { error: 'You can name at most 8 signers.' };
  const candidates = await getSignerCandidates(projectId, side);
  const byKey = new Map(candidates.map(c => [`${c.role}:${c.user_id}`, c]));
  const seen = new Set();
  const rows = [];
  for (const item of list) {
    const key = `${normalizeRole(item?.role)}:${Number(item?.user_id)}`;
    const c = byKey.get(key);
    if (!c) return { error: `A chosen signer is not on the ${flowSideLabel(side)} side of this project.` };
    if (seen.has(key)) return { error: 'The same person was chosen twice.' };
    seen.add(key);
    rows.push({ ...c, is_decider: item.decider === true || item.is_decider === true });
  }
  const deciders = rows.filter(r => r.is_decider);
  if (deciders.length !== 1) return { error: 'Choose exactly one deciding leader.' };
  if (deciders[0].is_team_member) return { error: 'The deciding signer must be a leader, not a team member.' };
  const others = rows.filter(r => !r.is_decider)
    .sort((a, b) => Number(!a.is_team_member) - Number(!b.is_team_member));
  const ordered = others.concat(deciders).map((r, i) => ({ ...r, order_no: i + 1 }));
  return { signers: ordered };
}

async function insertSignerRows(client, { table, recordId, projectId, stage, side, signers }) {
  for (const s of signers) {
    await client.query(
      `INSERT INTO record_signers
         (record_table, record_id, project_id, stage, side, signer_role, signer_user_id,
          signer_position, is_team_member, is_decider, order_no)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [table, recordId, projectId, stage, side, s.role, s.user_id, s.position, s.is_team_member, s.is_decider, s.order_no]
    );
  }
}

// Where the record is in its review chain right now.
async function getRecordFlowState(table, projectId, recordId) {
  const { rows: recRows } = await pool.query(`SELECT * FROM ${table} WHERE id=$1 AND project_id=$2`, [recordId, projectId]);
  const rec = recRows[0];
  if (!rec) return null;
  const uploaderSide = getSide(rec.role);
  const steps = uploaderSide ? FLOW_STEP_MAP[uploaderSide] : null;
  const { rows: reviews } = await pool.query(
    `SELECT reviewer_role, reviewer_id, action FROM document_reviews WHERE record_type=$1 AND record_id=$2`,
    [table, recordId]
  );
  const doneFor = (side) => reviews.some(r => getSide(r.reviewer_role) === side && (r.action === 'approved' || r.action === 'accepted'));
  const isRejected = rec.status === 'rejected';
  const isLocked = isRejected || rec.status === 'approved_record'
    || Boolean(steps && reviews.some(r => getSide(r.reviewer_role) === steps[1].side && r.action === 'accepted'));
  let stage = null;
  if (steps && !isLocked) stage = doneFor(steps[0].side) ? 2 : 1;
  return { rec, uploaderSide, steps, reviews, isRejected, isLocked, stage };
}

// ── Notifications to named people or the whole project ──────────────────────
// Email for the few events people must not miss. In-app notifications still happen for everything.
const FLOW_EMAIL_TABLE = {
  Client: 'clients', Contractor: 'contractors', Consultant: 'consultants',
  ClientPM: 'client_project_managers', ContractorPM: 'contractor_project_managers',
  ConsultantPM: 'consultant_project_managers', TeamMember: 'team_members',
};
async function emailFlowRecipients(recipients, subject, message, projectId) {
  try {
    const { rows: pr } = await pool.query('SELECT name FROM projects WHERE id=$1', [projectId]);
    const project = pr[0]?.name || 'your project';
    const from = process.env.MAIL_FROM || 'skyprincenkp16@gmail.com';
    const link = process.env.APP_BASE_URL ? `<p><a href="${flowEscape(process.env.APP_BASE_URL)}">Open OneProjectApp</a></p>` : '';
    const seen = new Set();
    for (const r of recipients || []) {
      const role = normalizeRole(r.recipient_role); const id = Number(r.recipient_role_id ?? r.user_id);
      const table = FLOW_EMAIL_TABLE[role];
      if (!table || !Number.isInteger(id) || seen.has(`${role}:${id}`)) continue;
      seen.add(`${role}:${id}`);
      const { rows } = await pool.query(`SELECT email FROM ${table} WHERE id=$1 LIMIT 1`, [id]).catch(() => ({ rows: [] }));
      const to = rows[0]?.email;
      if (!to) continue;
      await transporter.sendMail({
        from, to, subject: `${subject} - ${project}`,
        html: `<p>${flowEscape(message)}</p><p style="color:#64748b;font-size:12px;">Project: ${flowEscape(project)}</p>${link}`,
      }).catch(err => console.error('[record-flow] email failed (non-fatal):', err.message));
    }
  } catch (err) { console.error('[record-flow] email error (non-fatal):', err.message); }
}
async function notifyRecordUsers({ projectId, recordId, table, message, actorId, actorRole, recipients, email = false, emailSubject = '' }) {
  if (!recipients || !recipients.length) return null;
  let client;
  try {
    client = await pool.connect();
    await client.query('BEGIN');
    const n = await client.query(
      `INSERT INTO notifications (project_id, entity_id, entity_type, message, added_by_id, added_by_role)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
      [projectId, recordId, table, message, actorId, actorRole]
    );
    await insertNotificationRecipients(client, n.rows[0].id, recipients);
    await client.query('COMMIT');
    if (email) emailFlowRecipients(recipients, emailSubject || 'OneProjectApp update', message, projectId);   // not awaited
    return n.rows[0].id;
  } catch (err) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    console.error('[record-flow] notification failed (non-fatal):', err.message);
    return null;
  } finally { if (client) client.release(); }
}
const flowKey = (role, id) => ({ recipient_role: normalizeRole(role), recipient_role_id: Number(id), user_id: Number(id) });

// ── Signature profile (read from the server, not trusted from the browser) ──
async function loadSignerProfile(projectId, role, userId) {
  const { rows } = await pool.query(
    `SELECT signer_name, signature_image, stamp_image_url, stamp_style, mark_type
     FROM user_stamps WHERE user_id=$1 AND user_role=$2 AND project_id=$3 LIMIT 1`,
    [userId, role, projectId]
  );
  const st = rows[0];
  if (!st || (!st.signature_image && !st.stamp_image_url)) return null;   // nothing saved at all
  const [name, company, ps] = await Promise.all([
    resolveSignerNameForStamp(projectId, userId, role),
    resolveCompanyNameForStamp(projectId, userId, role),
    resolvePositionAndSideForStamp(projectId, userId, role),
  ]);
  return {
    name: st.signer_name || name || 'Signer',
    company: company || null,
    position: ps?.position || null,
    side: ps?.side || null,
    signature_image: st.signature_image,
    stamp_image_url: isDecisionMaker(role) ? st.stamp_image_url : null,
    mark_type: st.mark_type || null,
  };
}

// Reason a signer cannot sign yet. Only one case counts: the user has saved neither a signature nor a stamp
// for this project. Anything saved (signature and/or stamp image) is accepted.
async function explainMissingSignerSetup(projectId, role, userId, needStamp) {
  const { rows } = await pool.query(
    `SELECT signature_image, stamp_image_url FROM user_stamps WHERE user_id=$1 AND user_role=$2 AND project_id=$3 LIMIT 1`,
    [userId, role, projectId]
  );
  const st = rows[0];
  if (st && (st.signature_image || st.stamp_image_url)) return null;
  return 'You have not set up a signature or stamp for this project, so ' +
    (needStamp ? 'the decision' : 'your review') + ' cannot be signed. Open your Signature & Stamp setup, save it, then try again.';
}

async function embedImageFromSource(pdfDoc, source) {
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
    console.warn('[record-flow] could not embed signature image:', err.message);
    return null;
  }
}

async function hashRemoteFile(url) {
  try {
    if (!url) return null;
    const r = await fetch(url, { redirect: 'follow' });
    if (!r.ok) return null;
    return crypto.createHash('sha256').update(Buffer.from(await r.arrayBuffer())).digest('hex');
  } catch { return null; }
}

// ── PDF building blocks (neutral, print-friendly) ───────────────────────────
const PDF_W = 595.28, PDF_H = 841.89, PDF_M = 54;
const INK   = rgb(0.11, 0.14, 0.18);
const MUTED = rgb(0.42, 0.46, 0.5);
const RULE  = rgb(0.82, 0.85, 0.88);
const SOFT  = rgb(0.96, 0.97, 0.98);

function makePdfSafe(font) {
  const cache = new Map();
  return (value) => String(value ?? '')
    .replace(/[\u2018\u2019]/g, "'").replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2013\u2014]/g, '-').replace(/\u2026/g, '...')
    .replace(/\u00A0/g, ' ').replace(/[\r\t]/g, ' ')
    .split('').map(ch => {
      if (ch === '\n') return ch;
      if (cache.has(ch)) return cache.get(ch);
      let out = ch;
      try { font.widthOfTextAtSize(ch, 10); } catch { out = '?'; }
      cache.set(ch, out);
      return out;
    }).join('');
}

function wrapPdfText(text, font, size, maxWidth) {
  const lines = [];
  for (const para of String(text || '').split('\n')) {
    if (!para.trim()) { lines.push(''); continue; }
    let line = '';
    for (const word of para.split(/\s+/).filter(Boolean)) {
      let w = word;
      while (font.widthOfTextAtSize(w, size) > maxWidth) {
        let cut = w.length;
        while (cut > 1 && font.widthOfTextAtSize(w.slice(0, cut), size) > maxWidth) cut--;
        if (line) { lines.push(line); line = ''; }
        lines.push(w.slice(0, cut));
        w = w.slice(cut);
      }
      const candidate = line ? `${line} ${w}` : w;
      if (line && font.widthOfTextAtSize(candidate, size) > maxWidth) { lines.push(line); line = w; }
      else line = candidate;
    }
    lines.push(line);
  }
  return lines;
}

async function createLayout(pdfDoc, { startNewPage = true } = {}) {
  const regular = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const bold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const mono = await pdfDoc.embedFont(StandardFonts.Courier);
  const safe = makePdfSafe(regular);
  const L = { page: null, y: 0, regular, bold, mono, safe };
  L.newPage = () => { L.page = pdfDoc.addPage([PDF_W, PDF_H]); L.y = PDF_H - PDF_M; };
  L.ensure = (need) => { if (L.y - need < PDF_M + 20) L.newPage(); };
  L.text = (t, o = {}) => {
    const size = o.size || 10, font = o.font || regular, color = o.color || INK;
    const x = o.x ?? PDF_M, maxWidth = o.maxWidth ?? (PDF_W - 2 * PDF_M);
    for (const ln of wrapPdfText(safe(t), font, size, maxWidth)) {
      L.ensure(size * 1.4);
      if (ln) L.page.drawText(ln, { x, y: L.y - size, size, font, color });
      L.y -= size * 1.4;
    }
    L.y -= o.gap ?? 3;
  };
  L.rule = (gap = 8) => {
    L.ensure(gap * 2);
    L.page.drawLine({ start: { x: PDF_M, y: L.y }, end: { x: PDF_W - PDF_M, y: L.y }, thickness: 0.7, color: RULE });
    L.y -= gap;
  };
  L.metaRow = (label, value) => {
    if (value === null || value === undefined || value === '') return;
    const labelW = 120;
    const lines = wrapPdfText(safe(value), regular, 10, PDF_W - 2 * PDF_M - labelW);
    L.ensure(lines.length * 14 + 4);
    L.page.drawText(safe(label), { x: PDF_M, y: L.y - 9, size: 8.5, font: bold, color: MUTED });
    lines.forEach((ln, i) => L.page.drawText(ln, { x: PDF_M + labelW, y: L.y - 10 - i * 13.5, size: 10, font: regular, color: INK }));
    L.y -= lines.length * 13.5 + 4;
  };
  L.table = (headers, widths, rows) => {
    const size = 9, pad = 5;
    const drawHeader = () => {
      L.ensure(24);
      L.page.drawRectangle({ x: PDF_M, y: L.y - 20, width: widths.reduce((a, b) => a + b, 0), height: 20, color: SOFT, borderColor: RULE, borderWidth: 0.7 });
      let x = PDF_M;
      headers.forEach((h, i) => { L.page.drawText(safe(h), { x: x + pad, y: L.y - 14, size: 8.5, font: bold, color: MUTED }); x += widths[i]; });
      L.y -= 20;
    };
    drawHeader();
    for (const row of rows) {
      const cells = row.map((c, i) => wrapPdfText(safe(c), regular, size, widths[i] - pad * 2));
      const h = Math.max(...cells.map(c => c.length)) * 12 + pad * 2;
      if (L.y - h < PDF_M + 20) { L.newPage(); drawHeader(); }
      let x = PDF_M;
      cells.forEach((lines, i) => {
        L.page.drawRectangle({ x, y: L.y - h, width: widths[i], height: h, borderColor: RULE, borderWidth: 0.7 });
        lines.forEach((ln, j) => { if (ln) L.page.drawText(ln, { x: x + pad, y: L.y - pad - size - j * 12 + 2, size, font: regular, color: INK }); });
        x += widths[i];
      });
      L.y -= h;
    }
    L.y -= 10;
  };
  if (startNewPage) L.newPage();
  return L;
}

const FLOW_REF_PREFIX = { contractual_records: 'CON', administrative_records: 'ADM', safety_records: 'SAF', operational_records: 'OPS', financial_records: 'FIN' };
const flowRecordRef = (table, rec) => `${FLOW_REF_PREFIX[table] || 'REC'}-${String(rec.id).padStart(3, '0')}${rec.revision_no ? ` Rev ${rec.revision_no}` : ''}`;
const DEFAULT_FLOW_TZ = 'Africa/Kigali';
const flowValidTz = (tz) => { try { new Intl.DateTimeFormat('en-GB', { timeZone: tz }); return tz; } catch (_) { return DEFAULT_FLOW_TZ; } };
function flowFormatDateTime(value, tz) {
  if (!value) return '';
  return new Date(value).toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZoneName: 'short', timeZone: flowValidTz(tz || DEFAULT_FLOW_TZ) });
}
function flowFormatDate(value, tz) {
  if (!value) return '';
  return new Date(value).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: flowValidTz(tz || DEFAULT_FLOW_TZ) });
}
async function loadProjectMemberKeys(projectId) {
  const { rows } = await pool.query(
    `SELECT 'Client' AS role, client_id AS id FROM projects WHERE id=$1 AND client_id IS NOT NULL
     UNION ALL SELECT 'Contractor', contractor_id FROM contractor_assignments WHERE project_id=$1
     UNION ALL SELECT 'Consultant', consultant_id FROM consultant_assignments WHERE project_id=$1
     UNION ALL SELECT 'ClientPM', client_pm_id FROM client_pm_assignments WHERE project_id=$1
     UNION ALL SELECT 'ContractorPM', contractor_pm_id FROM contractor_pm_assignments WHERE project_id=$1
     UNION ALL SELECT 'ConsultantPM', consultant_pm_id FROM consultant_pm_assignments WHERE project_id=$1
     UNION ALL SELECT 'TeamMember', team_member_id FROM team_member_assignments WHERE project_id=$1`,
    [projectId]
  );
  return new Set(rows.map(r => `${r.role}:${r.id}`));
}
async function loadProjectTz(projectId) {
  const { rows } = await pool.query('SELECT time_zone FROM projects WHERE id=$1', [projectId]).catch(() => ({ rows: [] }));
  return flowValidTz(rows[0]?.time_zone || DEFAULT_FLOW_TZ);
}

function drawMetaBlock(L, ctx) {
  L.metaRow('To', ctx.toLine);
  L.metaRow('From', ctx.fromLine);
  L.metaRow('Cc', ctx.ccLine);
  L.metaRow('Project', ctx.projectName);
  L.metaRow('Contract ref.', ctx.contractRef);
  L.metaRow('Reference', ctx.recordRef);
  L.metaRow('Subject', `${ctx.decisionWord}: ${ctx.rec.title}`);
  L.metaRow('Date', flowFormatDate(ctx.issuedAt, ctx.tz));
  L.metaRow('Respond by', ctx.respondBy ? flowFormatDate(ctx.respondBy, ctx.tz) : '');
}

function drawQuerySchedule(L, queries) {
  if (!queries.length) return;
  L.ensure(60);
  L.text('Query schedule', { size: 11, font: L.bold, gap: 4 });
  L.table(
    ['No.', 'Reference', 'Query', 'Required action', 'Raised by'],
    [26, 68, 160, 142, 100],
    queries.map((q, i) => [String(i + 1), q.ref || '', q.query, q.required_action || '', q.by || ''])
  );
}

function drawFingerprint(L, ctx) {
  L.ensure(70);
  L.rule(8);
  L.text('Record fingerprint (SHA-256)', { size: 8.5, font: L.bold, color: MUTED, gap: 2 });
  L.text(ctx.fingerprint || 'Not available for this record', { size: 8, font: L.mono, color: INK, gap: 2 });
  L.text('This notice refers to the record above. The fingerprint identifies the exact file that was reviewed.', { size: 8, color: MUTED });
}

// The system letter (a full notice built from the form)
// ---- Formatted notice text (rich letter) ----------------------------------------------------
// The notice text is written in a small editor (bold, italic, underline, headings, lists, alignment).
// The server keeps only a safe subset of tags and draws it into the letter PDF.
const LETTER_TAGS = new Set(['p', 'div', 'br', 'b', 'strong', 'i', 'em', 'u', 'ul', 'ol', 'li', 'h1', 'h2', 'h3']);
const LETTER_BLOCKS = new Set(['p', 'div', 'h1', 'h2', 'h3', 'li']);
const looksLikeHtml = (v) => /<\/?[a-z][^>]*>/i.test(String(v || ''));
function decodeLetterEntities(t) {
  return String(t).replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'").replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n))).replace(/&amp;/g, '&');
}
function letterAlignFrom(attrs) {
  const m = /text-align\s*:\s*(left|right|center|justify)/i.exec(attrs) || /align\s*=\s*["']?(left|right|center|justify)/i.exec(attrs);
  return m ? m[1].toLowerCase() : null;
}
function sanitizeLetterHtml(html) {
  const raw = String(html || '').replace(/<(script|style)[\s\S]*?<\/\1>/gi, '').replace(/<!--[\s\S]*?-->/g, '');
  const out = []; const stack = [];
  for (const m of raw.matchAll(/<(\/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*)>|([^<]+)/g)) {
    if (m[4] !== undefined) { out.push(m[4].replace(/&(?!(amp|lt|gt|quot|nbsp|#\d+|#39|apos);)/g, '&amp;').replace(/>/g, '&gt;')); continue; }
    const closing = m[1] === '/'; const tag = m[2].toLowerCase();
    if (!LETTER_TAGS.has(tag)) continue;
    if (tag === 'br') { if (!closing) out.push('<br>'); continue; }
    if (closing) {
      const at = stack.lastIndexOf(tag);
      if (at === -1) continue;
      while (stack.length > at) out.push(`</${stack.pop()}>`);
    } else {
      const al = LETTER_BLOCKS.has(tag) && tag !== 'li' ? letterAlignFrom(m[3] || '') : null;
      out.push(al ? `<${tag} style="text-align:${al}">` : `<${tag}>`);
      stack.push(tag);
    }
  }
  while (stack.length) out.push(`</${stack.pop()}>`);
  return out.join('');
}
function letterHtmlToPlain(html) {
  return decodeLetterEntities(String(html || '').replace(/<(br)\s*\/?>|<\/(p|div|li|h1|h2|h3)>/gi, '\n').replace(/<[^>]+>/g, ''))
    .replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
}
function parseLetterBlocks(html) {
  const blocks = []; const lists = []; const fmt = { b: 0, i: 0, u: 0 }; let cur = null;
  const flush = () => {
    if (!cur) return;
    const hasText = cur.runs.some(r => r.text.trim());
    if (hasText) blocks.push(cur); else if (cur.type !== 'li') blocks.push({ type: 'blank', runs: [] });
    cur = null;
  };
  for (const m of String(html || '').matchAll(/<(\/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*)>|([^<]+)/g)) {
    if (m[4] !== undefined) {
      const text = decodeLetterEntities(m[4]).replace(/[ \t\r\n]+/g, ' ');
      if (!cur) { if (!text.trim()) continue; cur = { type: 'p', align: 'left', runs: [] }; }
      cur.runs.push({ text, b: fmt.b > 0, i: fmt.i > 0, u: fmt.u > 0 });
      continue;
    }
    const closing = m[1] === '/'; const tag = m[2].toLowerCase();
    if (tag === 'br') { if (!cur) cur = { type: 'p', align: 'left', runs: [] }; cur.runs.push({ text: '\n', b: false, i: false, u: false }); continue; }
    if (['b', 'strong'].includes(tag)) { fmt.b += closing ? -1 : 1; continue; }
    if (['i', 'em'].includes(tag)) { fmt.i += closing ? -1 : 1; continue; }
    if (tag === 'u') { fmt.u += closing ? -1 : 1; continue; }
    if (tag === 'ul' || tag === 'ol') { flush(); if (closing) lists.pop(); else lists.push({ ordered: tag === 'ol', n: 0 }); continue; }
    if (LETTER_BLOCKS.has(tag)) {
      flush();
      if (closing) continue;
      if (tag === 'li') {
        const l = lists[lists.length - 1] || { ordered: false, n: 0 };
        l.n += 1;
        cur = { type: 'li', align: 'left', ordered: l.ordered, num: l.n, level: Math.max(lists.length, 1), runs: [] };
      } else cur = { type: tag === 'div' ? 'p' : tag, align: letterAlignFrom(m[3] || '') || 'left', runs: [] };
    }
  }
  flush();
  return blocks;
}
async function drawLetterBody(L, pdfDoc, body) {
  if (!looksLikeHtml(body)) { L.text(body, { size: 10.5, gap: 8 }); return; }
  const fonts = {
    r: L.regular, b: L.bold,
    i: await pdfDoc.embedFont(StandardFonts.HelveticaOblique),
    bi: await pdfDoc.embedFont(StandardFonts.HelveticaBoldOblique),
  };
  const maxW = PDF_W - 2 * PDF_M;
  for (const blk of parseLetterBlocks(body)) {
    if (blk.type === 'blank') { L.y -= 8; continue; }
    const heading = { h1: 16, h2: 13, h3: 11.5 }[blk.type];
    const size = heading || 10.5;
    const lineH = size * 1.45;
    const indent = blk.type === 'li' ? 14 + (blk.level - 1) * 16 : 0;
    const left = PDF_M + indent;
    const width = maxW - indent;
    // words with their styles
    const words = [];
    for (const r of blk.runs) {
      const bold = heading ? true : r.b;
      const font = bold && r.i ? fonts.bi : bold ? fonts.b : r.i ? fonts.i : fonts.r;
      for (const part of r.text.split(/(\n|\s+)/)) {
        if (part === '') continue;
        if (part === '\n') words.push({ br: true });
        else words.push({ text: L.safe(part), font, u: r.u, space: /^\s+$/.test(part) });
      }
    }
    const measure = (w) => (w.w ??= w.font.widthOfTextAtSize(w.text, size));
    const lines = []; let line = []; let lw = 0;
    const push = () => { while (line.length && line[line.length - 1].space) line.pop(); lines.push(line); line = []; lw = 0; };
    for (const w of words) {
      if (w.br) { push(); continue; }
      if (w.space && !line.length) continue;
      const wd = measure(w);
      if (lw + wd > width && line.length && !w.space) push();
      if (!w.space && wd > width) {   // a single very long word: split it
        let chunk = '';
        for (const ch of w.text) {
          if (w.font.widthOfTextAtSize(chunk + ch, size) > width && chunk) { lines.push([{ text: chunk, font: w.font, u: w.u, w: w.font.widthOfTextAtSize(chunk, size) }]); chunk = ''; }
          chunk += ch;
        }
        if (chunk) { line.push({ text: chunk, font: w.font, u: w.u, w: w.font.widthOfTextAtSize(chunk, size) }); lw = line[0].w; }
        continue;
      }
      line.push(w); lw += wd;
    }
    if (line.length) push();
    if (!lines.length) lines.push([]);
    lines.forEach((ln, idx) => {
      L.ensure(lineH);
      const total = ln.reduce((a, w) => a + measure(w), 0);
      let x = left;
      if (blk.align === 'center') x = left + (width - total) / 2;
      else if (blk.align === 'right') x = left + width - total;
      if (blk.type === 'li' && idx === 0) {
        const marker = blk.ordered ? `${blk.num}.` : '\u2022';
        L.page.drawText(L.safe(marker), { x: left - 12, y: L.y - size, size, font: fonts.r, color: INK });
      }
      for (const w of ln) {
        if (w.text.trim()) L.page.drawText(w.text, { x, y: L.y - size, size, font: w.font, color: INK });
        if (w.u && w.text.trim()) L.page.drawLine({ start: { x, y: L.y - size - 1.5 }, end: { x: x + measure(w), y: L.y - size - 1.5 }, thickness: 0.6, color: INK });
        x += measure(w);
      }
      L.y -= lineH;
    });
    L.y -= heading ? 6 : 4;
  }
  L.y -= 4;
}

async function drawGeneratedLetter(pdfDoc, ctx, queries) {
  const L = await createLayout(pdfDoc);
  L.text(ctx.kindTitle, { size: 17, font: L.bold, gap: 2 });
  L.text(ctx.title, { size: 11.5, font: L.regular, color: MUTED, gap: 6 });
  L.rule(10);
  drawMetaBlock(L, ctx);
  L.rule(10);
  L.text(`Decision: ${ctx.decisionWord}`, { size: 12, font: L.bold, gap: 6 });
  if (ctx.body) await drawLetterBody(L, pdfDoc, ctx.body);
  drawQuerySchedule(L, queries);
  drawFingerprint(L, ctx);
}

// Annex pages added behind a user's own notice PDF
async function drawNoticeAnnex(pdfDoc, ctx, queries) {
  const L = await createLayout(pdfDoc);
  L.text(`Annex to ${ctx.kindTitle.toLowerCase()}`, { size: 14, font: L.bold, gap: 2 });
  L.text(ctx.title, { size: 10.5, color: MUTED, gap: 6 });
  L.rule(10);
  drawMetaBlock(L, ctx);
  L.rule(10);
  L.text(`Decision: ${ctx.decisionWord}`, { size: 12, font: L.bold, gap: 6 });
  if (ctx.body) await drawLetterBody(L, pdfDoc, ctx.body);
  drawQuerySchedule(L, queries);
  drawFingerprint(L, ctx);
}

// Deterministic: preview and the issued copy always show the same ID for the same signing event.
function decisionStampId(ctx, slot) {
  if (!ctx.table || !slot?.signed_at) return null;
  return deriveStampId({ k: 'decision', t: ctx.table, rec: ctx.rec?.id, u: slot.userId, r: slot.role,
    at: new Date(slot.signed_at).toISOString(), fp: ctx.fingerprint || '' });
}

async function appendSignaturePage(pdfDoc, ctx, slots, opts = {}) {
  const L = await createLayout(pdfDoc);
  L.text(opts.heading || 'Signatures', { size: 15, font: L.bold, gap: 2 });
  L.text(`${ctx.kindTitle}. Record #${ctx.rec.id}: ${ctx.rec.title}`, { size: 9.5, color: MUTED, gap: 8 });
  L.rule(10);
  if (opts.decisionLine) L.text(opts.decisionLine, { size: 11, font: L.bold, gap: 8 });
  const boxW = 235, boxH = 138, gapX = 17, gapY = 26;
  let col = 0;
  for (const slot of slots) {
    if (col === 0) L.ensure(boxH + gapY + 14);
    const x = PDF_M + col * (boxW + gapX);
    const top = L.y;
    L.page.drawText(L.safe(slot.caption), { x, y: top - 9, size: 8.5, font: L.bold, color: MUTED });
    const boxTop = top - 16;
    const signed = slot.status === 'signed' && slot.profile;
    if (!(slot.status === 'signed' && slot.profile)) {
      L.page.drawRectangle({
        x, y: boxTop - boxH, width: boxW, height: boxH,
        borderColor: MUTED, borderWidth: 0.8, borderDashArray: [3, 3], color: rgb(1, 1, 1),
      });
    }
    if (signed) {
      const p = slot.profile;
      const stampId = decisionStampId(ctx, slot);
      if (!ctx.preview && stampId) {
        await registerStamp(pool, { stampId, projectId: ctx.projectId, table: ctx.table, recordId: ctx.rec?.id, kind: 'decision',
          userId: slot.userId, role: slot.role, name: p.name, position: slot.position || p.position, company: p.company,
          label: ctx.decisionWord || 'APPROVED', tz: ctx.tz, fileHash: null, signedAt: slot.signed_at });
      }
      const spec = stampSpecFromProfile({ ...p, position: slot.position || p.position, side: slot.side || p.side },
        { label: ctx.decisionWord || 'APPROVED', signedAt: slot.signed_at, tz: ctx.tz, stampId, baseUrl: ctx.baseUrl });
      const lay = await layoutStamp(pdfDoc, spec, { width: boxW });
      lay.paint(L.page, x, boxTop - lay.height);
    } else {
      L.page.drawText(slot.pendingLabel || 'Awaiting signature', { x: x + 8, y: boxTop - 22, size: 9, font: L.bold, color: MUTED });
      L.page.drawText(L.safe(`${slot.position || ''}${slot.side ? ', ' + flowSideLabel(slot.side) + ' side' : ''}`), { x: x + 8, y: boxTop - 36, size: 8, font: L.regular, color: MUTED });
    }
    col += 1;
    if (col === 2) { col = 0; L.y = boxTop - boxH - gapY; }
  }
}

// Notice PDF = (system letter | the user's own PDF + annex) + signature page
async function addFlowFooters(doc, { left, fromIndex = 0 }) {
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const safe = makePdfSafe(font);
  const total = doc.getPageCount();
  for (let i = fromIndex; i < total; i++) {
    const page = doc.getPage(i); const { width } = page.getSize();
    const right = `Page ${i + 1} of ${total}`;
    page.drawLine({ start: { x: PDF_M, y: 34 }, end: { x: width - PDF_M, y: 34 }, thickness: 0.5, color: RULE });
    page.drawText(safe(String(left)).slice(0, 95), { x: PDF_M, y: 22, size: 8, font, color: MUTED });
    page.drawText(right, { x: width - PDF_M - font.widthOfTextAtSize(right, 8), y: 22, size: 8, font, color: MUTED });
  }
}

async function composeNoticePdf({ source, uploadedBytes, ctx, queries, slots }) {
  const out = await PDFDocument.create();
  let ownPages = 0;
  if (source === 'uploaded') {
    const up = await PDFDocument.load(uploadedBytes);
    const pages = await out.copyPages(up, up.getPageIndices());
    pages.forEach(p => out.addPage(p));
    ownPages = pages.length;
    if (queries.length || ctx.body) await drawNoticeAnnex(out, ctx, queries);
  } else {
    await drawGeneratedLetter(out, ctx, queries);
  }
  await appendSignaturePage(out, ctx, slots);
  await addFlowFooters(out, { left: `${ctx.projectName}  |  ${ctx.recordRef}  |  ${ctx.kindTitle}`, fromIndex: ownPages });   // never over the leader's own pages
  return Buffer.from(await out.save());
}

// The record itself carries the approvals: its latest file plus a sign-off page for this stage.
// Built only for approvals. A rejected record is never signed or stamped.
async function buildRecordWithSignoff({ rec, ctx, slots, stageLabel, decisionLine, stage, placementIn }) {
  const recUrl = rec.stamped_doc_url || rec.file_path;
  const remote = await fetch(recUrl, { redirect: 'follow' });
  if (!remote.ok) throw new Error('The record file is not reachable.');
  const doc = await PDFDocument.load(Buffer.from(await remote.arrayBuffer()), { ignoreEncryption: true });

  // 1) Only if the approver chose a spot: the decision block goes exactly there (never over content by default)
  let placement = null;
  if (placementIn) {
    const decider = slots.find(sl => sl.isDecider);
    placement = await drawRecordDecisionStamp(doc, { word: ctx.decisionWord, slot: decider, ctx, at: placementIn });
  }
  // 2) The sign-off page (every named signer) is always added at the end of the record
  const originalPages = doc.getPageCount();
  await appendSignaturePage(doc, { ...ctx, kindTitle: `Record sign-off, ${stageLabel}` }, slots, { heading: 'Record sign-off', decisionLine });
  await addFlowFooters(doc, { left: `${ctx.projectName}  |  ${ctx.recordRef}  |  Record sign-off`, fromIndex: originalPages });
  return { bytes: Buffer.from(await doc.save()), placement };
}

// Decision block at the position the approver picked: word, signature, company stamp, name/position, date.
async function drawRecordDecisionStamp(doc, { word, slot, ctx, at }) {
  const pageIdx = Math.min(Math.max((at.page || 1) - 1, 0), doc.getPageCount() - 1);
  const page = doc.getPage(pageIdx);
  const profile = slot?.profile;
  const spec = stampSpecFromProfile({ ...(profile || {}), position: slot?.position || profile?.position, side: slot?.side || profile?.side },
    { label: word || 'APPROVED', signedAt: slot?.signed_at, tz: ctx.tz, stampId: decisionStampId(ctx, slot), baseUrl: ctx.baseUrl });
  const box = await drawStampOnPage(doc, page, spec, { xRatio: at.x, yRatio: at.y });
  return { page: pageIdx + 1, x: box.xRatio, y: box.yRatio };
}

// Original record + the new notice, with divider strips (same look as the bundle)
async function buildDecisionBundle({ rec, noticeBytes, noticeLabel, recordBytes, tz }) {
  const out = await PDFDocument.create();
  const labelFont = await out.embedFont(StandardFonts.Helvetica);
  const labelBold = await out.embedFont(StandardFonts.HelveticaBold);
  const strip = (label, title, meta) => {
    const page = out.addPage([612, 72]);
    page.drawRectangle({ x: 0, y: 0, width: 612, height: 72, color: SOFT });
    page.drawRectangle({ x: 0, y: 0, width: 8, height: 72, color: INK });
    page.drawText(label, { x: 26, y: 43, size: 12, font: labelBold, color: INK });
    page.drawText(makePdfSafe(labelFont)(title), { x: 150, y: 44, size: 10, font: labelBold, color: INK, maxWidth: 420 });
    page.drawText(makePdfSafe(labelFont)(meta), { x: 150, y: 25, size: 9, font: labelFont, color: MUTED, maxWidth: 420 });
  };
  const recUrl = rec.stamped_doc_url || rec.file_path;
  let recDoc;
  if (recordBytes) {
    recDoc = await PDFDocument.load(recordBytes);
  } else {
    const remote = await fetch(recUrl, { redirect: 'follow' });
    if (!remote.ok) throw new Error('The original record file is not reachable.');
    recDoc = await PDFDocument.load(Buffer.from(await remote.arrayBuffer()));
  }
  strip(recordBytes ? 'RECORD + SIGN-OFF' : 'ORIGINAL RECORD', String(rec.title || 'Untitled'), `Added by ${flowRoleLabel(rec.role) || 'Unknown'}, ${flowFormatDate(rec.issued_date, tz)}`);
  (await out.copyPages(recDoc, recDoc.getPageIndices())).forEach(p => out.addPage(p));
  const noticeDoc = await PDFDocument.load(noticeBytes);
  strip(noticeLabel, 'Preview, not yet issued', 'Shown exactly as it will be issued');
  (await out.copyPages(noticeDoc, noticeDoc.getPageIndices())).forEach(p => out.addPage(p));
  return Buffer.from(await out.save());
}


function getStampStatusFromActor(previousStatus, actorRole) {
  const normalized = (previousStatus || 'none').toLowerCase();
  if (normalized === 'both') return 'both';
  const actor = (actorRole || 'approver').toLowerCase();
  const isRecorder = actor === 'recorder';
  if (normalized === 'none') return isRecorder ? 'recorder' : 'approver';
  if (normalized === 'approver' && isRecorder) return 'both';
  if (normalized === 'recorder' && !isRecorder) return 'both';
  return normalized;
}

function getSide(role) {
  if (!role) return null;
  const r = role.toLowerCase().replace(/[\s_-]+/g, '');
  if (r === 'contractor' || r === 'contractorpm') return 'contractor';
  if (r === 'consultant' || r === 'consultantpm') return 'consultant';
  if (r === 'client'     || r === 'clientpm')     return 'client';
  return null;
}

function isDecisionMaker(role) { return getSide(role) !== null; }

function normalizeRole(role) {
  if (!role) return role;
  return {
    Client: 'Client',
    Contractor: 'Contractor',
    Consultant: 'Consultant',
    ClientPM: 'ClientPM',
    'Client Project Manager': 'ClientPM',
    ContractorPM: 'ContractorPM',
    'Contractor Project Manager': 'ContractorPM',
    ConsultantPM: 'ConsultantPM',
    'Consultant Project Manager': 'ConsultantPM',
    TeamMember: 'TeamMember',
    'Team Member': 'TeamMember',
  }[role] || role;
}

function canEditSchedule(role) {
  return ['Contractor', 'Consultant', 'ContractorPM', 'ConsultantPM'].includes(normalizeRole(role));
}

async function recalculateScheduleProgress(client, table, foreignKey, milestoneId) {
  const milestoneTable = table === 'milestone_progress_entries' ? 'milestones' : 'additional_milestones';
  const { rows: milestoneRows } = await client.query(`SELECT quantity FROM ${milestoneTable} WHERE id=$1 FOR UPDATE`, [milestoneId]);
  if (!milestoneRows.length) return null;
  const planned = Number(milestoneRows[0].quantity) || 0;
  const { rows: entries } = await client.query(
    `SELECT id,qty_executed,report_date FROM ${table} WHERE ${foreignKey}=$1 ORDER BY report_date ASC,id ASC FOR UPDATE`,
    [milestoneId]
  );
  let cumulative = 0;
  for (const entry of entries) {
    cumulative += Number(entry.qty_executed) || 0;
    const pct = planned > 0 ? Math.min(100, cumulative / planned * 100) : 0;
    await client.query(`UPDATE ${table} SET cumulative_after_entry=$1,progress_pct_after_entry=$2 WHERE id=$3`, [cumulative, pct.toFixed(2), entry.id]);
  }
  const status = planned > 0 && cumulative >= planned ? 'completed' : cumulative > 0 ? 'in_progress' : 'planned';
  await client.query(`UPDATE ${milestoneTable} SET executed=$1,progress_pct=$2,activity_status=$3,completed_at=$4,updated_at=now() WHERE id=$5`, [cumulative, planned > 0 ? Math.min(100, cumulative / planned * 100).toFixed(2) : 0, status, status === 'completed' ? new Date() : null, milestoneId]);
  return { executed: cumulative, progress_pct: planned > 0 ? Math.min(100, cumulative / planned * 100) : 0, activity_status: status };
}

// Resolve a human-friendly display name for a given role+id within a project context
async function resolveDisplayNameFor(role, id, projectId = null) {
  if (!role || !id) return null;
  const r = normalizeRole(role);
  try {
    if (r === 'Client') {
      const { rows } = await pool.query('SELECT display_name, representative, company_name, company_email FROM clients WHERE id=$1 LIMIT 1', [id]);
      const row = rows[0];
      return row?.display_name || row?.representative || row?.company_name || row?.company_email || null;
    }
    if (r === 'Contractor') {
      const { rows } = await pool.query('SELECT display_name, email FROM contractors WHERE id=$1 LIMIT 1', [id]);
      const row = rows[0];
      if (row?.display_name) return row.display_name;
      // try to find project-specific assignment name/rep
      if (projectId) {
        const { rows: arows } = await pool.query('SELECT company_name, representative FROM contractor_assignments WHERE contractor_id=$1 AND project_id=$2 LIMIT 1', [id, projectId]);
        const a = arows[0];
        if (a?.representative) return a.representative;
        if (a?.company_name) return a.company_name;
      }
      return row?.email || null;
    }
    if (r === 'Consultant') {
      const { rows } = await pool.query('SELECT display_name, email FROM consultants WHERE id=$1 LIMIT 1', [id]);
      const row = rows[0];
      if (row?.display_name) return row.display_name;
      if (projectId) {
        const { rows: arows } = await pool.query('SELECT company_name, representative FROM consultant_assignments WHERE consultant_id=$1 AND project_id=$2 LIMIT 1', [id, projectId]);
        const a = arows[0];
        if (a?.representative) return a.representative;
        if (a?.company_name) return a.company_name;
      }
      return row?.email || null;
    }
    if (r === 'ClientPM') {
      const { rows } = await pool.query('SELECT display_name, email FROM client_project_managers WHERE id=$1 LIMIT 1', [id]);
      const row = rows[0];
      return row?.display_name || row?.email || null;
    }
    if (r === 'ContractorPM') {
      const { rows } = await pool.query('SELECT display_name, email FROM contractor_project_managers WHERE id=$1 LIMIT 1', [id]);
      const row = rows[0];
      return row?.display_name || row?.email || null;
    }
    if (r === 'ConsultantPM') {
      const { rows } = await pool.query('SELECT display_name, email FROM consultant_project_managers WHERE id=$1 LIMIT 1', [id]);
      const row = rows[0];
      return row?.display_name || row?.email || null;
    }
    if (r === 'TeamMember') {
      const { rows } = await pool.query('SELECT display_name, email FROM team_members WHERE id=$1 LIMIT 1', [id]);
      const row = rows[0];
      if (row?.display_name) return row.display_name;
      if (projectId) {
        const { rows: arows } = await pool.query('SELECT name, position FROM team_member_assignments WHERE team_member_id=$1 AND project_id=$2 LIMIT 1', [id, projectId]);
        const a = arows[0];
        if (a?.name) return a.name;
        if (a?.position) return a.position;
      }
      return row?.email || null;
    }
    return null;
  } catch (err) {
    console.warn('[resolveDisplayNameFor] DB lookup failed:', err.message);
    return null;
  }
}

function normalizeProjectId(value) {
  if (value === undefined || value === null) return null;
  const raw = String(value).trim();
  if (!raw) return null;
  return /^[0-9]+$/.test(raw) ? parseInt(raw, 10) : raw;
}

function parseJsonSafe(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value); } catch { return null; }
}

function daysBetween(startStr, endStr) {
  if (!startStr || !endStr) return 0;
  return Math.max(0, Math.round((new Date(endStr) - new Date(startStr)) / 86400000) + 1);
}

function roleTableMap(role) {
  const normalized = normalizeRole(role);
  switch (normalized) {
    case 'Client':       return { table: 'clients',                     emailCol: 'company_email' };
    case 'ClientPM':     return { table: 'client_project_managers',     emailCol: 'email' };
    case 'Consultant':   return { table: 'consultants',                 emailCol: 'email' };
    case 'ConsultantPM': return { table: 'consultant_project_managers', emailCol: 'email' };
    case 'Contractor':   return { table: 'contractors',                 emailCol: 'email' };
    case 'ContractorPM': return { table: 'contractor_project_managers', emailCol: 'email' };
    case 'TeamMember':   return { table: 'team_members',                emailCol: 'email' };
    default:             return null;
  }
}

async function getProjectMemberUserIds(projectId, excludeUserId) {
  const queries = [
    pool.query('SELECT client_id AS user_id FROM projects WHERE id=$1', [projectId]),
    pool.query('SELECT contractor_id  AS user_id FROM contractor_assignments  WHERE project_id=$1', [projectId]),
    pool.query('SELECT consultant_id  AS user_id FROM consultant_assignments  WHERE project_id=$1', [projectId]),
    pool.query('SELECT client_pm_id   AS user_id FROM client_pm_assignments   WHERE project_id=$1', [projectId]),
    pool.query('SELECT contractor_pm_id AS user_id FROM contractor_pm_assignments WHERE project_id=$1', [projectId]),
    pool.query('SELECT consultant_pm_id AS user_id FROM consultant_pm_assignments WHERE project_id=$1', [projectId]),
    pool.query('SELECT team_member_id AS user_id FROM team_member_assignments WHERE project_id=$1', [projectId]),
  ];
  const results = await Promise.all(queries);
  const ids = new Set();
  for (const r of results) {
    for (const row of r.rows) {
      const id = String(row.user_id);
      if (id && id !== String(excludeUserId)) ids.add(Number(id));
    }
  }
  return [...ids];
}

async function insertNotificationRecipients(dbClient, notificationId, recipients) {
  if (!recipients || !recipients.length) {
    console.warn(`[insertNotificationRecipients] No recipients to insert for notif=${notificationId}`);
    return;
  }
  console.log(`[insertNotificationRecipients] ⏳ Starting insert: notif=${notificationId}, ${recipients.length} recipients`);
  let successCount = 0;
  let skipCount = 0;

  for (const recipient of recipients) {
    try {
      console.log(`[insertNotificationRecipients] inserting: notif=${notificationId}, role=${recipient.recipient_role}, role_id=${recipient.recipient_role_id}`);
      const res = await dbClient.query(
        `INSERT INTO notification_recipients
           (notification_id, recipient_role, recipient_role_id, is_read, created_at)
         SELECT $1, $2, $3, false, NOW()
         WHERE NOT EXISTS (
           SELECT 1 FROM notification_recipients nr
           WHERE nr.notification_id = $1
             AND nr.recipient_role = $2
             AND nr.recipient_role_id = $3
         )
         RETURNING id`,
        [notificationId, recipient.recipient_role, recipient.recipient_role_id]
      );
      if (res.rows.length > 0) {
        console.log(`[insertNotificationRecipients] ✓ Inserted notification_recipients row ${res.rows[0].id}`);
        successCount++;
      } else {
        console.log(`[insertNotificationRecipients] ⊘ Skipped (already exists): notif=${notificationId}, role=${recipient.recipient_role}, role_id=${recipient.recipient_role_id}`);
        skipCount++;
      }
    } catch (err) {
      console.warn(`[insertNotificationRecipients] ✗ Insert failed for notif=${notificationId}, role=${recipient.recipient_role}, role_id=${recipient.recipient_role_id}: ${err.message}`);
      throw err;
    }
  }

  console.log(`[insertNotificationRecipients] ✓ Complete: notif=${notificationId}, ${successCount} inserted, ${skipCount} skipped`);
}

// =============================================================================
//  getProjectMembers — FIXED: a.position → correct columns per table
//
//  Schema reality:
//    contractor_assignments  → title_position (merged col, no separate position)
//    consultant_assignments  → title_position (merged col, no separate position)
//    client_pm_assignments   → no position col at all
//    contractor_pm_assignments → no position col at all
//    consultant_pm_assignments → no position col at all
//    team_member_assignments → position ✓
//    clients                 → title (no position)
// =============================================================================
async function getProjectMembers(projectId) {
  const { rows } = await pool.query(`
    -- Client
    SELECT
      'Client'                AS role,
      p.client_id             AS role_id,
      c.company_email         AS email,
      c.company_name,
      c.representative,
      c.title,
      c.display_name         AS display_name,
      NULL::text              AS title_position,
      NULL::text              AS position,
      c.profile_picture,
      NULL::text              AS assigned_part
    FROM projects p
    JOIN clients c ON p.client_id = c.id
    WHERE p.id = $1

    UNION ALL

    -- Contractor
    SELECT
      'Contractor'            AS role,
      a.contractor_id         AS role_id,
      c.email                 AS email,
      a.company_name,
      a.representative,
      NULL::text              AS title,
      c.display_name         AS display_name,
      a.title_position,
      NULL::text              AS position,
      c.profile_picture,
      NULL::text              AS assigned_part
    FROM contractor_assignments a
    JOIN contractors c ON a.contractor_id = c.id
    WHERE a.project_id = $1

    UNION ALL

    -- Consultant
    SELECT
      'Consultant'            AS role,
      a.consultant_id         AS role_id,
      c.email                 AS email,
      a.company_name,
      a.representative,
      NULL::text              AS title,
      c.display_name         AS display_name,
      a.title_position,
      NULL::text              AS position,
      c.profile_picture,
      NULL::text              AS assigned_part
    FROM consultant_assignments a
    JOIN consultants c ON a.consultant_id = c.id
    WHERE a.project_id = $1

    UNION ALL

    -- ClientPM
    SELECT
      'ClientPM'              AS role,
      a.client_pm_id          AS role_id,
      c.email                 AS email,
      NULL::text              AS company_name,
      NULL::text              AS representative,
      a.name                  AS title,
      c.display_name         AS display_name,
      NULL::text              AS title_position,
      NULL::text              AS position,
      c.profile_picture,
      NULL::text              AS assigned_part
    FROM client_pm_assignments a
    JOIN client_project_managers c ON a.client_pm_id = c.id
    WHERE a.project_id = $1

    UNION ALL

    -- ContractorPM
    SELECT
      'ContractorPM'          AS role,
      a.contractor_pm_id      AS role_id,
      c.email                 AS email,
      NULL::text              AS company_name,
      NULL::text              AS representative,
      a.name                  AS title,
      c.display_name         AS display_name,
      NULL::text              AS title_position,
      NULL::text              AS position,
      c.profile_picture,
      NULL::text              AS assigned_part
    FROM contractor_pm_assignments a
    JOIN contractor_project_managers c ON a.contractor_pm_id = c.id
    WHERE a.project_id = $1

    UNION ALL

    -- ConsultantPM
    SELECT
      'ConsultantPM'          AS role,
      a.consultant_pm_id      AS role_id,
      c.email                 AS email,
      NULL::text              AS company_name,
      NULL::text              AS representative,
      a.name                  AS title,
      c.display_name         AS display_name,
      NULL::text              AS title_position,
      NULL::text              AS position,
      c.profile_picture,
      NULL::text              AS assigned_part
    FROM consultant_pm_assignments a
    JOIN consultant_project_managers c ON a.consultant_pm_id = c.id
    WHERE a.project_id = $1

    UNION ALL

    -- TeamMember
    SELECT
      'TeamMember'            AS role,
      a.team_member_id        AS role_id,
      c.email                 AS email,
      NULL::text              AS company_name,
      NULL::text              AS representative,
      a.name                  AS title,
      c.display_name         AS display_name,
      NULL::text              AS title_position,
      a.position,
      c.profile_picture,
      a.assigned_part
    FROM team_member_assignments a
    JOIN team_members c ON a.team_member_id = c.id
    WHERE a.project_id = $1
  `, [projectId]);

    return rows.map(r => ({
    ...r,
    role_id:      Number(r.role_id),
    display_name: r.display_name || r.representative || r.title || r.email || 'Unknown',
  }));
}

async function getProjectRecipientKeys(projectId, excludeUserId, excludeRole, scope = 'global', scopeValue = null) {
  const members = await getProjectMembers(projectId);
  const normalizedExcludeRole = normalizeRole(excludeRole);
  const targetSide = scope === 'side' && scopeValue ? getSide(scopeValue) : null;
  
  console.log(`[getProjectRecipientKeys] projectId=${projectId}, excludeUserId=${excludeUserId}, excludeRole=${excludeRole} (normalized=${normalizedExcludeRole}), scope=${scope}, scopeValue=${scopeValue}, targetSide=${targetSide}`);
  console.log(`[getProjectRecipientKeys] Total members from getProjectMembers: ${members.length}`);
  if (members.length > 0) {
    console.log('[getProjectRecipientKeys] Sample members:', members.slice(0, 3).map(m => ({role: m.role, role_id: m.role_id, email: m.email})));
  }

  const filtered1 = members
    .filter(m => !(Number(m.role_id) === Number(excludeUserId) && normalizeRole(m.role) === normalizedExcludeRole));
  console.log(`[getProjectRecipientKeys] After excluding creator: ${filtered1.length}`);
  
  const filtered2 = filtered1.filter(m => {
    if (!targetSide) return true;
    const memberSide = getSide(m.role) || (m.role === 'TeamMember' ? m.assigned_part : null);
    const match = memberSide && memberSide.toLowerCase() === targetSide.toLowerCase();
    if (!match && m.role.includes('PM')) {
      console.warn(`[getProjectRecipientKeys] PM role mismatch: ${m.role} getSide=${getSide(m.role)} memberSide=${memberSide} targetSide=${targetSide}`);
    }
    return match;
  });
  console.log(`[getProjectRecipientKeys] After scope filter: ${filtered2.length}`);
  if (filtered2.length > 0) {
    console.log('[getProjectRecipientKeys] Final recipients:', filtered2.map(m => ({role: m.role, role_id: m.role_id, email: m.email})));
  }

  return filtered2
    .map(m => ({
      recipient_role:    normalizeRole(m.role),
      recipient_role_id: Number(m.role_id),
      user_id:           Number(m.role_id),
    }));
}

function escapeEmailHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[char]);
}

async function verifyClientPassword(clientId, password) {
  if (typeof password !== 'string' || !password) return false;
  const result = await pool.query('SELECT password_hash FROM clients WHERE id=$1', [clientId]);
  const passwordHash = result.rows[0]?.password_hash;
  return Boolean(passwordHash && await bcrypt.compare(password, passwordHash));
}

async function notifyProjectLifecycleChange(projectId, actorUserId, actorRole, { subject, message, emailBody }) {
  const result = { inAppSent: false, emailSent: 0, emailFailed: 0 };
  let projectName = `Project ${projectId}`;
  let members = [];
  let recipients = [];
  try {
    const projectResult = await pool.query('SELECT name FROM projects WHERE id=$1', [projectId]);
    projectName = projectResult.rows[0]?.name || projectName;
    members = await getProjectMembers(projectId);
    recipients = members
      .filter(member => !(Number(member.role_id) === Number(actorUserId) && normalizeRole(member.role) === normalizeRole(actorRole)))
      .map(member => ({
        recipient_role: normalizeRole(member.role),
        recipient_role_id: Number(member.role_id),
        user_id: Number(member.role_id),
      }));
  } catch (err) {
    console.error('[project lifecycle] failed to load notification recipients:', err.message);
    return result;
  }

  try {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SELECT set_config('app.project_deletion_purge','on',true)`);
      const notification = await client.query(
        `INSERT INTO notifications (project_id,entity_type,entity_id,message,added_by_id,added_by_role)
         VALUES ($1,'project_lifecycle',$2,$3,$4,$5) RETURNING id`,
        [projectId, projectId, message, actorUserId, normalizeRole(actorRole)]
      );
      await insertNotificationRecipients(client, notification.rows[0].id, recipients);
      await client.query('COMMIT');
      result.inAppSent = recipients.length > 0;
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('[project lifecycle] in-app notification failed:', err.message);
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('[project lifecycle] notification transaction failed:', err.message);
  }

  const uniqueEmails = [...new Set(members.map(member => String(member.email || '').trim()).filter(Boolean).map(email => email.toLowerCase()))];
  const displayEmails = new Map(members.map(member => [String(member.email || '').trim().toLowerCase(), String(member.email || '').trim()]));
  const deliveries = await Promise.allSettled(uniqueEmails.map(email => transporter.sendMail({
    from: 'skyprincenkp16@gmail.com',
    to: displayEmails.get(email),
    subject,
    html: `<p>Project <strong>${escapeEmailHtml(projectName)}</strong></p>${emailBody}`,
  })));
  result.emailSent = deliveries.filter(delivery => delivery.status === 'fulfilled').length;
  result.emailFailed = deliveries.length - result.emailSent;
  if (result.emailFailed) console.error(`[project lifecycle] ${result.emailFailed} member email(s) failed for project ${projectId}`);
  return result;
}

async function userHasProjectAccess(userId, role, projectId) {
  const projectCheck = {
    Client:       { table: 'projects',                  idCol: 'client_id' },
    Contractor:   { table: 'contractor_assignments',    idCol: 'contractor_id' },
    Consultant:   { table: 'consultant_assignments',    idCol: 'consultant_id' },
    ClientPM:     { table: 'client_pm_assignments',     idCol: 'client_pm_id' },
    ContractorPM: { table: 'contractor_pm_assignments', idCol: 'contractor_pm_id' },
    ConsultantPM: { table: 'consultant_pm_assignments', idCol: 'consultant_pm_id' },
    TeamMember:   { table: 'team_member_assignments',   idCol: 'team_member_id' },
  }[normalizeRole(role)];

  if (!projectCheck) return false;
  const query = projectCheck.table === 'projects'
    ? `SELECT 1 FROM ${projectCheck.table} WHERE id=$1 AND ${projectCheck.idCol}=$2`
    : `SELECT 1 FROM ${projectCheck.table} WHERE project_id=$1 AND ${projectCheck.idCol}=$2`;
  const { rows } = await pool.query(query, [projectId, userId]);
  return rows.length > 0;
}

function lifecycleProjectId(req) {
  const value = req.body?.projectId ?? req.body?.project_id ?? req.query?.projectId ?? req.params?.projectId;
  return /^\d+$/.test(String(value || '')) ? Number(value) : null;
}

async function getProjectScheduleClock(projectId, db = pool) {
  const { rows } = await db.query(
    `SELECT lifecycle_status,deletion_requested_at,
            TO_CHAR((
              (CASE WHEN lifecycle_status='pending_deletion' THEN deletion_requested_at ELSE NOW() END)
              - lifecycle_paused_seconds * INTERVAL '1 second'
            )::DATE,'YYYY-MM-DD') AS effective_today
     FROM projects WHERE id=$1`,
    [projectId]
  );
  if (!rows.length) return null;
  return {
    effective_today: rows[0].effective_today,
    paused: rows[0].lifecycle_status === 'pending_deletion',
    pause_started_at: rows[0].deletion_requested_at,
  };
}

async function resolveLifecycleProjectId(req) {
  const explicitId = lifecycleProjectId(req);
  if (explicitId) return explicitId;

  const idOnlyRoutes = [
    [/^\/api\/milestone-photos\/(\d+)$/, 'SELECT project_id FROM milestone_photos WHERE id=$1'],
    [/^\/api\/planning-execution-tracking\/(\d+)$/, 'SELECT pe.project_id FROM planning_execution_tracking t JOIN planning_execution pe ON pe.id=t.activity_id WHERE t.id=$1'],
    [/^\/chat\/messages\/(\d+)$/, 'SELECT project_id FROM project_chat_messages WHERE id=$1'],
  ];
  for (const [pattern, query] of idOnlyRoutes) {
    const match = req.path.match(pattern);
    if (!match) continue;
    const { rows } = await pool.query(query, [match[1]]);
    const projectId = Number(rows[0]?.project_id);
    return Number.isInteger(projectId) && projectId > 0 ? projectId : null;
  }
  return null;
}

async function getProjectWriteBlock(projectId, userId, role) {
  const project = await pool.query(
    'SELECT lifecycle_status FROM projects WHERE id=$1',
    [projectId]
  );
  if (!project.rows.length) return null;
  if (project.rows[0].lifecycle_status === 'pending_deletion') {
    return 'This project is read-only while deletion is scheduled.';
  }

  const exit = await pool.query(
    `SELECT 1 FROM project_exit_requests
     WHERE project_id=$1 AND user_id=$2 AND user_role=$3 AND status='pending'
     LIMIT 1`,
    [projectId, userId, normalizeRole(role)]
  );
  return exit.rows.length ? 'Your project access is read-only while your exit is scheduled.' : null;
}

async function requireProjectLifecycleWrite(req, res, next) {
  if (!req.user) return next();
  try {
    const projectId = await resolveLifecycleProjectId(req);
    if (!projectId) return next();
    const message = await getProjectWriteBlock(projectId, req.user.user_id, req.user.role);
    if (message) return res.status(423).json({ error: message, code: 'PROJECT_READ_ONLY' });
    return next();
  } catch (err) {
    console.error('[project lifecycle write guard]', err);
    return res.status(500).json({ error: 'Unable to verify project edit access.' });
  }
}

const lifecycleWriteExemptPaths = new Set([
  '/api/project-deletion/cancel',
  '/api/project-exit/request',
  '/api/project-exit/cancel',
  '/api/arrets/view',
  '/api/fetch-tab-records',
  '/api/mark-record-viewed',
  '/api/record-view',
  '/api/decision-preview',
  '/api/fetch-work-center-records',
  '/api/mark-work-center-viewed',
  '/api/planning-execution',
  '/api/document-approval',
  '/api/control-reports',
  '/profile/project-details',
  '/chat/mark-read',
  '/notifications/mark-all-read',
  '/api/notifications/mark-all-read',
]);

app.use(async (req, res, next) => {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  if (lifecycleWriteExemptPaths.has(req.path)) return next();
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return next();

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'supersecretkey');
    const userId = Number(decoded.sub);
    const role = normalizeRole(decoded.role);
    if (!Number.isInteger(userId) || !role) return next();
    const projectId = await resolveLifecycleProjectId(req);
    if (!projectId) return next();
    const message = await getProjectWriteBlock(projectId, userId, role);
    if (message) return res.status(423).json({ error: message, code: 'PROJECT_READ_ONLY' });
    return next();
  } catch (err) {
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') return next();
    console.error('[project lifecycle write guard]', err);
    return res.status(500).json({ error: 'Unable to verify project edit access.' });
  }
});

app.get('/api/project-lifecycle', authenticateToken, async (req, res) => {
  const projectId = lifecycleProjectId(req);
  if (!projectId) return res.status(400).json({ error: 'Valid projectId is required.' });
  try {
    if (!await userHasProjectAccess(req.user.user_id, req.user.role, projectId)) {
      return res.status(403).json({ error: 'Access denied to this project.' });
    }
    const result = await pool.query(
      `SELECT id,name,client_id,lifecycle_status,deletion_requested_at,deletion_scheduled_at,lifecycle_paused_seconds
       FROM projects WHERE id=$1`,
      [projectId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Project not found.' });
    const project = result.rows[0];
    const scheduleClock = await getProjectScheduleClock(projectId);
    const exit = await pool.query(
      `SELECT id,effective_at,status FROM project_exit_requests
       WHERE project_id=$1 AND user_id=$2 AND user_role=$3 AND status='pending'
       ORDER BY requested_at DESC LIMIT 1`,
      [projectId, req.user.user_id, normalizeRole(req.user.role)]
    );
    const exitRequest = exit.rows[0] || null;
    const isClientOwner = normalizeRole(req.user.role) === 'Client' && Number(project.client_id) === req.user.user_id;
    const readOnly = project.lifecycle_status === 'pending_deletion' || Boolean(exitRequest);
    return res.json({
      project,
      isClientOwner,
      exitRequest,
      writeAllowed: !readOnly,
      effective_schedule_today: scheduleClock?.effective_today || null,
      schedule_clock_paused: scheduleClock?.paused || false,
      readOnlyReason: project.lifecycle_status === 'pending_deletion'
        ? 'Project deletion is scheduled.'
        : exitRequest ? 'Your project exit is scheduled.' : null,
    });
  } catch (err) {
    console.error('[GET /api/project-lifecycle]', err);
    return res.status(500).json({ error: 'Unable to load project lifecycle.' });
  }
});

app.post('/api/project-deletion/request', authenticateToken, async (req, res) => {
  const projectId = lifecycleProjectId(req);
  if (!projectId) return res.status(400).json({ error: 'Valid projectId is required.' });
  if (normalizeRole(req.user.role) !== 'Client') {
    return res.status(403).json({ error: 'Only the client project owner can schedule deletion.' });
  }
  const projectName = String(req.body.projectName || '').trim();
  const password = req.body.password;
  if (!projectName || typeof password !== 'string' || !password) {
    return res.status(400).json({ error: 'Project name and password are required.' });
  }
  try {
    if (!await userHasProjectAccess(req.user.user_id, req.user.role, projectId)) {
      return res.status(403).json({ error: 'Only the client project owner can schedule deletion.' });
    }
    const projectCheck = await pool.query('SELECT name FROM projects WHERE id=$1 AND client_id=$2', [projectId, req.user.user_id]);
    if (!projectCheck.rows.length) return res.status(404).json({ error: 'Project not found.' });
    if (projectName !== projectCheck.rows[0].name) return res.status(400).json({ error: 'Project name does not match.' });
    if (!await verifyClientPassword(req.user.user_id, password)) return res.status(401).json({ error: 'Incorrect password.' });
    const result = await pool.query(
      `UPDATE projects
       SET lifecycle_status='pending_deletion',deletion_requested_at=NOW(),
           deletion_scheduled_at=NOW()+INTERVAL '60 days',deletion_requested_by=$2
       WHERE id=$1 AND client_id=$2 AND lifecycle_status='active'
       RETURNING deletion_scheduled_at`,
      [projectId, req.user.user_id]
    );
    if (!result.rows.length) return res.status(409).json({ error: 'Project is already scheduled for deletion or unavailable.' });
    const notice = `Project deletion scheduled. The project is read-only until ${new Date(result.rows[0].deletion_scheduled_at).toLocaleDateString()}.`;
    const notifications = await notifyProjectLifecycleChange(projectId, req.user.user_id, req.user.role, {
      subject: `Project deletion scheduled: ${projectCheck.rows[0].name}`,
      message: notice,
      emailBody: `<p>${escapeEmailHtml(notice)}</p><p>Project members can view existing records during the recovery period, but cannot make project changes.</p>`,
    });
    return res.json({ success: true, deletion_scheduled_at: result.rows[0].deletion_scheduled_at, notifications });
  } catch (err) {
    console.error('[POST /api/project-deletion/request]', err);
    return res.status(500).json({ error: 'Unable to schedule project deletion.' });
  }
});

app.post('/api/project-deletion/cancel', authenticateToken, async (req, res) => {
  const projectId = lifecycleProjectId(req);
  if (!projectId) return res.status(400).json({ error: 'Valid projectId is required.' });
  if (normalizeRole(req.user.role) !== 'Client') {
    return res.status(403).json({ error: 'Only the client project owner can cancel deletion.' });
  }
  const password = req.body.password;
  if (typeof password !== 'string' || !password) {
    return res.status(400).json({ error: 'Password is required to cancel deletion.' });
  }
  try {
    if (!await userHasProjectAccess(req.user.user_id, req.user.role, projectId)) {
      return res.status(403).json({ error: 'Only the client project owner can cancel deletion.' });
    }
    if (!await verifyClientPassword(req.user.user_id, password)) return res.status(401).json({ error: 'Incorrect password.' });
    const projectCheck = await pool.query('SELECT name FROM projects WHERE id=$1 AND client_id=$2', [projectId, req.user.user_id]);
    if (!projectCheck.rows.length) return res.status(404).json({ error: 'Project not found.' });
    const result = await pool.query(
      `UPDATE projects
         SET lifecycle_status='active',
           lifecycle_paused_seconds=lifecycle_paused_seconds + GREATEST(0,FLOOR(EXTRACT(EPOCH FROM (NOW()-deletion_requested_at)))::BIGINT),
           deletion_requested_at=NULL,deletion_scheduled_at=NULL,deletion_requested_by=NULL
       WHERE id=$1 AND client_id=$2 AND lifecycle_status='pending_deletion'
       RETURNING id`,
      [projectId, req.user.user_id]
    );
    if (!result.rows.length) return res.status(409).json({ error: 'No scheduled project deletion was found.' });
    const notice = `Project deletion was cancelled. Project "${projectCheck.rows[0].name}" is active again.`;
    const notifications = await notifyProjectLifecycleChange(projectId, req.user.user_id, req.user.role, {
      subject: `Project deletion cancelled: ${projectCheck.rows[0].name}`,
      message: notice,
      emailBody: `<p>${escapeEmailHtml(notice)}</p><p>Project members can edit and add project information again.</p>`,
    });
    return res.json({ success: true, notifications });
  } catch (err) {
    console.error('[POST /api/project-deletion/cancel]', err);
    return res.status(500).json({ error: 'Unable to cancel project deletion.' });
  }
});

app.post('/api/project-exit/request', authenticateToken, async (req, res) => {
  const projectId = lifecycleProjectId(req);
  if (!projectId) return res.status(400).json({ error: 'Valid projectId is required.' });
  if (normalizeRole(req.user.role) === 'Client') {
    return res.status(403).json({ error: 'Only a project member can schedule an exit.' });
  }
  try {
    if (!await userHasProjectAccess(req.user.user_id, req.user.role, projectId)) {
      return res.status(403).json({ error: 'Only a project member can schedule an exit.' });
    }
    const result = await pool.query(
      `INSERT INTO project_exit_requests (project_id,user_id,user_role,effective_at)
       SELECT $1,$2,$3,NOW()+INTERVAL '15 days'
       WHERE EXISTS (SELECT 1 FROM projects WHERE id=$1 AND lifecycle_status='active')
       ON CONFLICT (project_id,user_id,user_role) WHERE status='pending' DO NOTHING
       RETURNING id,effective_at,status`,
      [projectId, req.user.user_id, normalizeRole(req.user.role)]
    );
    if (result.rows.length) return res.json({ success: true, exitRequest: result.rows[0] });
    const existing = await pool.query(
      `SELECT id,effective_at,status FROM project_exit_requests
       WHERE project_id=$1 AND user_id=$2 AND user_role=$3 AND status='pending' LIMIT 1`,
      [projectId, req.user.user_id, normalizeRole(req.user.role)]
    );
    if (existing.rows.length) return res.json({ success: true, exitRequest: existing.rows[0] });
    return res.status(409).json({ error: 'Project is not active.' });
  } catch (err) {
    console.error('[POST /api/project-exit/request]', err);
    return res.status(500).json({ error: 'Unable to schedule project exit.' });
  }
});

app.post('/api/project-exit/cancel', authenticateToken, async (req, res) => {
  const projectId = lifecycleProjectId(req);
  if (!projectId) return res.status(400).json({ error: 'Valid projectId is required.' });
  try {
    const result = await pool.query(
      `UPDATE project_exit_requests SET status='cancelled'
       WHERE project_id=$1 AND user_id=$2 AND user_role=$3 AND status='pending'
       RETURNING id`,
      [projectId, req.user.user_id, normalizeRole(req.user.role)]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'No pending exit request was found.' });
    return res.json({ success: true });
  } catch (err) {
    console.error('[POST /api/project-exit/cancel]', err);
    return res.status(500).json({ error: 'Unable to cancel project exit.' });
  }
});

const exitAssignmentTargets = {
  Contractor: ['contractor_assignments', 'contractor_id'],
  Consultant: ['consultant_assignments', 'consultant_id'],
  ClientPM: ['client_pm_assignments', 'client_pm_id'],
  ContractorPM: ['contractor_pm_assignments', 'contractor_pm_id'],
  ConsultantPM: ['consultant_pm_assignments', 'consultant_pm_id'],
  TeamMember: ['team_member_assignments', 'team_member_id'],
};

function quoteSqlIdentifier(value) {
  return `"${String(value).replace(/"/g, '""')}"`;
}

async function queueProjectDeletionAssets(client, projectId) {
  const assetColumns = ['cloudinary_public_id', 'attachment_public_id', 'public_id', 'file_id', 'attachment_id', 'linked_file_id', 'supporting_file_public_id', 'stamped_doc_public_id'];
  const directColumns = await client.query(
    `SELECT c.table_name,c.column_name
     FROM information_schema.columns c
     WHERE c.table_schema='public'
       AND c.column_name=ANY($1::text[])
       AND EXISTS (
         SELECT 1 FROM information_schema.columns p
         WHERE p.table_schema=c.table_schema AND p.table_name=c.table_name AND p.column_name='project_id'
       )`,
    [assetColumns]
  );
  const queuedPublicIds = new Set();
  for (const { table_name, column_name } of directColumns.rows) {
    const assets = await client.query(
      `SELECT DISTINCT ${quoteSqlIdentifier(column_name)} AS public_id
       FROM ${quoteSqlIdentifier(table_name)}
       WHERE project_id::TEXT=$1::TEXT
         AND ${quoteSqlIdentifier(column_name)} IS NOT NULL
         AND ${quoteSqlIdentifier(column_name)}<>''`,
      [projectId]
    );
    for (const asset of assets.rows) queuedPublicIds.add(asset.public_id);
  }

  const indirectAssets = [
    ['planning_execution_tracking', 'planning_execution', 'activity_id', 'attachment_id'],
    ['workspace_work_center_progress', 'workspace_work_center', 'task_id', 'attachment_id'],
    ['milestone_attachments', 'milestones', 'milestone_id', 'cloudinary_public_id'],
    ['additional_milestone_attachments', 'additional_milestones', 'additional_milestone_id', 'cloudinary_public_id'],
    ['progress_entry_attachments', 'milestone_progress_entries', 'progress_entry_id', 'cloudinary_public_id'],
    ['arret_attachments', 'arrets', 'arret_id', 'public_id'],
    ['meeting_attachments', 'meetings', 'meeting_id', 'public_id'],
    ['meeting_attachments', 'meeting_minutes', 'minute_id', 'public_id'],
  ];
  for (const [tableName, parentName, foreignKey, assetColumn] of indirectAssets) {
    const schema = await client.query(
      `SELECT
         EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1) AS has_table,
         EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name=$2) AS has_asset_column,
         EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$3) AS has_parent,
         EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name=$3 AND column_name='project_id') AS parent_has_project,
         EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name=$4) AS has_foreign_key`,
      [tableName, assetColumn, parentName, foreignKey]
    );
    const available = schema.rows[0];
    if (!available.has_table || !available.has_asset_column || !available.has_parent || !available.parent_has_project || !available.has_foreign_key) continue;
    const assets = await client.query(
      `SELECT DISTINCT a.${quoteSqlIdentifier(assetColumn)} AS public_id
       FROM ${quoteSqlIdentifier(tableName)} a
       JOIN ${quoteSqlIdentifier(parentName)} p ON p.id=a.${quoteSqlIdentifier(foreignKey)}
       WHERE p.project_id::TEXT=$1::TEXT
         AND a.${quoteSqlIdentifier(assetColumn)} IS NOT NULL
         AND a.${quoteSqlIdentifier(assetColumn)}<>''`,
      [projectId]
    );
    for (const asset of assets.rows) queuedPublicIds.add(asset.public_id);
  }

  for (const publicId of queuedPublicIds) {
    await client.query(
      `INSERT INTO project_deletion_asset_cleanup (project_id,public_id)
       VALUES ($1,$2) ON CONFLICT (project_id,public_id) DO NOTHING`,
      [projectId, publicId]
    );
  }
}

async function processDueProjectExits() {
  const due = await pool.query(
    `SELECT id,project_id,user_id,user_role FROM project_exit_requests
     WHERE status='pending' AND effective_at<=NOW() ORDER BY effective_at LIMIT 50`
  );
  for (const request of due.rows) {
    const target = exitAssignmentTargets[normalizeRole(request.user_role)];
    if (!target) continue;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const locked = await client.query(
        `SELECT id FROM project_exit_requests
         WHERE id=$1 AND status='pending' AND effective_at<=NOW() FOR UPDATE SKIP LOCKED`,
        [request.id]
      );
      if (!locked.rows.length) {
        await client.query('COMMIT');
        continue;
      }
      await client.query(`SELECT set_config('app.project_deletion_purge','on',true)`);
      const [table, userColumn] = target;
      await client.query(
        `DELETE FROM ${quoteSqlIdentifier(table)} WHERE project_id=$1 AND ${quoteSqlIdentifier(userColumn)}=$2`,
        [request.project_id, request.user_id]
      );
      await client.query(
        `UPDATE project_exit_requests SET status='completed',completed_at=NOW() WHERE id=$1`,
        [request.id]
      );
      await client.query('COMMIT');

      try {
        const notification = await pool.query(
          `INSERT INTO notifications (project_id,entity_type,entity_id,message,added_by_id,added_by_role)
           VALUES ($1,'project_exit_requests',$2,$3,$4,$5) RETURNING id`,
          [request.project_id, request.id, `${request.user_role} exited the project after the scheduled notice period.`, request.user_id, request.user_role]
        );
        const recipients = await getProjectRecipientKeys(request.project_id, request.user_id, request.user_role);
        if (recipients.length) {
          const notifyClient = await pool.connect();
          try {
            await notifyClient.query('BEGIN');
            await insertNotificationRecipients(notifyClient, notification.rows[0].id, recipients);
            await notifyClient.query('COMMIT');
          } catch (err) {
            await notifyClient.query('ROLLBACK');
            throw err;
          } finally {
            notifyClient.release();
          }
        }
      } catch (err) {
        console.error('[project lifecycle] exit notification failed:', err.message);
      }
    } catch (err) {
      await client.query('ROLLBACK');
      console.error(`[project lifecycle] failed to complete exit request ${request.id}:`, err.message);
    } finally {
      client.release();
    }
  }
}

async function processDueProjectDeletions() {
  const due = await pool.query(
    `SELECT id FROM projects
     WHERE lifecycle_status='pending_deletion' AND deletion_scheduled_at<=NOW()
     ORDER BY deletion_scheduled_at LIMIT 10`
  );
  for (const { id } of due.rows) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const locked = await client.query(
        `SELECT id FROM projects
         WHERE id=$1 AND lifecycle_status='pending_deletion' AND deletion_scheduled_at<=NOW()
         FOR UPDATE SKIP LOCKED`,
        [id]
      );
      if (!locked.rows.length) {
        await client.query('COMMIT');
        continue;
      }
      await queueProjectDeletionAssets(client, id);
      await client.query(`SELECT set_config('app.project_deletion_purge','on',true)`);
      await client.query(
        `DELETE FROM projects
         WHERE id=$1 AND lifecycle_status='pending_deletion' AND deletion_scheduled_at<=NOW()`,
        [id]
      );
      await client.query('COMMIT');
      console.log(`[project lifecycle] permanently deleted project ${id}`);
    } catch (err) {
      await client.query('ROLLBACK');
      console.error(`[project lifecycle] failed to purge project ${id}:`, err.message);
    } finally {
      client.release();
    }
  }
}

async function processProjectAssetCleanup() {
  const pending = await pool.query(
    `SELECT id,public_id FROM project_deletion_asset_cleanup
     WHERE status='pending' ORDER BY id LIMIT 50`
  );
  for (const asset of pending.rows) {
    let deleted = false;
    let failed = false;
    for (const resourceType of ['image', 'video', 'raw']) {
      try {
        const result = await cloudinary.uploader.destroy(asset.public_id, { resource_type: resourceType });
        if (result.result === 'ok') {
          deleted = true;
          break;
        }
        if (result.result !== 'not found') failed = true;
      } catch (err) {
        failed = true;
      }
    }
    if (deleted || !failed) {
      await pool.query(
        `UPDATE project_deletion_asset_cleanup SET status='deleted',deleted_at=NOW() WHERE id=$1`,
        [asset.id]
      );
    } else {
      await pool.query(
        `UPDATE project_deletion_asset_cleanup SET attempts=attempts+1 WHERE id=$1`,
        [asset.id]
      );
    }
  }
}

async function processProjectLifecycleJobs() {
  try {
    await processDueProjectExits();
    await processDueProjectDeletions();
    await processProjectAssetCleanup();
  } catch (err) {
    console.error('[project lifecycle] scheduled processing failed:', err.message);
  }
}

setInterval(processProjectLifecycleJobs, 60 * 1000);

// =============================================================================
//  WORK CENTER & PLANNING HELPERS
// =============================================================================

function wcSide(role) {
  if (!role) return null;
  const normalized = normalizeRole(role);
  if (['Contractor',  'ContractorPM'].includes(normalized)) return 'Contractor';
  if (['Consultant',  'ConsultantPM'].includes(normalized)) return 'Consultant';
  if (['Client',      'ClientPM'].includes(normalized))     return 'Client';
  return null;
}

function isWCLeader(role) {
  const result = wcSide(role) !== null;
  console.log(`[AUTH] isWCLeader(${role || 'null'}) -> ${result} [normalized: ${normalizeRole(role) || 'null'}]`);
  return result;
}

function sideRoles(side) {
  if (side === 'Contractor') return ['Contractor', 'ContractorPM'];
  if (side === 'Consultant') return ['Consultant', 'ConsultantPM'];
  return ['Client', 'ClientPM'];
}

// =============================================================================
//  CHAT HELPERS
// =============================================================================

const CHAT_SENDER_JOINS = `
  LEFT JOIN project_chat_read_receipts r ON r.message_id = m.id
  LEFT JOIN project_chat_messages rm ON m.reply_to_message_id = rm.id
  LEFT JOIN clients c
    ON m.sender_role = 'Client' AND m.sender_id = c.id
  LEFT JOIN contractor_assignments ca_rep
    ON m.sender_role = 'Contractor' AND m.sender_id = ca_rep.contractor_id AND ca_rep.project_id = m.project_id
  LEFT JOIN contractors ct
    ON ca_rep.contractor_id = ct.id
  LEFT JOIN consultant_assignments csa_rep
    ON m.sender_role = 'Consultant' AND m.sender_id = csa_rep.consultant_id AND csa_rep.project_id = m.project_id
  LEFT JOIN consultants cns
    ON csa_rep.consultant_id = cns.id
  LEFT JOIN client_pm_assignments cpma_rep
    ON m.sender_role = 'ClientPM' AND m.sender_id = cpma_rep.client_pm_id AND cpma_rep.project_id = m.project_id
  LEFT JOIN client_project_managers cpm_u
    ON cpma_rep.client_pm_id = cpm_u.id
  LEFT JOIN contractor_pm_assignments ctrpma_rep
    ON m.sender_role = 'ContractorPM' AND m.sender_id = ctrpma_rep.contractor_pm_id AND ctrpma_rep.project_id = m.project_id
  LEFT JOIN contractor_project_managers ctrpm_u
    ON ctrpma_rep.contractor_pm_id = ctrpm_u.id
  LEFT JOIN consultant_pm_assignments cnspma_rep
    ON m.sender_role = 'ConsultantPM' AND m.sender_id = cnspma_rep.consultant_pm_id AND cnspma_rep.project_id = m.project_id
  LEFT JOIN consultant_project_managers cnspm_u
    ON cnspma_rep.consultant_pm_id = cnspm_u.id
  LEFT JOIN team_member_assignments tma_rep
    ON m.sender_role = 'TeamMember' AND m.sender_id = tma_rep.team_member_id AND tma_rep.project_id = m.project_id
  LEFT JOIN team_members tm
    ON tma_rep.team_member_id = tm.id
`;

const CHAT_SENDER_FIELDS = `
  COALESCE(json_agg(DISTINCT r.user_id) FILTER (WHERE r.user_id IS NOT NULL), '[]') AS read_by,
  COALESCE(
    jsonb_agg(DISTINCT jsonb_build_object(
      'user_id', r.user_id,
      'user_role', r.user_role,
      'read_at', r.read_at
    )) FILTER (WHERE r.user_id IS NOT NULL),
    '[]'::jsonb
  ) AS read_by_details,

  CASE m.sender_role
    WHEN 'Client'       THEN COALESCE(c.representative,          c.company_name,         c.company_email)
    WHEN 'Contractor'   THEN COALESCE(ca_rep.representative,     ct.email,               ca_rep.company_name)
    WHEN 'Consultant'   THEN COALESCE(csa_rep.representative,    cns.email,              csa_rep.company_name)
    WHEN 'ClientPM'     THEN COALESCE(cpma_rep.name,             cpm_u.email)
    WHEN 'ContractorPM' THEN COALESCE(ctrpma_rep.name,           ctrpm_u.email)
    WHEN 'ConsultantPM' THEN COALESCE(cnspma_rep.name,           cnspm_u.email)
    WHEN 'TeamMember'   THEN COALESCE(tma_rep.name,              tm.email)
    ELSE m.sender_email
  END AS sender_display_name,

  CASE m.sender_role
    WHEN 'Client'       THEN COALESCE(c.title,               '')
    WHEN 'Contractor'   THEN COALESCE(ca_rep.title_position,  '')
    WHEN 'Consultant'   THEN COALESCE(csa_rep.title_position, '')
    WHEN 'ClientPM'     THEN COALESCE(cpma_rep.name,          '')
    WHEN 'ContractorPM' THEN COALESCE(ctrpma_rep.name,        '')
    WHEN 'ConsultantPM' THEN COALESCE(cnspma_rep.name,        '')
    WHEN 'TeamMember'   THEN COALESCE(tma_rep.position, tma_rep.name, '')
    ELSE ''
  END AS sender_position,

  CASE m.sender_role
    WHEN 'Client'       THEN COALESCE(c.company_name,            c.title,               '')
    WHEN 'Contractor'   THEN COALESCE(ca_rep.company_name,       ca_rep.title_position, '')
    WHEN 'Consultant'   THEN COALESCE(csa_rep.company_name,      csa_rep.title_position,'')
    WHEN 'ClientPM'     THEN COALESCE(cpma_rep.name,             '')
    WHEN 'ContractorPM' THEN COALESCE(ctrpma_rep.name,           '')
    WHEN 'ConsultantPM' THEN COALESCE(cnspma_rep.name,           '')
    WHEN 'TeamMember'   THEN COALESCE(tma_rep.name,              '')
    ELSE ''
  END AS sender_company,

  rm.id           AS reply_to_message_id,
  rm.content      AS reply_to_content,
  rm.sender_role  AS reply_to_sender_role,
  rm.sender_email AS reply_to_sender_email
`;

const CHAT_GROUP_BY = `
  GROUP BY
    m.id,
    c.id, c.representative, c.company_name, c.company_email, c.title,
    ca_rep.id, ca_rep.representative, ca_rep.company_name, ca_rep.title_position,
    ct.id, ct.email,
    csa_rep.id, csa_rep.representative, csa_rep.company_name, csa_rep.title_position,
    cns.id, cns.email,
    cpma_rep.id, cpma_rep.name,
    cpm_u.id, cpm_u.email,
    ctrpma_rep.id, ctrpma_rep.name,
    ctrpm_u.id, ctrpm_u.email,
    cnspma_rep.id, cnspma_rep.name,
    cnspm_u.id, cnspm_u.email,
    tma_rep.id, tma_rep.name, tma_rep.position, tma_rep.assigned_part,
    tm.id, tm.email,
    rm.id, rm.content, rm.sender_role, rm.sender_email
`;

async function markMessagesRead(messageIds, userId, userRole) {
  if (!messageIds.length) return;
  try {
    await pool.query(
      `INSERT INTO project_chat_read_receipts (message_id, user_id, user_role, read_at)
       SELECT unnest($1::int[]), $2, $3, NOW()
       ON CONFLICT (message_id, user_id) DO NOTHING`,
      [messageIds, userId, userRole]
    );
  } catch (err) {
    console.error('[markMessagesRead] batch insert failed, falling back to loop:', err.message);
    for (const mid of messageIds) {
      await pool.query(
        `INSERT INTO project_chat_read_receipts (message_id, user_id, user_role, read_at)
         VALUES ($1,$2,$3,NOW()) ON CONFLICT (message_id,user_id) DO NOTHING`,
        [mid, userId, userRole]
      ).catch(() => {});
    }
  }
}

// =============================================================================
//  CHAT ROUTES
// =============================================================================

app.get('/chat/members', authenticateToken, async (req, res) => {
  const { projectId } = req.query;
  if (!projectId) return res.status(400).json({ success: false, error: 'projectId is required' });
  try {
    const hasAccess = await userHasProjectAccess(req.user.user_id, req.user.role, projectId);
    if (!hasAccess) return res.status(403).json({ success: false, error: 'Access denied to this project' });
    const members = await getProjectMembers(projectId);
    res.json({ success: true, members });
  } catch (err) {
    console.error('[GET /chat/members]', err);
    res.status(500).json({ success: false, error: 'Failed to load chat members' });
  }
});

app.get('/chat/conversations', authenticateToken, async (req, res) => {
  const { projectId } = req.query;
  if (!projectId) return res.status(400).json({ success: false, error: 'projectId is required' });

  try {
    const hasAccess = await userHasProjectAccess(req.user.user_id, req.user.role, projectId);
    if (!hasAccess) return res.status(403).json({ success: false, error: 'Access denied to this project' });

    const normalizedUserRole = normalizeRole(req.user.role);
    const userId             = req.user.user_id;

    const [members, messageRows] = await Promise.all([
      getProjectMembers(projectId),
      pool.query(
        `SELECT m.id, m.is_group, m.sender_role, m.sender_id,
                m.recipient_role, m.recipient_id,
                m.content, m.attachment_name, m.created_at,
                COALESCE(
                  json_agg(DISTINCT r.user_id) FILTER (WHERE r.user_id IS NOT NULL),
                  '[]'
                ) AS read_by
         FROM project_chat_messages m
         LEFT JOIN project_chat_read_receipts r ON r.message_id = m.id
         WHERE m.project_id = $1
           AND (
             m.is_group = true
             OR (m.sender_role = $2 AND m.sender_id = $3)
             OR (m.recipient_role = $2 AND m.recipient_id = $3)
           )
         GROUP BY m.id
         ORDER BY m.created_at DESC`,
        [projectId, normalizedUserRole, userId]
      ),
    ]);

    const messages      = messageRows.rows;
    const groupMessages = messages.filter(m => m.is_group === true);
    const lastGroupMsg  = groupMessages[0] || null;

    const groupUnread = groupMessages.reduce((count, msg) => {
      const isMine = msg.sender_role === normalizedUserRole && Number(msg.sender_id) === userId;
      if (isMine) return count;
      const readBy = Array.isArray(msg.read_by) ? msg.read_by : [];
      return readBy.map(Number).includes(userId) ? count : count + 1;
    }, 0);

    const conversationMap = new Map();
    for (const msg of messages) {
      if (msg.is_group) continue;
      const isIncoming = msg.recipient_role === normalizedUserRole && Number(msg.recipient_id) === userId;
      const otherRole  = isIncoming ? msg.sender_role        : msg.recipient_role;
      const otherId    = isIncoming ? Number(msg.sender_id)  : Number(msg.recipient_id);
      if (!otherRole || !otherId) continue;

      const key      = `${otherRole}-${otherId}`;
      const existing = conversationMap.get(key) || {
        otherRole, otherId, lastMessage: '', time: '', lastAt: null, unreadCount: 0,
      };

      if (!existing.lastAt || new Date(msg.created_at) > new Date(existing.lastAt)) {
        existing.lastAt      = msg.created_at;
        existing.lastMessage = msg.content
          || (msg.attachment_name ? `📎 ${msg.attachment_name}` : 'Attachment');
        existing.time = new Date(msg.created_at).toLocaleTimeString([], {
          hour: '2-digit', minute: '2-digit',
        });
      }

      if (isIncoming) {
        const readBy = Array.isArray(msg.read_by) ? msg.read_by : [];
        if (!readBy.map(Number).includes(userId)) existing.unreadCount += 1;
      }

      conversationMap.set(key, existing);
    }

    // ── THE FIX: build display_name from actual schema fields ──────────────
    const enrichedMembers = members.map(member => {
      const key          = `${member.role}-${member.role_id}`;
      const conversation = conversationMap.get(key);
      const role         = normalizeRole(member.role);

      let displayName;
      if (role === 'Client') {
        // representative - title - Client
        displayName = [member.representative, member.title, 'Client']
          .filter(Boolean).join(' - ');
      } else if (role === 'Contractor' || role === 'Consultant') {
        // representative - title_position - Role
        displayName = [member.representative, member.title_position, role]
          .filter(Boolean).join(' - ');
      } else if (role === 'ContractorPM' || role === 'ConsultantPM' || role === 'ClientPM') {
        // name - Human PM label
        // getProjectMembers aliases assignment.name → member.title for PM rows
        const pmLabel = {
          ContractorPM: 'Contractor PM',
          ConsultantPM: 'Consultant PM',
          ClientPM:     'Client PM',
        }[role];
        displayName = [member.title, pmLabel].filter(Boolean).join(' - ');
      } else if (role === 'TeamMember') {
        // name - position - assigned_part - Team Member
        // getProjectMembers aliases assignment.name → member.title for TM rows
        displayName = [member.title, member.position, member.assigned_part, 'Team Member']
          .filter(Boolean).join(' - ');
      } else {
        displayName = member.display_name || member.email || role;
      }

      return {
        ...member,
        display_name: displayName,
        lastMessage:  conversation?.lastMessage || 'Tap to chat',
        time:         conversation?.time        || '',
        sortAt:       conversation?.lastAt      || null,
        unreadCount:  conversation?.unreadCount || 0,
      };
    });

    res.json({
      success: true,
      group: {
        lastMessage:  lastGroupMsg?.content
          || (lastGroupMsg?.attachment_name ? `📎 ${lastGroupMsg.attachment_name}` : 'Group chat for the project'),
        time:         lastGroupMsg
          ? new Date(lastGroupMsg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
          : '',
        unreadCount:  groupUnread,
        membersCount: members.length,
        lastAt:       lastGroupMsg?.created_at || null,
      },
      members: enrichedMembers,
    });
  } catch (err) {
    console.error('[GET /chat/conversations]', err);
    res.status(500).json({ success: false, error: 'Failed to load chat conversations' });
  }
});

app.get('/chat/messages', authenticateToken, async (req, res) => {
  const { projectId, recipientRole, recipientId, isGroup } = req.query;
  if (!projectId) return res.status(400).json({ success: false, error: 'projectId is required' });

  try {
    const normalizedUserRole = normalizeRole(req.user.role);
    const userId             = req.user.user_id;

    const hasAccess = await userHasProjectAccess(userId, req.user.role, projectId);
    if (!hasAccess) return res.status(403).json({ success: false, error: 'Access denied to this project' });

    let rows;

    if (isGroup === 'true' || isGroup === '1') {
      const result = await pool.query(
        `SELECT m.*, ${CHAT_SENDER_FIELDS}
         FROM project_chat_messages m
         ${CHAT_SENDER_JOINS}
         WHERE m.project_id = $1 AND m.is_group = true
         ${CHAT_GROUP_BY}
         ORDER BY m.created_at ASC`,
        [projectId]
      );
      rows = result.rows;
    } else {
      if (!recipientRole || !recipientId) {
        return res.status(400).json({
          success: false,
          error: 'recipientRole and recipientId are required for direct chat',
        });
      }
      const normalizedRecipientRole = normalizeRole(recipientRole);
      const result = await pool.query(
        `SELECT m.*, ${CHAT_SENDER_FIELDS}
         FROM project_chat_messages m
         ${CHAT_SENDER_JOINS}
         WHERE m.project_id = $1
           AND m.is_group = false
           AND (
             (m.sender_role = $2 AND m.sender_id = $3 AND m.recipient_role = $4 AND m.recipient_id = $5)
             OR
             (m.sender_role = $4 AND m.sender_id = $5 AND m.recipient_role = $2 AND m.recipient_id = $3)
           )
         ${CHAT_GROUP_BY}
         ORDER BY m.created_at ASC`,
        [projectId, normalizedUserRole, userId, normalizedRecipientRole, Number(recipientId)]
      );
      rows = result.rows;
    }

    const unreadIds = rows
      .filter(m => {
        const isMine = m.sender_role === normalizedUserRole && Number(m.sender_id) === userId;
        if (isMine) return false;
        const readBy = Array.isArray(m.read_by) ? m.read_by.map(Number) : [];
        return !readBy.includes(userId);
      })
      .map(m => m.id);

    // Log all attachment URLs in messages for debugging
    const messagesWithAttachments = rows.filter(m => m.attachment_url);
    if (messagesWithAttachments.length) {
      console.log(`[GET /chat/messages] Returning ${messagesWithAttachments.length} messages with attachments:`, 
        messagesWithAttachments.map(m => ({
          id: m.id,
          url: m.attachment_url,
          mime: m.attachment_mime,
          name: m.attachment_name
        }))
      );
    }

    // Validate attachment metadata is present for audio/media playback
    rows.forEach(m => {
      if (m.attachment_url && !m.attachment_mime) {
        console.warn(`[GET /chat/messages] ⚠️ MISSING attachment_mime for message id=${m.id}, url=${m.attachment_url}, name=${m.attachment_name}`);
      }
    });

    if (unreadIds.length) {
      markMessagesRead(unreadIds, userId, normalizedUserRole).catch(e =>
        console.error('[GET /chat/messages] markMessagesRead error:', e.message)
      );
    }

    res.json({ success: true, messages: rows });
  } catch (err) {
    console.error('[GET /chat/messages]', err);
    res.status(500).json({ success: false, error: 'Failed to load chat messages' });
  }
});

app.post('/chat/messages', authenticateToken, async (req, res) => {
  const {
    projectId, recipientRole, recipientId, content, isGroup,
    replyToMessageId, attachmentUrl, attachmentName, attachmentMime,
  } = req.body;

  const contentText = typeof content === 'string' ? content.trim() : '';

  if (!projectId) {
    return res.status(400).json({ success: false, error: 'projectId is required' });
  }
  if (!contentText && !attachmentUrl) {
    return res.status(400).json({ success: false, error: 'content or attachmentUrl is required' });
  }

  try {
    const hasAccess = await userHasProjectAccess(req.user.user_id, req.user.role, projectId);
    if (!hasAccess) return res.status(403).json({ success: false, error: 'Access denied to this project' });

    const isGroupChat          = isGroup === true || isGroup === 'true' || isGroup === 1 || isGroup === '1';
    const normalizedSenderRole = normalizeRole(req.user.role);

    let recipientEmail      = null;
    let normalizedRecipRole = null;
    let resolvedRecipId     = null;

    if (!isGroupChat) {
      if (!recipientRole || !recipientId) {
        return res.status(400).json({
          success: false,
          error: 'recipientRole and recipientId are required for direct chat',
        });
      }
      normalizedRecipRole = normalizeRole(recipientRole);
      resolvedRecipId     = Number(recipientId);

      const members   = await getProjectMembers(projectId);
      const recipient = members.find(
        m => normalizeRole(m.role) === normalizedRecipRole && Number(m.role_id) === resolvedRecipId
      );
      if (!recipient) {
        return res.status(400).json({ success: false, error: 'Recipient not found in project members' });
      }
      recipientEmail = recipient.email;
    }

    let resolvedReplyId = null;
    if (replyToMessageId) {
      const replyCheck = await pool.query(
        'SELECT id FROM project_chat_messages WHERE id = $1 AND project_id = $2',
        [Number(replyToMessageId), projectId]
      );
      if (replyCheck.rows.length) resolvedReplyId = replyCheck.rows[0].id;
    }

    const { rows } = await pool.query(
      `INSERT INTO project_chat_messages
         (project_id,
          sender_role, sender_id, sender_email,
          recipient_role, recipient_id, recipient_email,
          reply_to_message_id,
          is_group, content,
          attachment_url, attachment_name, attachment_mime,
          delivered)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, false)
       RETURNING *`,
      [
        projectId,
        normalizedSenderRole, req.user.user_id, req.user.email || '',
        isGroupChat ? null : normalizedRecipRole,
        isGroupChat ? null : resolvedRecipId,
        isGroupChat ? null : recipientEmail,
        resolvedReplyId,
        isGroupChat, contentText,
        attachmentUrl  || null,
        attachmentName || null,
        attachmentMime || null,
      ]
    );

    const messageId = rows[0].id;
    const chatMsg = rows[0];

    console.log('[POST /chat/messages] Message inserted:', {id: messageId, content: contentText?.substring(0,50), attachment_url: chatMsg.attachment_url, attachment_mime: chatMsg.attachment_mime, attachment_name: chatMsg.attachment_name});

    // Do not mark the sender's own message as read/delivered here.
    // The recipient should generate a read receipt when they open the message.

    // Validate attachment fields are preserved for playback/rendering
    if (attachmentUrl || attachmentName || attachmentMime) {
      if (!chatMsg.attachment_url || !chatMsg.attachment_mime) {
        console.warn(`[POST /chat/messages] ⚠️ CRITICAL: attachment metadata missing in DB response: id=${messageId}, sent_url=${attachmentUrl}, returned_url=${chatMsg.attachment_url}, sent_mime=${attachmentMime}, returned_mime=${chatMsg.attachment_mime}, sent_name=${attachmentName}`);
      } else {
        console.log(`[POST /chat/messages] ✓ Attachment metadata preserved in DB: url exists, mime=${chatMsg.attachment_mime}`);
      }
    }

    res.status(201).json({ success: true, message: 'Message saved', chatMessage: chatMsg });
  } catch (err) {
    console.error('[POST /chat/messages]', err);
    res.status(500).json({ success: false, error: 'Failed to send chat message' });
  }
});

app.post('/chat/mark-read', authenticateToken, async (req, res) => {
  const { messageIds, projectId } = req.body;

  if (!Array.isArray(messageIds) || !messageIds.length) {
    return res.status(400).json({ success: false, error: 'messageIds array is required' });
  }
  if (!projectId) {
    return res.status(400).json({ success: false, error: 'projectId is required' });
  }

  try {
    const hasAccess = await userHasProjectAccess(req.user.user_id, req.user.role, projectId);
    if (!hasAccess) return res.status(403).json({ success: false, error: 'Access denied to this project' });

    const normalizedRole = normalizeRole(req.user.role);
    const client         = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `INSERT INTO project_chat_read_receipts (message_id, user_id, user_role, read_at)
         SELECT unnest($1::int[]), $2, $3, NOW()
         ON CONFLICT (message_id, user_id) DO NOTHING`,
        [messageIds.map(Number), req.user.user_id, normalizedRole]
      );
      await client.query(
        `UPDATE project_chat_messages
         SET delivered = true, delivered_at = NOW()
         WHERE id = ANY($1::int[]) AND delivered = false`,
        [messageIds.map(Number)]
      );
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }

    res.json({ success: true, message: 'Marked read' });
  } catch (err) {
    console.error('[POST /chat/mark-read]', err);
    res.status(500).json({ success: false, error: 'Failed to mark messages read' });
  }
});

app.get('/chat/unread-count', authenticateToken, async (req, res) => {
  const { projectId } = req.query;
  if (!projectId) return res.status(400).json({ success: false, error: 'projectId is required' });

  try {
    const hasAccess = await userHasProjectAccess(req.user.user_id, req.user.role, projectId);
    if (!hasAccess) return res.status(403).json({ success: false, error: 'Access denied' });

    const normalizedRole = normalizeRole(req.user.role);
    const userId         = req.user.user_id;

    const { rows } = await pool.query(
      `SELECT COUNT(*) AS count
       FROM project_chat_messages m
       WHERE m.project_id = $1
         AND NOT (m.sender_role = $2 AND m.sender_id = $3)
         AND (
           m.is_group = true
           OR (m.recipient_role = $2 AND m.recipient_id = $3)
         )
         AND NOT EXISTS (
           SELECT 1 FROM project_chat_read_receipts r
           WHERE r.message_id = m.id AND r.user_id = $3
         )`,
      [projectId, normalizedRole, userId]
    );

    res.json({ success: true, count: parseInt(rows[0].count, 10) });
  } catch (err) {
    console.error('[GET /chat/unread-count]', err);
    res.status(500).json({ success: true, count: 0 });
  }
});

app.delete('/chat/messages/:messageId', authenticateToken, async (req, res) => {
  const messageId = Number(req.params.messageId);
  const { projectId } = req.query;
  if (!projectId) return res.status(400).json({ success: false, error: 'projectId is required' });

  try {
    const hasAccess = await userHasProjectAccess(req.user.user_id, req.user.role, projectId);
    if (!hasAccess) return res.status(403).json({ success: false, error: 'Access denied' });

    const { rows } = await pool.query(
      `SELECT sender_id, sender_role, attachment_url FROM project_chat_messages
       WHERE id = $1 AND project_id = $2`,
      [messageId, projectId]
    );
    if (!rows.length) return res.status(404).json({ success: false, error: 'Message not found' });

    const msg = rows[0];
    if (Number(msg.sender_id) !== req.user.user_id || normalizeRole(msg.sender_role) !== normalizeRole(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Only the sender can delete this message' });
    }

    await pool.query(
      `UPDATE project_chat_messages
       SET content = '', attachment_url = NULL, attachment_name = NULL, attachment_mime = NULL
       WHERE id = $1`,
      [messageId]
    );

    res.json({ success: true, message: 'Message deleted' });
  } catch (err) {
    console.error('[DELETE /chat/messages/:messageId]', err);
    res.status(500).json({ success: false, error: 'Failed to delete message' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  ROOT
// ─────────────────────────────────────────────────────────────────────────────
app.get('/', (_req, res) => res.send('Backend is running successfully!'));

// ─────────────────────────────────────────────────────────────────────────────
//  GENERIC PROFILE / ATTACHMENT ROUTES
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/profile-picture', authenticateToken, upload.single('picture'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const result = await uploadToCloudinary(req.file.buffer, 'oneprojectapp/profile_pictures', 'image');
    await pool.query('UPDATE clients SET profile_picture=$1 WHERE id=$2', [result.secure_url, req.user.user_id]);
    res.json({ success: true, url: result.secure_url });
  } catch (err) {
    console.error('Profile pic error:', err);
    res.status(500).json({ error: 'Failed to upload profile picture' });
  }
});

app.post('/api/upload-attachment', authenticateToken, upload.single('attachment'), requireProjectLifecycleWrite, async (req, res) => {
  try {
    if (!req.file) {
      console.error('[POST /api/upload-attachment] No file in request');
      return res.status(400).json({ error: 'No file uploaded' });
    }
    console.log('[POST /api/upload-attachment] File received:', {name: req.file.originalname, mime: req.file.mimetype, size: req.file.size});
    const resourceType = req.file.mimetype?.startsWith('image/') ? 'image'
      : req.file.mimetype?.startsWith('video/') ? 'video'
      : req.file.mimetype?.startsWith('audio/') ? 'video'
      : 'raw';
    console.log('[POST /api/upload-attachment] resourceType:', resourceType);
    const result = await uploadToCloudinary(req.file.buffer, 'oneprojectapp/attachments', resourceType);
    console.log('[POST /api/upload-attachment] Cloudinary response:', {url: result.secure_url});
    res.json({ success: true, url: result.secure_url, name: req.file.originalname, mime: req.file.mimetype });
  } catch (err) {
    console.error('Attachment upload error:', err);
    res.status(500).json({ error: 'Failed to upload attachment' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  AUTH ROUTES
// ─────────────────────────────────────────────────────────────────────────────
app.post('/finalize-account', async (req, res) => {
  const { clientEmail } = req.body;
  try {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = uuidv4();
    await pool.query(
      `INSERT INTO email_tokens (email,token,expires_at,attempts,session_id,verified,pending_password,reset_flow,created_at,project_flow)
       VALUES ($1,$2,NOW()+interval '3 minutes',0,$3,false,false,false,NOW(),false)`,
      [clientEmail, code, sessionId]
    );
    await transporter.sendMail({
      from: 'skyprincenkp16@gmail.com', to: clientEmail,
      subject: 'Verify your OneProjectApp account',
      html: `<p>Your verification code is: <b>${code}</b></p><p>Expires in 3 minutes.</p>`,
    });
    res.json({ success: true, message: 'Verification email sent.', sessionId });
  } catch (err) {
    console.error('Finalize error:', err);
    res.status(500).json({ success: false, error: 'Server error finalizing account.' });
  }
});

app.post('/verify-code', async (req, res) => {
  const { email, code } = req.body;
  try {
    const result = await pool.query(
      `SELECT * FROM email_tokens WHERE email=$1 AND token=$2 AND expires_at>NOW() AND verified=false ORDER BY expires_at DESC LIMIT 1`,
      [email, code]
    );
    if (!result.rows.length) return res.json({ success: false, verified: false, error: 'Invalid or expired code.' });
    await pool.query('UPDATE email_tokens SET verified=true WHERE id=$1', [result.rows[0].id]);
    res.json({ success: true, verified: true, message: 'Verification successful.' });
  } catch (err) {
    console.error('Verification error:', err);
    res.status(500).json({ success: false, verified: false, error: 'Server error verifying code.' });
  }
});

app.post('/commit-account', upload.single('clientPicture'), async (req, res) => {
  try {
    let projectDetails = {};
    try { if (req.body.projectDetails) projectDetails = JSON.parse(req.body.projectDetails); }
    catch { return res.status(400).json({ success: false, error: 'Invalid project details format.' }); }

    const { contractor, consultant, teamMember, contractorPM, consultantPM, client, project } = projectDetails;
    const hashedPassword = client?.password_hash ? await bcrypt.hash(client.password_hash, 10) : null;

    let clientPictureUrl = null, clientPictureId = null;
    if (req.file) {
      const r = await uploadToCloudinary(req.file.buffer, 'oneprojectapp/clients', 'image');
      clientPictureUrl = r.secure_url; clientPictureId = r.public_id;
    } else if (req.body.clientPictureBase64) {
      const r = await cloudinary.uploader.upload(req.body.clientPictureBase64, { folder: 'oneprojectapp/clients', resource_type: 'image' });
      clientPictureUrl = r.secure_url; clientPictureId = r.public_id;
    }

    const clientResult = await pool.query(
  `INSERT INTO clients (company_name,company_email,representative,title,telephone,password_hash,verified,created_at,profile_picture,profile_picture_id)
   VALUES ($1,$2,$3,$4,$5,$6,true,NOW(),$7,$8)
   ON CONFLICT (company_email) DO UPDATE SET
     company_name       = EXCLUDED.company_name,
     representative     = EXCLUDED.representative,
     title              = CASE 
                            WHEN EXCLUDED.title IS NOT NULL AND EXCLUDED.title != EXCLUDED.company_email 
                            THEN EXCLUDED.title 
                            ELSE clients.title 
                          END,
     telephone          = EXCLUDED.telephone,
     password_hash      = EXCLUDED.password_hash,
     profile_picture    = COALESCE(EXCLUDED.profile_picture, clients.profile_picture),
     profile_picture_id = COALESCE(EXCLUDED.profile_picture_id, clients.profile_picture_id),
     verified           = true
   RETURNING id, company_email`,
  [
    client?.company_name   || null,
    client?.company_email  || null,
    client?.representative || null,
    client?.title && client.title !== client.company_email ? client.title : null,
    client?.telephone      || null,
    hashedPassword,
    clientPictureUrl,
    clientPictureId,
  ]
);
    const client_id = clientResult.rows[0].id;

    const projectResult = await pool.query(
      `INSERT INTO projects (name,location,contract_reference,client_id,created_at) VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT (name,client_id) DO NOTHING RETURNING id`,
      [project?.name||null,project?.location||null,project?.contract_reference||null,client_id]
    );
    const project_id = projectResult.rows[0]?.id ||
      (await pool.query('SELECT id FROM projects WHERE name=$1 AND client_id=$2',[project?.name,client_id])).rows[0].id;

    async function addRoleUser(user, tableName, assignmentTable, fkColumn) {
      if (!user?.email) return;
      const existing = await pool.query(`SELECT id FROM ${tableName} WHERE email=$1`,[user.email]);
      let role_id;
      if (existing.rows.length > 0) {
        role_id = existing.rows[0].id;
      } else {
        let rolePicUrl = null, rolePicId = null;
        if (user.profile_picture && !user.profile_picture_id) {
          const r = await cloudinary.uploader.upload(user.profile_picture,{folder:`oneprojectapp/${tableName}`,resource_type:'image'});
          rolePicUrl = r.secure_url; rolePicId = r.public_id;
        } else { rolePicUrl = user.profile_picture||null; rolePicId = user.profile_picture_id||null; }
        const roleResult = await pool.query(
          `INSERT INTO ${tableName} (email,password_hash,verified,profile_picture,profile_picture_id,created_at) VALUES ($1,$2,true,$3,$4,NOW()) RETURNING id`,
          [user.email,user.password_hash||null,rolePicUrl,rolePicId]
        );
        role_id = roleResult.rows[0].id;
      }
      await pool.query(
        `INSERT INTO ${assignmentTable} (project_id,${fkColumn},company_name,title_position,telephone,task,representative,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW()) ON CONFLICT (project_id,${fkColumn}) DO NOTHING`,
        [project_id,role_id,user.company_name||null,user.title_position||user.title||null,user.telephone||null,user.task||null,user.representative||null]
      );
    }

    await addRoleUser(contractor,   'contractors',                'contractor_assignments',   'contractor_id');
    await addRoleUser(consultant,   'consultants',                'consultant_assignments',   'consultant_id');
    await addRoleUser(teamMember,   'team_members',               'team_member_assignments',  'team_member_id');
    await addRoleUser(contractorPM, 'contractor_project_managers','contractor_pm_assignments','contractor_pm_id');
    await addRoleUser(consultantPM, 'consultant_project_managers','consultant_pm_assignments','consultant_pm_id');

    const SECRET = process.env.JWT_SECRET || 'supersecretkey';
    const accessToken  = jwt.sign({sub:client_id,companyEmail:clientResult.rows[0].company_email,role:'Client',projects:[project_id]},SECRET,{expiresIn:'15m'});
    const refreshToken = crypto.randomBytes(64).toString('hex');
    await pool.query(`INSERT INTO refresh_tokens (user_id,role,token,expires_at) VALUES ($1,'Client',$2,NOW()+interval '24 hours')`,[client_id,refreshToken]);
    res.json({success:true,message:'Account saved.',clientId:client_id,projectId:project_id,clientPictureUrl,clientPictureId,accessToken,refreshToken});
  } catch (err) {
    console.error('Commit error:', err);
    res.status(500).json({ success: false, error: 'Server error committing account.' });
  }
});

app.post('/resend-verification', async (req, res) => {
  const { email } = req.body;
  try {
    await pool.query('DELETE FROM email_tokens WHERE email=$1 AND verified=false',[email]);
    const code=Math.floor(100000+Math.random()*900000).toString(), sessionId=uuidv4();
    await pool.query(`INSERT INTO email_tokens (email,token,expires_at,attempts,session_id,verified,pending_password,reset_flow,created_at,project_flow) VALUES ($1,$2,NOW()+interval '3 minutes',0,$3,false,false,false,NOW(),false)`,[email,code,sessionId]);
    await transporter.sendMail({from:'skyprincenkp16@gmail.com',to:email,subject:'Resend Verification Code - OneProjectApp',html:`<p>Your new verification code is: <b>${code}</b></p><p>Expires in 3 minutes.</p>`});
    res.json({success:true,message:'Verification code resent.',sessionId});
  } catch(err){console.error('Resend error:',err);res.status(500).json({success:false,error:'Failed to resend verification.'});}
});

app.post('/firstlogin-send', async (req, res) => {
  const { email } = req.body;
  try {
    const code=Math.floor(100000+Math.random()*900000).toString(), sessionId=uuidv4();
    await pool.query(`INSERT INTO email_tokens (email,token,expires_at,session_id,verified,reset_flow) VALUES ($1,$2,NOW()+interval '3 minutes',$3,false,false)`,[email,code,sessionId]);
    await transporter.sendMail({from:'skyprincenkp16@gmail.com',to:email,subject:'OneProjectApp Verification Code',html:`<p>Your verification code is: <b>${code}</b></p><p>Expires in 3 minutes.</p>`});
    res.json({success:true,message:'Verification code sent.',sessionId});
  } catch(err){console.error('First login send error:',err);res.status(500).json({success:false,error:'Failed to send verification.'});}
});

app.post('/firstlogin-resend', async (req, res) => {
  const { email } = req.body;
  try {
    await pool.query('DELETE FROM email_tokens WHERE email=$1 AND verified=false AND reset_flow=false',[email]);
    const code=Math.floor(100000+Math.random()*900000).toString(), sessionId=uuidv4();
    await pool.query(`INSERT INTO email_tokens (email,token,expires_at,session_id,verified,reset_flow) VALUES ($1,$2,NOW()+interval '3 minutes',$3,false,false)`,[email,code,sessionId]);
    await transporter.sendMail({from:'skyprincenkp16@gmail.com',to:email,subject:'OneProjectApp Verification Code (Resend)',html:`<p>Your new verification code is: <b>${code}</b></p><p>Expires in 3 minutes.</p>`});
    res.json({success:true,message:'New verification code sent.',sessionId});
  } catch(err){console.error('First login resend error:',err);res.status(500).json({success:false,error:'Failed to resend verification.'});}
});

app.post('/verify-password-code', async (req, res) => {
  const { email, token } = req.body;
  try {
    const check = await pool.query(`SELECT * FROM email_tokens WHERE email=$1 AND token=$2 AND expires_at>NOW() AND verified=false AND reset_flow=false ORDER BY expires_at DESC LIMIT 1`,[email,token]);
    if (!check.rows.length) return res.json({success:false,verified:false,error:'Invalid or expired code.'});
    await pool.query('UPDATE email_tokens SET verified=true WHERE id=$1',[check.rows[0].id]);
    res.json({success:true,verified:true,message:'Code verified. You may now set your password.'});
  } catch(err){console.error('Verify password code error:',err);res.status(500).json({success:false,verified:false,error:'Failed to verify code.'});}
});

app.post('/set-password', async (req, res) => {
  const { email, password, role } = req.body;
  try {
    const map = roleTableMap(role);
    if (!map) return res.json({success:false,error:'Invalid role.'});
    const hash = await bcrypt.hash(password,10);
    const updateRes = await pool.query(`UPDATE ${map.table} SET password_hash=$1,verified=true WHERE ${map.emailCol}=$2 RETURNING id,${map.emailCol} AS email`,[hash,email]);
    if (!updateRes.rows.length) return res.json({success:false,error:'Account not found.'});
    const user=updateRes.rows[0], SECRET=process.env.JWT_SECRET||'supersecretkey';
    const payload = role==='Client'?{sub:user.id,role,companyEmail:user.email}:{sub:user.id,role,email:user.email};
    const accessToken=jwt.sign(payload,SECRET,{expiresIn:'15m'}), refreshToken=crypto.randomBytes(64).toString('hex');
    await pool.query(`INSERT INTO refresh_tokens (user_id,role,token,expires_at) VALUES ($1,$2,$3,NOW()+interval '24 hours')`,[user.id,role,refreshToken]);
    res.json({success:true,role,message:'Password set successfully.',accessToken,refreshToken});
  } catch(err){console.error('Set password error:',err);res.status(500).json({success:false,error:'Failed to set password.'});}
});

app.post('/reset-send', async (req, res) => {
  const { email, role } = req.body;
  try {
    const map = roleTableMap(role);
    if (!map) return res.json({success:false,error:'Invalid role.'});
    const result = await pool.query(`SELECT password_hash FROM ${map.table} WHERE ${map.emailCol}=$1`,[email]);
    if (!result.rows.length||!result.rows[0].password_hash) return res.json({success:false,error:'No password set yet. Please follow the first-login flow.'});
    await pool.query('DELETE FROM email_tokens WHERE email=$1 AND reset_flow=true',[email]);
    const code=Math.floor(100000+Math.random()*900000).toString(), sessionId=uuidv4();
    const insertResult = await pool.query(`INSERT INTO email_tokens (email,token,expires_at,session_id,verified,reset_flow) VALUES ($1,$2,NOW()+interval '3 minutes',$3,false,true) RETURNING *`,[email,code,sessionId]);
    await transporter.sendMail({from:'skyprincenkp16@gmail.com',to:email,subject:'Reset your password - OneProjectApp',html:`<p>Your reset code is: <b>${code}</b></p><p>Expires in 3 minutes.</p>`});
    res.json({success:true,message:'Reset code sent.',sessionId,expiresAt:insertResult.rows[0].expires_at});
  } catch(err){console.error('Reset send error:',err);res.status(500).json({success:false,error:'Failed to send reset code.'});}
});

app.post('/reset-resend', async (req, res) => {
  const { email, role } = req.body;
  try {
    const map = roleTableMap(role);
    if (!map) return res.json({success:false,error:'Invalid role.'});
    const result = await pool.query(`SELECT password_hash FROM ${map.table} WHERE ${map.emailCol}=$1`,[email]);
    if (!result.rows.length||!result.rows[0].password_hash) return res.json({success:false,error:'No password set yet.'});
    await pool.query('DELETE FROM email_tokens WHERE email=$1 AND reset_flow=true',[email]);
    const code=Math.floor(100000+Math.random()*900000).toString(), sessionId=uuidv4();
    const insertResult = await pool.query(`INSERT INTO email_tokens (email,token,expires_at,session_id,verified,reset_flow) VALUES ($1,$2,NOW()+interval '3 minutes',$3,false,true) RETURNING *`,[email,code,sessionId]);
    await transporter.sendMail({from:'skyprincenkp16@gmail.com',to:email,subject:'Resend reset code - OneProjectApp',html:`<p>Your new reset code is: <b>${code}</b></p><p>Expires in 3 minutes.</p>`});
    res.json({success:true,message:'New reset code sent.',sessionId,expiresAt:insertResult.rows[0].expires_at});
  } catch(err){console.error('Reset resend error:',err);res.status(500).json({success:false,error:'Failed to resend reset code.'});}
});

app.post('/reset-verify', async (req, res) => {
  const { email, token } = req.body;
  try {
    const check = await pool.query(`SELECT * FROM email_tokens WHERE email=$1 AND token=$2 AND expires_at>NOW() AND verified=false AND reset_flow=true ORDER BY expires_at DESC LIMIT 1`,[email,token]);
    if (!check.rows.length) return res.json({success:false,verified:false,error:'Invalid or expired code.'});
    await pool.query('UPDATE email_tokens SET verified=true WHERE id=$1',[check.rows[0].id]);
    res.json({success:true,verified:true,message:'Code verified. You may now set your new password.'});
  } catch(err){console.error('Verify reset code error:',err);res.status(500).json({success:false,verified:false,error:'Failed to verify reset code.'});}
});

app.post('/reset-set-password', async (req, res) => {
  const { email, password, role } = req.body;
  try {
    const map = roleTableMap(role);
    if (!map) return res.json({success:false,error:'Invalid role.'});
    const hash = await bcrypt.hash(password,10);
    const updateRes = await pool.query(`UPDATE ${map.table} SET password_hash=$1,verified=true WHERE ${map.emailCol}=$2 RETURNING id,${map.emailCol} AS email`,[hash,email]);
    if (!updateRes.rows.length) return res.json({success:false,error:'Account not found.'});
    const user=updateRes.rows[0], SECRET=process.env.JWT_SECRET||'supersecretkey';
    const payload = role==='Client'?{sub:user.id,companyEmail:user.email,role}:{sub:user.id,email:user.email,role};
    const accessToken=jwt.sign(payload,SECRET,{expiresIn:'15m'}), refreshToken=crypto.randomBytes(64).toString('hex');
    await pool.query(`INSERT INTO refresh_tokens (user_id,role,token,expires_at) VALUES ($1,$2,$3,NOW()+interval '24 hours')`,[user.id,role,refreshToken]);
    res.json({success:true,role,message:'Password reset successfully.',accessToken,refreshToken});
  } catch(err){console.error('Reset set password error:',err);res.status(500).json({success:false,error:'Failed to reset password.'});}
});

app.post('/login', async (req, res) => {
  const { email, company_email, password, role } = req.body;
  try {
    const map = roleTableMap(role);
    if (!map) return res.json({success:false,error:'Invalid role.'});
    const assignmentInfo = {
      'Client':                      {table:'projects',                 fk:'client_id'},
      'Client Project Manager':      {table:'client_pm_assignments',    fk:'client_pm_id'},
      'Consultant':                  {table:'consultant_assignments',    fk:'consultant_id'},
      'Consultant Project Manager':  {table:'consultant_pm_assignments', fk:'consultant_pm_id'},
      'Contractor':                  {table:'contractor_assignments',    fk:'contractor_id'},
      'Contractor Project Manager':  {table:'contractor_pm_assignments', fk:'contractor_pm_id'},
      'Team Member':                 {table:'team_member_assignments',   fk:'team_member_id'},
    };
    const loginEmail = role==='Client'?company_email:email;
    const selectFields = role==='Client'?'id,company_name,company_email,representative,title,telephone,password_hash,verified,profile_picture,created_at':'id,email,password_hash,verified,profile_picture,created_at';
    const result = await pool.query(`SELECT ${selectFields} FROM ${map.table} WHERE TRIM(LOWER(${map.emailCol}))=TRIM(LOWER($1))`,[loginEmail]);
    if (!result.rows.length) return res.json({success:false,error:'Account not found.'});
    const user = result.rows[0];
    if (!user.password_hash) return res.json({success:false,error:'No password set yet. Follow the first-login guideline.'});
    if (!await bcrypt.compare(password,user.password_hash)) return res.json({success:false,error:'Invalid password.'});
    if (!user.verified) return res.json({success:false,error:'Account not verified.'});
    let projectAssignments=[];
    if (role==='Client') {
      const r=await pool.query('SELECT id FROM projects WHERE client_id=$1',[user.id]);
      projectAssignments=r.rows.map(r=>r.id);
    } else {
      const ai=assignmentInfo[role];
      const r=await pool.query(`SELECT project_id FROM ${ai.table} WHERE ${ai.fk}=$1`,[user.id]);
      projectAssignments=r.rows.map(r=>r.project_id);
    }
    const SECRET=process.env.JWT_SECRET||'supersecretkey';
    const payload=role==='Client'?{sub:user.id,companyEmail:user.company_email,role,projects:projectAssignments}:{sub:user.id,email:user.email,role,projects:projectAssignments};
    const accessToken=jwt.sign(payload,SECRET,{expiresIn:'15m'}), refreshToken=crypto.randomBytes(64).toString('hex');
    await pool.query(`INSERT INTO refresh_tokens (user_id,role,token,expires_at) VALUES ($1,$2,$3,NOW()+interval '24 hours')`,[user.id,role,refreshToken]);
    res.json({success:true,message:'Login successful.',accessToken,refreshToken,role,projects:projectAssignments});
  } catch(err){console.error('Login error:',err);res.status(500).json({success:false,error:'Server error logging in.'});}
});

app.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({success:false,error:'No refresh token provided.'});
  try {
    const tokenRes = await pool.query('SELECT user_id,role,expires_at FROM refresh_tokens WHERE token=$1',[refreshToken]);
    if (!tokenRes.rows.length) return res.status(401).json({success:false,error:'Refresh token not recognized.'});
    const {user_id, role: storedRole, expires_at}=tokenRes.rows[0];
    const role = normalizeRole(storedRole);
    if (new Date(expires_at)<new Date()) return res.status(403).json({success:false,error:'Refresh token expired.'});
    const map=roleTableMap(role);
    if (!map) return res.status(400).json({success:false,error:'Invalid role.'});
    const userRes=await pool.query(`SELECT id,${map.emailCol} AS email FROM ${map.table} WHERE id=$1`,[user_id]);
    if (!userRes.rows.length) return res.status(404).json({success:false,error:'User not found.'});
    const user=userRes.rows[0];
    const assignmentInfo={
      Client: {table:'projects',fk:'client_id'},
      ClientPM: {table:'client_pm_assignments',fk:'client_pm_id'},
      Consultant: {table:'consultant_assignments',fk:'consultant_id'},
      ConsultantPM: {table:'consultant_pm_assignments',fk:'consultant_pm_id'},
      Contractor: {table:'contractor_assignments',fk:'contractor_id'},
      ContractorPM: {table:'contractor_pm_assignments',fk:'contractor_pm_id'},
      TeamMember: {table:'team_member_assignments',fk:'team_member_id'},
    };
    let projectAssignments=[];
    if (role==='Client'){const r=await pool.query('SELECT id FROM projects WHERE client_id=$1',[user_id]);projectAssignments=r.rows.map(r=>r.id);}
    else{const ai=assignmentInfo[role];const r=await pool.query(`SELECT project_id FROM ${ai.table} WHERE ${ai.fk}=$1`,[user_id]);projectAssignments=r.rows.map(r=>r.project_id);}
    const SECRET=process.env.JWT_SECRET||'supersecretkey';
    const payload=role==='Client'?{sub:user_id,companyEmail:user.email,role,projects:projectAssignments}:{sub:user_id,email:user.email,role,projects:projectAssignments};
    const newAccessToken=jwt.sign(payload,SECRET,{expiresIn:'15m'});
    res.json({success:true,accessToken:newAccessToken,refreshToken,role,projects:projectAssignments});
  } catch(err){console.error('Refresh error:',err);res.status(500).json({success:false,error:'Server error refreshing token.'});}
});

app.post('/logout', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({success:false,error:'No refresh token provided.'});
  try {
    const result=await pool.query('DELETE FROM refresh_tokens WHERE token=$1 RETURNING id',[refreshToken]);
    if (!result.rows.length) return res.status(404).json({success:false,error:'Refresh token not found.'});
    res.json({success:true,message:'Logged out successfully.'});
  } catch(err){console.error('Logout error:',err);res.status(500).json({success:false,error:'Server error during logout.'});}
});

app.post('/sendgrid-events', async (req, res) => {
  const events = req.body;
  for (const e of events) {
    if (['bounce','dropped','blocked'].includes(e.event)) {
      await pool.query('UPDATE clients SET verified=false WHERE company_email=$1',[e.email]).catch(()=>{});
    }
  }
  res.status(200).send('OK');
});

app.post('/check-email', async (req, res) => {
  const { email, role } = req.body;
  try {
    const map=roleTableMap(role);
    if (!map) return res.json({success:false,exists:false,error:'Invalid role.'});
    const result=await pool.query(`SELECT id FROM ${map.table} WHERE ${map.emailCol}=$1`,[email]);
    res.json({success:true,exists:result.rows.length>0});
  } catch(err){console.error('Check email error:',err);res.status(500).json({success:false,error:'Server error checking email.'});}
});

app.post('/cleanup-tokens', async (req, res) => {
  try {
    const result=await pool.query('DELETE FROM email_tokens WHERE expires_at<NOW() AND verified=false');
    res.json({success:true,message:'Expired tokens cleaned up.',deletedCount:result.rowCount});
  } catch(err){console.error('Cleanup error:',err);res.status(500).json({success:false,error:'Failed to cleanup tokens.'});}
});

setInterval(async () => {
  try {
    const r=await pool.query('DELETE FROM email_tokens WHERE expires_at<NOW() AND verified=false');
    if(r.rowCount>0) console.log(`Scheduled cleanup: ${r.rowCount} expired tokens deleted.`);
  } catch(err){console.error('Scheduled cleanup error:',err);}
}, 3*60*1000);

// ─────────────────────────────────────────────────────────────────────────────
//  PROFILE ROUTES
// ─────────────────────────────────────────────────────────────────────────────
function buildProfileRoutes({routePrefix,jwtRole,dbTable,emailCol,cloudFolder,assignmentTable,assignmentFk,isClientRole,extraProfileFields}) {
  app.get(`${routePrefix}/profile`, authenticateToken, async (req, res) => {
    if (req.user.role!==jwtRole) return res.status(403).json({error:`Access denied: ${jwtRole} only`});
    try {
      const fields=[emailCol,'profile_picture',...(extraProfileFields||[])].join(',');
      const result=await pool.query(`SELECT ${fields} FROM ${dbTable} WHERE id=$1 AND ${emailCol}=$2`,[req.user.user_id,req.user.email]);
      if (!result.rows.length) return res.status(404).json({error:`${jwtRole} not found`});
      res.json({...result.rows[0],role:jwtRole});
    } catch(err){console.error(`Fetch ${jwtRole} profile error:`,err);res.status(500).json({error:'Failed to fetch profile'});}
  });

  app.post(`${routePrefix}/upload-picture`, authenticateToken, upload.single('profile_picture'), async (req, res) => {
    if (req.user.role!==jwtRole) return res.status(403).json({error:`Access denied: ${jwtRole} only`});
    try {
      if (!req.file) return res.status(400).json({error:'No file uploaded or file too large.'});
      if (!req.file.mimetype.startsWith('image/')) return res.status(400).json({error:'Only image files allowed.'});
      const cdResult=await uploadToCloudinary(req.file.buffer,cloudFolder,'image');
      await pool.query(`UPDATE ${dbTable} SET profile_picture=$1,profile_picture_id=$2 WHERE id=$3 AND ${emailCol}=$4`,[cdResult.secure_url,cdResult.public_id,req.user.user_id,req.user.email]);
      res.json({success:true,url:cdResult.secure_url});
    } catch(err){console.error(`Upload ${jwtRole} picture error:`,err);res.status(500).json({error:'Failed to upload picture'});}
  });

  app.post(`${routePrefix}/delete-picture`, authenticateToken, async (req, res) => {
    if (req.user.role!==jwtRole) return res.status(403).json({error:`Access denied: ${jwtRole} only`});
    try {
      const result=await pool.query(`SELECT profile_picture_id FROM ${dbTable} WHERE id=$1 AND ${emailCol}=$2`,[req.user.user_id,req.user.email]);
      if (result.rows.length>0&&result.rows[0].profile_picture_id) await cloudinary.uploader.destroy(result.rows[0].profile_picture_id);
      await pool.query(`UPDATE ${dbTable} SET profile_picture=NULL,profile_picture_id=NULL WHERE id=$1 AND ${emailCol}=$2`,[req.user.user_id,req.user.email]);
      res.json({success:true});
    } catch(err){console.error(`Delete ${jwtRole} picture error:`,err);res.status(500).json({error:'Failed to delete picture'});}
  });

  app.post(`${routePrefix}/projects`, authenticateToken, async (req, res) => {
    if (req.user.role!==jwtRole) return res.status(403).json({error:`Access denied: ${jwtRole} only`});
    try {
      let rows;
      if (isClientRole) {
        const r=await pool.query('SELECT id,name,location,contract_reference,created_at FROM projects WHERE client_id=$1',[req.user.user_id]);
        rows=r.rows;
      } else {
        const baseFields = 'p.id,p.name,p.location,p.contract_reference,p.created_at';
        const extraFields = assignmentTable === 'team_member_assignments' ? ',a.position,a.assigned_part' : ',a.title_position';
        const r=await pool.query(`SELECT ${baseFields}${extraFields} FROM ${assignmentTable} a JOIN projects p ON a.project_id=p.id WHERE a.${assignmentFk}=$1`,[req.user.user_id]);
        rows=r.rows;
      }
      res.json({projects:rows});
    } catch(err){console.error(`Fetch ${jwtRole} projects error:`,err);res.status(500).json({error:'Failed to fetch projects'});}
  });

  app.post(`${routePrefix}/project-details`, authenticateToken, async (req, res) => {
    if (req.user.role!==jwtRole) return res.status(403).json({error:`Access denied: ${jwtRole} only`});
    try {
      const {projectId}=req.body;
      let project;
      if (isClientRole) {
        const r=await pool.query('SELECT id,name,location,contract_reference,created_at FROM projects WHERE id=$1 AND client_id=$2',[projectId,req.user.user_id]);
        if (!r.rows.length) return res.status(404).json({error:'Project not found or not owned by client'});
        project=r.rows[0];
      } else {
        const baseFields = 'p.id,p.name,p.location,p.contract_reference,p.created_at';
        const extraFields = assignmentTable === 'team_member_assignments' ? ',a.position,a.assigned_part' : ',a.title_position';
        const r=await pool.query(`SELECT ${baseFields}${extraFields} FROM ${assignmentTable} a JOIN projects p ON a.project_id=p.id WHERE a.${assignmentFk}=$1 AND p.id=$2`,[req.user.user_id,projectId]);
        if (!r.rows.length) return res.status(404).json({error:'Project not found or not assigned'});
        project=r.rows[0];
      }
      res.json({project});
    } catch(err){console.error(`Fetch ${jwtRole} project-details error:`,err);res.status(500).json({error:'Failed to fetch project details'});}
  });
}

buildProfileRoutes({routePrefix:'/client',jwtRole:'Client',dbTable:'clients',emailCol:'company_email',cloudFolder:'oneprojectapp/clients',isClientRole:true,extraProfileFields:['representative','title','telephone','company_name','profile_picture_id']});
buildProfileRoutes({routePrefix:'/contractor',jwtRole:'Contractor',dbTable:'contractors',emailCol:'email',cloudFolder:'oneprojectapp/contractors',assignmentTable:'contractor_assignments',assignmentFk:'contractor_id',extraProfileFields:['profile_picture_id']});
buildProfileRoutes({routePrefix:'/consultant',jwtRole:'Consultant',dbTable:'consultants',emailCol:'email',cloudFolder:'oneprojectapp/consultants',assignmentTable:'consultant_assignments',assignmentFk:'consultant_id',extraProfileFields:['profile_picture_id']});
buildProfileRoutes({routePrefix:'/client-project-manager',jwtRole:'ClientPM',dbTable:'client_project_managers',emailCol:'email',cloudFolder:'oneprojectapp/client_project_managers',assignmentTable:'client_pm_assignments',assignmentFk:'client_pm_id',extraProfileFields:['profile_picture_id']});
buildProfileRoutes({routePrefix:'/contractor-project-manager',jwtRole:'ContractorPM',dbTable:'contractor_project_managers',emailCol:'email',cloudFolder:'oneprojectapp/contractor_project_managers',assignmentTable:'contractor_pm_assignments',assignmentFk:'contractor_pm_id',extraProfileFields:['profile_picture_id']});
buildProfileRoutes({routePrefix:'/consultant-project-manager',jwtRole:'ConsultantPM',dbTable:'consultant_project_managers',emailCol:'email',cloudFolder:'oneprojectapp/consultant_project_managers',assignmentTable:'consultant_pm_assignments',assignmentFk:'consultant_pm_id',extraProfileFields:['profile_picture_id']});
buildProfileRoutes({routePrefix:'/team-member',jwtRole:'TeamMember',dbTable:'team_members',emailCol:'email',cloudFolder:'oneprojectapp/team_members',assignmentTable:'team_member_assignments',assignmentFk:'team_member_id',extraProfileFields:['profile_picture_id']});

// ─── Client legacy routes ──────────────────────────────────────────────────
app.post('/client/check-email', async (req, res) => {
  const {email}=req.body;
  try {
    const result=await pool.query('SELECT company_email FROM clients WHERE company_email=$1',[email]);
    res.json({exists:result.rows.length>0});
  } catch(err){console.error('Check email error:',err);res.status(500).json({error:'Server error'});}
});

app.post('/client/login', async (req, res) => {
  const {email,password}=req.body;
  try {
    const result=await pool.query('SELECT company_email,password_hash FROM clients WHERE company_email=$1',[email]);
    if (!result.rows.length) return res.status(401).json({success:false,error:'Client not found.'});
    const client=result.rows[0];
    if (!await bcrypt.compare(password,client.password_hash)) return res.status(401).json({success:false,error:'Invalid password.'});
    res.json({success:true,clientEmail:client.company_email});
  } catch(err){console.error('Login error:',err);res.status(500).json({success:false,error:'Server error'});}
});

app.post('/client/profile-picture', async (req, res) => {
  const {email}=req.body;
  try {
    const result=await pool.query('SELECT profile_picture FROM clients WHERE TRIM(LOWER(company_email))=TRIM(LOWER($1))',[email]);
    if (!result.rows.length) return res.json({success:false,error:'Client not found.'});
    res.json({success:true,profile_picture:result.rows[0].profile_picture||null});
  } catch(err){console.error('Profile picture fetch error:',err);res.status(500).json({success:false,error:'Server error.'});}
});

// ─────────────────────────────────────────────────────────────────────────────
//  PROJECT FLOW ROUTES
// ─────────────────────────────────────────────────────────────────────────────
app.post('/project-send', async (req, res) => {
  const {email}=req.body;
  try {
    await pool.query('DELETE FROM email_tokens WHERE email=$1 AND project_flow=true',[email]);
    const code=Math.floor(100000+Math.random()*900000).toString(), sessionId=uuidv4();
    const insertResult=await pool.query(`INSERT INTO email_tokens (email,token,expires_at,session_id,verified,project_flow) VALUES ($1,$2,NOW()+interval '3 minutes',$3,false,true) RETURNING *`,[email,code,sessionId]);
    await transporter.sendMail({from:'skyprincenkp16@gmail.com',to:email,subject:'Project Verification - OneProjectApp',html:`<p>Your project verification code is: <b>${code}</b></p><p>Expires in 3 minutes.</p>`});
    res.json({success:true,message:'Project verification code sent.',sessionId,expiresAt:insertResult.rows[0].expires_at});
  } catch(err){console.error('Project send error:',err);res.status(500).json({success:false,error:'Failed to send project code.'});}
});

app.post('/project-resend', async (req, res) => {
  const {email}=req.body;
  try {
    await pool.query('DELETE FROM email_tokens WHERE email=$1 AND project_flow=true',[email]);
    const code=Math.floor(100000+Math.random()*900000).toString(), sessionId=uuidv4();
    const insertResult=await pool.query(`INSERT INTO email_tokens (email,token,expires_at,session_id,verified,project_flow) VALUES ($1,$2,NOW()+interval '3 minutes',$3,false,true) RETURNING *`,[email,code,sessionId]);
    await transporter.sendMail({from:'skyprincenkp16@gmail.com',to:email,subject:'Resend Project Verification - OneProjectApp',html:`<p>Your new project verification code is: <b>${code}</b></p><p>Expires in 3 minutes.</p>`});
    res.json({success:true,message:'New project code sent.',sessionId,expiresAt:insertResult.rows[0].expires_at});
  } catch(err){console.error('Project resend error:',err);res.status(500).json({success:false,error:'Failed to resend project code.'});}
});

app.post('/project-check-existence', async (req, res) => {
  const { clientEmail, projectName, contractReference } = req.body;
  if (!clientEmail || !projectName || !contractReference) {
    return res.status(400).json({ success: false, error: 'clientEmail, projectName, and contractReference are required.' });
  }

  try {
    const clientResult = await pool.query(
      `SELECT id FROM clients WHERE TRIM(LOWER(company_email)) = TRIM(LOWER($1))`,
      [clientEmail]
    );

    if (!clientResult.rows.length) {
      return res.json({ success: true, exists: false });
    }

    const clientId = clientResult.rows[0].id;
    const existing = await pool.query(
      `SELECT name, contract_reference FROM projects
       WHERE client_id = $1
         AND (TRIM(LOWER(name)) = TRIM(LOWER($2))
           OR TRIM(LOWER(contract_reference)) = TRIM(LOWER($3)))
       LIMIT 1`,
      [clientId, projectName, contractReference]
    );

    if (!existing.rows.length) {
      return res.json({ success: true, exists: false });
    }

    const conflict = existing.rows[0];
    const sameName = conflict.name && conflict.name.trim().toLowerCase() === projectName.trim().toLowerCase();
    const sameReference = conflict.contract_reference && conflict.contract_reference.trim().toLowerCase() === contractReference.trim().toLowerCase();
    let message = 'A project with this name or contract reference already exists for your account.';
    if (sameName && !sameReference) {
      message = 'A project with this name already exists for your account.';
    } else if (sameReference && !sameName) {
      message = 'A project with this contract reference already exists for your account.';
    }

    res.json({ success: true, exists: true, message });
  } catch (err) {
    console.error('[POST /project-check-existence]', err);
    res.status(500).json({ success: false, error: 'Server error checking project uniqueness.' });
  }
});

app.post('/project-verify', async (req, res) => {
  const {email,token}=req.body;
  try {
    const check=await pool.query(`SELECT * FROM email_tokens WHERE email=$1 AND token=$2 AND expires_at>NOW() AND verified=false AND project_flow=true ORDER BY expires_at DESC LIMIT 1`,[email,token]);
    if (!check.rows.length) return res.json({success:false,error:'Invalid or expired project code.'});
    await pool.query('UPDATE email_tokens SET verified=true WHERE id=$1',[check.rows[0].id]);
    res.json({success:true,message:'Project code verified.'});
  } catch(err){console.error('Project verify error:',err);res.status(500).json({success:false,error:'Failed to verify project code.'});}
});

app.post('/project-save', async (req, res) => {
  const {project,contractor,consultant,clientEmail}=req.body;
  try {
    const clientResult=await pool.query(`SELECT id,company_email FROM clients WHERE TRIM(LOWER(company_email))=TRIM(LOWER($1)) AND verified=true`,[clientEmail]);
    if (!clientResult.rows.length) return res.json({success:false,error:'Client not found or not verified.'});
    const client_id=clientResult.rows[0].id;
    const projectResult=await pool.query(`INSERT INTO projects (name,location,contract_reference,client_id,created_at) VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT (name,client_id) DO NOTHING RETURNING id`,[project.name,project.location,project.contract_reference,client_id]);
    const project_id=projectResult.rows[0]?.id||(await pool.query('SELECT id FROM projects WHERE name=$1 AND client_id=$2',[project.name,client_id])).rows[0].id;
    async function upsertAndAssign(party,partyTable,assignTable,fk){
      if (!party?.email) return;
      let r=await pool.query(`SELECT id FROM ${partyTable} WHERE TRIM(LOWER(email))=TRIM(LOWER($1))`,[party.email]);
      let id;
      if (!r.rows.length){const ins=await pool.query(`INSERT INTO ${partyTable} (email,verified,created_at) VALUES ($1,true,NOW()) RETURNING id`,[party.email]);id=ins.rows[0].id;}
      else id=r.rows[0].id;
      await pool.query(`INSERT INTO ${assignTable} (project_id,${fk},company_name,representative,title_position,telephone,task,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW()) ON CONFLICT (project_id,${fk}) DO NOTHING`,[project_id,id,party.company_name||null,party.representative||null,party.title_position||party.title||null,party.telephone||null,party.task||null]);
    }
    await upsertAndAssign(contractor,'contractors','contractor_assignments','contractor_id');
    await upsertAndAssign(consultant,'consultants','consultant_assignments','consultant_id');
    const SECRET=process.env.JWT_SECRET||'supersecretkey';
    const accessToken=jwt.sign({sub:client_id,companyEmail:clientResult.rows[0].company_email,role:'Client',projects:[project_id]},SECRET,{expiresIn:'15m'});
    const refreshToken=crypto.randomBytes(64).toString('hex');
    await pool.query(`INSERT INTO refresh_tokens (user_id,role,token,expires_at) VALUES ($1,'Client',$2,NOW()+interval '24 hours')`,[client_id,refreshToken]);
    res.json({success:true,message:'Project saved.',projectId:project_id,accessToken,refreshToken});
  } catch(err){console.error('Project save error:',err);res.status(500).json({success:false,error:'Server error saving project.'});}
});

// ─────────────────────────────────────────────────────────────────────────────
//  UNIFIED PROJECT DETAILS
// ─────────────────────────────────────────────────────────────────────────────
app.post('/profile/project-details', async (req, res) => {
  try {
    const authHeader=req.headers.authorization;
    if (!authHeader) return res.status(401).json({error:'Authorization header missing'});
    let decoded;
    try{decoded=jwt.verify(authHeader.split(' ')[1],process.env.JWT_SECRET||'supersecretkey');}
    catch{return res.status(401).json({error:'Invalid or expired token'});}
    const {sub:userId,role}=decoded;
    const {projectId}=req.body;
    const side=getSide(role);
    if (side==='client'){
      const uRes=await pool.query('SELECT id,company_email AS email,profile_picture FROM clients WHERE id=$1',[userId]);
      if (!uRes.rows.length) return res.status(404).json({error:'Client not found'});
      const pRes=await pool.query('SELECT id,name,location,contract_reference,created_at FROM projects WHERE id=$1 AND client_id=$2',[projectId,userId]);
      if (!pRes.rows.length) return res.status(404).json({error:'Project not found'});
      return res.json({user:{...uRes.rows[0],role},project:pRes.rows[0]});
    }
    const sideMap={contractor:{uTable:'contractors',aTable:'contractor_assignments',fk:'contractor_id'},consultant:{uTable:'consultants',aTable:'consultant_assignments',fk:'consultant_id'}};
    const sm=sideMap[side];
    if (!sm) return res.status(400).json({error:'Unsupported role'});
    const uRes=await pool.query(`SELECT id,email,profile_picture FROM ${sm.uTable} WHERE id=$1`,[userId]);
    if (!uRes.rows.length) return res.status(404).json({error:'User not found'});
    const aRes=await pool.query(`SELECT 1 FROM ${sm.aTable} WHERE ${sm.fk}=$1 AND project_id=$2`,[userId,projectId]);
    if (!aRes.rows.length) return res.status(403).json({error:'Project not linked to user'});
    const pRes=await pool.query('SELECT id,name,location,contract_reference,created_at FROM projects WHERE id=$1',[projectId]);
    return res.json({user:{...uRes.rows[0],role},project:pRes.rows[0]});
  } catch(err){console.error('Unified project-details error:',err);res.status(500).json({error:'Failed to fetch project details'});}
});

// ─────────────────────────────────────────────────────────────────────────────
//  ASSIGN TEAM / ASSIGN
// ─────────────────────────────────────────────────────────────────────────────
app.post('/assign-team', async (req, res) => {
  try {
    const authHeader=req.headers.authorization;
    if (!authHeader) return res.status(401).json({success:false,error:'Authorization header missing'});
    let decoded;
    try{decoded=jwt.verify(authHeader.split(' ')[1],process.env.JWT_SECRET||'supersecretkey');}
    catch{return res.status(401).json({success:false,error:'Invalid or expired token'});}
    const {sub:userId,role}=decoded;
    const {projectId,assignments}=req.body;
    if (!projectId||!Array.isArray(assignments)) return res.status(400).json({success:false,error:'Invalid payload'});
    if (!await userHasProjectAccess(userId, role, projectId)) {
      return res.status(403).json({success:false,error:'Project not linked to this user'});
    }
    const side=getSide(role);
    if (!side) return res.status(403).json({success:false,error:'Unsupported role'});
    const client=await pool.connect();
    try {
      for (const a of assignments) {
        if (a.role==='Project Manager'){
          const pmTableMap={client:{pmTable:'client_project_managers',aTable:'client_pm_assignments',fk:'client_pm_id'},contractor:{pmTable:'contractor_project_managers',aTable:'contractor_pm_assignments',fk:'contractor_pm_id'},consultant:{pmTable:'consultant_project_managers',aTable:'consultant_pm_assignments',fk:'consultant_pm_id'}};
          const pm=pmTableMap[side];
          await client.query(`INSERT INTO ${pm.aTable} (project_id,${pm.fk},name,telephone,task) VALUES ($1,(SELECT id FROM ${pm.pmTable} WHERE email=$2),$3,$4,$5) ON CONFLICT DO NOTHING`,[projectId,a.email,a.name||null,a.telephone||null,a.task||null]);
        } else if (a.role==='Team Member'){
          const assignedPart=a.assigned_part||(side==='client'?'Client':side==='contractor'?'Contractor':'Consultant');
          await client.query(`INSERT INTO team_member_assignments (project_id,team_member_id,name,position,telephone,assigned_part,assigned_by,assigned_by_role) VALUES ($1,(SELECT id FROM team_members WHERE email=$2),$3,$4,$5,$6,$7,$8) ON CONFLICT (project_id,team_member_id) DO NOTHING`,[projectId,a.email,a.name||null,a.position||null,a.telephone||null,assignedPart,a.assigned_by||userId,a.assigned_by_role||role]);
        }
      }
      const pmCheckMap={client:'SELECT 1 FROM client_pm_assignments WHERE project_id=$1 LIMIT 1',contractor:'SELECT 1 FROM contractor_pm_assignments WHERE project_id=$1 LIMIT 1',consultant:'SELECT 1 FROM consultant_pm_assignments WHERE project_id=$1 LIMIT 1'};
      const hasPMCheck=await client.query(pmCheckMap[side],[projectId]);
      res.json({success:true,message:hasPMCheck.rows.length>0?'PM is already assigned.':'Assignments saved',role,projectId,hasPM:hasPMCheck.rows.length>0});
    } finally{client.release();}
  } catch(err){console.error('Assign team error:',err);res.status(500).json({success:false,error:'Server error'});}
});

app.post('/assign', async (req, res) => {
  try {
    const authHeader=req.headers.authorization;
    if (!authHeader) return res.status(401).json({success:false,error:'Authorization header missing'});
    let decoded;
    try{decoded=jwt.verify(authHeader.split(' ')[1],process.env.JWT_SECRET||'supersecretkey');}
    catch{return res.status(401).json({success:false,error:'Invalid or expired token'});}
    const {sub:userId,role:jwtRole}=decoded;
    const {projectId,assignment}=req.body;
    if (!projectId||!assignment?.role||!assignment?.email) return res.status(400).json({success:false,error:'Invalid payload'});
    if (!await userHasProjectAccess(userId, jwtRole, projectId)) {
      return res.status(403).json({success:false,error:'Project not linked to this user'});
    }
    const side=getSide(jwtRole);
    if (!side) return res.status(403).json({success:false,error:'Unsupported role'});
    const client=await pool.connect();
    try {
      let insertQuery,params,roleLabel;
      if (assignment.role==='Client Project Manager'){
        await client.query(`INSERT INTO client_project_managers (email,verified) VALUES ($1,true) ON CONFLICT (email) DO NOTHING`,[assignment.email]);
        insertQuery=`INSERT INTO client_pm_assignments (project_id,client_pm_id,name,telephone,task) VALUES ($1,(SELECT id FROM client_project_managers WHERE email=$2),$3,$4,$5) RETURNING client_pm_id AS assigned_id`;
        params=[projectId,assignment.email,assignment.name||null,assignment.telephone||null,assignment.task||null]; roleLabel='Client';
      } else if (assignment.role==='Contractor Project Manager'){
        await client.query(`INSERT INTO contractor_project_managers (email,verified) VALUES ($1,true) ON CONFLICT (email) DO NOTHING`,[assignment.email]);
        insertQuery=`INSERT INTO contractor_pm_assignments (project_id,contractor_pm_id,name,telephone,task) VALUES ($1,(SELECT id FROM contractor_project_managers WHERE email=$2),$3,$4,$5) RETURNING contractor_pm_id AS assigned_id`;
        params=[projectId,assignment.email,assignment.name||null,assignment.telephone||null,assignment.task||null]; roleLabel='Contractor';
      } else if (assignment.role==='Consultant Project Manager'){
        await client.query(`INSERT INTO consultant_project_managers (email,verified) VALUES ($1,true) ON CONFLICT (email) DO NOTHING`,[assignment.email]);
        insertQuery=`INSERT INTO consultant_pm_assignments (project_id,consultant_pm_id,name,telephone,task) VALUES ($1,(SELECT id FROM consultant_project_managers WHERE email=$2),$3,$4,$5) RETURNING consultant_pm_id AS assigned_id`;
        params=[projectId,assignment.email,assignment.name||null,assignment.telephone||null,assignment.task||null]; roleLabel='Consultant';
      } else if (assignment.role==='Team Member'){
        await client.query(`INSERT INTO team_members (email,verified) VALUES ($1,true) ON CONFLICT (email) DO NOTHING`,[assignment.email]);
        const assignedPart=assignment.assigned_part||(side==='client'?'Client':side==='contractor'?'Contractor':'Consultant');
        insertQuery=`INSERT INTO team_member_assignments (project_id,team_member_id,name,position,telephone,assigned_part,assigned_by,assigned_by_role) VALUES ($1,(SELECT id FROM team_members WHERE email=$2),$3,$4,$5,$6,$7,$8) RETURNING team_member_id AS assigned_id`;
        params=[projectId,assignment.email,assignment.name||null,assignment.position||null,assignment.telephone||null,assignedPart,assignment.assigned_by||userId,assignment.assigned_by_role||jwtRole]; roleLabel='TeamMember';
      } else {
        return res.status(400).json({success:false,error:'Unsupported role'});
      }
      const result=await client.query(insertQuery,params);
      res.json({success:true,message:'Assignment saved',role:roleLabel,projectId,assignedId:result.rows[0]?.assigned_id});
    } finally{client.release();}
  } catch(err){console.error('Assign route error:',err);res.status(500).json({success:false,error:'Server error'});}
});

// ─────────────────────────────────────────────────────────────────────────────
//  /api/me  &  /api/user-assignment
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/me', authenticateToken, async (req, res) => {
  try {
    const id = req.user.user_id;
    const role = req.user.role;
    let name = null, company_name = null, position = null, assigned_part = null;
    const r = normalizeRole(role);
    if (r === 'Client') {
      const { rows } = await pool.query('SELECT display_name, representative, company_name, company_email FROM clients WHERE id=$1 LIMIT 1', [id]);
      const row = rows[0]; name = row?.display_name || row?.representative || row?.company_email || null; company_name = row?.company_name || null;
    } else if (r === 'Contractor') {
      const { rows } = await pool.query('SELECT display_name, email FROM contractors WHERE id=$1 LIMIT 1', [id]);
      const row = rows[0]; name = row?.display_name || row?.email || null;
    } else if (r === 'Consultant') {
      const { rows } = await pool.query('SELECT display_name, email FROM consultants WHERE id=$1 LIMIT 1', [id]);
      const row = rows[0]; name = row?.display_name || row?.email || null;
    } else if (r === 'ClientPM') {
      const { rows } = await pool.query('SELECT display_name, email FROM client_project_managers WHERE id=$1 LIMIT 1', [id]);
      const row = rows[0]; name = row?.display_name || row?.email || null;
    } else if (r === 'ContractorPM') {
      const { rows } = await pool.query('SELECT display_name, email FROM contractor_project_managers WHERE id=$1 LIMIT 1', [id]);
      const row = rows[0]; name = row?.display_name || row?.email || null;
    } else if (r === 'ConsultantPM') {
      const { rows } = await pool.query('SELECT display_name, email FROM consultant_project_managers WHERE id=$1 LIMIT 1', [id]);
      const row = rows[0]; name = row?.display_name || row?.email || null;
    } else if (r === 'TeamMember') {
      const { rows } = await pool.query('SELECT display_name, email FROM team_members WHERE id=$1 LIMIT 1', [id]);
      const row = rows[0]; name = row?.display_name || row?.email || null;
      const { rows: assignmentRows } = await pool.query('SELECT position, assigned_part FROM team_member_assignments WHERE team_member_id=$1 ORDER BY id DESC LIMIT 1', [id]);
      position = assignmentRows[0]?.position || null;
      assigned_part = assignmentRows[0]?.assigned_part || null;
    }
    return res.json({ id, role, email: req.user.email, name, company_name, position, assigned_part });
  } catch (err) {
    console.error('GET /api/me error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/user-assignment', authenticateToken, async (req, res) => {
  try {
    const { projectId } = req.query;
    const { user_id, role } = req.user;
    if (!projectId) return res.status(400).json({ error: 'projectId is required' });

    const isLeader = isWCLeader(role);
    let side = null;
    if (isLeader) {
      side = wcSide(role);
    } else if (role === 'TeamMember') {
      const result = await pool.query(
        `SELECT assigned_part FROM team_member_assignments WHERE project_id = $1 AND team_member_id = $2 ORDER BY id DESC LIMIT 1`,
        [projectId, user_id]
      );
      if (result.rows.length > 0) side = result.rows[0].assigned_part;
    }
    return res.json({ userId: user_id, role, side, isLeader });
  } catch (err) {
    console.error('GET /api/user-assignment:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  NOTIFICATIONS  (both /notifications/* and /api/notifications/*)
// ─────────────────────────────────────────────────────────────────────────────
async function getUnreadCount(projectId, userRole, userId) {
  try {
    const normalizedRole = normalizeRole(userRole);
    const result = await pool.query(
      `SELECT COUNT(DISTINCT n.id) AS count
       FROM notifications n
       INNER JOIN notification_recipients nr ON nr.notification_id = n.id
       WHERE n.project_id = $1
         AND NOT (n.added_by_id = $3 AND n.added_by_role = $2)
         AND nr.recipient_role = $2
         AND nr.recipient_role_id = $3
         AND nr.is_read = false`,
      [projectId, normalizedRole, userId]
    );
    return parseInt(result.rows[0].count, 10);
  } catch (err) {
    console.error('[getUnreadCount] Error:', err.message);
    throw err;
  }
}

async function getNotifications(projectId, userRole, userId) {
  try {
    const normalizedRole = normalizeRole(userRole);
    const { rows } = await pool.query(
      `SELECT n.id, n.entity_type, n.entity_id, n.message,
              n.added_by_role, n.created_at,
              nr.is_read
       FROM notifications n
       INNER JOIN notification_recipients nr ON nr.notification_id = n.id
       WHERE n.project_id = $1
         AND NOT (n.added_by_id = $3 AND n.added_by_role = $2)
         AND nr.recipient_role = $2
         AND nr.recipient_role_id = $3
       ORDER BY n.created_at DESC`,
      [projectId, normalizedRole, userId]
    );
    return rows;
  } catch (err) {
    console.error('[getNotifications] Error:', err.message);
    throw err;
  }
}

for (const prefix of ['/notifications', '/api/notifications']) {
  app.get(`${prefix}/unread-count`, authenticateToken, async (req, res) => {
    try {
      const count = await getUnreadCount(req.query.projectId, req.user.role, req.user.user_id);
      res.json({ count });
    } catch (err) { console.error('Unread count error:', err); res.status(500).json({ count: 0 }); }
  });

  app.get(`${prefix}`, authenticateToken, async (req, res) => {
    try {
      const notifications = await getNotifications(req.query.projectId, req.user.role, req.user.user_id);
      res.json({ notifications });
    } catch (err) { console.error('Fetch notifications error:', err); res.status(500).json({ notifications: [] }); }
  });

  app.put(`${prefix}/:id/read`, authenticateToken, async (req, res) => {
    try {
      await pool.query(
        `UPDATE notification_recipients
         SET is_read = true, read_at = NOW()
         WHERE notification_id = $1
           AND recipient_role = $2
           AND recipient_role_id = $3`,
        [req.params.id, req.user.role, req.user.user_id]
      );
      res.json({ success: true });
    } catch (err) {
      console.error('Mark read error:', err);
      res.status(500).json({ success: false });
    }
  });

  app.post(`${prefix}/mark-all-read`, authenticateToken, async (req, res) => {
    const { notificationIds } = req.body;
    if (!Array.isArray(notificationIds) || !notificationIds.length) return res.json({ success: true, updated: 0 });
    try {
      let updated = 0;
      for (const notifId of notificationIds) {
        await pool.query(
          `UPDATE notification_recipients
           SET is_read = true, read_at = NOW()
           WHERE notification_id = $1
             AND recipient_role = $2
             AND recipient_role_id = $3`,
          [notifId, req.user.role, req.user.user_id]
        );
        updated += 1;
      }
      res.json({ success: true, updated });
    } catch (err) { console.error('Mark all read error:', err); res.status(500).json({ success: false }); }
  });

  // Diagnostic endpoint: lightweight DB checks for notifications
  app.get(`${prefix}/diagnose`, authenticateToken, async (req, res) => {
    const projectId = normalizeProjectId(req.query.projectId);
    try {
      const t1 = await pool.query("SELECT to_regclass('public.notifications') AS reg");
      const t2 = await pool.query("SELECT to_regclass('public.notification_recipients') AS reg");
      const tableExists = { notifications: !!t1.rows[0].reg, notification_recipients: !!t2.rows[0].reg };

      let counts = { notifications: null, notification_recipients: null, orphaned_notifications: null };
      if (projectId && tableExists.notifications && tableExists.notification_recipients) {
        const r1 = await pool.query('SELECT COUNT(*) FROM notifications WHERE project_id = $1', [projectId]);
        const r2 = await pool.query('SELECT COUNT(nr.*) FROM notification_recipients nr JOIN notifications n ON n.id = nr.notification_id WHERE n.project_id = $1', [projectId]);
        const r3 = await pool.query('SELECT COUNT(n.id) FROM notifications n LEFT JOIN notification_recipients nr ON nr.notification_id = n.id WHERE n.project_id = $1 AND nr.id IS NULL', [projectId]);
        counts.notifications = Number(r1.rows[0].count);
        counts.notification_recipients = Number(r2.rows[0].count);
        counts.orphaned_notifications = Number(r3.rows[0].count);
      }

      const fnRes = await pool.query("SELECT proname FROM pg_proc WHERE proname = 'create_notification_for_project' LIMIT 1");
      const functions = { create_notification_for_project: fnRes.rows.length > 0 };

      res.json({ tables: tableExists, counts, functions });
    } catch (err) {
      console.error('[diagnose] error:', err.message);
      res.status(500).json({ error: err.message });
    }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
//  ADD RECORD
//  Order of work: cheap checks first, permanent actions (upload, insert) last.
//  Every file sent to Cloudinary is tracked, so it is removed again if a later
//  step fails. Nothing is left behind by a rejected request.
// ─────────────────────────────────────────────────────────────────────────────
const RECORD_MAX_FILE_BYTES = 10 * 1024 * 1024;
const RECORD_MAX_SUPPORTING = 10;
const RECORD_NOTICE_KINDS   = ['notice', 'rejection_notice', 'acceptance_notice'];
const RECORD_SUPPORTING_EXT = /\.(xlsx?|docx?|dwg|dxf|jpe?g|png|webp|zip|csv)$/i;
const RECORD_TITLE_MIN = 3;
const RECORD_TITLE_MAX = 200;
const RECORD_TEXT_MIN  = 10;
const RECORD_HTML_MAX  = 50000;

// Records use their own multer so oversized files are refused while streaming in,
// instead of being fully loaded into memory by the shared 200 MB upload.
const recordMulter = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: RECORD_MAX_FILE_BYTES, files: 1 + RECORD_MAX_SUPPORTING },
  fileFilter: (_req, file, cb) => {
    const name = file.originalname || '';
    if (file.fieldname === 'officialDocument') {
      if (!/\.pdf$/i.test(name)) return cb(new Error('The official document must be a PDF.'));
    } else if (file.fieldname === 'supportingFiles') {
      if (!RECORD_SUPPORTING_EXT.test(name)) return cb(new Error(`"${name}" is not an allowed supporting file type.`));
    } else {
      return cb(new Error('Unexpected file field.'));
    }
    cb(null, true);
  },
}).fields([
  { name: 'officialDocument', maxCount: 1 },
  { name: 'supportingFiles', maxCount: RECORD_MAX_SUPPORTING },
]);

// Turns multer failures into the same { success, message } shape the form expects.
function recordUpload(req, res, next) {
  recordMulter(req, res, (err) => {
    if (!err) return next();
    let message = err.message || 'File upload failed.';
    if (err.code === 'LIMIT_FILE_SIZE') message = 'Each file must be 10 MB or smaller.';
    else if (err.code === 'LIMIT_FILE_COUNT' || err.code === 'LIMIT_UNEXPECTED_FILE') {
      message = `Attach one official PDF and up to ${RECORD_MAX_SUPPORTING} supporting files.`;
    }
    return res.status(400).json({ success: false, message });
  });
}

function stripHtmlToText(html) {
  return String(html || '')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&[a-z0-9#]+;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// Keeps the extension, drops anything that is not a safe filename character.
function safeFileName(name) {
  const clean = String(name || 'file').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
  return (clean || 'file').slice(-100);
}

function uploadRecordFile(file, folder, publicId) {
  return new Promise((resolve, reject) => {
    const opts = { folder, resource_type: 'auto' };
    if (publicId) opts.public_id = publicId;
    const stream = cloudinary.uploader.upload_stream(opts, (err, result) => (err ? reject(err) : resolve(result)));
    Readable.from(file.buffer).pipe(stream);
  });
}

async function removeUploadedRecordFiles(uploaded) {
  await Promise.all(uploaded.map(u =>
    cloudinary.uploader.destroy(u.public_id, { resource_type: u.resource_type || 'image' })
      .catch(err => console.error('[add-record] cleanup failed for', u.public_id, err.message))
  ));
}

async function handleAddRecord(req, res) {
  const uploaded = [];   // everything sent to Cloudinary, so it can be undone
  let client = null;
  try {
    const { user_id: userId, role } = req.user;
    const projectId = req.body.projectId;
    const title = String(req.body.title || '').trim();
    const description = String(req.body.description || '').trim();
    const officialFile = req.files?.officialDocument?.[0] || null;
    const supportingFiles = req.files?.supportingFiles || [];
    // The attachment arrives pre-converted-to-PDF (and pre-stamped, if the user
    // chose to stamp) from the client. clientStamped is a claim we verify below.
    const clientStamped = req.body.applyStamp === 'true' || req.body.clientStamped === 'true';   // the SERVER draws the stamp
    const stampType = 'STAMPED';
    const stampPageRaw = req.body.stampPage;
    const stampPage = stampPageRaw === 'append' ? 'append' : Number.parseInt(stampPageRaw, 10);
    const stampX = Number.parseFloat(req.body.stampX);
    const stampY = Number.parseFloat(req.body.stampY);
    const fail = (status, message) => res.status(status).json({ success: false, message });
    console.log('[add-record] 📝 Request:', { userId, role, clientStamped, stampType, stampPage, stampX, stampY });

    // ── STEP 1. Text fields (free) ───────────────────────────────────────────
    const table = resolveTable(req.body.recordType);
    if (!table) return fail(400, 'Invalid or missing recordType.');
    if (!projectId) return fail(400, 'projectId is required.');
    if (title.length < RECORD_TITLE_MIN) return fail(400, `Title must be at least ${RECORD_TITLE_MIN} characters.`);
    if (title.length > RECORD_TITLE_MAX) return fail(400, `Title must be ${RECORD_TITLE_MAX} characters or fewer.`);
    if (stripHtmlToText(description).length < RECORD_TEXT_MIN) return fail(400, `Content must be at least ${RECORD_TEXT_MIN} characters.`);
    if (description.length > RECORD_HTML_MAX) return fail(400, 'The description is too long.');
    // Notices are never added on their own: they are issued with a decision.
    if (req.body.noticeTiedId || (req.body.recordKind && req.body.recordKind !== 'new')) {
      return fail(400, 'Notices are issued together with a decision, using the review and sign form.');
    }
    const revisionOfId = req.body.revisionOfId ? Number(req.body.revisionOfId) : null;
    if (req.body.revisionOfId && !Number.isInteger(revisionOfId)) return fail(400, 'Invalid revision reference.');

    // ── STEP 2. Project membership (one small query) ─────────────────────────
    const memberCheck = await pool.query(
      `SELECT 1 FROM assignments_view WHERE project_id = $1 AND role_id = $2 AND role = $3
       UNION ALL SELECT 1 FROM projects WHERE id = $1 AND client_id = $2 AND $3 = 'Client'
       LIMIT 1`,
      [projectId, userId, role]
    );
    if (!memberCheck.rows.length) return fail(403, 'You are not assigned to this project.');

    // ── STEP 3. Required signers from the next review side ───────────────────
    const uploaderSide = getSide(role);
    if (!uploaderSide) return fail(403, 'Only a side leader can add a record that goes through review.');
    const stage1 = FLOW_STEP_MAP[uploaderSide][0];
    const plan = await validateSignerPlan(projectId, stage1.side, req.body.signers);
    if (plan.error) return fail(400, plan.error);

    // ── STEP 4. Resubmission: the rejected record and its open queries ───────
    let parent = null;
    let openQueries = [];
    const responses = new Map();
    if (revisionOfId) {
      const { rows } = await pool.query(
        `SELECT id, title, role, status, superseded_by_id, revision_no FROM ${table} WHERE id=$1 AND project_id=$2`,
        [revisionOfId, projectId]
      );
      parent = rows[0];
      if (!parent) return fail(400, 'The record you are resubmitting no longer exists.');
      if (parent.status !== 'rejected') return fail(409, 'Only a rejected record can be resubmitted.');
      if (parent.superseded_by_id) return fail(409, 'This record already has a newer revision.');
      if (getSide(parent.role) !== uploaderSide) return fail(403, 'Only the side that added the record can resubmit it.');
      const { rows: q } = await pool.query(
        `SELECT id, seq FROM record_queries WHERE record_table=$1 AND record_id=$2 AND status IN ('open','reopened') ORDER BY seq`,
        [table, revisionOfId]
      );
      openQueries = q;
      let list = [];
      try { list = JSON.parse(req.body.queryResponses || '[]'); } catch { return fail(400, 'The query answers are not valid.'); }
      for (const item of Array.isArray(list) ? list : []) responses.set(Number(item?.id), String(item?.response || '').trim());
      const missing = openQueries.filter(oq => (responses.get(oq.id) || '').length < 3);
      if (missing.length) return fail(400, `Answer every query before resubmitting (${missing.length} still need an answer).`);
    }

    // ── STEP 5. Stamp claim (database + metadata) ────────────────────────────
    let signerProfile = null, stampId = null, stampTz = null;   // the server owns the stamp; the browser only sends where to put it
    if (clientStamped) {
      if (!isDecisionMaker(role)) return fail(403, 'Only decision makers can stamp documents.');
      signerProfile = await loadSignerProfile(projectId, role, userId);
      if (!signerProfile) return fail(400, 'No stamp profile found. Set up your stamp first.');
      if ((stampPage !== 'append' && (!Number.isInteger(stampPage) || stampPage < 1)) || !Number.isFinite(stampX) || !Number.isFinite(stampY) || stampX < 0 || stampX > 1 || stampY < 0 || stampY > 1) {
        return fail(400, 'Invalid stamp placement metadata supplied.');
      }
    }

    // ── STEP 6. Files, checked in memory (still nothing permanent) ───────────
    if (!officialFile) return fail(400, 'An official PDF document is required.');
    if (!/\.pdf$/i.test(officialFile.originalname || '') || officialFile.buffer.subarray(0, 5).toString('latin1') !== '%PDF-') {
      return fail(400, 'The official document must be a PDF.');
    }
    try {
      const pdfDoc = await PDFDocument.load(officialFile.buffer);   // parsed once
      if (!pdfDoc.getPageCount()) return fail(400, 'The official PDF has no pages.');
    } catch (parseErr) {
      console.error('[add-record] PDF parse failed:', parseErr.message);
      return fail(400, clientStamped ? 'The stamped PDF could not be verified as a valid PDF.' : 'The official document is not a valid PDF.');
    }
    // The server draws the stamp: signed identity comes from the database, never from the browser.
    if (clientStamped) {
      try {
        stampTz = await loadProjectTz(projectId);
        const origHash = crypto.createHash('sha256').update(officialFile.buffer).digest('hex');
        stampId = deriveStampId({ k: 'record', p: projectId, u: userId, r: role, ts: Date.now(), h: origHash, n: crypto.randomBytes(4).toString('hex') });
        const spec = stampSpecFromProfile(signerProfile, { label: 'SIGNED', signedAt: new Date(), tz: stampTz, stampId, baseUrl: publicBaseUrl(req) });
        const stamped = await stampPdfBuffer(officialFile.buffer, spec, { page: stampPage, x: stampX, y: stampY });
        officialFile.buffer = stamped.bytes;
        officialFile.size = stamped.bytes.length;
      } catch (stampErr) {
        console.error('[add-record] stamping failed:', stampErr);
        return fail(500, 'The stamp could not be added to the PDF. Check that the PDF is readable and try again.');
      }
    }
    const fileHash = crypto.createHash('sha256').update(officialFile.buffer).digest('hex');

    // ── STEP 7. Upload (first permanent action, tracked for cleanup) ─────────
    let filePath, attachmentId;
    const supportingFileRows = [];
    try {
      const official = await uploadRecordFile(officialFile, 'oneproject/records', `${Date.now()}-${safeFileName(officialFile.originalname)}`);
      uploaded.push({ public_id: official.public_id, resource_type: official.resource_type });
      filePath = official.secure_url;
      attachmentId = official.public_id;
      const settled = await Promise.allSettled(supportingFiles.map(f => uploadRecordFile(f, 'oneproject/record-supporting')));
      settled.forEach((s, i) => {
        if (s.status !== 'fulfilled') return;
        uploaded.push({ public_id: s.value.public_id, resource_type: s.value.resource_type });
        supportingFileRows.push({
          name: supportingFiles[i].originalname, mime: supportingFiles[i].mimetype, size: supportingFiles[i].size,
          url: s.value.secure_url, public_id: s.value.public_id,
        });
      });
      if (settled.some(s => s.status === 'rejected')) throw new Error('A supporting file failed to upload.');
      console.log('[add-record] ✅ Official PDF and supporting files uploaded');
    } catch (uploadErr) {
      console.error('[add-record] ❌ Cloudinary upload error:', uploadErr);
      await removeUploadedRecordFiles(uploaded);
      return fail(500, 'File upload failed. Please try again.');
    }

    // ── STEP 8. One transaction: record, named signers, revision link ────────
    const stampApplied = clientStamped;
    const signedByUserId = stampApplied ? userId : null;
    const signedByRole = stampApplied ? role : null;
    const revisionNo = parent ? (Number(parent.revision_no) || 0) + 1 : 0;
    let recordId;
    try {
      client = await pool.connect();
      await client.query('BEGIN');
      const recRes = await client.query(
        `INSERT INTO ${table} (
          project_id, title, description, file_path, attachment_id,
          uploaded_by, role, record_kind, notice_tied_id,
          signed_by_id, signed_by_role, signed_at, stamp_type, stamp_status,
          supporting_files, signature_hash, revision_of_id, revision_no
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'new', NULL, $8, $9, ${signedByUserId ? 'NOW()' : 'NULL'}, $10, $11, $12, $13, $14, $15)
        RETURNING id`,
        [
          projectId, title, description, filePath, attachmentId,
          userId, role, signedByUserId, signedByRole, stampApplied ? stampType : null, stampApplied ? 'recorder' : 'none',
          JSON.stringify(supportingFileRows), fileHash, parent ? parent.id : null, revisionNo,
        ]
      );
      recordId = recRes.rows[0].id;
      if (stampApplied && stampId) {
        await registerStamp(client, { stampId, projectId: Number(projectId), table, recordId, kind: 'record_upload', userId, role,
          name: signerProfile.name, position: signerProfile.position, company: signerProfile.company, label: 'SIGNED', tz: stampTz, fileHash, signedAt: new Date() });
      }
      await insertSignerRows(client, { table, recordId, projectId: Number(projectId), stage: 1, side: stage1.side, signers: plan.signers });
      if (parent) {
        const upd = await client.query(`UPDATE ${table} SET superseded_by_id=$1 WHERE id=$2 AND superseded_by_id IS NULL`, [recordId, parent.id]);
        if (!upd.rowCount) throw new Error('REVISION_RACE');
        for (const oq of openQueries) {
          await client.query(
            `UPDATE record_queries SET response=$1, status='answered', responded_at=NOW(),
                    responded_in_record_id=$2, responded_by_role=$3, responded_by_id=$4 WHERE id=$5`,
            [responses.get(oq.id), recordId, role, userId, oq.id]
          );
        }
      }
      await client.query('COMMIT');
      console.log('[add-record] ✅ Record inserted into DB:', recordId);
    } catch (dbErr) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      console.error('[add-record] ❌ Database error:', dbErr);
      await removeUploadedRecordFiles(uploaded);   // undo the uploads
      if (dbErr.message === 'REVISION_RACE') return fail(409, 'This record already has a newer revision.');
      return fail(500, 'Server error saving record.');
    } finally { if (client) { client.release(); client = null; } }

    // ── STEP 9. Notifications (non-fatal, never block the saved record) ──────
    const whole = parent
      ? `Revision ${revisionNo} of record #${parent.id} added by ${role}: "${title}" (${openQueries.length} ${openQueries.length === 1 ? 'query' : 'queries'} answered)`
      : `New record added by ${role}: "${title}"`;
    const projectRecipients = await getProjectRecipientKeys(projectId, userId, role).catch(() => []);
    const notificationId = await notifyRecordUsers({ email: Boolean(parent), emailSubject: 'Revision submitted', projectId, recordId, table, message: whole, actorId: userId, actorRole: role, recipients: projectRecipients });
    await notifyRecordUsers({ email: true, emailSubject: 'Action needed: review and sign',
      projectId, recordId, table, actorId: userId, actorRole: role,
      message: `You are named to review and sign "${title}" (${stage1.label}).`,
      recipients: plan.signers.map(s => flowKey(s.role, s.user_id)),
    });

    return res.json({
      success: true,
      message: parent ? `Revision ${revisionNo} submitted.` : 'Record saved.',
      recordId, notificationId, attachmentId, recordKind: 'new', revisionNo, stamped: stampApplied,
    });
  } catch (err) {
    console.error('[add-record] ❌ Route error:', err);
    if (client) { await client.query('ROLLBACK').catch(() => {}); client.release(); }
    await removeUploadedRecordFiles(uploaded);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
}

app.post('/api/add-record', authenticateToken, recordUpload, requireProjectLifecycleWrite, handleAddRecord);
app.post('/records',        authenticateToken, recordUpload, requireProjectLifecycleWrite, handleAddRecord);

// ── Decisions: one multer for the notice PDF and supporting files ────────────
const decisionMulter = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: RECORD_MAX_FILE_BYTES, files: 1 + RECORD_MAX_SUPPORTING },
  fileFilter: (_req, file, cb) => {
    const name = file.originalname || '';
    if (file.fieldname === 'noticePdf') {
      if (!/\.pdf$/i.test(name)) return cb(new Error('Your notice must be a PDF.'));
    } else if (file.fieldname === 'supportingFiles') {
      if (!RECORD_SUPPORTING_EXT.test(name)) return cb(new Error(`"${name}" is not an allowed supporting file type.`));
    } else return cb(new Error('Unexpected file field.'));
    cb(null, true);
  },
}).fields([{ name: 'noticePdf', maxCount: 1 }, { name: 'supportingFiles', maxCount: RECORD_MAX_SUPPORTING }]);

function decisionUpload(req, res, next) {
  decisionMulter(req, res, (err) => {
    if (!err) return next();
    let message = err.message || 'File upload failed.';
    if (err.code === 'LIMIT_FILE_SIZE') message = 'Each file must be 10 MB or smaller.';
    else if (err.code === 'LIMIT_FILE_COUNT' || err.code === 'LIMIT_UNEXPECTED_FILE') message = `Attach one notice PDF and up to ${RECORD_MAX_SUPPORTING} supporting files.`;
    return res.status(400).json({ success: false, message });
  });
}

function parseQueryList(raw) {
  let list = raw;
  if (typeof list === 'string') {
    try { list = JSON.parse(list || '[]'); } catch { return { error: 'The query list is not valid.' }; }
  }
  if (!Array.isArray(list)) return { queries: [] };
  const out = [];
  for (const item of list) {
    const query = String(item?.query || '').trim();
    if (!query) continue;
    out.push({
      ref: String(item?.ref || '').trim().slice(0, 120),
      query: query.slice(0, 1500),
      required_action: String(item?.required_action || '').trim().slice(0, 1000),
      by: String(item?.by || '').trim().slice(0, 120),
    });
  }
  if (out.length > FLOW_MAX_QUERIES) return { error: `At most ${FLOW_MAX_QUERIES} queries per notice.` };
  return { queries: out };
}

function flowEscape(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ── Who can be named ─────────────────────────────────────────────────────────
app.get('/api/signer-candidates', authenticateToken, async (req, res) => {
  const projectId = Number(req.query.projectId);
  const stage = Number(req.query.stage || 1);
  if (!Number.isInteger(projectId)) return res.status(400).json({ error: 'projectId is required.' });
  try {
    if (!await userHasProjectAccess(req.user.user_id, req.user.role, projectId)) return res.status(403).json({ error: 'Access denied to this project.' });
    let uploaderSide = getSide(req.user.role);
    const table = resolveTable(req.query.recordType);
    if (table && req.query.recordId) {
      const { rows } = await pool.query(`SELECT role FROM ${table} WHERE id=$1 AND project_id=$2`, [Number(req.query.recordId), projectId]);
      if (rows.length) uploaderSide = getSide(rows[0].role);
    }
    if (!uploaderSide) return res.status(400).json({ error: 'Signers can only be chosen for records added by a side leader.' });
    const step = FLOW_STEP_MAP[uploaderSide][stage - 1];
    if (!step) return res.json({ side: null, stage, label: null, candidates: [] });
    res.json({ side: step.side, stage, label: step.label, candidates: await getSignerCandidates(projectId, step.side) });
  } catch (err) {
    console.error('[signer-candidates]', err);
    res.status(500).json({ error: 'Failed to load signers.' });
  }
});

// ── Everything a decision needs, checked before anything is uploaded ────────
async function prepareDecision(req, { preview }) {
  const fail = (status, message) => ({ fail: { status, message } });
  const { user_id: userId, role } = req.user;
  const projectId = Number(req.body.projectId);
  const recordId = Number(req.body.recordId);
  const table = resolveTable(req.body.recordType);
  if (!table) return fail(400, 'Invalid or missing recordType.');
  if (!Number.isInteger(projectId) || !Number.isInteger(recordId)) return fail(400, 'projectId and recordId are required.');
  const decision = req.body.decision;
  if (!FLOW_NOTICE_KIND[decision]) return fail(400, 'Choose approve, accept or reject.');
  const source = req.body.noticeSource === 'uploaded' ? 'uploaded' : 'generated';
  const title = String(req.body.title || '').trim();
  const bodyInput = String(req.body.body || '').trim();
  const body = looksLikeHtml(bodyInput) ? sanitizeLetterHtml(bodyInput) : bodyInput;
  const bodyPlain = looksLikeHtml(body) ? letterHtmlToPlain(body) : body;
  if (title.length < RECORD_TITLE_MIN || title.length > RECORD_TITLE_MAX) return fail(400, `The notice title must be ${RECORD_TITLE_MIN} to ${RECORD_TITLE_MAX} characters.`);
  if (body.length > 60000) return fail(400, 'The notice text is too long.');
  if (source === 'generated' && bodyPlain.length < RECORD_TEXT_MIN) return fail(400, `Write the notice text (at least ${RECORD_TEXT_MIN} characters).`);
  const respondBy = /^\d{4}-\d{2}-\d{2}$/.test(String(req.body.respondBy || '')) ? req.body.respondBy : null;
  const parsedQueries = parseQueryList(req.body.queries);
  if (parsedQueries.error) return fail(400, parsedQueries.error);
  const queries = decision === 'rejected' ? parsedQueries.queries : [];
  if (decision === 'rejected' && !queries.length) return fail(400, 'A rejection needs at least one query, with its reference and the action required.');
  if (!isDecisionMaker(role)) return fail(403, 'Only decision makers can issue a decision.');
  if (!await userHasProjectAccess(userId, role, projectId)) return fail(403, 'You are not assigned to this project.');

  const state = await getRecordFlowState(table, projectId, recordId);
  if (!state) return fail(404, 'Record not found. It may have been deleted.');
  if (!state.steps) return fail(400, 'This record has no review chain.');
  if (state.rec.notice_tied_id) return fail(400, 'A notice is final and cannot be decided again.');
  if (state.isLocked) return fail(409, 'This record is already closed.');
  const stage = state.stage;
  const step = state.steps[stage - 1];
  if (getSide(role) !== step.side) return fail(403, `This stage is decided by the ${flowSideLabel(step.side)} side.`);
  if (decision !== 'rejected' && decision !== step.action) return fail(400, `This stage ends with: ${step.action}.`);

  const { rows: planRows } = await pool.query(
    `SELECT * FROM record_signers WHERE record_table=$1 AND record_id=$2 AND stage=$3 AND status <> 'replaced' ORDER BY order_no, id`,
    [table, recordId, stage]
  );
  let deciderRow = null;
  if (planRows.length) {
    deciderRow = planRows.find(r => r.is_decider) || null;
    if (!deciderRow || deciderRow.signer_role !== role || Number(deciderRow.signer_user_id) !== Number(userId)) {
      return fail(403, 'You are not the deciding signer named for this stage.');
    }
    const waiting = planRows.filter(r => !r.is_decider && r.status !== 'signed');
    if (waiting.length) return fail(409, `Waiting for ${waiting.map(w => w.signer_position || flowRoleLabel(w.signer_role)).join(', ')} to sign first.`);
    const objecting = planRows.filter(r => !r.is_decider && r.status === 'signed' && r.outcome === 'queries');
    if (decision !== 'rejected') {
      const { rows: unresolved } = await pool.query(
        `SELECT seq FROM record_queries WHERE record_table=$1 AND responded_in_record_id=$2 AND issuer_side=$3 AND status <> 'resolved' ORDER BY seq`,
        [table, recordId, step.side]
      );
      if (unresolved.length) {
        return fail(409, `You cannot ${decision === 'accepted' ? 'accept' : 'approve'} while ${unresolved.length === 1 ? 'an answered query is' : unresolved.length + ' answered queries are'} still unresolved (${unresolved.map(u => 'no. ' + u.seq).join(', ')}). Mark each as Resolved, or Reopen it, then decide.`);
      }
    }
    if (decision !== 'rejected' && objecting.length) {
      return fail(409, `You cannot ${decision === 'accepted' ? 'accept' : 'approve'} while queries from ${objecting.map(o => o.signer_position || flowRoleLabel(o.signer_role)).join(', ')} are open. They must clear them by signing again with "No queries", or you can reject this record. If they have left the project, replace them.`);
    }
  }

  const setupProblem = await explainMissingSignerSetup(projectId, role, userId, true);
  if (setupProblem) return fail(400, setupProblem);
  const profile = await loadSignerProfile(projectId, role, userId);
  if (!profile) return fail(400, 'Your signature could not be loaded. Save it again in your Signature & Stamp setup and retry.');

  let nextPlan = null;
  if (decision === 'approved' && state.steps[stage]) {
    const nextStep = state.steps[stage];
    if (req.body.nextSigners || !preview) {
      const r = await validateSignerPlan(projectId, nextStep.side, req.body.nextSigners);
      if (r.error) return fail(400, r.error);
      nextPlan = { side: nextStep.side, stage: stage + 1, signers: r.signers };
    }
  }

  const noticeFile = req.files?.noticePdf?.[0] || null;
  const supportingFiles = req.files?.supportingFiles || [];
  if (source === 'uploaded') {
    if (!noticeFile) return fail(400, 'Attach your notice as a PDF, or use the system letter.');
    if (!/\.pdf$/i.test(noticeFile.originalname || '') || noticeFile.buffer.subarray(0, 5).toString('latin1') !== '%PDF-') return fail(400, 'Your notice must be a valid PDF.');
    try { await PDFDocument.load(noticeFile.buffer); } catch { return fail(400, 'Your notice PDF could not be read.'); }
  }

  const issuedAt = new Date();
  const stageRows = planRows.length ? planRows : [{
    signer_role: role, signer_user_id: userId, signer_position: profile.position, side: step.side,
    is_team_member: false, is_decider: true, status: 'pending', order_no: 1,
  }];
  const slots = [];
  for (const r of stageRows) {
    const isMe = Boolean(r.is_decider);
    const p = isMe ? profile : (r.status === 'signed' ? await loadSignerProfile(projectId, r.signer_role, r.signer_user_id) : null);
    slots.push({
      isDecider: Boolean(r.is_decider),
      caption: r.is_decider ? 'Decision by' : (r.is_team_member ? 'Checked by (team)' : 'Co-signed by'),
      position: r.signer_position, side: r.side,
      status: isMe ? (preview ? 'pending' : 'signed') : (r.status === 'signed' && p ? 'signed' : 'pending'),
      pendingLabel: isMe && preview ? 'Signs when issued' : 'Awaiting signature',
      profile: p, signed_at: isMe ? issuedAt : r.signed_at,
      userId: isMe ? userId : r.signer_user_id, role: isMe ? role : r.signer_role,
    });
  }

  const fingerprint = state.rec.signature_hash || await hashRemoteFile(state.rec.file_path);
  const { rows: pr } = await pool.query('SELECT name, contract_reference FROM projects WHERE id=$1', [projectId]);
  const kind = FLOW_NOTICE_KIND[decision];
  const deciderSlot = slots.find(sl => sl.isDecider);
  const issuerLabel = `${deciderSlot?.profile?.position || flowRoleLabel(role)}, ${flowSideLabel(step.side)} side`;
  for (const q of queries) if (!q.by) q.by = issuerLabel;   // every query says who raised it
  const [toName, toCompany] = await Promise.all([
    resolveDisplayNameFor(state.rec.role, state.rec.uploaded_by, projectId).catch(() => null),
    resolveCompanyNameForStamp(projectId, state.rec.uploaded_by, state.rec.role).catch(() => null),
  ]);
  const joinParts = (...a) => a.filter(Boolean).join(', ');
  const ccList = slots.filter(sl => !sl.isDecider).map(sl => sl.position || sl.profile?.position).filter(Boolean);
  const ctx = {
    tz: await loadProjectTz(projectId), projectName: pr[0]?.name || '', contractRef: pr[0]?.contract_reference || '',
    recordRef: flowRecordRef(table, state.rec),
    toLine: joinParts(toName, flowRoleLabel(state.rec.role), toCompany),
    fromLine: joinParts(deciderSlot?.profile?.name, issuerLabel, deciderSlot?.profile?.company),
    ccLine: ccList.join('; '),
    rec: state.rec, categoryLabel: FLOW_TABLE_LABELS[table],
    issuerRole: role, issuerSide: step.side, issuedAt, respondBy, title, body,
    table, projectId, preview, baseUrl: publicBaseUrl(req),
    kindTitle: FLOW_NOTICE_TITLE[kind], decisionWord: FLOW_DECISION_WORD[decision], fingerprint,
  };
  const noticeSlots = slots.filter(sl => sl.isDecider);   // the notice carries the leader's signature and stamp only
  const noticeBytes = await composeNoticePdf({ source, uploadedBytes: noticeFile?.buffer, ctx, queries, slots: noticeSlots });
  let recordBytes = null, recordStampPlacement = null;
  let placementIn = null;   // where the approver chose to stamp the record (optional)
  if (decision !== 'rejected' && req.body.stampPlacement) {
    try {
      const sp = JSON.parse(String(req.body.stampPlacement));
      const pg = parseInt(sp.page, 10), px = Number(sp.x), py = Number(sp.y);
      if (pg >= 1 && px >= 0 && px <= 1 && py >= 0 && py <= 1) placementIn = { page: pg, x: px, y: py };
    } catch (_) { /* ignore a malformed placement: the sign-off page still carries the signatures */ }
  }
  if (decision !== 'rejected') {
    try {
      const built = await buildRecordWithSignoff({
        stage, placementIn, rec: state.rec, ctx, slots, stageLabel: step.label,
        decisionLine: `Decision: ${ctx.decisionWord}, ${flowFormatDate(issuedAt, ctx.tz)}. The signed notice is attached to this record.`,
      });
      recordBytes = built.bytes; recordStampPlacement = built.placement;
    } catch (stampErr) {
      console.error('[prepareDecision] record sign-off failed:', stampErr);
      return fail(502, 'The record file could not be opened to add the sign-off page, so nothing was issued. Check that the record PDF is readable and try again.');
    }
  }
  return { data: { tz: ctx.tz, recordBytes, recordStampPlacement, table, projectId, recordId, state, stage, step, decision, kind, source, title, body, respondBy, queries, planRows, deciderRow, nextPlan, noticeBytes, supportingFiles, ctx, profile, issuedAt } };
}

// Does this user have a signature or stamp saved for the record's project? The database answers, using the
// project of the record itself (not whatever project the browser thinks is active).
app.get('/api/signing-readiness', authenticateToken, async (req, res) => {
  const { user_id: userId, role } = req.user;
  try {
    let projectId = parseInt(req.query.projectId, 10);
    const recordId = parseInt(req.query.recordId, 10);
    const table = req.query.recordType ? resolveTable(req.query.recordType) : null;
    if (table && recordId) {
      const { rows } = await pool.query(`SELECT project_id FROM ${table} WHERE id=$1`, [recordId]);
      if (!rows[0]) return res.status(404).json({ error: 'Record not found.' });
      projectId = rows[0].project_id;
    }
    if (!projectId) return res.status(400).json({ error: 'projectId or recordId required' });
    if (!await userHasProjectAccess(userId, role, projectId)) return res.status(403).json({ error: 'You are not a member of this project.' });
    const problem = await explainMissingSignerSetup(projectId, role, userId, String(req.query.mode) !== 'review');
    res.json({ ready: !problem, message: problem });
  } catch (err) {
    console.error('GET signing-readiness:', err);
    res.status(500).json({ error: 'Could not check your signature setup.' });
  }
});

app.post('/api/decision-preview', authenticateToken, decisionUpload, async (req, res) => {
  try {
    const r = await prepareDecision(req, { preview: true });
    if (r.fail) return res.status(r.fail.status).json({ success: false, message: r.fail.message });
    const d = r.data;
    const bundle = await buildDecisionBundle({ rec: d.state.rec, noticeBytes: d.noticeBytes, noticeLabel: FLOW_NOTICE_TITLE[d.kind].split(' (')[0], recordBytes: d.recordBytes, tz: d.tz });
    res.set('Content-Type', 'application/pdf');
    res.set('Content-Disposition', 'inline; filename="decision-preview.pdf"');
    return res.send(bundle);
  } catch (err) {
    console.error('[decision-preview]', err);
    return res.status(500).json({ success: false, message: 'The preview could not be built.' });
  }
});

app.post('/api/issue-decision', authenticateToken, decisionUpload, requireProjectLifecycleWrite, async (req, res) => {
  const uploaded = [];
  let client = null;
  try {
    const r = await prepareDecision(req, { preview: false });
    if (r.fail) return res.status(r.fail.status).json({ success: false, message: r.fail.message });
    const d = r.data;
    const { user_id: userId, role } = req.user;
    const fail = (status, message) => res.status(status).json({ success: false, message });

    // Upload the signed notice (permanent step, tracked for cleanup)
    const noticeHash = crypto.createHash('sha256').update(d.noticeBytes).digest('hex');
    let noticeUrl, noticeAttachmentId, stampedRecordUrl = null, stampedRecordPublicId = null, stampedRecordType = 'raw', previousSignedCopy = null;
    const supportingRows = [];
    try {
      const up = await uploadRecordFile({ buffer: d.noticeBytes }, 'oneproject/records', `${Date.now()}-notice-${d.recordId}.pdf`);
      uploaded.push({ public_id: up.public_id, resource_type: up.resource_type });
      noticeUrl = up.secure_url; noticeAttachmentId = up.public_id;
      if (d.recordBytes) {
        const upRec = await uploadRecordFile({ buffer: d.recordBytes }, 'oneproject/records', `${Date.now()}-signed-record-${d.recordId}.pdf`);
        uploaded.push({ public_id: upRec.public_id, resource_type: upRec.resource_type });
        stampedRecordUrl = upRec.secure_url; stampedRecordPublicId = upRec.public_id; stampedRecordType = upRec.resource_type;
      }
      const settled = await Promise.allSettled(d.supportingFiles.map(f => uploadRecordFile(f, 'oneproject/record-supporting')));
      settled.forEach((s, i) => {
        if (s.status !== 'fulfilled') return;
        uploaded.push({ public_id: s.value.public_id, resource_type: s.value.resource_type });
        supportingRows.push({ name: d.supportingFiles[i].originalname, mime: d.supportingFiles[i].mimetype, size: d.supportingFiles[i].size, url: s.value.secure_url, public_id: s.value.public_id });
      });
      if (settled.some(s => s.status === 'rejected')) throw new Error('A supporting file failed to upload.');
    } catch (uploadErr) {
      console.error('[issue-decision] upload failed:', uploadErr);
      await removeUploadedRecordFiles(uploaded);
      return fail(500, 'File upload failed. Please try again.');
    }

    // One transaction: notice, decision, signers, queries, next stage
    let noticeId;
    try {
      client = await pool.connect();
      await client.query('BEGIN');
      const lock = await client.query(`SELECT status FROM ${d.table} WHERE id=$1 AND project_id=$2 FOR UPDATE`, [d.recordId, d.projectId]);
      if (!lock.rows.length || ['rejected', 'approved_record'].includes(lock.rows[0].status)) throw Object.assign(new Error('closed'), { http: 409, publicMessage: 'This record was just closed by someone else.' });
      const dup = await client.query(
        `SELECT 1 FROM document_reviews WHERE record_type=$1 AND record_id=$2 AND reviewer_id=$3 AND reviewer_role=$4 AND action IN ('approved','accepted','rejected')`,
        [d.table, d.recordId, userId, role]
      );
      if (dup.rows.length) throw Object.assign(new Error('dup'), { http: 409, publicMessage: 'You already decided this record.' });

      const description = d.body && looksLikeHtml(d.body) ? d.body : d.body
        ? d.body.split(/\n{2,}/).map(p => `<p>${flowEscape(p).replace(/\n/g, '<br>')}</p>`).join('')
        : `<p>Notice attached as PDF.${d.queries.length ? ` ${d.queries.length} ${d.queries.length === 1 ? 'query' : 'queries'} raised.` : ''}</p>`;
      const nIns = await client.query(
        `INSERT INTO ${d.table} (
           project_id, title, description, file_path, attachment_id, uploaded_by, role, record_kind, notice_tied_id,
           signed_by_id, signed_by_role, signed_at, stamp_type, stamp_status,
           supporting_files, signature_hash, stamped_doc_url, notice_source, respond_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),'SIGNED','recorder',$12,$13,$14,$15,$16)
         RETURNING id`,
        [d.projectId, d.title, description, noticeUrl, noticeAttachmentId, userId, role, d.kind, d.recordId,
         userId, role, JSON.stringify(supportingRows), noticeHash, noticeUrl, d.source, d.respondBy]
      );
      noticeId = nIns.rows[0].id;

      // The decision, recorded the way the review chain already understands it
      const assign = await client.query(`SELECT role_email AS email, title_position AS position FROM assignments_view WHERE project_id=$1 AND role_id=$2 AND role=$3 LIMIT 1`, [d.projectId, userId, role]);
      const summary = d.decision === 'rejected' ? `${d.queries.length} ${d.queries.length === 1 ? 'query' : 'queries'} raised in notice #${noticeId}` : `Notice #${noticeId} issued`;
      await client.query(
        `INSERT INTO document_reviews (record_type, record_id, record_kind, reviewer_id, reviewer_role, reviewer_email, reviewer_position, action, comment)
         VALUES ($1,$2,'new',$3,$4,$5,$6,$7,$8)
         ON CONFLICT (record_type, record_id, reviewer_id, reviewer_role)
         DO UPDATE SET action=EXCLUDED.action, action_date=NOW(), comment=EXCLUDED.comment`,
        [d.table, d.recordId, userId, role, assign.rows[0]?.email || null, assign.rows[0]?.position || d.profile.position || null, d.decision, summary]
      );
      let newStatus;
      if (d.decision === 'rejected') newStatus = 'rejected';
      else if (d.decision === 'accepted') newStatus = 'approved_record';
      else newStatus = { contractor: 'pending_client_acceptance', consultant: 'pending_contractor_acceptance', client: 'pending_contractor_acceptance' }[d.state.uploaderSide] || 'pending_review';
      await client.query(`UPDATE ${d.table} SET status=$1 WHERE id=$2 AND project_id=$3`, [newStatus, d.recordId, d.projectId]);
      if (stampedRecordUrl) {
        // Approval only: the record's latest copy now carries the sign-off page. The original upload (file_path) is kept.
        const cur = await client.query(`SELECT stamp_status, stamped_doc_public_id FROM ${d.table} WHERE id=$1`, [d.recordId]);
        previousSignedCopy = cur.rows[0]?.stamped_doc_public_id || null;
        await client.query(
          `UPDATE ${d.table} SET stamped_doc_url=$1, signed_by_id=$2, signed_by_role=$3, signed_at=NOW(), stamp_type='STAMPED', stamp_status=$4,
                stamp_page=$5, stamp_x=$6, stamp_y=$7, stamped_doc_public_id=$10 WHERE id=$8 AND project_id=$9`,
          [stampedRecordUrl, userId, role, getStampStatusFromActor(cur.rows[0]?.stamp_status, 'approver'),
           d.recordStampPlacement?.page ?? null, d.recordStampPlacement?.x ?? null, d.recordStampPlacement?.y ?? null, d.recordId, d.projectId, stampedRecordPublicId]
        );
      }

      // Signers of this stage: tie them to the notice; record the decider's signature
      if (d.deciderRow) {
        await client.query(`UPDATE record_signers SET status='signed', outcome=$1, signed_at=NOW(), notice_id=$2, first_viewed_at=COALESCE(first_viewed_at, NOW()) WHERE id=$3`, [d.decision, noticeId, d.deciderRow.id]);
        await client.query(`UPDATE record_signers SET notice_id=$1 WHERE record_table=$2 AND record_id=$3 AND stage=$4 AND status='signed' AND notice_id IS NULL`, [noticeId, d.table, d.recordId, d.stage]);
      } else {
        await client.query(
          `INSERT INTO record_signers (record_table, record_id, project_id, stage, side, signer_role, signer_user_id, signer_position, is_team_member, is_decider, order_no, status, outcome, signed_at, notice_id, first_viewed_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,FALSE,TRUE,1,'signed',$9,NOW(),$10,NOW())`,
          [d.table, d.recordId, d.projectId, d.stage, d.step.side, role, userId, d.profile.position, d.decision, noticeId]
        );
      }
      for (let i = 0; i < d.queries.length; i++) {
        const q = d.queries[i];
        await client.query(
          `INSERT INTO record_queries (record_table, record_id, notice_id, project_id, seq, ref, query, required_action, issuer_role, issuer_side, raised_by)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
          [d.table, d.recordId, noticeId, d.projectId, i + 1, q.ref, q.query, q.required_action, role, d.step.side, q.by || null]
        );
      }
      if (d.nextPlan) await insertSignerRows(client, { table: d.table, recordId: d.recordId, projectId: d.projectId, stage: d.nextPlan.stage, side: d.nextPlan.side, signers: d.nextPlan.signers });
      await client.query('COMMIT');
    } catch (dbErr) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      console.error('[issue-decision] database error:', dbErr);
      await removeUploadedRecordFiles(uploaded);
      if (dbErr.http) return fail(dbErr.http, dbErr.publicMessage);
      return fail(500, 'The decision could not be saved. Nothing was changed.');
    } finally { if (client) { client.release(); client = null; } }

    // The earlier signed copy of this record is superseded: remove it from storage (non-fatal)
    if (previousSignedCopy && previousSignedCopy !== stampedRecordPublicId) {
      await removeUploadedRecordFiles([{ public_id: previousSignedCopy, resource_type: stampedRecordType }]).catch(() => {});
    }

    // Notifications (non-fatal)
    const q = d.queries.length;
    const message = d.decision === 'rejected'
      ? `${role} rejected record #${d.recordId} "${d.state.rec.title}" with ${q} ${q === 1 ? 'query' : 'queries'} (notice #${noticeId})`
      : `${role} ${d.decision} record #${d.recordId} "${d.state.rec.title}" with notice #${noticeId}`;
    const recipients = await getProjectRecipientKeys(d.projectId, userId, role).catch(() => []);
    await notifyRecordUsers({ projectId: d.projectId, recordId: d.recordId, table: d.table, message, actorId: userId, actorRole: role, recipients });
    if (d.state.rec.uploaded_by && !(Number(d.state.rec.uploaded_by) === Number(userId) && normalizeRole(d.state.rec.role) === normalizeRole(role))) {
      emailFlowRecipients([flowKey(d.state.rec.role, d.state.rec.uploaded_by)], `Decision issued: ${FLOW_DECISION_WORD[d.decision]}`, message, d.projectId);   // not awaited
    }
    if (d.nextPlan) {
      await notifyRecordUsers({ email: true, emailSubject: 'Action needed: review and sign',
        projectId: d.projectId, recordId: d.recordId, table: d.table, actorId: userId, actorRole: role,
        message: `You are named to review and sign "${d.state.rec.title}" (${d.state.steps[d.stage].label}).`,
        recipients: d.nextPlan.signers.map(s => flowKey(s.role, s.user_id)),
      });
    }
    return res.json({ success: true, message: 'Decision issued and signed.', noticeId, recordStatus: d.decision === 'rejected' ? 'rejected' : d.decision === 'accepted' ? 'approved_record' : 'pending' });
  } catch (err) {
    console.error('[issue-decision] route error:', err);
    if (client) { await client.query('ROLLBACK').catch(() => {}); client.release(); }
    await removeUploadedRecordFiles(uploaded);
    return res.status(500).json({ success: false, message: 'Server error. Nothing was changed.' });
  }
});

// ── A named signer who is not the decider signs first (team member etc.) ────
app.post('/api/record-signoff', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
  const { user_id: userId, role } = req.user;
  const projectId = Number(req.body.projectId);
  const recordId = Number(req.body.recordId);
  const table = resolveTable(req.body.recordType);
  const fail = (status, message) => res.status(status).json({ success: false, message });
  if (!table || !Number.isInteger(projectId) || !Number.isInteger(recordId)) return fail(400, 'Invalid request.');
  const outcome = req.body.outcome === 'queries' ? 'queries' : req.body.outcome === 'clear' ? 'clear' : null;
  if (!outcome) return fail(400, 'Choose "No queries" or "Queries raised".');
  const note = String(req.body.note || '').trim().slice(0, 2000);
  const parsed = parseQueryList(req.body.queries);
  if (parsed.error) return fail(400, parsed.error);
  if (outcome === 'queries' && !parsed.queries.length) return fail(400, 'Add at least one query, or choose "No queries".');
  try {
    const state = await getRecordFlowState(table, projectId, recordId);
    if (!state || state.isLocked || !state.stage) return fail(409, 'This record is not waiting for signatures.');
    const { rows } = await pool.query(
      `SELECT * FROM record_signers WHERE record_table=$1 AND record_id=$2 AND stage=$3 AND signer_role=$4 AND signer_user_id=$5 AND is_decider=FALSE AND (status='pending' OR (status='signed' AND outcome='queries' AND notice_id IS NULL))`,
      [table, recordId, state.stage, role, userId]
    );
    const mine = rows[0];
    if (!mine) return fail(403, 'You are not a named signer for this stage, or your review is already final.');
    const setupProblem = await explainMissingSignerSetup(projectId, role, userId, false);
    if (setupProblem) return fail(400, setupProblem);
    const profile = await loadSignerProfile(projectId, role, userId);
    if (!profile) return fail(400, 'Your signature could not be loaded. Save it again in your Signature & Stamp setup and retry.');
    // Signing again after raising queries keeps the earlier review in the history
    const earlier = mine.status === 'signed' ? [{ outcome: mine.outcome, note: mine.findings?.note || '', queries: mine.findings?.queries || [], signed_at: mine.signed_at }] : [];
    const raisedBy = `${mine.signer_position || flowRoleLabel(role)}, ${flowSideLabel(mine.side)} side`;
    const findings = { note, queries: outcome === 'queries' ? parsed.queries.map(q => ({ ...q, by: raisedBy })) : [], history: [...(mine.findings?.history || []), ...earlier] };
    await pool.query(
      `UPDATE record_signers SET status='signed', outcome=$1, findings=$2, signed_at=NOW(), first_viewed_at=COALESCE(first_viewed_at, NOW()) WHERE id=$3`,
      [outcome, JSON.stringify(findings), mine.id]
    );
    if (role === 'TeamMember') {
      const summary = outcome === 'clear' ? 'Checked, no queries' : `${findings.queries.length} ${findings.queries.length === 1 ? 'query' : 'queries'} raised`;
      const comment = note ? `${summary}. ${note}` : summary;
      const part = await pool.query(`SELECT assigned_part FROM team_member_assignments WHERE project_id=$1 AND team_member_id=$2 LIMIT 1`, [projectId, userId]);
      const email = await pool.query(`SELECT role_email AS email, title_position AS position FROM assignments_view WHERE project_id=$1 AND role_id=$2 AND role=$3 LIMIT 1`, [projectId, userId, role]);
      await pool.query(
        `INSERT INTO document_reviews (record_type, record_id, record_kind, reviewer_id, reviewer_role, reviewer_email, reviewer_position, reviewer_assigned_part, action, comment)
         VALUES ($1,$2,'new',$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (record_type, record_id, reviewer_id, reviewer_role)
         DO UPDATE SET action=EXCLUDED.action, action_date=NOW(), comment=EXCLUDED.comment`,
        [table, recordId, userId, role, email.rows[0]?.email || null, mine.signer_position || email.rows[0]?.position || null, part.rows[0]?.assigned_part || null, outcome === 'clear' ? 'approved' : 'rejected', comment]
      );
    }
    const { rows: deciders } = await pool.query(`SELECT signer_role, signer_user_id FROM record_signers WHERE record_table=$1 AND record_id=$2 AND stage=$3 AND is_decider=TRUE AND status='pending'`, [table, recordId, state.stage]);
    await notifyRecordUsers({
      projectId, recordId, table, actorId: userId, actorRole: role,
      message: `${mine.signer_position || flowRoleLabel(role)} signed the review of "${state.rec.title}": ${outcome === 'clear' ? 'no queries' : findings.queries.length + ' queries raised'}.`,
      recipients: deciders.map(x => flowKey(x.signer_role, x.signer_user_id)),
    });
    res.json({ success: true, message: 'Your review is signed.' });
  } catch (err) {
    console.error('[record-signoff]', err);
    res.status(500).json({ success: false, message: 'Your sign-off could not be saved.' });
  }
});

// ── "Under review": only named signers count, and only while still pending ──
app.post('/api/record-view', authenticateToken, async (req, res) => {
  const { user_id: userId, role } = req.user;
  const projectId = Number(req.body.projectId);
  const recordId = Number(req.body.recordId);
  const table = resolveTable(req.body.recordType);
  if (!table || !Number.isInteger(projectId) || !Number.isInteger(recordId)) return res.status(400).json({ error: 'Invalid request.' });
  try {
    const state = await getRecordFlowState(table, projectId, recordId);
    if (!state || !state.stage) return res.json({ success: true, skipped: true });
    const { rows: prior } = await pool.query(
      `SELECT 1 FROM record_signers WHERE record_table=$1 AND record_id=$2 AND stage=$3 AND first_viewed_at IS NOT NULL LIMIT 1`,
      [table, recordId, state.stage]
    );
    const upd = await pool.query(
      `UPDATE record_signers SET first_viewed_at=COALESCE(first_viewed_at, NOW()), last_viewed_at=NOW()
       WHERE record_table=$1 AND record_id=$2 AND stage=$3 AND signer_role=$4 AND signer_user_id=$5 AND status='pending'
       RETURNING signer_position, side, first_viewed_at`,
      [table, recordId, state.stage, role, userId]
    );
    if (!upd.rowCount) return res.json({ success: true, skipped: true });
    if (!prior.length) {
      const s = upd.rows[0];
      await notifyRecordUsers({
        projectId, recordId, table, actorId: userId, actorRole: role,
        message: `Your record "${state.rec.title}" is under review. Opened by ${s.signer_position || flowRoleLabel(role)}, ${flowSideLabel(s.side)} side.`,
        recipients: [flowKey(state.rec.role, state.rec.uploaded_by)],
      });
    }
    res.json({ success: true, first_viewed_at: upd.rows[0].first_viewed_at });
  } catch (err) {
    if (err && err.code === '55000') return res.status(204).end();   // read-only project: nothing to record
    console.error('[record-view]', err);
    res.status(500).json({ error: 'Failed to record the view.' });
  }
});

// ── Reminder to the signers who have not signed yet ─────────────────────────
app.post('/api/record-remind', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
  const { user_id: userId, role } = req.user;
  const projectId = Number(req.body.projectId);
  const recordId = Number(req.body.recordId);
  const table = resolveTable(req.body.recordType);
  const fail = (status, message) => res.status(status).json({ success: false, message });
  if (!table || !Number.isInteger(projectId) || !Number.isInteger(recordId)) return fail(400, 'Invalid request.');
  try {
    const state = await getRecordFlowState(table, projectId, recordId);
    if (!state) return fail(404, 'Record not found.');
    const isUploader = String(state.rec.uploaded_by) === String(userId) && getSide(state.rec.role) === getSide(role);
    if (!isUploader && !(isDecisionMaker(role) && getSide(role) === state.uploaderSide)) return fail(403, 'Only the side that added the record can send a reminder.');
    if (!state.stage || state.isLocked) return fail(409, 'This record is not waiting on anyone.');
    const { rows } = await pool.query(
      `SELECT id, signer_role, signer_user_id FROM record_signers
       WHERE record_table=$1 AND record_id=$2 AND stage=$3 AND status='pending'
         AND (reminder_sent_at IS NULL OR reminder_sent_at < NOW() - INTERVAL '${FLOW_REMIND_COOLDOWN_HOURS} hours')`,
      [table, recordId, state.stage]
    );
    if (!rows.length) return fail(409, `A reminder was already sent in the last ${FLOW_REMIND_COOLDOWN_HOURS} hours, or nobody is waiting.`);
    await pool.query(`UPDATE record_signers SET reminder_sent_at=NOW() WHERE id = ANY($1::int[])`, [rows.map(r => r.id)]);
    await notifyRecordUsers({ email: true, emailSubject: 'Reminder: waiting for your signature',
      projectId, recordId, table, actorId: userId, actorRole: role,
      message: `Reminder: "${state.rec.title}" is waiting for your signature.`,
      recipients: rows.map(r => flowKey(r.signer_role, r.signer_user_id)),
    });
    res.json({ success: true, reminded: rows.length });
  } catch (err) {
    console.error('[record-remind]', err);
    res.status(500).json({ success: false, message: 'The reminder could not be sent.' });
  }
});

// ── The leader of that side replaces a pending signer (kept in the history) ─
app.post('/api/record-signer-replace', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
  const { user_id: userId, role } = req.user;
  const projectId = Number(req.body.projectId);
  const signerId = Number(req.body.signerId);
  const newUserId = Number(req.body.newUserId);
  const newRole = normalizeRole(req.body.newRole);
  const fail = (status, message) => res.status(status).json({ success: false, message });
  if (!Number.isInteger(projectId) || !Number.isInteger(signerId) || !Number.isInteger(newUserId) || !newRole) return fail(400, 'Invalid request.');
  let client = null;
  try {
    const { rows } = await pool.query(`SELECT * FROM record_signers WHERE id=$1 AND project_id=$2`, [signerId, projectId]);
    const row = rows[0];
    if (!row) return fail(404, 'Signer not found.');
    let replaceable = row.status === 'pending';
    if (!replaceable && row.status === 'signed' && row.outcome === 'queries' && !row.notice_id && !row.is_decider) {
      // A checker whose queries block approval can be replaced only if they left the project
      replaceable = !(await userHasProjectAccess(row.signer_user_id, row.signer_role, projectId));
      if (!replaceable) return fail(409, 'This team member is still on the project. They can clear their queries by signing again, or you can reject the record.');
    }
    if (!replaceable) return fail(409, 'Only a pending signer, or a team member who has left the project, can be replaced.');
    if (!isDecisionMaker(role) || getSide(role) !== row.side) return fail(403, 'Only a leader of the same side can replace a signer.');
    const state = await getRecordFlowState(row.record_table, projectId, row.record_id);
    if (!state || state.isLocked || state.stage !== row.stage) return fail(409, 'This signer can no longer be replaced.');
    const candidates = await getSignerCandidates(projectId, row.side);
    const cand = candidates.find(c => c.role === newRole && c.user_id === newUserId);
    if (!cand) return fail(400, `The replacement must be on the ${flowSideLabel(row.side)} side of this project.`);
    if (row.is_decider && cand.is_team_member) return fail(400, 'The deciding signer must be a leader.');
    const { rows: dupe } = await pool.query(
      `SELECT 1 FROM record_signers WHERE record_table=$1 AND record_id=$2 AND stage=$3 AND status<>'replaced' AND signer_role=$4 AND signer_user_id=$5`,
      [row.record_table, row.record_id, row.stage, cand.role, cand.user_id]
    );
    if (dupe.length) return fail(409, 'That person is already named for this stage.');
    client = await pool.connect();
    await client.query('BEGIN');
    const ins = await client.query(
      `INSERT INTO record_signers (record_table, record_id, project_id, stage, side, signer_role, signer_user_id, signer_position, is_team_member, is_decider, order_no)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
      [row.record_table, row.record_id, projectId, row.stage, row.side, cand.role, cand.user_id, cand.position, cand.is_team_member, row.is_decider, row.order_no]
    );
    await client.query(`UPDATE record_signers SET status='replaced', replaced_at=NOW(), replaced_by_user_id=$1, replaced_by_role=$2, replaced_by_signer_id=$3 WHERE id=$4`, [userId, role, ins.rows[0].id, row.id]);
    await client.query('COMMIT');
    await notifyRecordUsers({ email: true, emailSubject: 'Action needed: review and sign',
      projectId, recordId: row.record_id, table: row.record_table, actorId: userId, actorRole: role,
      message: `You are named to review and sign "${state.rec.title}" in place of ${row.signer_position || flowRoleLabel(row.signer_role)}.`,
      recipients: [flowKey(cand.role, cand.user_id)],
    });
    await notifyRecordUsers({
      projectId, recordId: row.record_id, table: row.record_table, actorId: userId, actorRole: role,
      message: `${row.signer_position || flowRoleLabel(row.signer_role)} was replaced by ${cand.position} as a signer of "${state.rec.title}".`,
      recipients: [flowKey(state.rec.role, state.rec.uploaded_by)],
    });
    res.json({ success: true, message: 'Signer replaced.' });
  } catch (err) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    console.error('[record-signer-replace]', err);
    res.status(500).json({ success: false, message: 'The signer could not be replaced.' });
  } finally { if (client) client.release(); }
});

// ── Reviewer closes or reopens an answered query ────────────────────────────
app.post('/api/query-status', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
  const { user_id: userId, role } = req.user;
  const projectId = Number(req.body.projectId);
  const queryId = Number(req.body.queryId);
  const status = req.body.status;
  const fail = (code, message) => res.status(code).json({ success: false, message });
  if (!Number.isInteger(projectId) || !Number.isInteger(queryId) || !['resolved', 'reopened'].includes(status)) return fail(400, 'Invalid request.');
  try {
    const { rows } = await pool.query(`SELECT * FROM record_queries WHERE id=$1 AND project_id=$2`, [queryId, projectId]);
    const q = rows[0];
    if (!q) return fail(404, 'Query not found.');
    if (!isDecisionMaker(role) || getSide(role) !== q.issuer_side) return fail(403, 'Only the side that raised the query can resolve or reopen it.');
    if (status === 'resolved' && q.status !== 'answered') return fail(409, 'Only an answered query can be resolved.');
    if (status === 'reopened' && !['answered', 'resolved'].includes(q.status)) return fail(409, 'Only an answered or resolved query can be reopened.');
    await pool.query(
      `UPDATE record_queries SET status=$1, resolved_at=${status === 'resolved' ? 'NOW()' : 'NULL'}, resolved_by_role=$2, resolved_by_id=$3 WHERE id=$4`,
      [status, role, userId, queryId]
    );
    if (q.responded_by_id) {
      await notifyRecordUsers({ email: status === 'reopened', emailSubject: 'Query reopened',
        projectId, recordId: q.responded_in_record_id || q.record_id, table: q.record_table, actorId: userId, actorRole: role,
        message: `Query ${q.seq} was ${status === 'resolved' ? 'resolved' : 'reopened'} by ${role}.`,
        recipients: [flowKey(q.responded_by_role, q.responded_by_id)],
      });
    }
    res.json({ success: true });
  } catch (err) {
    console.error('[query-status]', err);
    res.status(500).json({ success: false, message: 'The query could not be updated.' });
  }
});

// ── Card data: signing plan, queries, revisions, buttons ────────────────────
async function buildRecordFlowView(c) {
  const { rec, projectId, userId, userRole, userSide, userIsDM, isUploader, isLocked, isRejected, steps,
          btnState, pendingRole, approveLabel, workflowSteps, embeddedNotices, signersByRecord, queriesByRecord, allQueries, nameOf, projectTz, memberKeys, table } = c;
  const isNoticeRecord = Boolean(rec.notice_tied_id);
  const planRows = signersByRecord.get(rec.id) || [];
  const pendingIdx = workflowSteps.findIndex(s => s.status === 'pending');
  const stage = !isNoticeRecord && !isLocked && pendingIdx >= 0 ? pendingIdx + 1 : null;
  const isMe = (r) => r.signer_role === userRole && Number(r.signer_user_id) === Number(userId);

  const publicSigner = async (r) => {
  const openQueries = r.status === 'signed' && r.outcome === 'queries' && !r.notice_id && !r.is_decider;
  const sameSideLeader = Boolean(stage) && r.stage === stage && userIsDM && userSide === r.side;
  // Only leaders of the signer's own side are told that someone is no longer on the project
  const leftProject = sameSideLeader && (r.status === 'pending' || openQueries)
    ? !memberKeys.has(`${normalizeRole(r.signer_role)}:${r.signer_user_id}`) : false;
  return {
    open_queries: openQueries, left_project: leftProject,
    can_resign: Boolean(stage) && r.stage === stage && openQueries && isMe(r),
    id: r.id, position: r.signer_position || flowRoleLabel(r.signer_role), side: r.side, role: r.signer_role,
    is_team_member: r.is_team_member, is_decider: r.is_decider, order_no: r.order_no, status: r.status,
    outcome: r.outcome, signed_at: r.signed_at, first_viewed_at: r.first_viewed_at, last_viewed_at: r.last_viewed_at,
    reminder_sent_at: r.reminder_sent_at,
    // The personal name is shown to the signer's own side (signed or not); findings only after signing. The other side sees position, side and time.
    name: (userSide === r.side || isMe(r)) ? await nameOf(r.signer_role, r.signer_user_id) : null,
    queries_raised: Array.isArray(r.findings?.queries) ? r.findings.queries.length : 0,
    user_id: r.signer_user_id,
    findings: (r.status === 'signed' && (userSide === r.side || isMe(r))) ? { note: r.findings?.note || '', queries: Array.isArray(r.findings?.queries) ? r.findings.queries : [] } : null,
    is_me: isMe(r),
    can_replace: sameSideLeader && (r.status === 'pending' || (openQueries && leftProject)),
  };
  };

  const stages = [];
  for (const st of [1, 2]) {
    const rows = planRows.filter(r => r.stage === st);
    if (!rows.length) continue;
    const active = rows.filter(r => r.status !== 'replaced');
    stages.push({
      stage: st, side: rows[0].side, label: steps?.[st - 1]?.label || null,
      signed_count: active.filter(r => r.status === 'signed').length, total: active.length,
      signers: await Promise.all(active.map(publicSigner)),
      replaced: rows.filter(r => r.status === 'replaced').map(r => ({
        position: r.signer_position || flowRoleLabel(r.signer_role), replaced_at: r.replaced_at, replaced_by_role: r.replaced_by_role,
      })),
    });
  }

  const stageRows = planRows.filter(r => r.stage === stage && r.status !== 'replaced');
  let btn = btnState, pend = pendingRole, label = approveLabel;
  if (isNoticeRecord) btn = 'notice_final';
  else if (!isUploader && stage && stageRows.length) {
    const me = stageRows.find(isMe);
    if (me && me.status === 'pending') {
      if (me.is_decider) {
        const waiting = stageRows.filter(r => !r.is_decider && r.status !== 'signed');
        const objecting = stageRows.filter(r => !r.is_decider && r.status === 'signed' && r.outcome === 'queries' && !r.notice_id);
        if (waiting.length) { btn = 'awaiting_signers'; pend = waiting.map(w => w.signer_position || flowRoleLabel(w.signer_role)).join(', '); }
        else if (objecting.length) { btn = 'queries_open'; pend = objecting.map(o => o.signer_position || flowRoleLabel(o.signer_role)).join(', '); }
        else { btn = 'can_approve'; label = steps[stage - 1].action === 'accepted' ? 'Accept' : 'Approve'; }
      } else btn = 'sign_review';
    } else if (me && me.status === 'signed' && me.outcome === 'queries' && !me.notice_id && !me.is_decider) btn = 'sign_review_again';
    else if (me && me.status === 'signed') btn = 'signed_waiting';
    else if (userIsDM && userSide === steps[stage - 1].side) btn = 'not_named';
    else if (!userIsDM && userSide === steps[stage - 1].side) btn = 'not_named_comment';   // unnamed team members can only comment
  }

  const qOut = (q) => ({
    id: q.id, notice_id: q.notice_id, seq: q.seq, ref: q.ref, query: q.query, required_action: q.required_action,
    status: q.status, response: q.response, responded_at: q.responded_at, resolved_at: q.resolved_at, issuer_side: q.issuer_side, raised_by: q.raised_by || null, created_at: q.created_at,
    can_review: userIsDM && userSide === q.issuer_side && ['answered', 'resolved'].includes(q.status),
  });
  const ownQueries = (queriesByRecord.get(rec.id) || []).map(qOut);
  const previousQueries = rec.revision_of_id ? (queriesByRecord.get(rec.revision_of_id) || []).map(qOut) : [];

  const notices = await Promise.all(embeddedNotices.map(async n => {
    const signed = planRows.filter(r => r.notice_id === n.id && r.status === 'signed').sort((a, b) => a.order_no - b.order_no);
    return {
      ...n,
      signatories: await Promise.all(signed.map(async r => ({
        position: r.signer_position || flowRoleLabel(r.signer_role), side: r.side, signed_at: r.signed_at,
        is_decider: r.is_decider, name: await nameOf(r.signer_role, r.signer_user_id),
      }))),
      query_count: allQueries.filter(q => q.notice_id === n.id).length,
    };
  }));

  return {
    status: isNoticeRecord ? 'issued' : rec.status,
    is_locked: isLocked || isNoticeRecord,
    is_notice_record: isNoticeRecord,
    workflow_steps: isNoticeRecord ? [] : workflowSteps,
    btn_state: btn, pending_role: pend, approve_label: label,
    revision_of_id: rec.revision_of_id || null, revision_no: rec.revision_no || 0, superseded_by_id: rec.superseded_by_id || null,
    notice_source: rec.notice_source || null, respond_by: rec.respond_by || null,
    current_stage: stage, time_zone: projectTz, reference: flowRecordRef(table, rec),
    signing_plan: stages,
    my_signer: stage ? (() => { const me = stageRows.find(r => isMe(r) && r.status === 'pending'); return me ? { id: me.id, stage, is_decider: me.is_decider, first_viewed_at: me.first_viewed_at } : null; })() : null,
    can_remind: Boolean(stage) && (isUploader || (userIsDM && userSide === getSide(rec.role))),
    can_resubmit: isRejected && !rec.superseded_by_id && !isNoticeRecord && (isUploader || (userIsDM && userSide === getSide(rec.role))),
    queries: ownQueries,
    revision_queries: previousQueries,
    embedded_notices: notices,
  };
}


app.get('/api/arrets', authenticateToken, async (req, res) => {
  const projectId = normalizeProjectId(req.query.projectId);
  if (!projectId) return res.status(400).json({ error: 'Missing projectId' });

  try {
    if (!await userHasProjectAccess(req.user.user_id, req.user.role, projectId))
      return res.status(403).json({ error: 'You are not assigned to this project.' });

    const { rows: arrets } = await pool.query(
      `SELECT a.*, 
              EXISTS(
                SELECT 1 FROM arret_views v
                WHERE v.arret_id = a.id AND v.viewer_id = $2 AND v.viewer_role = $3
              ) AS is_viewed
       FROM arrets a
       WHERE a.project_id = $1
       ORDER BY a.issued_date DESC, a.id DESC`,
      [projectId, req.user.user_id, req.user.role]
    );

    const arretIds = arrets.map(r => r.id).filter(Boolean);
    const attachmentsByArret = {};
    if (arretIds.length) {
      try {
        const { rows: attachments } = await pool.query(
          `SELECT arret_id, file_name, file_mime, file_url, public_id
           FROM arret_attachments
           WHERE arret_id = ANY($1::int[])`,
          [arretIds]
        );
        for (const attachment of attachments) {
          attachmentsByArret[attachment.arret_id] = attachmentsByArret[attachment.arret_id] || [];
          attachmentsByArret[attachment.arret_id].push(attachment);
        }
      } catch (err) {
        if (!err.message.includes('relation "arret_attachments" does not exist')) throw err;
      }
    }

    const result = arrets.map(arret => ({
      ...arret,
      is_viewed: Boolean(arret.is_viewed),
      attachments: attachmentsByArret[arret.id] || (arret.attachment_url ? [{
        file_name: arret.attachment_name,
        file_mime: arret.attachment_mime,
        file_url: arret.attachment_url,
        public_id: arret.attachment_public_id,
      }] : []),
    }));

    return res.json({ arrets: result });
  } catch (err) {
    console.error('GET /api/arrets:', err);
    return res.status(500).json({ error: 'Failed to load arrets' });
  }
});

app.post('/api/arrets', authenticateToken, upload.array('attachments'), requireProjectLifecycleWrite, async (req, res) => {
  const projectId = normalizeProjectId(req.body.projectId);
  const title = (req.body.title || '').trim();
  const description = (req.body.description || '').trim();
  if (!projectId || !title || !description)
    return res.status(400).json({ success: false, message: 'projectId, title, and description are required.' });

  try {
    if (!await userHasProjectAccess(req.user.user_id, req.user.role, projectId))
      return res.status(403).json({ success: false, message: 'You are not assigned to this project.' });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const arretRes = await client.query(
        `INSERT INTO arrets (project_id, title, description, issued_date, created_by, creator_role, creator_email, status, is_resolved, created_at, updated_at)
         VALUES ($1,$2,$3,NOW(),$4,$5,$6,'open',false,NOW(),NOW()) RETURNING *`,
        [projectId, title, description, req.user.user_id, req.user.role, req.user.email || null]
      );
      const arret = arretRes.rows[0];
      const attachments = [];

      for (const file of req.files || []) {
        const uploaded = await scheduleCloudinaryUpload(
          file.buffer, file.originalname, 'oneproject/arrets'
        );
        const attachment = {
          arret_id: arret.id,
          file_name: file.originalname,
          file_mime: file.mimetype,
          file_url: uploaded.secure_url || uploaded.url || null,
          public_id: uploaded.public_id || null,
        };

        try {
          await client.query(
            `INSERT INTO arret_attachments (arret_id, file_name, file_mime, file_url, public_id)
             VALUES ($1,$2,$3,$4,$5)`,
            [attachment.arret_id, attachment.file_name, attachment.file_mime, attachment.file_url, attachment.public_id]
          );
        } catch (err) {
          if (err.message.includes('relation "arret_attachments" does not exist')) {
            await client.query(
              `UPDATE arrets SET attachment_url=$1, attachment_name=$2, attachment_mime=$3, attachment_public_id=$4 WHERE id=$5`,
              [attachment.file_url, attachment.file_name, attachment.file_mime, attachment.public_id, arret.id]
            );
          } else {
            throw err;
          }
        }
        attachments.push(attachment);
      }

      await client.query('COMMIT');
      return res.status(201).json({ success: true, arret: { ...arret, attachments }, message: 'Arret saved.' });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('POST /api/arrets transaction error:', err);
      return res.status(500).json({ success: false, message: 'Failed to save arret.' });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('POST /api/arrets:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.post('/api/arrets/view', authenticateToken, async (req, res) => {
  const projectId = normalizeProjectId(req.body.projectId);
  const arretId = parseInt(req.body.arretId, 10);
  if (!projectId || !arretId) return res.status(400).json({ error: 'projectId and arretId are required' });

  try {
    if (!await userHasProjectAccess(req.user.user_id, req.user.role, projectId))
      return res.status(403).json({ error: 'You are not assigned to this project.' });

    const { rows } = await pool.query(`SELECT 1 FROM arrets WHERE id=$1 AND project_id=$2`, [arretId, projectId]);
    if (!rows.length) return res.status(404).json({ error: 'Arret not found' });

    // Use upsert pattern to ensure role-scoped view records (prevents users with same ID across roles from clobbering each other's views)
    try {
      await pool.query(
        `INSERT INTO arret_views (arret_id, viewer_id, viewer_role, viewer_email, viewed_at)
         VALUES ($1,$2,$3,$4,NOW())
         ON CONFLICT (arret_id, viewer_id, viewer_role)
         DO UPDATE SET viewed_at = NOW(), viewer_email = EXCLUDED.viewer_email`,
        [arretId, req.user.user_id, req.user.role, req.user.email || null]
      );
    } catch (err) {
      if (err.message.includes('column "viewer_email" does not exist')) {
        await pool.query(
          `INSERT INTO arret_views (arret_id, viewer_id, viewer_role, viewed_at)
           VALUES ($1,$2,$3,NOW())
           ON CONFLICT (arret_id, viewer_id, viewer_role)
           DO UPDATE SET viewed_at = NOW()`,
          [arretId, req.user.user_id, req.user.role]
        );
      } else if (err.message.includes('relation "arret_views" does not exist')) {
        console.warn('[POST /api/arrets/view] arret_views table missing; skipping view record.', err.message);
      } else {
        throw err;
      }
    }

    return res.json({ success: true });
  } catch (err) {
    console.error('POST /api/arrets/view:', err);
    return res.status(500).json({ error: 'Failed to mark arret as viewed' });
  }
});

// GET /api/arrets/:id — Fetch individual arret with attachments
app.get('/api/arrets/:id', authenticateToken, async (req, res) => {
  const projectId = normalizeProjectId(req.query.projectId);
  const arretId = parseInt(req.params.id, 10);
  if (!projectId || !arretId) return res.status(400).json({ error: 'projectId and arretId are required' });

  try {
    if (!await userHasProjectAccess(req.user.user_id, req.user.role, projectId))
      return res.status(403).json({ error: 'You are not assigned to this project.' });

    const { rows } = await pool.query(`SELECT * FROM arrets WHERE id=$1 AND project_id=$2`, [arretId, projectId]);
    if (!rows.length) return res.status(404).json({ error: 'Arret not found' });

    const arret = rows[0];

    // Fetch attachments
    let attachments = [];
    try {
      const { rows: attRows } = await pool.query(
        `SELECT id, file_name, file_mime, file_url, public_id FROM arret_attachments WHERE arret_id=$1`,
        [arretId]
      );
      attachments = attRows;
    } catch (err) {
      // arret_attachments may not exist
      if (arret.attachment_url) {
        attachments = [{
          file_name: arret.attachment_name || 'attachment',
          file_mime: arret.attachment_mime || 'application/octet-stream',
          file_url: arret.attachment_url,
          public_id: arret.attachment_public_id || null
        }];
      }
    }

    // Mark as viewed
    try {
      await pool.query(
        `INSERT INTO arret_views (arret_id, viewer_id, viewer_role, viewer_email, viewed_at)
         VALUES ($1,$2,$3,$4,NOW())
         ON CONFLICT (arret_id, viewer_id, viewer_role)
         DO UPDATE SET viewed_at = NOW(), viewer_email = EXCLUDED.viewer_email`,
        [arretId, req.user.user_id, req.user.role, req.user.email || null]
      );
    } catch (err) {
      // Silently continue if viewing fails
      console.warn(`[GET /api/arrets/:id] Could not mark arret ${arretId} as viewed:`, err.message);
    }

    return res.json({ success: true, arret: { ...arret, attachments } });
  } catch (err) {
    console.error('GET /api/arrets/:id:', err);
    return res.status(500).json({ error: 'Failed to fetch arret' });
  }
});

// PUT /api/arrets/:id — Update arret title/description and optionally status by creator only
app.put('/api/arrets/:id', authenticateToken, async (req, res) => {
  const projectId = normalizeProjectId(req.body.projectId);
  const arretId = parseInt(req.params.id, 10);
  const { title, description, status } = req.body;

  if (!projectId || !arretId) return res.status(400).json({ error: 'projectId and arretId are required' });
  if (!title || !description) return res.status(400).json({ error: 'Title and description are required.' });
  if (status && !['open', 'closed', 'resolved'].includes(status))
    return res.status(400).json({ error: 'Valid status required: open, closed, resolved' });

  try {
    if (!await userHasProjectAccess(req.user.user_id, req.user.role, projectId))
      return res.status(403).json({ error: 'You are not assigned to this project.' });

    const { rows } = await pool.query(`SELECT * FROM arrets WHERE id=$1 AND project_id=$2`, [arretId, projectId]);
    if (!rows.length) return res.status(404).json({ error: 'Arret not found' });

    const arret = rows[0];
    if (Number(arret.created_by) !== Number(req.user.user_id) || String(arret.creator_role) !== String(req.user.role)) {
      return res.status(403).json({ error: 'Only the arret creator can edit this arret.' });
    }

    const updatedFields = [title.trim(), description.trim(), status || arret.status, arretId];
    const updateRes = await pool.query(
      `UPDATE arrets SET title=$1, description=$2, status=$3, is_resolved=($3 = 'resolved'), updated_at=NOW() WHERE id=$4 RETURNING *`,
      updatedFields
    );

    return res.json({ success: true, arret: updateRes.rows[0], message: 'Arret updated.' });
  } catch (err) {
    console.error('PUT /api/arrets/:id:', err);
    return res.status(500).json({ error: 'Failed to update arret' });
  }
});

// DELETE /api/arrets/:id — Delete arret (creator only)
app.delete('/api/arrets/:id', authenticateToken, async (req, res) => {
  const projectId = normalizeProjectId(req.body.projectId);
  const arretId = parseInt(req.params.id, 10);

  if (!projectId || !arretId) return res.status(400).json({ error: 'projectId and arretId are required' });

  try {
    if (!await userHasProjectAccess(req.user.user_id, req.user.role, projectId))
      return res.status(403).json({ error: 'You are not assigned to this project.' });

    // Check arret exists and verify creator
    const { rows } = await pool.query(`SELECT * FROM arrets WHERE id=$1 AND project_id=$2`, [arretId, projectId]);
    if (!rows.length) return res.status(404).json({ error: 'Arret not found' });

    const arret = rows[0];
    if (Number(arret.created_by) !== Number(req.user.user_id) || String(arret.creator_role) !== String(req.user.role)) {
      return res.status(403).json({ error: 'Only the arret creator can delete it.' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Delete attachments
      try {
        await client.query(`DELETE FROM arret_attachments WHERE arret_id=$1`, [arretId]);
      } catch (err) {
        // Table may not exist, continue
      }

      // Delete arret views
      try {
        await client.query(`DELETE FROM arret_views WHERE arret_id=$1`, [arretId]);
      } catch (err) {
        // Table may not exist, continue
      }

      // Delete related notifications
      const notifRes = await client.query(
        `DELETE FROM notifications WHERE entity_id=$1 AND entity_type='arrets' RETURNING id`,
        [arretId]
      );

      // Delete the arret
      await client.query(`DELETE FROM arrets WHERE id=$1`, [arretId]);

      await client.query('COMMIT');
      return res.json({ success: true, message: 'Arret deleted.' });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('DELETE /api/arrets/:id:', err);
    return res.status(500).json({ error: 'Failed to delete arret' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  FETCH TAB RECORDS
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/fetch-tab-records', authenticateToken, async (req, res) => {
  const { projectId, recordType } = req.body;
  const table = resolveTable(recordType);
  if (!table) return res.status(400).json({ error: 'Invalid or missing recordType.' });
  const userId   = req.user.user_id;
  const userRole = req.user.role;
  const userSide = getSide(userRole);
  const userIsDM = isDecisionMaker(userRole);
  try {
    // Everyone assigned to the project can read its records. Nobody else can.
    if (!await userHasProjectAccess(userId, userRole, projectId)) {
      return res.status(403).json({ error: 'You are not assigned to this project.' });
    }
    const { rows: records } = await pool.query(
      `SELECT r.id, r.title, r.description, r.file_path, r.supporting_files,
              r.issued_date, r.role AS uploader_role,
              r.uploaded_by, r.status, r.record_kind, r.notice_tied_id,
              r.signed_by_id, r.signed_by_role, r.signed_at,
              r.stamp_type, r.stamped_doc_url, r.signature_hash, r.stamp_status,
              r.revision_of_id, r.revision_no, r.superseded_by_id, r.notice_source, r.respond_by
       FROM ${table} r WHERE r.project_id = $1 ORDER BY r.issued_date DESC`,
      [projectId]
    );
    // Signers, queries and names for every record of this tab, loaded once
    const { rows: allSignerRows } = await pool.query(
      `SELECT * FROM record_signers WHERE record_table=$1 AND project_id=$2 ORDER BY stage, order_no, id`, [table, projectId]);
    const signersByRecord = new Map();
    for (const sr of allSignerRows) { if (!signersByRecord.has(sr.record_id)) signersByRecord.set(sr.record_id, []); signersByRecord.get(sr.record_id).push(sr); }
    const { rows: allQueries } = await pool.query(
      `SELECT * FROM record_queries WHERE record_table=$1 AND project_id=$2 ORDER BY record_id, seq`, [table, projectId]);
    const queriesByRecord = new Map();
    for (const qr of allQueries) { if (!queriesByRecord.has(qr.record_id)) queriesByRecord.set(qr.record_id, []); queriesByRecord.get(qr.record_id).push(qr); }
    const nameCache = new Map();
    const projectTz = await loadProjectTz(projectId);
    const memberKeys = await loadProjectMemberKeys(projectId);
    const nameOf = async (r, id) => {
      const k = `${r}:${id}`;
      if (!nameCache.has(k)) nameCache.set(k, await resolveDisplayNameFor(r, id, projectId).catch(() => null));
      return nameCache.get(k);
    };
    const enriched = await Promise.all(records.map(async rec => {
      const { rows: reviews } = await pool.query(
        `SELECT dr.reviewer_id, dr.reviewer_role, dr.action, dr.action_date,
                dr.comment, dr.reviewer_email, dr.reviewer_position,
                COALESCE(
                  dr.reviewer_assigned_part,
                  CASE WHEN dr.reviewer_role = 'TeamMember' THEN (
                    SELECT tma.assigned_part
                    FROM team_member_assignments tma
                    WHERE tma.project_id = $3
                      AND tma.team_member_id = dr.reviewer_id
                    ORDER BY tma.id DESC
                    LIMIT 1
                  ) END
                ) AS reviewer_assigned_part
         FROM document_reviews dr WHERE dr.record_type = $1 AND dr.record_id = $2 ORDER BY dr.action_date ASC`,
        [table, rec.id, projectId]
      );
      const annotatedReviews = reviews.map(r => ({ ...r, is_decision_maker: isDecisionMaker(r.reviewer_role) }));
      const isUploader = String(rec.uploaded_by) === String(userId) && getSide(rec.uploader_role) === getSide(userRole);
      let isViewed = isUploader;
      if (!isUploader) {
        const { rows: viewed } = await pool.query(
          `SELECT 1 FROM document_reviews WHERE record_type=$1 AND record_id=$2 AND reviewer_id=$3 AND reviewer_role=$4 LIMIT 1`,
          [table, rec.id, userId, userRole]
        );
        isViewed = viewed.length > 0;
      }
      const myReviewRow = reviews.find(r => String(r.reviewer_id) === String(userId) && getSide(r.reviewer_role) === getSide(userRole));
      const myReview    = myReviewRow ? { action: myReviewRow.action, comment: myReviewRow.comment || '' } : {};
      const uploaderSide  = getSide(rec.uploader_role);
      const step2SideMap  = { contractor: 'client', consultant: 'contractor', client: 'contractor' };
      const step2Side     = step2SideMap[uploaderSide];
      const isRejected    = rec.status === 'rejected';
      const isLocked      = isRejected || rec.status === 'approved_record' || annotatedReviews.some(r => getSide(r.reviewer_role) === step2Side && r.action === 'accepted');
      const stepMap = {
        contractor: [{ side:'consultant',step:1,label:'Consultant Approval',action:'approved'},{side:'client',step:2,label:'Client Acceptance',action:'accepted'}],
        consultant: [{ side:'client',step:1,label:'Client Approval',action:'approved'},{side:'contractor',step:2,label:'Contractor Acceptance',action:'accepted'}],
        client:     [{ side:'consultant',step:1,label:'Consultant Approval',action:'approved'},{side:'contractor',step:2,label:'Contractor Acceptance',action:'accepted'}],
      };
      const steps = uploaderSide ? stepMap[uploaderSide] : null;
      // Each step reports its own outcome plus who decided and when.
      // done / rejected come from real reviews; the first undecided step is
      // 'pending' (the record is waiting on it), later ones are 'waiting', and
      // once the record is closed any undecided step is 'skipped'.
      const workflowSteps = steps ? steps.map(s => {
        const doneReview     = annotatedReviews.find(r => getSide(r.reviewer_role) === s.side && (r.action === 'approved' || r.action === 'accepted'));
        const rejectedReview = annotatedReviews.find(r => getSide(r.reviewer_role) === s.side && r.action === 'rejected');
        const decided = doneReview || rejectedReview || null;
        return {
          label: s.label,
          side: s.side,
          status: doneReview ? 'done' : rejectedReview ? 'rejected' : 'waiting',
          by: decided ? decided.reviewer_role : null,
          at: decided ? decided.action_date : null,
        };
      }) : [];
      {
        const openIdx = workflowSteps.findIndex(st => st.status === 'waiting');
        const anyRejected = workflowSteps.some(st => st.status === 'rejected');
        const closed = isRejected || isLocked;
        workflowSteps.forEach((st, i) => {
          if (st.status !== 'waiting') return;
          if (closed) st.status = (isRejected && i === openIdx && !anyRejected) ? 'rejected' : 'skipped';
          else if (i === openIdx) st.status = 'pending';
        });
      }
      let btnState = 'none', pendingRole = null, approveLabel = null;
      if (isUploader) { btnState = 'uploader'; }
      else if (userIsDM && myReviewRow && ['approved', 'accepted', 'rejected'].includes(myReviewRow.action)) { btnState = 'acted'; }
      else if (isLocked) { btnState = 'locked'; }
      else if (!userIsDM) { btnState = 'team_member'; }
      else if (userSide === uploaderSide) { btnState = 'none'; }
      else {
        const workflowActions = ['approved', 'accepted', 'rejected'];
        const alreadyActed = myReviewRow && workflowActions.includes(myReviewRow.action);
        if (alreadyActed) { btnState = 'acted'; }
        else if (steps) {
          const myStep = steps.find(s => s.side === userSide);
          if (!myStep) { btnState = 'none'; }
          else if (myStep.step === 2) {
            const step1 = steps.find(s => s.step === 1);
            const step1Done = annotatedReviews.some(r => getSide(r.reviewer_role) === step1.side && (r.action === 'approved' || r.action === 'accepted'));
            if (!step1Done) { btnState = 'awaiting'; pendingRole = step1.side; }
            else { btnState = 'can_approve'; approveLabel = myStep.action === 'accepted' ? 'Accept' : 'Approve'; }
          } else { btnState = 'can_approve'; approveLabel = myStep.action === 'accepted' ? 'Accept' : 'Approve'; }
        }
      }
      // All notices tied to this record — full data, newest first, for card embedding
      const { rows: embeddedNotices } = await pool.query(
        `SELECT id, title, description, file_path, supporting_files, issued_date,
                role AS uploader_role, record_kind,
                signed_by_id, signed_by_role, signed_at, stamp_type, stamped_doc_url,
                notice_source, respond_by
         FROM ${table}
         WHERE notice_tied_id = $1 AND project_id = $2
         ORDER BY issued_date DESC`,
        [rec.id, projectId]
      );
      // Notice issued by the current user (for button state)
      const { rows: myNoticeRows } = await pool.query(
        `SELECT id FROM ${table} WHERE notice_tied_id=$1 AND project_id=$2 AND uploaded_by=$3 LIMIT 1`,
        [rec.id, projectId, userId]
      );
      const myIssuedNotice = myNoticeRows.length > 0
        ? { id: myNoticeRows[0].id }
        : null;
      let tiedRecordTitle = null;
      if (rec.notice_tied_id) {
        const { rows: tied } = await pool.query(`SELECT title FROM ${table} WHERE id = $1`, [rec.notice_tied_id]);
        tiedRecordTitle = tied[0]?.title || null;
      }
      const signedByDisplayName = rec.signed_by_id ? await resolveDisplayNameFor(rec.signed_by_role, rec.signed_by_id, projectId) : null;
      const flowView = await buildRecordFlowView({
        rec, projectId, userId, userRole, userSide, userIsDM, isUploader, isLocked, isRejected, steps,
        btnState, pendingRole, approveLabel, workflowSteps, embeddedNotices,
        signersByRecord, queriesByRecord, allQueries, nameOf, projectTz, memberKeys, table,
      });
      return {
        ...rec,
        signed_by_display_name: signedByDisplayName,
        reviews: annotatedReviews,
        is_uploader: isUploader,
        is_viewed: isViewed,
        is_locked: isLocked,
        is_decision_maker: userIsDM,
        btn_state: btnState,
        pending_role: pendingRole,
        approve_label: approveLabel,
        my_review: myReview,
        workflow_steps: workflowSteps,
        my_issued_notice: myIssuedNotice,
        embedded_notices: embeddedNotices,
        tied_record_title: tiedRecordTitle,
        ...flowView,
      };
    }));
    res.json({ records: enriched });
  } catch (err) {
    console.error('Fetch tab records error:', err);
    res.status(500).json({ error: 'Failed to fetch records.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  MARK RECORD VIEWED
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/mark-record-viewed', authenticateToken, async (req, res) => {
  const { recordId, projectId, recordType } = req.body;
  const reviewerId = req.user.user_id, reviewerRole = req.user.role;
  const table = resolveTable(recordType);
  if (!table) return res.status(400).json({ error: 'Invalid or missing recordType.' });
  try {
    if (!await userHasProjectAccess(reviewerId, reviewerRole, projectId)) return res.status(403).json({ error: 'You are not assigned to this project.' });
    const { rows: rec } = await pool.query(`SELECT uploaded_by, role FROM ${table} WHERE id=$1 AND project_id=$2`, [recordId, projectId]);
    if (!rec.length) return res.status(400).json({ error: 'Record not found.' });
    if (String(rec[0].uploaded_by) === String(reviewerId) && getSide(rec[0].role) === getSide(reviewerRole)) return res.json({ success: true, skipped: true });
    const assignRow = await pool.query(`SELECT av.role_email AS email, av.title_position AS position FROM assignments_view av WHERE av.project_id=$1 AND av.role_id=$2 AND av.role=$3 LIMIT 1`, [projectId, reviewerId, reviewerRole]);
    await pool.query(
      `INSERT INTO document_reviews (record_type, record_id, record_kind, reviewer_id, reviewer_role, reviewer_email, reviewer_position, action)
       VALUES ($1,$2,'new',$3,$4,$5,$6,'no_action') ON CONFLICT (record_type, record_id, reviewer_id, reviewer_role) DO NOTHING`,
      [table, recordId, reviewerId, reviewerRole, assignRow.rows[0]?.email || null, assignRow.rows[0]?.position || null]
    );
    res.json({ success: true });
  } catch (err) { console.error('Mark viewed error:', err); res.status(500).json({ error: 'Failed to mark as viewed.' }); }
});

// ─────────────────────────────────────────────────────────────────────────────
//  REVIEW RECORD
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/review-record', authenticateToken, upload.single('attachment'), requireProjectLifecycleWrite, async (req, res) => {
  const { projectId, recordId, recordType, action, comment, actorType, stampDocument } = req.body;
  const reviewerId = req.user.user_id, reviewerRole = req.user.role;
  const table = resolveTable(recordType);
  if (!table) return res.status(400).json({ error: 'Invalid or missing recordType.' });
  const workflowActions = ['approved', 'accepted', 'rejected'];
  const isWorkflow = workflowActions.includes(action);
  const isDecisionMakerActor = isDecisionMaker(reviewerRole) && actorType !== 'team_member';
  if (!isWorkflow && action !== 'no_action') return res.status(400).json({ error: 'Invalid action.' });
  if (isWorkflow && !isDecisionMaker(reviewerRole) && actorType !== 'team_member') return res.status(403).json({ error: 'Only decision makers can run workflow actions.' });
  if (isWorkflow && isDecisionMakerActor) return res.status(400).json({ error: 'A decision is issued together with a signed notice. Use the review and sign form.' });
  // Only a real team member can act as one. The role comes from the login token, never from the request.
  if (actorType === 'team_member' && normalizeRole(reviewerRole) !== 'TeamMember') return res.status(403).json({ error: 'Only team members can act as team members.' });
  try {
    if (!await userHasProjectAccess(reviewerId, reviewerRole, projectId)) return res.status(403).json({ error: 'You are not assigned to this project.' });
    const { rows: recRows } = await pool.query(`SELECT id, role, uploaded_by, file_path, attachment_id, stamp_status, stamp_type FROM ${table} WHERE id=$1 AND project_id=$2`, [recordId, projectId]);
    if (!recRows.length) return res.status(400).json({ error: 'Record not found. It may have been deleted.' });
    const rec = recRows[0];
    if (String(rec.uploaded_by) === String(reviewerId) && getSide(rec.role) === getSide(reviewerRole)) return res.status(403).json({ error: 'You cannot review your own record.' });
    const assignRow = await pool.query(`SELECT av.role_email AS email, av.title_position AS position FROM assignments_view av WHERE av.project_id=$1 AND av.role_id=$2 AND av.role=$3 LIMIT 1`, [projectId, reviewerId, reviewerRole]);
    const reviewerEmail = assignRow.rows[0]?.email || null, reviewerPosition = assignRow.rows[0]?.position || null;
    const { rows: existing } = await pool.query(`SELECT id, action FROM document_reviews WHERE record_type=$1 AND record_id=$2 AND reviewer_id=$3 AND reviewer_role=$4 LIMIT 1`, [table, recordId, reviewerId, reviewerRole]);
    if (action === 'no_action' && comment?.trim()) {
      if (existing.length > 0) { await pool.query(`UPDATE document_reviews SET comment=$1, action_date=NOW() WHERE id=$2`, [comment.trim(), existing[0].id]); }
      else {
        let _cap = null;
        if (reviewerRole === 'TeamMember') { const {rows:_tr} = await pool.query(`SELECT assigned_part FROM team_member_assignments WHERE project_id=$1 AND team_member_id=$2 LIMIT 1`,[projectId,reviewerId]); _cap=_tr[0]?.assigned_part||null; }
        await pool.query(`INSERT INTO document_reviews (record_type,record_id,record_kind,reviewer_id,reviewer_role,reviewer_email,reviewer_position,reviewer_assigned_part,action,comment) VALUES ($1,$2,'new',$3,$4,$5,$6,$7,'no_action',$8)`, [table, recordId, reviewerId, reviewerRole, reviewerEmail, reviewerPosition, _cap, comment.trim()]);
      }
      return res.json({ success: true, message: 'Comment saved.' });
    }
    if (existing.length > 0) {
      if (existing[0].action === 'rejected') {
        return res.status(409).json({ error: 'This record is already rejected and cannot move to a later approval stage.' });
      }
      if (isDecisionMakerActor && workflowActions.includes(existing[0].action)) return res.status(409).json({ error: `You already ${existing[0].action} this record.` });
      await pool.query(`UPDATE document_reviews SET action=$1, action_date=NOW(), comment=COALESCE($2,comment) WHERE id=$3`, [action, comment?.trim() || null, existing[0].id]);
    } else {
      let reviewerAssignedPart = null;
      if (reviewerRole === 'TeamMember') {
        const { rows: tmRows } = await pool.query(`SELECT assigned_part FROM team_member_assignments WHERE project_id=$1 AND team_member_id=$2 LIMIT 1`, [projectId, reviewerId]);
        reviewerAssignedPart = tmRows[0]?.assigned_part || null;
      }
      await pool.query(`INSERT INTO document_reviews (record_type,record_id,record_kind,reviewer_id,reviewer_role,reviewer_email,reviewer_position,reviewer_assigned_part,action,comment) VALUES ($1,$2,'new',$3,$4,$5,$6,$7,$8,$9)`, [table, recordId, reviewerId, reviewerRole, reviewerEmail, reviewerPosition, reviewerAssignedPart, action, comment?.trim() || null]);
    }

    let stampedDocUrl = null;
    let stampedAttachmentId = null;
    let stampApplied = false;
    const isSignatureActor = actorType === 'team_member' || isDecisionMakerActor;
    const isApprovalStampAction = isWorkflow && action !== 'rejected';
    if (isSignatureActor && isApprovalStampAction && stampDocument === 'true' && req.file) {
      if (!/\.pdf$/i.test(req.file.originalname || '')) {
        return res.status(400).json({ error: 'Stamped documents must be submitted as PDF.' });
      }
      try {
        // The server draws the stamp from the saved profile at the position the reviewer picked.
        const rvProfile = await loadSignerProfile(projectId, reviewerRole, reviewerId);
        if (!rvProfile) return res.status(400).json({ error: 'Your signature could not be loaded. Save it again in your Signature & Stamp setup and retry.' });
        const pgRaw = req.body.stampPage;
        const placement = { page: pgRaw === 'append' ? 'append' : (parseInt(pgRaw, 10) || 1), x: Number.parseFloat(req.body.stampX), y: Number.parseFloat(req.body.stampY) };
        if (!Number.isFinite(placement.x) || !Number.isFinite(placement.y) || placement.x < 0 || placement.x > 1 || placement.y < 0 || placement.y > 1) {
          return res.status(400).json({ error: 'Invalid stamp placement supplied.' });
        }
        const rvTz = await loadProjectTz(projectId);
        const rvStampId = deriveStampId({ k: 'review', p: projectId, rec: recordId, u: reviewerId, r: reviewerRole, ts: Date.now(), n: crypto.randomBytes(4).toString('hex') });
        const rvSpec = stampSpecFromProfile(rvProfile, { label: 'APPROVED', signedAt: new Date(), tz: rvTz, stampId: rvStampId, baseUrl: publicBaseUrl(req) });
        const rvStamped = await stampPdfBuffer(req.file.buffer, rvSpec, placement);
        req.file.buffer = rvStamped.bytes;
        req.file.size = rvStamped.bytes.length;
        await registerStamp(pool, { stampId: rvStampId, projectId: Number(projectId), table, recordId: Number(recordId), kind: 'review', userId: reviewerId, role: reviewerRole,
          name: rvProfile.name, position: rvProfile.position, company: rvProfile.company, label: 'APPROVED', tz: rvTz,
          fileHash: crypto.createHash('sha256').update(rvStamped.bytes).digest('hex'), signedAt: new Date() });
        const r = await new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: 'oneproject/records', resource_type: 'auto', public_id: `${Date.now()}-${req.file.originalname.replace(/\s+/g, '-')}` },
            (err, result) => err ? reject(err) : resolve(result)
          );
          Readable.from(req.file.buffer).pipe(stream);
        });
        stampedDocUrl = r.secure_url;
        stampedAttachmentId = r.public_id;
        stampApplied = true;
        // Only decision makers should change the overall stamp_status.
        if (isDecisionMakerActor) {
          const nextStampStatus = getStampStatusFromActor(rec.stamp_status, 'approver');
          await pool.query(
            `UPDATE ${table} SET file_path=$1, attachment_id=$2, stamped_doc_url=$3, signed_by_id=$4, signed_by_role=$5, signed_at=NOW(), stamp_type=$6, stamp_status=$7 WHERE id=$8 AND project_id=$9`,
            [stampedDocUrl, stampedAttachmentId, stampedDocUrl, reviewerId, reviewerRole, 'STAMPED', nextStampStatus, recordId, projectId]
          );
        } else {
          // Team members can attach a signed PDF, but must not change stamp_status.
          await pool.query(
            `UPDATE ${table} SET file_path=$1, attachment_id=$2, stamped_doc_url=$3, signed_by_id=$4, signed_by_role=$5, signed_at=NOW(), stamp_type=$6 WHERE id=$7 AND project_id=$8`,
            [stampedDocUrl, stampedAttachmentId, stampedDocUrl, reviewerId, reviewerRole, 'STAMPED', recordId, projectId]
          );
        }
      } catch (uploadErr) {
        console.error('Review-record stamp upload failed:', uploadErr);
        return res.status(500).json({ error: 'Failed to stamp and replace the document.' });
      }
    }

    if (isDecisionMakerActor && isWorkflow) {
      const uploaderSide = getSide(rec.role);
      let newStatus;
      if (action === 'rejected') {
        newStatus = 'rejected';
        await pool.query(
          `UPDATE ${table} SET status=$1 WHERE id=$2 AND project_id=$3`,   // rejecting never clears earlier stamps
          [newStatus, recordId, projectId]
        );
      } else {
        if (action === 'accepted') { newStatus = 'approved_record'; }
        else { const m = { contractor: 'pending_client_acceptance', consultant: 'pending_contractor_acceptance', client: 'pending_contractor_acceptance' }; newStatus = m[uploaderSide] || 'pending_review'; }
        await pool.query(`UPDATE ${table} SET status=$1 WHERE id=$2 AND project_id=$3`, [newStatus, recordId, projectId]);
      }
      const notifMsg = `${reviewerRole} ${action} record #${recordId} (uploaded by ${rec.role})`;
      const dbClient = await pool.connect();
      try {
        await dbClient.query('BEGIN');
        console.log('[notifications] creating notification', { projectId, entity_id: recordId, entity_type: table, message: notifMsg, added_by_id: reviewerId, added_by_role: reviewerRole });
        const notifRes = await dbClient.query(`INSERT INTO notifications (project_id,entity_id,entity_type,message,added_by_id,added_by_role) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`, [projectId, recordId, table, notifMsg, reviewerId, reviewerRole]);
        const notificationId = notifRes.rows[0].id;
        console.log('[notifications] created', { notificationId, projectId, entity_id: recordId });
        const recipients = await getProjectRecipientKeys(projectId, reviewerId, reviewerRole);
        await insertNotificationRecipients(dbClient, notificationId, recipients);
        await dbClient.query('COMMIT');
      } catch (notifErr) { await dbClient.query('ROLLBACK'); console.error('Notification insert error (non-fatal):', notifErr); } finally { dbClient.release(); }
    }
    res.json({ success: true, message: `Action '${action}' recorded successfully.` });
  } catch (err) { console.error('Review record error:', err); res.status(500).json({ error: 'Failed to process review.' }); }
});

// ─────────────────────────────────────────────────────────────────────────────
//  DOWNLOAD / DELETE RECORD
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/download-file', authenticateToken, async (req, res) => {
  const { recordId, recordType, filename, disposition, supportingIndex } = req.query;
  const table = resolveTable(recordType);
  if (!table) return res.status(400).json({ error: 'Invalid or missing recordType.' });
  try {
    const { rows } = await pool.query(`SELECT project_id, file_path, stamped_doc_url, supporting_files FROM ${table} WHERE id=$1`, [recordId]);
    if (!rows.length) return res.status(404).json({ error: 'File not found.' });
    // The record decides which project the file belongs to, so a user cannot reach another project's files.
    if (!await userHasProjectAccess(req.user.user_id, req.user.role, rows[0].project_id)) {
      return res.status(403).json({ error: 'You are not assigned to this project.' });
    }
    let filePath = rows[0].stamped_doc_url || rows[0].file_path;
    if (supportingIndex !== undefined && supportingIndex !== '') {
      let list = rows[0].supporting_files;
      if (typeof list === 'string') { try { list = JSON.parse(list); } catch (_) { list = []; } }
      const idx = Number(supportingIndex);
      filePath = Array.isArray(list) && Number.isInteger(idx) && idx >= 0 ? (list[idx]?.url || null) : null;
    }
    if (!filePath) return res.status(404).json({ error: 'File not found.' });
    if (rows[0].stamped_doc_url) {
      console.log('Download proxy using stamped_doc_url for record', recordId);
    }
    if (filePath.startsWith('http')) {
      console.log('Download proxy fetching remote file for record', recordId, filePath);
      try {
        const remoteResp = await fetch(filePath, { method: 'GET', redirect: 'follow' });
        if (!remoteResp.ok) {
          console.warn('Remote file fetch failed with status', remoteResp.status, 'for', filePath);
          return res.status(remoteResp.status).json({ error: 'File not available.' });
        }
        const contentType = remoteResp.headers.get('content-type') || 'application/octet-stream';
        const contentLength = remoteResp.headers.get('content-length');
        const safeName = (filename || filePath.split('/').pop().split('?')[0] || `attachment-${recordId}`)
          .replace(/\\/g, '_')
          .replace(/"/g, '_');
        res.setHeader('Content-Type', contentType);
        const contentDisposition = disposition === 'inline' ? 'inline' : 'attachment';
        res.setHeader('Content-Disposition', `${contentDisposition}; filename="${safeName}"`);
        if (contentLength) res.setHeader('Content-Length', contentLength);
        const buffer = Buffer.from(await remoteResp.arrayBuffer());
        return res.send(buffer);
      } catch (headErr) {
        console.warn('Remote file fetch failed for', filePath, headErr.message);
        return res.status(502).json({ error: 'File not reachable.' });
      }
    }
    res.status(404).json({ error: 'File not accessible.' });
  } catch (err) {
    console.error('Download file error:', err);
    res.status(500).json({ error: 'Failed to download file.' });
  }
});

app.get('/api/download-record-bundle', authenticateToken, async (req, res) => {
  const { projectId, recordType, noticeId, noticeIds, recordId, mode = 'both' } = req.query;
  const table = resolveTable(recordType);
  if (!table || !projectId || !recordId || !['notice', 'record', 'both'].includes(mode)) {
    return res.status(400).json({ error: 'Invalid record bundle request.' });
  }
  try {
    if (!await userHasProjectAccess(req.user.user_id, req.user.role, projectId)) {
      return res.status(403).json({ error: 'You are not assigned to this project.' });
    }
    const selectedNoticeIds = mode === 'both'
      ? String(noticeIds || noticeId || '').split(',').map(id => id.trim()).filter(Boolean)
      : [noticeId].filter(Boolean);
    const ids = mode === 'notice' ? selectedNoticeIds.slice(0, 1)
      : mode === 'record' ? [recordId]
      : [...selectedNoticeIds, recordId];
    if (ids.some(id => !id) || (mode !== 'record' && !selectedNoticeIds.length)) {
      return res.status(400).json({ error: 'Missing document ID.' });
    }
    if (mode !== 'record') {
      const { rows: relation } = await pool.query(
        `SELECT 1 FROM ${table}
         WHERE id = ANY($1::int[]) AND notice_tied_id=$2 AND project_id=$3
         LIMIT 1`,
        [selectedNoticeIds.map(Number), recordId, projectId]
      );
      if (relation.length !== 1 || mode === 'both') {
        const { rows: matchingNotices } = await pool.query(
          `SELECT id FROM ${table}
           WHERE id = ANY($1::int[]) AND notice_tied_id=$2 AND project_id=$3`,
          [selectedNoticeIds.map(Number), recordId, projectId]
        );
        if (matchingNotices.length !== selectedNoticeIds.length) {
          return res.status(400).json({ error: 'One or more notices are not tied to this record.' });
        }
      }
    }
    const { rows } = await pool.query(
      `SELECT id, title, file_path, stamped_doc_url, role AS added_by, issued_date
       FROM ${table} WHERE project_id=$1 AND id = ANY($2::int[])`,
      [projectId, ids.map(Number)]
    );
    const byId = new Map(rows.map(row => [String(row.id), row]));
    const output = await PDFDocument.create();
    const labelFont = await output.embedFont(StandardFonts.Helvetica);
    const labelBoldFont = await output.embedFont(StandardFonts.HelveticaBold);
    for (const [index, id] of ids.entries()) {
      const row = byId.get(String(id));
      const filePath = row?.stamped_doc_url || row?.file_path;
      if (!filePath) return res.status(404).json({ error: 'Official document not found.' });
      const isOriginal = mode === 'record' || (mode === 'both' && index === selectedNoticeIds.length);
      const label = isOriginal ? 'ORIGINAL RECORD' : `NOTICE ${index + 1}`;
      const strip = output.addPage([612, 72]);
      const stripColor = isOriginal ? rgb(0.04, 0.32, 0.42) : rgb(0.57, 0.35, 0.04);
      strip.drawRectangle({ x: 0, y: 0, width: 612, height: 72, color: rgb(0.98, 0.99, 1) });
      strip.drawRectangle({ x: 0, y: 0, width: 8, height: 72, color: stripColor });
      strip.drawText(label, { x: 26, y: 43, size: 12, font: labelBoldFont, color: stripColor });
      strip.drawText(String(row.title || 'Untitled document'), {
        x: 150, y: 44, size: 10, font: labelBoldFont, color: rgb(0.12, 0.16, 0.2), maxWidth: 420
      });
      strip.drawText(`Added by ${row.added_by || 'Unknown'} · ${row.issued_date ? new Date(row.issued_date).toLocaleDateString() : 'Date not recorded'}`, {
        x: 150, y: 25, size: 9, font: labelFont, color: rgb(0.4, 0.45, 0.5), maxWidth: 420
      });
      const remote = await fetch(filePath, { redirect: 'follow' });
      if (!remote.ok) return res.status(502).json({ error: 'Official document is not reachable.' });
      const source = await PDFDocument.load(Buffer.from(await remote.arrayBuffer()));
      const pages = await output.copyPages(source, source.getPageIndices());
      pages.forEach(page => output.addPage(page));
    }
    const merged = await output.save();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="record-${recordId}-${mode}.pdf"`);
    return res.send(Buffer.from(merged));
  } catch (err) {
    console.error('Bundle download error:', err);
    return res.status(500).json({ error: 'Failed to create the document bundle.' });
  }
});


// ─────────────────────────────────────────────────────────────────────────────
// Helper: Resolve company_name based on role and project
async function resolvePositionAndSideForStamp(projectId, userId, role) {
  try {
    const normalizedRole = normalizeRole(role);

    if (normalizedRole === 'TeamMember') {
      const { rows } = await pool.query(
        `SELECT position, assigned_part FROM team_member_assignments
         WHERE project_id=$1 AND team_member_id=$2 LIMIT 1`,
        [projectId, userId]
      );
      return {
        position: rows[0]?.position || null,
        side: rows[0]?.assigned_part || null,
      };
    }

    if (normalizedRole === 'Client') {
      const { rows } = await pool.query(
        `SELECT title, representative FROM clients WHERE id=$1 LIMIT 1`,
        [userId]
      );
      return {
        position: rows[0]?.title || rows[0]?.representative || null,
        side: 'Client',
      };
    }

    if (normalizedRole === 'Contractor') {
      const { rows } = await pool.query(
        `SELECT title_position, representative FROM contractor_assignments
         WHERE project_id=$1 AND contractor_id=$2 LIMIT 1`,
        [projectId, userId]
      );
      return {
        position: rows[0]?.title_position || rows[0]?.representative || null,
        side: 'Contractor',
      };
    }

    if (normalizedRole === 'Consultant') {
      const { rows } = await pool.query(
        `SELECT title_position, representative FROM consultant_assignments
         WHERE project_id=$1 AND consultant_id=$2 LIMIT 1`,
        [projectId, userId]
      );
      return {
        position: rows[0]?.title_position || rows[0]?.representative || null,
        side: 'Consultant',
      };
    }

    if (normalizedRole === 'ClientPM') {
      return { position: null, side: 'Client' };
    }

    if (normalizedRole === 'ContractorPM') {
      return { position: null, side: 'Contractor' };
    }

    if (normalizedRole === 'ConsultantPM') {
      return { position: null, side: 'Consultant' };
    }

    return { position: null, side: null };
  } catch (err) {
    console.warn('resolvePositionAndSideForStamp error:', err.message);
    return { position: null, side: null };
  }
}

async function resolveCompanyNameForStamp(projectId, userId, role) {
  try {
    const normalizedRole = normalizeRole(role);
    let companyRole = normalizedRole;

    if (normalizedRole === 'TeamMember') {
      const { rows } = await pool.query(
        `SELECT assigned_part FROM team_member_assignments
         WHERE project_id=$1 AND team_member_id=$2 LIMIT 1`,
        [projectId, userId]
      );
      const side = rows[0]?.assigned_part;
      const normalizedSide = getSide(side);
      companyRole = normalizedSide
        ? `${normalizedSide[0].toUpperCase()}${normalizedSide.slice(1)}`
        : null;
    }

    if (companyRole === 'Client' || companyRole === 'ClientPM') {
      const { rows } = await pool.query(
        `SELECT c.company_name FROM projects p
         JOIN clients c ON p.client_id = c.id
         WHERE p.id=$1 LIMIT 1`,
        [projectId]
      );
      return rows[0]?.company_name || null;
    } else if (companyRole === 'Contractor' || companyRole === 'ContractorPM') {
      const { rows } = await pool.query(
        `SELECT ca.company_name FROM contractor_assignments ca
         WHERE ca.project_id=$1
           AND ($2::boolean OR ca.contractor_id=$3)
         LIMIT 1`,
        [projectId, companyRole === 'ContractorPM', userId]
      );
      return rows[0]?.company_name || null;
    } else if (companyRole === 'Consultant' || companyRole === 'ConsultantPM') {
      const { rows } = await pool.query(
        `SELECT ca.company_name FROM consultant_assignments ca
         WHERE ca.project_id=$1
           AND ($2::boolean OR ca.consultant_id=$3)
         LIMIT 1`,
        [projectId, companyRole === 'ConsultantPM', userId]
      );
      return rows[0]?.company_name || null;
    }
    return null;
  } catch (err) {
    console.warn('resolveCompanyNameForStamp error:', err.message);
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: Resolve signer name from schema fields for stamp rendering
async function resolveSignerNameForStamp(projectId, userId, role) {
  try {
    if (role === 'Client') {
      const { rows } = await pool.query(`SELECT representative FROM clients WHERE id=$1 LIMIT 1`, [userId]);
      return rows[0]?.representative || null;
    }
    if (role === 'Contractor') {
      const { rows } = await pool.query(
        `SELECT representative FROM contractor_assignments
         WHERE project_id=$1 AND contractor_id=$2 LIMIT 1`,
        [projectId, userId]
      );
      if (rows[0]?.representative) return rows[0].representative;
      const { rows: userRows } = await pool.query(`SELECT email FROM contractors WHERE id=$1 LIMIT 1`, [userId]);
      return userRows[0]?.email || null;
    }
    if (role === 'Consultant') {
      const { rows } = await pool.query(
        `SELECT representative FROM consultant_assignments
         WHERE project_id=$1 AND consultant_id=$2 LIMIT 1`,
        [projectId, userId]
      );
      if (rows[0]?.representative) return rows[0].representative;
      const { rows: userRows } = await pool.query(`SELECT email FROM consultants WHERE id=$1 LIMIT 1`, [userId]);
      return userRows[0]?.email || null;
    }
    if (role === 'ClientPM') {
      const { rows } = await pool.query(
        `SELECT name FROM client_pm_assignments
         WHERE project_id=$1 AND client_pm_id=$2 LIMIT 1`,
        [projectId, userId]
      );
      return rows[0]?.name || null;
    }
    if (role === 'ContractorPM') {
      const { rows } = await pool.query(
        `SELECT name FROM contractor_pm_assignments
         WHERE project_id=$1 AND contractor_pm_id=$2 LIMIT 1`,
        [projectId, userId]
      );
      return rows[0]?.name || null;
    }
    if (role === 'ConsultantPM') {
      const { rows } = await pool.query(
        `SELECT name FROM consultant_pm_assignments
         WHERE project_id=$1 AND consultant_pm_id=$2 LIMIT 1`,
        [projectId, userId]
      );
      return rows[0]?.name || null;
    }
    if (role === 'TeamMember') {
      const { rows } = await pool.query(
        `SELECT name FROM team_member_assignments
         WHERE project_id=$1 AND team_member_id=$2 LIMIT 1`,
        [projectId, userId]
      );
      if (rows[0]?.name) return rows[0].name;
      const { rows: userRows } = await pool.query(`SELECT email FROM team_members WHERE id=$1 LIMIT 1`, [userId]);
      return userRows[0]?.email || null;
    }
    return null;
  } catch (err) {
    console.warn('resolveSignerNameForStamp error:', err.message);
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/my-stamp', authenticateToken, async (req, res) => {
  const { user_id, role } = req.user;
  const projectId = parseInt(req.query.projectId, 10);
  if (!projectId) return res.status(400).json({ error: 'projectId required' });
  try {
    const { rows } = await pool.query(
      `SELECT id, signer_name, signature_image, stamp_image_url, stamp_style, mark_type, updated_at
       FROM user_stamps WHERE user_id=$1 AND user_role=$2 AND project_id=$3 LIMIT 1`,
      [user_id, role, projectId]
    );
    const stamp = rows[0] || null;
    if (stamp) {
      const [signerName, companyName, positionSide] = await Promise.all([
        resolveSignerNameForStamp(projectId, user_id, role),
        resolveCompanyNameForStamp(projectId, user_id, role),
        resolvePositionAndSideForStamp(projectId, user_id, role),
      ]);
      stamp.signer_name = stamp.signer_name || signerName;
      stamp.company_name = companyName;
      stamp.position = positionSide.position;
      stamp.side = positionSide.side;
    }
    res.json({ stamp });
  } catch (err) { console.error('GET my-stamp:', err); res.status(500).json({ error: 'Failed.' }); }
});

// Open-redirect endpoint: used by frontend fallback to let the browser
// navigate directly to the remote file URL (so the browser downloads from
// Cloudinary and avoids server proxy issues).
app.get('/api/open-remote-file', authenticateToken, async (req, res) => {
  const { recordId, recordType } = req.query;
  const table = resolveTable(recordType);
  if (!table) return res.status(400).send('Invalid recordType');
  try {
    const { rows } = await pool.query(`SELECT file_path, stamped_doc_url FROM ${table} WHERE id=$1`, [recordId]);
    if (!rows.length) return res.status(404).send('Not found');
    const filePath = rows[0].stamped_doc_url || rows[0].file_path;
    if (!filePath) return res.status(404).send('No file available');
    if (!filePath.startsWith('http')) return res.status(400).send('File is not a remote URL');
    console.log('Open-remote-file redirect for record', recordId, filePath);
    return res.redirect(filePath);
  } catch (err) {
    console.error('Open-remote-file error:', err.message);
    return res.status(500).send('Server error');
  }
});

app.post('/api/my-stamp', authenticateToken, photoUpload.fields([{ name: 'stampImage', maxCount: 1 }, { name: 'stampImageFile', maxCount: 1 }, { name: 'signatureImageFile', maxCount: 1 }]), requireProjectLifecycleWrite, async (req, res) => {
  const { user_id, role } = req.user;
  const projectId = parseInt(req.query.projectId, 10);
  const normalizedRole = normalizeRole(role);
  const isDM = isDecisionMaker(normalizedRole);
  const isTM = normalizedRole === 'TeamMember';
  if (!projectId) return res.status(400).json({ error: 'projectId required' });
  if (!isDM && !isTM) return res.status(403).json({ error: 'Only decision makers and team members can create a signature profile.' });
  try {
    // One mark, four ways to make it: draw | signature_image | stamp_image | combined (stamp + signature in one image)
    const { signatureBase64 } = req.body;
    const MARK_TYPES = ['draw', 'signature_image', 'stamp_image', 'combined'];
    const markType = MARK_TYPES.includes(req.body.markType) ? req.body.markType : (signatureBase64 ? 'draw' : 'signature_image');
    const usesStampImage = markType === 'stamp_image' || markType === 'combined';
    const signerName = typeof req.body.signerName === 'string' ? req.body.signerName.trim() : null;
    if (usesStampImage && !isDM) {
      return res.status(403).json({ error: 'Stamp images are only available to decision makers. Team members can draw a signature or upload a signature image.' });
    }

    let newMark = null;
    if (usesStampImage) {
      const f = req.files?.stampImage?.[0] || req.files?.stampImageFile?.[0];
      if (f) newMark = (await uploadToCloudinary(f.buffer, 'oneproject/stamps/company', 'image')).secure_url;
    } else if (markType === 'draw' && signatureBase64) {
      if (!/^data:image\/(png|jpeg);base64,/i.test(signatureBase64)) return res.status(400).json({ error: 'The drawn signature is not a valid image.' });
      newMark = signatureBase64;
    } else if (markType === 'signature_image' && req.files?.signatureImageFile?.[0]) {
      newMark = (await uploadToCloudinary(req.files.signatureImageFile[0].buffer, 'oneproject/stamps/signatures', 'image')).secure_url;
    }

    let rows;
    if (!newMark) {
      // No new image: allowed only when the saved row already holds a suitable image for this mode.
      const cur = await pool.query(`SELECT signature_image, stamp_image_url FROM user_stamps WHERE user_id=$1 AND user_role=$2 AND project_id=$3 LIMIT 1`, [user_id, role, projectId]);
      const have = usesStampImage ? cur.rows[0]?.stamp_image_url : cur.rows[0]?.signature_image;
      if (!have) return res.status(400).json({ error: usesStampImage ? 'Upload your stamp image first.' : 'Add a signature (drawn or uploaded) first.' });
      ({ rows } = await pool.query(
        `UPDATE user_stamps SET mark_type=$4, signer_name=COALESCE($5, signer_name), updated_at=NOW()
         WHERE user_id=$1 AND user_role=$2 AND project_id=$3
         RETURNING id, signer_name, signature_image, stamp_image_url, stamp_style, mark_type, updated_at`,
        [user_id, role, projectId, markType, signerName]
      ));
    } else {
      // The image is stored in signature_image in every mode (legacy readers still find it);
      // stamp_image_url additionally holds it for the stamp modes, and is cleared otherwise.
      ({ rows } = await pool.query(
        `INSERT INTO user_stamps (user_id, user_role, project_id, signer_name, signature_image, stamp_image_url, stamp_style, mark_type, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'compact', $7, NOW())
         ON CONFLICT ON CONSTRAINT uniq_user_stamp_project
         DO UPDATE SET
           signer_name     = COALESCE(EXCLUDED.signer_name, user_stamps.signer_name),
           signature_image = EXCLUDED.signature_image,
           stamp_image_url = EXCLUDED.stamp_image_url,
           stamp_style     = 'compact',
           mark_type       = EXCLUDED.mark_type,
           updated_at      = NOW()
         RETURNING id, signer_name, signature_image, stamp_image_url, stamp_style, mark_type, updated_at`,
        [user_id, role, projectId, signerName, newMark, usesStampImage ? newMark : null, markType]
      ));
    }
    const stamp = rows[0];
    const [companyName, positionSide] = await Promise.all([
      resolveCompanyNameForStamp(projectId, user_id, role),
      resolvePositionAndSideForStamp(projectId, user_id, role),
    ]);
    stamp.company_name = companyName;
    stamp.position = positionSide.position;
    stamp.side = positionSide.side;
    res.json({ success: true, stamp });
  } catch (err) { console.error('POST my-stamp:', err); res.status(500).json({ error: 'Failed to save stamp.' }); }
});

// -- Live stamp preview: the SAME renderer as the real stamp, returned as a one-page PDF --
app.post('/api/stamp-preview', authenticateToken, photoUpload.fields([{ name: 'markImage', maxCount: 1 }]), async (req, res) => {
  const { user_id, role } = req.user;
  const projectId = parseInt(req.query.projectId, 10);
  if (!projectId) return res.status(400).json({ error: 'projectId required' });
  try {
    const saved = await loadSignerProfile(projectId, role, user_id).catch(() => null);
    const [name, company, ps] = await Promise.all([
      resolveSignerNameForStamp(projectId, user_id, role),
      resolveCompanyNameForStamp(projectId, user_id, role),
      resolvePositionAndSideForStamp(projectId, user_id, role),
    ]);
    let markSource = null;
    const f = req.files?.markImage?.[0];
    if (f && /^image\/(png|jpeg)$/i.test(f.mimetype)) markSource = `data:${f.mimetype};base64,${f.buffer.toString('base64')}`;
    else if (typeof req.body.markDataUrl === 'string' && /^data:image\/(png|jpeg);base64,/i.test(req.body.markDataUrl)) markSource = req.body.markDataUrl;
    else markSource = pickMark(saved);
    const label = String(req.body.label || 'APPROVED').toUpperCase() === 'SIGNED' ? 'SIGNED' : 'APPROVED';
    const tz = await loadProjectTz(projectId);
    const spec = stampSpecFromProfile(
      { name: saved?.name || name || 'Your Name', company: company || null, position: ps?.position || null, side: ps?.side || null, mark_type: req.body.markType || saved?.mark_type, signature_image: markSource, stamp_image_url: null },
      { label, signedAt: new Date(), tz, stampId: 'OP-7F3A-92C1', baseUrl: publicBaseUrl(req) }
    );
    const out = await buildStampPreviewPdf(spec);
    res.set({ 'Content-Type': 'application/pdf', 'Cache-Control': 'no-store', 'X-Stamp-Box': `${out.width},${out.height}`, 'Access-Control-Expose-Headers': 'X-Stamp-Box' });
    res.send(out.bytes);
  } catch (err) { console.error('POST stamp-preview:', err); res.status(500).json({ error: 'Could not build the stamp preview.' }); }
});

// -- Verification (public: the Stamp ID is the credential) --
const STAMP_ID_RE = /^OP-[0-9A-F]{4}-[0-9A-F]{4}$/;
async function lookupStamp(id) {
  if (!STAMP_ID_RE.test(String(id || '').toUpperCase())) return null;
  const { rows } = await pool.query(
    `SELECT r.*, p.name AS project_name FROM stamp_registry r LEFT JOIN projects p ON p.id = r.project_id WHERE r.stamp_id = $1`,
    [String(id).toUpperCase()]
  );
  return rows[0] || null;
}
const stampPublicView = (r) => ({
  valid: true, stampId: r.stamp_id, signer: r.signer_name, position: r.signer_position, company: r.company_name,
  action: r.label, project: r.project_name || null, signedAt: formatStampDate(r.signed_at, r.tz || 'UTC'),
  fileCheckAvailable: Boolean(r.file_hash),
});
app.get('/api/verify-stamp/:id', async (req, res) => {
  try {
    const r = await lookupStamp(req.params.id);
    if (!r) return res.status(404).json({ valid: false, message: 'No stamp with this ID was issued by OneProject.' });
    res.json(stampPublicView(r));
  } catch (err) { console.error('verify-stamp:', err); res.status(500).json({ valid: false, message: 'Verification is unavailable right now.' }); }
});
// Optional: upload the PDF you were given; it matches only if it is byte-identical to the stamped file.
app.post('/api/verify-stamp/:id', upload.single('file'), async (req, res) => {
  try {
    const r = await lookupStamp(req.params.id);
    if (!r) return res.status(404).json({ valid: false, message: 'No stamp with this ID was issued by OneProject.' });
    if (!r.file_hash) return res.json({ ...stampPublicView(r), fileMatches: null, message: 'This stamp has no stored file fingerprint to compare against.' });
    if (!req.file) return res.status(400).json({ message: 'Attach the PDF to compare.' });
    const h = crypto.createHash('sha256').update(req.file.buffer).digest('hex');
    res.json({ ...stampPublicView(r), fileMatches: h === r.file_hash });
  } catch (err) { console.error('verify-stamp file:', err); res.status(500).json({ message: 'Verification is unavailable right now.' }); }
});
app.get('/verify/:id', async (req, res) => {
  const esc = (v) => String(v ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  let r = null;
  try { r = await lookupStamp(req.params.id); } catch (_) { /* shown as unavailable below */ }
  const row = (k, v) => v ? `<tr><th>${k}</th><td>${esc(v)}</td></tr>` : '';
  const v = r ? stampPublicView(r) : null;
  res.set('Content-Type', 'text/html; charset=utf-8').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Stamp verification</title>
<style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#f4f5f7;color:#1c232d;margin:0;padding:24px}main{max-width:460px;margin:8vh auto;background:#fff;border:1px solid #d5d9df;border-radius:10px;padding:22px}h1{font-size:18px;margin:0 0 4px}p{color:#5b6572;font-size:13px;margin:0 0 14px}table{border-collapse:collapse;width:100%;font-size:14px}th{text-align:left;color:#5b6572;font-weight:600;padding:6px 10px 6px 0;width:34%;vertical-align:top}td{padding:6px 0}.ok{font-weight:700}</style></head><body><main>
${v ? `<h1 class="ok">Stamp verified</h1><p>This stamp was issued by OneProject.</p><table>${row('Stamp ID', v.stampId)}${row('Action', v.action)}${row('Signed by', v.signer)}${row('Position', v.position)}${row('Company', v.company)}${row('Project', v.project)}${row('Date and time', v.signedAt)}</table>`
 : `<h1>Stamp not found</h1><p>No stamp with the ID ${esc(req.params.id)} was issued by OneProject. Check the ID printed on the document.</p>`}
</main></body></html>`);
});

app.delete('/api/delete-record', authenticateToken, async (req, res) => {
  const { projectId, recordId, recordType } = req.body;
  const userId = req.user.user_id;
  const table  = resolveTable(recordType);
  if (!table) return res.status(400).json({ error: 'Invalid or missing recordType.' });
  try {
    const { rows } = await pool.query(`SELECT uploaded_by, role FROM ${table} WHERE id=$1 AND project_id=$2`, [recordId, projectId]);
    if (!rows.length) return res.status(404).json({ error: 'Record not found.' });
    if (String(rows[0].uploaded_by) !== String(userId) || getSide(rows[0].role) !== getSide(req.user.role)) return res.status(403).json({ error: 'Only the uploader can delete this record.' });
    const { rows: decidedRows } = await pool.query(`SELECT 1 FROM document_reviews WHERE record_type=$1 AND record_id=$2 AND action IN ('approved','accepted','rejected') LIMIT 1`, [table, recordId]);
    const { rows: signedRows } = await pool.query(`SELECT 1 FROM record_signers WHERE record_table=$1 AND record_id=$2 AND status='signed' LIMIT 1`, [table, recordId]);
    if (decidedRows.length || signedRows.length) return res.status(409).json({ error: 'A record under review can no longer be deleted.' });
    // A deleted revision gives the rejected record back its open queries
    await pool.query(`UPDATE ${table} SET superseded_by_id=NULL WHERE superseded_by_id=$1 AND project_id=$2`, [recordId, projectId]);
    await pool.query(`UPDATE record_queries SET status='open', response=NULL, responded_at=NULL, responded_in_record_id=NULL, responded_by_role=NULL, responded_by_id=NULL WHERE record_table=$1 AND responded_in_record_id=$2`, [table, recordId]);
    await pool.query('DELETE FROM record_signers WHERE record_table=$1 AND record_id=$2', [table, recordId]);
    await pool.query('DELETE FROM record_queries WHERE record_table=$1 AND record_id=$2', [table, recordId]);
    await pool.query(`DELETE FROM notification_recipients WHERE notification_id IN (SELECT id FROM notifications WHERE entity_id=$1 AND entity_type=$2)`, [recordId, table]);
    await pool.query('DELETE FROM notifications WHERE entity_id=$1 AND entity_type=$2', [recordId, table]);
    await pool.query('DELETE FROM document_reviews WHERE record_type=$1 AND record_id=$2', [table, recordId]);
    await pool.query(`DELETE FROM ${table} WHERE id=$1 AND project_id=$2`, [recordId, projectId]);
    res.json({ success: true, message: 'Record deleted successfully.' });
  } catch (err) { console.error('Delete record error:', err); res.status(500).json({ error: 'Failed to delete record.' }); }
});

// ─────────────────────────────────────────────────────────────────────────────
//  MEETINGS
// ─────────────────────────────────────────────────────────────────────────────
function meetingParticipantLabel(member) {
  const role = member.role || '';
  if (role === 'Client') return [member.representative, member.title, role].filter(Boolean).join(' · ');
  if (role === 'Contractor' || role === 'Consultant') return [member.representative, member.title_position, role].filter(Boolean).join(' · ');
  if (role.endsWith('PM')) return [member.title, role.replace(/([A-Z])/g, ' $1').trim()].filter(Boolean).join(' · ');
  if (role === 'TeamMember') return [member.title, member.position, member.assigned_part, 'Team Member'].filter(Boolean).join(' · ');
  return member.display_name || member.representative || member.email || role || 'Project participant';
}

async function normalizeMeetingParticipants(projectId, rawParticipants, legacyParticipants = '') {
  let submitted;
  try { submitted = rawParticipants ? JSON.parse(rawParticipants) : []; }
  catch { throw new Error('Participant data is invalid.'); }
  if (!Array.isArray(submitted)) throw new Error('Participants must be a list.');
  if (!submitted.length && legacyParticipants) {
    submitted = String(legacyParticipants).split(/\r?\n/).map(name => ({ source: 'manual', name }));
  }
  const members = await getProjectMembers(projectId);
  const memberMap = new Map(members.map(member => [`${member.role}:${member.role_id}`, member]));
  return submitted.map(person => {
    const attendanceType = ['required', 'optional', 'information'].includes(person?.attendance_type)
      ? person.attendance_type
      : 'required';
    if (person?.source === 'manual') {
      const name = String(person.name || '').trim();
      if (!name || name.length > 160) throw new Error('Manual participant names must be between 1 and 160 characters.');
      const email = String(person.email || '').trim().toLowerCase();
      if (email && (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254)) {
        throw new Error(`Enter a valid email address for external participant ${name}.`);
      }
      return { source: 'manual', name, email, attendance_type: attendanceType };
    }
    const member = memberMap.get(`${person?.role}:${person?.role_id}`);
    if (!member) throw new Error('A selected participant is not a member of this project.');
    return {
      source: 'project', role: member.role, role_id: member.role_id,
      name: meetingParticipantLabel(member), email: member.email || '', company_name: member.company_name || '',
      attendance_type: attendanceType,
    };
  });
}

function isValidMeetingTimeZone(value) {
  try {
    new Intl.DateTimeFormat('en', { timeZone: value }).format();
    return true;
  } catch {
    return false;
  }
}

function meetingLocalTimeToUtc(value, timeZone) {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(value);
  if (!match || !isValidMeetingTimeZone(timeZone)) return null;
  const [, year, month, day, hour, minute] = match;
  const desired = Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute));
  let candidate = desired;
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone, year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  });
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const parts = formatter.formatToParts(new Date(candidate))
      .reduce((result, part) => (result[part.type] = part.value, result), {});
    const asUtc = Date.UTC(Number(parts.year), Number(parts.month) - 1, Number(parts.day), Number(parts.hour), Number(parts.minute));
    const adjustment = desired - asUtc;
    if (!adjustment) break;
    candidate += adjustment;
  }
  const finalParts = formatter.formatToParts(new Date(candidate))
    .reduce((result, part) => (result[part.type] = part.value, result), {});
  if (finalParts.year !== year || finalParts.month !== month || finalParts.day !== day
    || finalParts.hour !== hour || finalParts.minute !== minute) return null;
  return new Date(candidate);
}

function sanitizeMeetingHtml(value) {
  return String(value ?? '')
    .replace(/<(script|style|iframe|object|svg|math)[^>]*>[\s\S]*?<\/\1\s*>/gi, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<\/?([a-z][a-z0-9]*)\b[^>]*>/gi, (tag, name) => {
      const allowed = new Set(['p', 'br', 'strong', 'b', 'em', 'i', 'u', 'ul', 'ol', 'li', 'h2', 'h3', 'blockquote']);
      const normalized = name.toLowerCase();
      if (!allowed.has(normalized)) return '';
      return /^<\//.test(tag) ? `</${normalized}>` : `<${normalized}>`;
    });
}

function meetingHtmlToPlainText(value) {
  return sanitizeMeetingHtml(value)
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|li|h2|h3|blockquote)>/gi, '\n')
    .replace(/<[^>]*>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/[ \t]+\n/g, '\n')
    .trim();
}

function pdfPlainText(value) {
  return String(value || '')
    .replace(/[\u00b7\u2022]/g, '-').replace(/[\u2013\u2014]/g, '-')
    .replace(/[\u2018\u2019]/g, "'").replace(/[\u201c\u201d]/g, '"')
    .normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[^\x20-\x7E\n]/g, '?');
}

// ── Meeting rules, helpers and PDF builders ─────────────────────────────────
const MEETING_TYPES = ['site', 'office', 'virtual'];
const MEETING_TYPE_LABELS = { site: 'Site meeting', office: 'Office meeting', virtual: 'Virtual meeting' };
const MEETING_SCOPES = ['global', 'side'];
const MEETING_LIMITS = { title: 200, location: 300, purpose: 5000, agenda: 8000, virtual_link: 500, safety_notes: 2000, chairperson: 160, minute_taker: 160, meeting_number: 80 };
const MEETING_FIELD_LABELS = { title: 'Title', location: 'Location', purpose: 'Purpose', agenda: 'Agenda' };
const MEETING_MIGRATION = 'backend/migrations/2026-10-12-meeting-cancel-and-report-audit.sql';
const MEETING_PROFESSIONAL_MIGRATION = 'backend/migrations/2026-10-13-professional-meetings.sql';

const meetingAttachmentUpload = multer({
  limits: { fileSize: 25 * 1024 * 1024, files: 10 },
  storage: multer.memoryStorage(),
});
function meetingAttachmentsMiddleware(req, res, next) {
  meetingAttachmentUpload.array('attachments', 10)(req, res, err => {
    if (!err) return next();
    const message = err.code === 'LIMIT_FILE_SIZE' ? 'Each attachment must be 25 MB or smaller.'
      : (err.code === 'LIMIT_UNEXPECTED_FILE' || err.code === 'LIMIT_FILE_COUNT') ? 'You can attach up to 10 files.'
      : 'Could not read the uploaded files.';
    return res.status(400).json({ error: message });
  });
}
function meetingReportMiddleware(req, res, next) {
  meetingMinutePdfUpload.single('report')(req, res, err => {
    if (!err) return next();
    const message = err.code === 'LIMIT_FILE_SIZE' ? 'The meeting report must be 50 MB or smaller.'
      : err.message === 'Meeting report must be a PDF' ? 'Attach one valid PDF meeting report.'
      : 'Could not read the uploaded report.';
    return res.status(400).json({ error: message });
  });
}

// The optional columns arrive with the 2026-10-12 migration; the API works before and after it.
let meetingColumnsCache = { at: 0, value: null };
async function getMeetingColumns() {
  if (meetingColumnsCache.value && Date.now() - meetingColumnsCache.at < 60000) return meetingColumnsCache.value;
  const { rows } = await pool.query(
    `SELECT table_name, column_name FROM information_schema.columns
     WHERE table_schema = current_schema() AND table_name IN ('meetings','meeting_minutes')`);
  const has = (table, column) => rows.some(row => row.table_name === table && row.column_name === column);
  const value = {
    cancel: ['status', 'cancelled_at', 'cancelled_by', 'cancelled_by_role', 'cancel_reason'].every(column => has('meetings', column)),
    reportAudit: has('meeting_minutes', 'report_uploaded_at') && has('meeting_minutes', 'report_version'),
  };
  meetingColumnsCache = { at: Date.now(), value };
  return value;
}

function isMeetingCancelled(meeting) {
  return meeting?.status === 'cancelled' || Boolean(meeting?.cancelled_at);
}

function isMeetingPlannerRow(meeting, user) {
  return Number(meeting.created_by) === Number(user.user_id)
    && normalizeRole(meeting.created_role) === normalizeRole(user.role);
}

// Side (contractor / consultant / client) that a user belongs to on a project.
// Team members take the side of their assigned part, like the notification logic does.
async function getMeetingUserSide(userId, role, projectId) {
  const side = getSide(role);
  if (side) return side;
  if (normalizeRole(role) === 'TeamMember') {
    const { rows } = await pool.query(
      'SELECT assigned_part FROM team_member_assignments WHERE project_id=$1 AND team_member_id=$2 ORDER BY id DESC LIMIT 1',
      [projectId, userId]);
    const part = String(rows[0]?.assigned_part || '').trim().toLowerCase();
    return part || null;
  }
  return null;
}
const meetingSideKeys = side => [side, `${side}pm`, `${side}projectmanager`];

// Global meetings are visible to the whole project; side meetings only to that side.
async function canViewMeeting(user, meeting) {
  if (!await userHasProjectAccess(user.user_id, user.role, meeting.project_id)) return false;
  if (meeting.scope !== 'side') return true;
  const userSide = await getMeetingUserSide(user.user_id, user.role, meeting.project_id);
  return Boolean(userSide) && userSide === getSide(meeting.scope_value);
}

async function getMeetingLabels(projectId) {
  const members = await getProjectMembers(projectId);
  return new Map(members.map(member => [`${normalizeRole(member.role)}:${Number(member.role_id)}`, meetingParticipantLabel(member)]));
}
const meetingActorKey = (role, id) => `${normalizeRole(role)}:${Number(id)}`;

const MEETING_DATE_FORMAT = { weekday: 'short', day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' };
function formatMeetingWhen(meeting) {
  const date = meeting?.scheduled_at ? new Date(meeting.scheduled_at)
    : meeting?.date_time ? new Date(meeting.date_time) : null;
  if (!date || Number.isNaN(date.getTime())) return null;
  const options = meeting.time_zone ? { ...MEETING_DATE_FORMAT, timeZone: meeting.time_zone } : MEETING_DATE_FORMAT;
  const parts = new Intl.DateTimeFormat('en-GB', options)
    .formatToParts(date).reduce((out, part) => (out[part.type] = part.value, out), {});
  return `${parts.weekday} ${parts.day} ${parts.month} ${parts.year}, ${parts.hour}:${parts.minute}${meeting.time_zone ? ` ${meeting.time_zone}` : ''}`;
}

function parseMeetingBody(body, projectTimeZone = '') {
  const clean = value => String(value ?? '').trim();
  const meeting = {
    meeting_type: clean(body.meeting_type).toLowerCase() || (String(body.is_draft).toLowerCase() === 'true' ? 'site' : ''), title: clean(body.title), location: clean(body.location),
    purpose: sanitizeMeetingHtml(body.purpose), date_time: clean(body.date_time),
    end_time: clean(body.end_time), time_zone: clean(body.time_zone || projectTimeZone),
    virtual_link: clean(body.virtual_link), safety_notes: clean(body.safety_notes),
    chairperson: clean(body.chairperson), minute_taker: clean(body.minute_taker),
    meeting_number: clean(body.meeting_number), scope: clean(body.scope),
    agenda_items: body.agenda_items,
    is_draft: String(body.is_draft).toLowerCase() === 'true',
    recurrence_frequency: clean(body.recurrence_frequency),
    recurrence_until: clean(body.recurrence_until),
  };
  if (!meeting.is_draft && (!meeting.meeting_type || !meeting.title || !meeting.date_time || !meeting.end_time
    || !meeting.purpose || !meeting.scope || !meeting.chairperson || !meeting.minute_taker)) {
    return { error: 'All required fields must be provided' };
  }
  if (!MEETING_TYPES.includes(meeting.meeting_type)) return { error: 'Meeting type must be site, office or virtual.' };
  if (!meeting.is_draft && !MEETING_SCOPES.includes(meeting.scope)) return { error: 'Invalid meeting scope.' };
  if (meeting.is_draft && !meeting.scope) meeting.scope = 'global';
  if (!meeting.is_draft && !isValidMeetingTimeZone(meeting.time_zone)) return { error: 'Choose a valid project time zone.' };
  if (meeting.is_draft && !meeting.time_zone) meeting.time_zone = 'UTC';
  if (!isValidMeetingTimeZone(meeting.time_zone)) return { error: 'Choose a valid project time zone.' };
  if (meeting.meeting_type !== 'virtual') meeting.virtual_link = '';
  if (meeting.virtual_link) {
    try {
      const parsedLink = new URL(meeting.virtual_link);
      if (!['https:', 'http:'].includes(parsedLink.protocol)) throw new Error('invalid protocol');
    } catch {
      return { error: 'Enter a valid virtual meeting link.' };
    }
  }
  if (!meeting.is_draft && meeting.meeting_type === 'virtual' && !meeting.virtual_link) {
    return { error: 'Enter a valid virtual meeting link.' };
  }
  if (!meeting.is_draft && meeting.meeting_type !== 'virtual' && !meeting.location) {
    return { error: 'Enter the meeting location.' };
  }
  let agendaItems;
  try { agendaItems = meeting.agenda_items ? typeof meeting.agenda_items === 'string' ? JSON.parse(meeting.agenda_items) : meeting.agenda_items : []; }
  catch { return { error: 'Agenda data is invalid.' }; }
  if (!Array.isArray(agendaItems) || (!meeting.is_draft && !agendaItems.length)) return { error: 'Add at least one agenda item.' };
  if (agendaItems.length > 100) return { error: 'A meeting cannot have more than 100 agenda items.' };
  if (agendaItems.some(item => clean(item?.title).length > 300 || clean(item?.presenter).length > 160)) {
    return { error: 'Agenda topics must be 300 characters or fewer and presenter names 160 characters or fewer.' };
  }
  meeting.agenda_items = agendaItems.map((item, index) => ({
    title: clean(item?.title),
    presenter: clean(item?.presenter),
    duration_minutes: Number(item?.duration_minutes),
    details: sanitizeMeetingHtml(item?.details),
    position: index + 1,
  }));
  if (!meeting.is_draft && meeting.agenda_items.some(item =>
    !item.title || !Number.isInteger(item.duration_minutes) || item.duration_minutes < 1 || item.duration_minutes > 480)) {
    return { error: 'Each agenda item needs a topic and a duration from 1 to 480 minutes.' };
  }
  meeting.agenda = meeting.agenda_items.map(item => `${item.title}: ${meetingHtmlToPlainText(item.details)}`).join('\n');
  if (!meeting.is_draft && meeting.agenda.length > MEETING_LIMITS.agenda) return { error: `Agenda must not exceed ${MEETING_LIMITS.agenda} characters.` };
  for (const [field, max] of Object.entries(MEETING_LIMITS)) {
    const length = field === 'purpose' ? meetingHtmlToPlainText(meeting[field]).length : String(meeting[field] || '').length;
    if (length > max) return { error: `${MEETING_FIELD_LABELS[field] || field.replaceAll('_', ' ')} must not exceed ${max} characters.` };
  }
  const instant = meeting.date_time ? meetingLocalTimeToUtc(meeting.date_time, meeting.time_zone) : null;
  const endInstant = meeting.end_time ? meetingLocalTimeToUtc(meeting.end_time, meeting.time_zone) : null;
  if (!meeting.is_draft && (!instant || !endInstant || instant.getTime() <= Date.now())) {
    return { error: 'Meeting date and time must be in the future.' };
  }
  if (!meeting.is_draft && (endInstant <= instant || endInstant - instant > 12 * 60 * 60 * 1000)) return { error: 'End time must be after the start time and no more than 12 hours later.' };
  if (!meeting.is_draft && meeting.recurrence_frequency && !['weekly', 'biweekly', 'monthly'].includes(meeting.recurrence_frequency)) return { error: 'Choose a supported recurrence frequency.' };
  if (!meeting.is_draft && meeting.recurrence_frequency) {
    const until = new Date(`${meeting.recurrence_until}T00:00:00Z`);
    if (!meeting.recurrence_until || Number.isNaN(until.getTime()) || until <= instant || until > new Date(instant.getTime() + 366 * 24 * 60 * 60 * 1000)) {
      return { error: 'Choose a recurrence end date within one year of the first meeting.' };
    }
  }
  if (meeting.is_draft && !meeting.date_time) meeting.date_time = '2000-01-01T00:00';
  if (meeting.is_draft && !meeting.title) meeting.title = 'Untitled draft';
  meeting.scheduledInstant = instant;
  meeting.endInstant = endInstant;
  return { value: meeting };
}

async function notifyMeetingChange(client, meeting, actor, message) {
  const { rows } = await client.query(
    `INSERT INTO notifications (project_id,entity_id,entity_type,message,added_by_id,added_by_role) VALUES ($1,$2,'meetings',$3,$4,$5) RETURNING id`,
    [meeting.project_id, meeting.id, message, actor.user_id, actor.role]);
  const recipients = await getProjectRecipientKeys(meeting.project_id, actor.user_id, actor.role, meeting.scope, meeting.scope_value);
  await insertNotificationRecipients(client, rows[0].id, recipients);
}

function addMeetingRecurrence(localValue, frequency, count) {
  const [datePart, timePart] = localValue.split('T');
  const [year, month, day] = datePart.split('-').map(Number);
  const [hour, minute] = timePart.split(':').map(Number);
  if (frequency === 'monthly') {
    const monthIndex = month - 1 + count;
    const targetYear = year + Math.floor(monthIndex / 12);
    const targetMonth = monthIndex % 12;
    const targetDay = Math.min(day, new Date(Date.UTC(targetYear, targetMonth + 1, 0)).getUTCDate());
    return `${targetYear}-${String(targetMonth + 1).padStart(2, '0')}-${String(targetDay).padStart(2, '0')}T${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`;
  }
  const date = new Date(Date.UTC(year, month - 1, day + count * (frequency === 'biweekly' ? 14 : 7), hour, minute));
  return `${date.toISOString().slice(0, 10)}T${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`;
}

function getMeetingOccurrences(meeting) {
  if (!meeting.recurrence_frequency || meeting.is_draft) return [{ start: meeting.date_time, end: meeting.end_time, time_zone: meeting.time_zone }];
  const until = meeting.recurrence_until;
  const duration = meetingLocalTimeToUtc(meeting.end_time, meeting.time_zone)
    .getTime() - meetingLocalTimeToUtc(meeting.date_time, meeting.time_zone).getTime();
  const occurrences = [];
  for (let index = 0; index < 52; index += 1) {
    const start = addMeetingRecurrence(meeting.date_time, meeting.recurrence_frequency, index);
    if (start.slice(0, 10) > until) break;
    const startInstant = meetingLocalTimeToUtc(start, meeting.time_zone);
    if (!startInstant) throw new Error(`The recurring meeting time does not exist in ${meeting.time_zone} on ${start.slice(0, 10)} because of a daylight-saving transition.`);
    if (index && startInstant.getTime() > Date.now()) {
      const endDate = new Date(startInstant.getTime() + duration);
      const endParts = new Intl.DateTimeFormat('en-CA', {
        timeZone: meeting.time_zone, year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
      }).formatToParts(endDate).reduce((result, part) => (result[part.type] = part.value, result), {});
      const end = `${endParts.year}-${endParts.month}-${endParts.day}T${endParts.hour}:${endParts.minute}`;
      occurrences.push({ start, end, time_zone: meeting.time_zone });
    }
    if (!index) occurrences.push({ start, end: meeting.end_time, time_zone: meeting.time_zone });
    if (occurrences.length >= 52) break;
  }
  return occurrences;
}

function participantKey(person) {
  return person.source === 'project'
    ? `project:${person.role}:${person.role_id}`
    : `manual:${String(person.email || '').toLowerCase()}`;
}

async function createMeetingRsvps(client, meeting, participants) {
  const invitations = [];
  for (const person of participants) {
    const key = participantKey(person);
    const token = person.source === 'manual' ? crypto.randomBytes(32).toString('hex') : null;
    await client.query(
      `INSERT INTO meeting_rsvps
        (meeting_id,participant_key,participant_name,participant_email,participant_role,participant_role_id,participant_source,token_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (meeting_id,participant_key) DO UPDATE SET
         participant_name=EXCLUDED.participant_name, participant_email=EXCLUDED.participant_email,
         participant_role=EXCLUDED.participant_role, participant_role_id=EXCLUDED.participant_role_id,
         participant_source=EXCLUDED.participant_source, token_hash=COALESCE(EXCLUDED.token_hash,meeting_rsvps.token_hash),
         reminder_sent_at=NULL`,
      [meeting.id, key, person.name, person.email || null, person.role || null, person.role_id || null, person.source, token ? crypto.createHash('sha256').update(token).digest('hex') : null]
    );
    if (person.source === 'manual' && person.email) invitations.push({ ...person, token });
  }
  return invitations;
}

async function findMeetingConflicts(projectId, occurrences, participants, actor, excludeMeetingId = null) {
  if (!participants.length) return [];
  const occurrenceWindows = occurrences.map(occurrence => ({
    start: meetingLocalTimeToUtc(occurrence.start, occurrence.time_zone),
    end: meetingLocalTimeToUtc(occurrence.end, occurrence.time_zone),
  }));
  const minStart = new Date(Math.min(...occurrenceWindows.map(window => window.start.getTime())));
  const maxEnd = new Date(Math.max(...occurrenceWindows.map(window => window.end.getTime())));
  const { rows } = await pool.query(
    `SELECT id,project_id,scope,scope_value,title,scheduled_at,end_at,time_zone,participant_details
       FROM meetings
      WHERE project_id=$1 AND is_draft=false AND status='scheduled'
        AND scheduled_at < $2 AND end_at > $3 AND ($4::integer IS NULL OR id<>$4)`,
    [projectId, maxEnd, minStart, excludeMeetingId]
  );
  const inviteeKeys = new Set(participants.map(participantKey));
  const conflicts = rows.filter(row => {
    const meetingStart = new Date(row.scheduled_at).getTime();
    const meetingEnd = new Date(row.end_at).getTime();
    if (!occurrenceWindows.some(window =>
      meetingStart < window.end.getTime() && meetingEnd > window.start.getTime())) return false;
    const rowKeys = new Set((row.participant_details || []).map(participantKey));
    return [...inviteeKeys].some(key => rowKeys.has(key));
  });
  const visible = [];
  let hiddenCount = 0;
  for (const row of conflicts) {
    if (await canViewMeeting(actor, row)) visible.push({
      id: row.id,
      title: row.title,
      when: formatMeetingWhen(row),
    });
    else hiddenCount += 1;
  }
  if (hiddenCount) visible.push({ title: 'Another project meeting (details hidden)', when: '' });
  return visible;
}

function escapeMeetingEmail(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

async function sendMeetingInvitations(meeting, invitees, baseUrl) {
  const when = formatMeetingWhen(meeting);
  const results = await Promise.allSettled(invitees.map(person => {
    const rsvpUrl = person.token
      ? `${baseUrl}/api/meetings/rsvp?token=${encodeURIComponent(person.token)}`
      : `${baseUrl}/dashboard.html`;
    return transporter.sendMail({
      from: 'skyprincenkp16@gmail.com',
      to: person.email,
      subject: `${meeting.is_draft ? 'Draft: ' : ''}Meeting invitation — ${meeting.title}`,
      text: `${meeting.title}\n${when}\n${meeting.location || meeting.virtual_link}\n${meeting.purpose ? meetingHtmlToPlainText(meeting.purpose) : ''}\nRSVP: ${rsvpUrl}`,
      html: `<p>You are invited to <strong>${escapeMeetingEmail(meeting.title)}</strong>.</p><p>${escapeMeetingEmail(when || '')}</p><p>${escapeMeetingEmail(meeting.location || meeting.virtual_link || '')}</p><p><a href="${escapeMeetingEmail(rsvpUrl)}">Respond to this invitation</a></p>`,
    });
  }));
  results.forEach((result, index) => {
    if (result.status === 'rejected') console.error('Meeting invitation email failed:', invitees[index].email, result.reason);
  });
  return results.flatMap((result, index) => result.status === 'rejected' ? [invitees[index].email] : []);
}

async function destroyUploadedMeetingFiles(files) {
  await Promise.all(files.map(file =>
    cloudinary.uploader.destroy(file.public_id, { resource_type: file.resource_type || 'image' }).catch(() => {})));
}

async function buildMeetingBriefPdf(meeting, references = []) {
  const pdf = await PDFDocument.create();
  const regular = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const pageSize = [612, 792];
  let page = pdf.addPage(pageSize);
  let y = 744;
  const addPage = () => { page = pdf.addPage(pageSize); y = 744; };
  const drawLines = (value, font, size, color, indent = 0) => {
    const maxWidth = 516 - indent;
    const paragraphs = pdfPlainText(value).split('\n');
    for (const paragraph of paragraphs) {
      const words = paragraph.split(/\s+/).filter(Boolean).flatMap(word => {
        if (font.widthOfTextAtSize(word, size) <= maxWidth) return [word];
        const chunks = [];
        let chunk = '';
        for (const character of word) {
          const candidate = chunk + character;
          if (chunk && font.widthOfTextAtSize(candidate, size) > maxWidth) {
            chunks.push(chunk);
            chunk = character;
          } else chunk = candidate;
        }
        if (chunk) chunks.push(chunk);
        return chunks;
      });
      let line = '';
      const lines = [];
      for (const word of words) {
        const candidate = line ? `${line} ${word}` : word;
        if (line && font.widthOfTextAtSize(candidate, size) > maxWidth) {
          lines.push(line);
          line = word;
        } else line = candidate;
      }
      if (line || !words.length) lines.push(line);
      for (const text of lines) {
        if (y < 56) addPage();
        if (text) page.drawText(text, { x: 48 + indent, y, size, font, color, maxWidth });
        y -= size + 5;
      }
    }
  };
  const section = (label, value) => {
    drawLines(label.toUpperCase(), bold, 9, rgb(0.04, 0.39, 0.43));
    drawLines(value || 'Not provided', regular, 11, rgb(0.12, 0.16, 0.2), 8);
    y -= 7;
  };

  const cancelled = isMeetingCancelled(meeting);
  page.drawRectangle({ x: 0, y: 766, width: 612, height: 26, color: rgb(0.02, 0.34, 0.39) });
  page.drawText(pdfPlainText(`MEETING PLAN${meeting.project_name ? `  |  ${meeting.project_name}` : ''}`), { x: 48, y: 775, size: 10, font: bold, color: rgb(1, 1, 1), maxWidth: 410 });
  if (cancelled) {
    page.drawRectangle({ x: 470, y: 766, width: 142, height: 26, color: rgb(0.7, 0.13, 0.13) });
    page.drawText('CANCELLED', { x: 502, y: 775, size: 10, font: bold, color: rgb(1, 1, 1) });
  }
  y = 724;
  drawLines(meeting.title || 'Meeting', bold, 20, rgb(0.1, 0.17, 0.21));
  y -= 8;
  if (meeting.project_reference) section('Project reference', meeting.project_reference);
  if (meeting.meeting_number) section('Meeting number', meeting.meeting_number);
  section('Meeting type', MEETING_TYPE_LABELS[meeting.meeting_type] || meeting.meeting_type);
  section('Date and time', meeting.is_draft ? 'Not scheduled (draft)' : formatMeetingWhen(meeting));
  if (meeting.end_at) section('End time', formatMeetingWhen({ scheduled_at: meeting.end_at, time_zone: meeting.time_zone }));
  if (meeting.location || meeting.meeting_type !== 'virtual') section('Location / access details', meeting.location || '—');
  if (meeting.virtual_link) section('Virtual meeting link', meeting.virtual_link);
  if (meeting.safety_notes) section('Site access / safety notes', meeting.safety_notes);
  section('Visibility', meeting.scope === 'side'
    ? `${String(getSide(meeting.scope_value) || 'Team').replace(/^./, c => c.toUpperCase())} side only`
    : 'All project participants');
  if (meeting.planned_by_name) section('Planned by', meeting.planned_by_name);
  if (meeting.chairperson) section('Chairperson', meeting.chairperson);
  if (meeting.minute_taker) section('Minute-taker', meeting.minute_taker);
  section('Purpose', meetingHtmlToPlainText(meeting.purpose));
  const selected = Array.isArray(meeting.participant_details) && meeting.participant_details.length
    ? meeting.participant_details.map(person => `${person.name || 'Project participant'}${person.email ? ` <${person.email}>` : ''} (${{ required: 'required', optional: 'optional', information: 'for information' }[person.attendance_type] || 'required'})`).join('\n')
    : meeting.participants;
  section('Participants', selected);
  const agendaText = Array.isArray(meeting.agenda_items) && meeting.agenda_items.length
    ? meeting.agenda_items.map((item, index) => `${index + 1}. ${item.title} — ${item.duration_minutes} min${item.presenter ? ` · ${item.presenter}` : ''}\n${meetingHtmlToPlainText(item.details)}`).join('\n')
    : meetingHtmlToPlainText(meeting.agenda);
  section('Agenda', agendaText);
  if (references.length) section('Attachments / references', references.map(file => file.name).join('\n'));

  const generated = new Date().toISOString().slice(0, 10);
  pdf.getPages().forEach(pg => {
    pg.drawLine({ start: { x: 48, y: 40 }, end: { x: 564, y: 40 }, thickness: 0.5, color: rgb(0.8, 0.84, 0.87) });
    pg.drawText(pdfPlainText(`OneProjectApp  |  Meeting plan #${meeting.id}  |  Generated ${generated}`), { x: 48, y: 26, size: 8, font: regular, color: rgb(0.45, 0.5, 0.54) });
  });
  return Buffer.from(await pdf.save());
}

async function buildMergedMeetingReportPdf(meeting, references, uploadedReport) {
  const coverBytes = await buildMeetingBriefPdf(meeting, references);
  const cover = await PDFDocument.load(coverBytes);
  const source = await PDFDocument.load(uploadedReport);
  const merged = await PDFDocument.create();
  for (const document of [cover, source]) {
    const pages = await merged.copyPages(document, document.getPageIndices());
    pages.forEach(page => merged.addPage(page));
  }
  return Buffer.from(await merged.save());
}

app.get('/api/meetings', authenticateToken, async (req, res) => {
  const { view, scope, project_id } = req.query;
  if (!project_id || !view || !scope) return res.status(400).json({ error: 'project_id, view and scope are required' });
  if (!['scheduled', 'minutes'].includes(view)) return res.status(400).json({ error: 'view must be scheduled or minutes' });
  if (!MEETING_SCOPES.includes(scope)) return res.status(400).json({ error: 'Invalid meeting scope.' });
  try {
    if (!await userHasProjectAccess(req.user.user_id, req.user.role, project_id)) return res.status(403).json({ error: 'Access denied to this project' });
    const params = [project_id, scope, new Date(), req.user.user_id, req.user.role];
    let scopeFilter = '';
    if (scope === 'side') {
      // The side always comes from the signed-in user, never from the query string.
      const side = await getMeetingUserSide(req.user.user_id, req.user.role, project_id);
      if (!side) return res.status(403).json({ error: 'Your role does not belong to a project side.' });
      params.push(meetingSideKeys(side));
      scopeFilter = ` AND LOWER(REGEXP_REPLACE(COALESCE(m.scope_value,''), '[\\s_-]+', '', 'g')) = ANY($6)`;
    }
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 500, 1), 500);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    params.push(limit, offset);
    const { rows } = await pool.query(`
      SELECT m.*, p.name AS project_name, p.contract_reference AS project_reference,
        to_char(m.date_time, 'YYYY-MM-DD"T"HH24:MI') AS date_time_local,
        to_char(m.scheduled_at AT TIME ZONE COALESCE(m.time_zone, p.time_zone, 'UTC'), 'YYYY-MM-DD"T"HH24:MI') AS start_time_local,
        to_char(m.end_at AT TIME ZONE COALESCE(m.time_zone, p.time_zone, 'UTC'), 'YYYY-MM-DD"T"HH24:MI') AS end_time_local,
        EXISTS (SELECT 1 FROM meeting_minutes mm WHERE mm.meeting_id = m.id) AS has_minute,
        (SELECT json_build_object('id',mm.id,'attendees',mm.attendees,'agenda_discussed',mm.agenda_discussed,'decisions',mm.decisions,'action_items',mm.action_items,'next_meeting_date',mm.next_meeting_date,
          'created_by',mm.created_by,'created_role',mm.created_role,
          'uploaded_at',COALESCE(to_jsonb(mm)->>'report_uploaded_at', to_jsonb(mm)->>'created_at'),
          'version',to_jsonb(mm)->>'report_version',
          'attachments',(SELECT COALESCE(json_agg(json_build_object('name',a.name,'url',a.url)),'[]') FROM meeting_attachments a WHERE a.minute_id=mm.id)) FROM meeting_minutes mm WHERE mm.meeting_id=m.id LIMIT 1) AS minute,
        (SELECT COALESCE(json_agg(json_build_object('name',a.name,'url',a.url)),'[]') FROM meeting_attachments a WHERE a.meeting_id=m.id AND a.minute_id IS NULL) AS attachments,
        (SELECT COALESCE(json_agg(json_build_object('participant_key',r.participant_key,'participant_name',r.participant_name,'response',r.response,'participant_source',r.participant_source,'participant_role',r.participant_role,'participant_role_id',r.participant_role_id)),'[]')
         FROM meeting_rsvps r WHERE r.meeting_id=m.id) AS rsvps,
        (SELECT COUNT(*) + 1 FROM meetings recurring WHERE recurring.recurrence_group=m.recurrence_group
           AND recurring.scheduled_at < m.scheduled_at) AS series_index
      FROM meetings m JOIN projects p ON p.id=m.project_id
      WHERE m.project_id=$1 AND m.scope=$2 AND (m.is_draft = false OR (m.is_draft = true AND m.created_by=$4 AND m.created_role=$5))
        AND (m.is_draft = false OR '${view}' = 'scheduled')
        AND (m.is_draft = true OR COALESCE(m.scheduled_at, m.date_time::timestamptz) ${view==='scheduled'?'>=':'<'} $3)
      ${scopeFilter}
      ORDER BY m.is_draft DESC, COALESCE(m.scheduled_at, m.date_time::timestamptz) ${view==='scheduled'?'ASC':'DESC'}
      LIMIT $${params.length - 1} OFFSET $${params.length}
    `, params);
    if (rows.length) {
      const labels = await getMeetingLabels(project_id);
      rows.forEach(row => {
        row.planned_by_name = labels.get(meetingActorKey(row.created_role, row.created_by)) || null;
        if (row.minute) row.minute.uploaded_by_name = labels.get(meetingActorKey(row.minute.created_role, row.minute.created_by)) || null;
      });
    }
    res.json(rows);
  } catch (err) { console.error('GET /api/meetings:', err); res.status(500).json({ error: 'Failed to load meetings' }); }
});

app.get('/api/meetings/:id/pdf', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT m.*, p.name AS project_name, p.contract_reference AS project_reference,
        to_char(m.date_time, 'YYYY-MM-DD"T"HH24:MI') AS date_time_local,
        (SELECT COALESCE(json_agg(json_build_object('name',a.name)), '[]'::json)
         FROM meeting_attachments a WHERE a.meeting_id=m.id AND a.minute_id IS NULL) AS meeting_references
      FROM meetings m JOIN projects p ON p.id=m.project_id WHERE m.id=$1
    `, [req.params.id]);
    const meeting = rows[0];
    if (!meeting) return res.status(404).json({ error: 'Meeting not found' });
    if (!await canViewMeeting(req.user, meeting)) return res.status(403).json({ error: 'Access denied to this meeting' });
    if (meeting.is_draft && !isMeetingPlannerRow(meeting, req.user)) return res.status(404).json({ error: 'Meeting not found' });
    meeting.planned_by_name = (await getMeetingLabels(meeting.project_id)).get(meetingActorKey(meeting.created_role, meeting.created_by)) || null;
    const pdf = await buildMeetingBriefPdf(meeting, meeting.meeting_references || []);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="meeting-${meeting.id}-plan.pdf"`);
    return res.send(pdf);
  } catch (err) {
    console.error('Meeting plan PDF error:', err);
    return res.status(500).json({ error: 'Could not generate the meeting plan PDF' });
  }
});

app.get('/api/meetings/:id/ics', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT m.*, p.name AS project_name FROM meetings m JOIN projects p ON p.id=m.project_id WHERE m.id=$1`,
      [req.params.id]
    );
    const meeting = rows[0];
    if (!meeting) return res.status(404).json({ error: 'Meeting not found.' });
    if (!await canViewMeeting(req.user, meeting)) return res.status(403).json({ error: 'Access denied to this meeting.' });
    if (meeting.is_draft) return res.status(409).json({ error: 'Draft meetings cannot be added to a calendar.' });
    const icsEscape = value => String(value || '').replace(/\\/g, '\\\\').replace(/\r\n|\r|\n/g, '\\n').replace(/,/g, '\\,').replace(/;/g, '\\;');
    const icsDate = value => new Date(value).toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
    const foldIcsLine = line => {
      const chunks = [];
      let chunk = '';
      let bytes = 0;
      for (const character of line) {
        const characterBytes = Buffer.byteLength(character, 'utf8');
        if (bytes + characterBytes > 75) {
          chunks.push(chunk);
          chunk = ` ${character}`;
          bytes = 1 + characterBytes;
        } else {
          chunk += character;
          bytes += characterBytes;
        }
      }
      chunks.push(chunk);
      return chunks.join('\r\n');
    };
    const cancelled = isMeetingCancelled(meeting);
    const contents = [
      'BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//OneProjectApp//Meeting Plan//EN',
      'CALSCALE:GREGORIAN', `METHOD:${cancelled ? 'CANCEL' : 'PUBLISH'}`, 'BEGIN:VEVENT',
      `UID:meeting-${meeting.id}@oneprojectapp`,
      `DTSTAMP:${icsDate(new Date())}`,
      `DTSTART:${icsDate(meeting.scheduled_at)}`,
      `DTEND:${icsDate(meeting.end_at)}`,
      ...(cancelled ? ['STATUS:CANCELLED'] : []),
      `SUMMARY:${icsEscape(meeting.title)}`,
      `LOCATION:${icsEscape(meeting.location || meeting.virtual_link)}`,
      `DESCRIPTION:${icsEscape(`${meeting.project_name}\n${meetingHtmlToPlainText(meeting.purpose)}\n${meeting.virtual_link || ''}`)}`,
      'END:VEVENT', 'END:VCALENDAR',
    ].map(foldIcsLine).join('\r\n');
    res.setHeader('Content-Type', 'text/calendar; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="meeting-${meeting.id}.ics"`);
    return res.send(contents);
  } catch (err) {
    console.error('Meeting calendar download error:', err);
    return res.status(500).json({ error: 'Could not create the calendar file.' });
  }
});

app.get('/api/meetings/rsvp', async (req, res) => {
  const token = String(req.query.token || '');
  if (!/^[a-f0-9]{64}$/i.test(token)) return res.status(400).send('This invitation link is invalid.');
  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const { rows } = await pool.query(
      `SELECT r.participant_name,m.title,m.scheduled_at,m.time_zone,m.location,m.virtual_link,m.id AS meeting_id
         FROM meeting_rsvps r JOIN meetings m ON m.id=r.meeting_id
        WHERE r.token_hash=$1 AND m.is_draft=false AND m.status='scheduled'`,
      [tokenHash]
    );
    if (!rows.length) return res.status(404).send('This invitation has expired or is no longer available.');
    const meeting = rows[0];
    const heading = `RSVP for ${escapeMeetingEmail(meeting.title)}`;
    const form = `<p>Hello ${escapeMeetingEmail(meeting.participant_name)}, please respond to this invitation.</p>
      <p>${escapeMeetingEmail(formatMeetingWhen(meeting) || '')}<br>${escapeMeetingEmail(meeting.location || meeting.virtual_link || '')}</p>
      <form method="post" action="/api/meetings/${meeting.meeting_id}/rsvp">
      <input type="hidden" name="token" value="${escapeMeetingEmail(token)}">
      <button name="response" value="accepted">Accept</button>
      <button name="response" value="declined">Decline</button></form>`;
    return res.type('html').send(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${heading}</title><main style="font:16px system-ui;max-width:600px;margin:4rem auto;padding:1rem"><h1>${heading}</h1>${form}</main>`);
  } catch (err) {
    console.error('External meeting RSVP lookup failed:', err);
    return res.status(500).send('Could not load this invitation.');
  }
});

app.post('/api/meetings/:id/rsvp', express.urlencoded({ extended: false }), async (req, res, next) => {
  if (req.body?.token) {
    const token = String(req.body.token);
    const response = String(req.body.response || '');
    if (!/^[a-f0-9]{64}$/i.test(token) || !['accepted', 'declined'].includes(response)) {
      return res.status(400).send('The invitation response is invalid.');
    }
    try {
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const { rowCount } = await pool.query(
        `UPDATE meeting_rsvps r SET response=$1,responded_at=NOW()
          FROM meetings m
         WHERE r.meeting_id=m.id AND m.id=$2 AND r.token_hash=$3 AND m.is_draft=false AND m.status='scheduled'`,
        [response, req.params.id, tokenHash]
      );
      if (!rowCount) return res.status(404).send('This invitation has expired or is no longer available.');
      return res.type('html').send(`<!doctype html><meta charset="utf-8"><title>RSVP saved</title><main style="font:16px system-ui;max-width:600px;margin:4rem auto;padding:1rem"><h1>Response saved</h1><p>Thank you. Your response was recorded as ${response}.</p></main>`);
    } catch (err) {
      console.error('External meeting RSVP update failed:', err);
      return res.status(500).send('Could not save your response.');
    }
  }
  return authenticateToken(req, res, async () => {
    const response = String(req.body?.response || '');
    if (!['accepted', 'declined'].includes(response)) return res.status(400).json({ error: 'RSVP must be accepted or declined.' });
    try {
      const { rows } = await pool.query('SELECT * FROM meetings WHERE id=$1 AND is_draft=false AND status=$2', [req.params.id, 'scheduled']);
      const meeting = rows[0];
      if (!meeting) return res.status(404).json({ error: 'Meeting not found.' });
      const normalizeRsvpRole = role => String(role || '').trim().toLowerCase()
        .replace(/[\s_-]+/g, '')
        .replace(/^(client|contractor|consultant)projectmanager$/, '$1pm');
      const person = (meeting.participant_details || []).find(entry => entry.source === 'project'
        && normalizeRsvpRole(entry.role) === normalizeRsvpRole(req.user.role)
        && String(entry.role_id) === String(req.user.user_id));
      if (!person) return res.status(403).json({ error: 'You are not an invitee for this meeting.' });
      const { rowCount } = await pool.query(
        'UPDATE meeting_rsvps SET response=$1,responded_at=NOW() WHERE meeting_id=$2 AND participant_key=$3',
        [response, req.params.id, `project:${person.role}:${person.role_id}`]
      );
      if (!rowCount) return res.status(404).json({ error: 'RSVP record not found.' });
      return res.json({ success: true, response });
    } catch (err) {
      console.error('Internal meeting RSVP failed:', err);
      return res.status(500).json({ error: 'Could not save your response.' });
    }
  });
});

app.post('/api/meetings', authenticateToken, meetingAttachmentsMiddleware, requireProjectLifecycleWrite, async (req, res) => {
  const { project_id, participants, participant_details } = req.body;
  if (!project_id) return res.status(400).json({ error: 'All required fields must be provided' });
  if (normalizeRole(req.user.role) === 'TeamMember') return res.status(403).json({ error: 'Team members cannot schedule meetings.' });
  if (!await userHasProjectAccess(req.user.user_id, req.user.role, project_id)) return res.status(403).json({ error: 'Access denied to this project' });
  const { rows: projectRows } = await pool.query('SELECT name,contract_reference,time_zone FROM projects WHERE id=$1', [project_id]);
  const project = projectRows[0];
  if (!project) return res.status(404).json({ error: 'Project not found.' });
  const parsed = parseMeetingBody(req.body, project.time_zone);
  if (parsed.error) return res.status(400).json({ error: parsed.error });
  const m = parsed.value;
  // Who can see a side meeting is decided by the planner's own role, not by the request body.
  if (m.scope === 'side' && !getSide(req.user.role)) return res.status(403).json({ error: 'Only a project side can plan side meetings.' });
  const scopeValue = m.scope === 'side' ? req.user.role : null;
  let participantDetails;
  try { participantDetails = await normalizeMeetingParticipants(project_id, participant_details, participants); }
  catch (err) { return res.status(400).json({ error: err.message }); }
  if (!m.is_draft && !participantDetails.length) return res.status(400).json({ error: 'Select or add at least one participant' });
  if (!m.is_draft && participantDetails.some(person => person.source === 'manual' && !person.email)) {
    return res.status(400).json({ error: 'Add an email address for each external participant before scheduling.' });
  }
  let occurrences;
  try { occurrences = getMeetingOccurrences(m); }
  catch (err) { return res.status(400).json({ error: err.message }); }
  if (!m.is_draft && req.body.confirm_conflicts !== 'true') {
    const conflicts = await findMeetingConflicts(project_id, occurrences, participantDetails, req.user);
    if (conflicts.length) return res.status(409).json({ error: 'One or more participants have another meeting during this time.', conflicts });
  }
  const client = await pool.connect();
  const uploaded = [];
  const createdMeetings = [];
  const inviteesByMeeting = [];
  const seriesId = occurrences.length > 1 ? uuidv4() : null;
  try {
    await client.query('BEGIN');
    const participantNames = participantDetails.map(person => person.name).join('\n');
    const attachmentRecords = [];
    for (const file of req.files || []) {
      const result = await uploadToCloudinary(file.buffer, 'meeting_attachments');
      uploaded.push({ public_id: result.public_id, resource_type: result.resource_type });
      attachmentRecords.push({ name: file.originalname, url: result.secure_url, public_id: result.public_id });
    }
    for (let index = 0; index < occurrences.length; index += 1) {
      const occurrence = occurrences[index];
      const startInstant = m.is_draft ? null : meetingLocalTimeToUtc(occurrence.start, m.time_zone);
      const endInstant = m.is_draft ? null : meetingLocalTimeToUtc(occurrence.end, m.time_zone);
      const recurrenceRule = m.recurrence_frequency
        ? { frequency: m.recurrence_frequency, until: m.recurrence_until }
        : null;
      const { rows } = await client.query(
        `INSERT INTO meetings
          (project_id,meeting_type,title,meeting_number,date_time,scheduled_at,end_at,time_zone,location,virtual_link,safety_notes,
           participants,participant_details,purpose,agenda,agenda_items,chairperson,minute_taker,scope,scope_value,created_by,created_role,is_draft,
           recurrence_group,recurrence_rule)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16::jsonb,$17,$18,$19,$20,$21,$22,$23,$24,$25::jsonb)
         RETURNING *`,
        [project_id,m.meeting_type,m.title,m.meeting_number || null,occurrence.start,startInstant,endInstant,m.time_zone,
          m.location || '',m.virtual_link || null,m.safety_notes || null,participantNames,JSON.stringify(participantDetails),
          m.purpose,m.agenda,JSON.stringify(m.agenda_items),m.chairperson || null,m.minute_taker || null,m.scope,scopeValue,
          req.user.user_id,req.user.role,m.is_draft,seriesId,recurrenceRule ? JSON.stringify(recurrenceRule) : null]
      );
      const meeting = { ...rows[0], project_name: project.name, project_reference: project.contract_reference };
      createdMeetings.push(meeting);
      const invitees = m.is_draft ? [] : await createMeetingRsvps(client, meeting, participantDetails);
      inviteesByMeeting.push(invitees);
      for (const file of attachmentRecords) {
        await client.query(
          'INSERT INTO meeting_attachments (meeting_id,name,url,public_id) VALUES ($1,$2,$3,$4)',
          [meeting.id,file.name,file.url,file.public_id]
        );
      }
      if (!m.is_draft) {
        const when = formatMeetingWhen(meeting) || occurrence.start;
        const notifMsg = m.scope === 'side'
          ? `New ${m.meeting_type} meeting scheduled by ${req.user.role} for ${getSide(req.user.role)} side: "${m.title}" on ${when}`
          : `New ${m.meeting_type} meeting scheduled by ${req.user.role}: "${m.title}" on ${when}`;
        await notifyMeetingChange(client, meeting, req.user, notifMsg);
      }
    }
    await client.query('COMMIT');
    const apiBase = String(process.env.PUBLIC_API_URL || 'https://oneprojectapp-backend.onrender.com').replace(/\/$/, '');
    const failedInvitations = [];
    for (let index = 0; index < createdMeetings.length; index += 1) {
      if (inviteesByMeeting[index].length) {
        failedInvitations.push(...await sendMeetingInvitations(createdMeetings[index], inviteesByMeeting[index], apiBase));
      }
    }
    res.status(201).json({
      meeting: createdMeetings[0],
      occurrences: createdMeetings.length,
      notification_warnings: failedInvitations.length ? [`Could not email these external invitees: ${failedInvitations.join(', ')}`] : [],
    });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    await destroyUploadedMeetingFiles(uploaded);
    console.error('POST /api/meetings:', err);
    const schemaOutOfDate = ['42703', '42P01'].includes(err.code)
      && /scheduled_at|participant_details|purpose|time_zone|end_at|agenda_items|meeting_rsvps|is_draft|meeting_number|virtual_link|safety_notes|chairperson|minute_taker|recurrence_group|recurrence_rule/.test(err.message || '');
    res.status(500).json({ error: schemaOutOfDate
      ? `Meeting database schema is out of date. Run ${MEETING_PROFESSIONAL_MIGRATION} and retry.`
      : 'Failed to create meeting' });
  } finally { client.release(); }
});

app.put('/api/meetings/:id', authenticateToken, meetingAttachmentsMiddleware, requireProjectLifecycleWrite, async (req, res) => {
  const { project_id, participants, participant_details } = req.body;
  if (!project_id) return res.status(400).json({ error: 'All required fields must be provided' });
  if (normalizeRole(req.user.role) === 'TeamMember') return res.status(403).json({ error: 'Team members cannot edit meetings.' });
  const client = await pool.connect();
  const uploaded = [];
  try {
    if (!await userHasProjectAccess(req.user.user_id, req.user.role, project_id)) return res.status(403).json({ error: 'Access denied to this project' });
    const { rows: projectRows } = await client.query('SELECT name,contract_reference,time_zone FROM projects WHERE id=$1', [project_id]);
    const project = projectRows[0];
    if (!project) return res.status(404).json({ error: 'Project not found.' });
    const parsed = parseMeetingBody(req.body, project.time_zone);
    if (parsed.error) return res.status(400).json({ error: parsed.error });
    const m = parsed.value;
    const { rows: existingRows } = await client.query('SELECT * FROM meetings WHERE id=$1 AND project_id=$2', [req.params.id, project_id]);
    const existing = existingRows[0];
    if (!existing) return res.status(404).json({ error: 'Meeting not found' });
    if (!isMeetingPlannerRow(existing, req.user)) return res.status(403).json({ error: 'Only the meeting planner can edit this meeting' });
    if (isMeetingCancelled(existing)) return res.status(409).json({ error: 'A cancelled meeting cannot be edited.' });
    let participantDetails;
    try { participantDetails = await normalizeMeetingParticipants(project_id, participant_details, participants); }
    catch (err) { return res.status(400).json({ error: err.message }); }
    if (!m.is_draft && !participantDetails.length) return res.status(400).json({ error: 'Select or add at least one participant' });
    if (!m.is_draft && participantDetails.some(person => person.source === 'manual' && !person.email)) {
      return res.status(400).json({ error: 'Add an email address for each external participant before scheduling.' });
    }
    if (!m.is_draft && req.body.confirm_conflicts !== 'true') {
      const conflicts = await findMeetingConflicts(project_id, [{ start: m.date_time, end: m.end_time, time_zone: m.time_zone }], participantDetails, req.user, existing.id);
      if (conflicts.length) return res.status(409).json({ error: 'One or more participants have another meeting during this time.', conflicts });
    }

    await client.query('BEGIN');
    // Scope and side stay as they were planned; they cannot be changed from the request body.
    const { rows } = await client.query(
      `UPDATE meetings SET meeting_type=$1,title=$2,meeting_number=$3,date_time=$4,scheduled_at=$5,end_at=$6,time_zone=$7,
        location=$8,virtual_link=$9,safety_notes=$10,participants=$11,participant_details=$12::jsonb,purpose=$13,agenda=$14,
        agenda_items=$15::jsonb,chairperson=$16,minute_taker=$17,is_draft=$18
       WHERE id=$19 AND project_id=$20 RETURNING *`,
      [m.meeting_type,m.title,m.meeting_number || null,m.date_time,m.scheduledInstant,m.endInstant,m.time_zone,m.location || '',
        m.virtual_link || null,m.safety_notes || null,participantDetails.map(person => person.name).join('\n'),JSON.stringify(participantDetails),
        m.purpose,m.agenda,JSON.stringify(m.agenda_items),m.chairperson || null,m.minute_taker || null,m.is_draft,req.params.id,project_id]
    );
    const meetingTimeChanged = !existing.is_draft && !m.is_draft
      && (new Date(existing.scheduled_at).getTime() !== m.scheduledInstant.getTime()
        || new Date(existing.end_at).getTime() !== m.endInstant.getTime());
    if (meetingTimeChanged) {
      await client.query(
        `UPDATE meeting_rsvps SET response='pending',responded_at=NULL,reminder_sent_at=NULL WHERE meeting_id=$1`,
        [req.params.id]
      );
    }
    await client.query('DELETE FROM meeting_rsvps WHERE meeting_id=$1 AND NOT (participant_key = ANY($2::text[]))',
      [req.params.id, participantDetails.map(participantKey)]);
    const meeting = { ...rows[0], project_name: project.name, project_reference: project.contract_reference };
    const invitees = m.is_draft ? [] : await createMeetingRsvps(client, meeting, participantDetails);
    for (const file of req.files || []) {
      const result = await uploadToCloudinary(file.buffer, 'meeting_attachments');
      uploaded.push({ public_id: result.public_id, resource_type: result.resource_type });
      await client.query('INSERT INTO meeting_attachments (meeting_id,name,url,public_id) VALUES ($1,$2,$3,$4)', [req.params.id,file.originalname,result.secure_url,result.public_id]);
    }
    if (!m.is_draft) {
      const when = formatMeetingWhen(meeting) || m.date_time;
      await notifyMeetingChange(client, meeting, req.user, `Meeting updated by ${req.user.role}: "${m.title}" is now on ${when}`);
    }
    await client.query('COMMIT');
    let failedInvitations = [];
    if (invitees.length) {
      const apiBase = String(process.env.PUBLIC_API_URL || 'https://oneprojectapp-backend.onrender.com').replace(/\/$/, '');
      failedInvitations = await sendMeetingInvitations(meeting, invitees, apiBase);
    }
    return res.json({
      ...meeting,
      notification_warnings: failedInvitations.length ? [`Could not email these external invitees: ${failedInvitations.join(', ')}`] : [],
    });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    await destroyUploadedMeetingFiles(uploaded);
    console.error('PUT /api/meetings/:id:', err);
    const schemaOutOfDate = ['42703', '42P01'].includes(err.code)
      && /scheduled_at|participant_details|purpose|time_zone|end_at|agenda_items|meeting_rsvps|is_draft|meeting_number|virtual_link|safety_notes|chairperson|minute_taker|recurrence_group|recurrence_rule/.test(err.message || '');
    return res.status(500).json({ error: schemaOutOfDate
      ? `Meeting database schema is out of date. Run ${MEETING_PROFESSIONAL_MIGRATION} and retry.`
      : 'Failed to update meeting' });
  } finally { client.release(); }
});

app.patch('/api/meetings/:id/cancel', authenticateToken, requireProjectLifecycleWrite, async (req, res) => {
  const projectId = req.body?.project_id;
  if (!projectId) return res.status(400).json({ error: 'project_id is required' });
  if (normalizeRole(req.user.role) === 'TeamMember') return res.status(403).json({ error: 'Team members cannot cancel meetings.' });
  const reason = String(req.body?.reason || '').trim().slice(0, 500) || null;
  let client;
  try {
    if (!(await getMeetingColumns()).cancel) {
      return res.status(503).json({ error: `Cancelling meetings needs a database update. Run ${MEETING_MIGRATION} and retry.` });
    }
    if (!await userHasProjectAccess(req.user.user_id, req.user.role, projectId)) return res.status(403).json({ error: 'Access denied to this project' });
    const { rows: found } = await pool.query(`SELECT *, to_char(date_time, 'YYYY-MM-DD"T"HH24:MI') AS date_time_local FROM meetings WHERE id=$1 AND project_id=$2`, [req.params.id, projectId]);
    const meeting = found[0];
    if (!meeting) return res.status(404).json({ error: 'Meeting not found' });
    if (!isMeetingPlannerRow(meeting, req.user)) return res.status(403).json({ error: 'Only the meeting planner can cancel this meeting' });
    if (isMeetingCancelled(meeting)) return res.status(409).json({ error: 'This meeting is already cancelled.' });
    const when = new Date(meeting.scheduled_at || meeting.date_time);
    if (Number.isNaN(when.getTime()) || when.getTime() <= Date.now()) return res.status(400).json({ error: 'Only upcoming meetings can be cancelled.' });
    const { rows: externalInvitees } = await pool.query(
      `SELECT participant_name,participant_email FROM meeting_rsvps
        WHERE meeting_id=$1 AND participant_source='manual' AND participant_email IS NOT NULL`,
      [req.params.id]
    );

    client = await pool.connect();
    await client.query('BEGIN');
    const { rows } = await client.query(
      `UPDATE meetings SET status='cancelled', cancelled_at=NOW(), cancelled_by=$1, cancelled_by_role=$2, cancel_reason=$3 WHERE id=$4 AND project_id=$5 RETURNING *`,
      [req.user.user_id, req.user.role, reason, req.params.id, projectId]);
    await notifyMeetingChange(client, rows[0], req.user,
      `Meeting cancelled by ${req.user.role}: "${meeting.title}" (was ${formatMeetingWhen(meeting) || 'scheduled'})${reason ? `. Reason: ${reason}` : ''}`);
    await client.query('COMMIT');
    const cancelWhen = formatMeetingWhen(meeting) || '';
    const cancellationResults = await Promise.allSettled(externalInvitees.map(invitee =>
      Promise.resolve().then(() => transporter.sendMail({
        from: 'skyprincenkp16@gmail.com',
        to: invitee.participant_email,
        subject: `Cancelled: ${meeting.title}`,
        text: `The meeting "${meeting.title}"${cancelWhen ? ` on ${cancelWhen}` : ''} has been cancelled.${reason ? `\nReason: ${reason}` : ''}`,
        html: `<p>The meeting <strong>${escapeMeetingEmail(meeting.title)}</strong>${cancelWhen ? ` on ${escapeMeetingEmail(cancelWhen)}` : ''} has been cancelled.</p>${reason ? `<p>Reason: ${escapeMeetingEmail(reason)}</p>` : ''}`,
      }))
    ));
    const notificationWarnings = cancellationResults.flatMap((result, index) => {
      if (result.status === 'fulfilled') return [];
      console.error('Meeting cancellation email failed:', externalInvitees[index].participant_email, result.reason);
      return [externalInvitees[index].participant_email];
    });
    return res.json({
      ...rows[0],
      notification_warnings: notificationWarnings.length
        ? [`Could not email these external invitees: ${notificationWarnings.join(', ')}`]
        : [],
    });
  } catch (err) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    console.error('PATCH /api/meetings/:id/cancel:', err);
    return res.status(500).json({ error: 'Failed to cancel the meeting' });
  } finally { client?.release(); }
});

async function saveMeetingMinutePdf(req, res, replaceExisting) {
  const meetingId = req.params.id;
  const projectId = req.body.project_id;
  if (!projectId) return res.status(400).json({ error: 'project_id is required' });
  if (normalizeRole(req.user.role) === 'TeamMember') return res.status(403).json({ error: 'Team members cannot edit meeting minutes.' });
  if (!req.file || !req.file.buffer.subarray(0, 5).equals(Buffer.from('%PDF-'))) {
    return res.status(400).json({ error: 'Attach one valid PDF meeting report.' });
  }
  if (!await userHasProjectAccess(req.user.user_id, req.user.role, projectId)) return res.status(403).json({ error: 'Access denied to this project' });

  let client;
  let uploadedPdf;
  try {
    const { rows: meetingRows } = await pool.query(`SELECT *, to_char(date_time, 'YYYY-MM-DD"T"HH24:MI') AS date_time_local FROM meetings WHERE id=$1 AND project_id=$2`, [meetingId, projectId]);
    const meeting = meetingRows[0];
    if (!meeting) return res.status(404).json({ error: 'Meeting not found' });
    if (!isMeetingPlannerRow(meeting, req.user)) {
      return res.status(403).json({ error: 'Only the meeting planner can edit its meeting report' });
    }
    if (meeting.is_draft) return res.status(409).json({ error: 'A draft meeting cannot have a report.' });
    if (isMeetingCancelled(meeting)) return res.status(409).json({ error: 'A cancelled meeting cannot have a report.' });
    const heldAt = new Date(meeting.scheduled_at || meeting.date_time);
    if (!Number.isNaN(heldAt.getTime()) && heldAt.getTime() > Date.now()) {
      return res.status(400).json({ error: 'A report can only be added after the meeting has taken place.' });
    }
    const { rows: minuteRows } = await pool.query('SELECT * FROM meeting_minutes WHERE meeting_id=$1 LIMIT 1', [meetingId]);
    const existingMinute = minuteRows[0];
    if (replaceExisting && !existingMinute) return res.status(404).json({ error: 'Meeting report not found' });
    if (!replaceExisting && existingMinute) return res.status(409).json({ error: 'A meeting report already exists; use edit to replace it' });

    const labels = await getMeetingLabels(projectId);
    meeting.planned_by_name = labels.get(meetingActorKey(meeting.created_role, meeting.created_by)) || null;
    const { rows: referenceRows } = await pool.query('SELECT name FROM meeting_attachments WHERE meeting_id=$1 AND minute_id IS NULL ORDER BY id', [meetingId]);
    const { rows: projectRows } = await pool.query('SELECT name, contract_reference FROM projects WHERE id=$1', [projectId]);
    meeting.project_name = projectRows[0]?.name || null;
    meeting.project_reference = projectRows[0]?.contract_reference || null;
    const mergedPdf = await buildMergedMeetingReportPdf(meeting, referenceRows, req.file.buffer);
    uploadedPdf = await uploadToCloudinary(mergedPdf, 'meeting_attachments', 'raw');

    const audit = (await getMeetingColumns()).reportAudit;
    client = await pool.connect();
    await client.query('BEGIN');
    let minute;
    let oldAttachment = null;
    if (existingMinute) {
      const { rows: oldRows } = await client.query('SELECT id,public_id FROM meeting_attachments WHERE minute_id=$1 ORDER BY id DESC LIMIT 1', [existingMinute.id]);
      oldAttachment = oldRows[0] || null;
      const { rows } = await client.query(
        `UPDATE meeting_minutes SET attendees='',agenda_discussed='',decisions='',action_items='',created_by=$1,created_role=$2${audit ? ',report_uploaded_at=NOW(),report_version=COALESCE(report_version,1)+1' : ''} WHERE id=$3 RETURNING *`,
        [req.user.user_id,req.user.role,existingMinute.id]
      );
      minute = rows[0];
      await client.query('DELETE FROM meeting_attachments WHERE minute_id=$1', [minute.id]);
    } else {
      const { rows } = await client.query(
        `INSERT INTO meeting_minutes (meeting_id,project_id,attendees,agenda_discussed,decisions,action_items,next_meeting_date,scope,scope_value,created_by,created_role${audit ? ',report_uploaded_at,report_version' : ''}) VALUES ($1,$2,'','','','',NULL,$3,$4,$5,$6${audit ? ',NOW(),1' : ''}) RETURNING *`,
        [meetingId,projectId,meeting.scope,meeting.scope_value||null,req.user.user_id,req.user.role]
      );
      minute = rows[0];
    }
    const reportName = `meeting-${meetingId}-report.pdf`;
    await client.query('INSERT INTO meeting_attachments (minute_id,name,url,public_id) VALUES ($1,$2,$3,$4)', [minute.id,reportName,uploadedPdf.secure_url,uploadedPdf.public_id]);
    if (!existingMinute) {
      const message = `Meeting report recorded by ${req.user.role}: "${meeting.title}"`;
      const { rows: notificationRows } = await client.query(
        `INSERT INTO notifications (project_id,entity_id,entity_type,message,added_by_id,added_by_role) VALUES ($1,$2,'meeting_minutes',$3,$4,$5) RETURNING id`,
        [projectId,minute.id,message,req.user.user_id,req.user.role]
      );
      const recipients = await getProjectRecipientKeys(projectId, req.user.user_id, req.user.role, meeting.scope, meeting.scope_value);
      await insertNotificationRecipients(client, notificationRows[0].id, recipients);
    }
    await client.query('COMMIT');
    if (oldAttachment?.public_id) await cloudinary.uploader.destroy(oldAttachment.public_id, { resource_type: 'raw' }).catch(() => {});
    minute.attachments = [{ id: minute.id, name: reportName, url: uploadedPdf.secure_url }];
    minute.uploaded_at = minute.report_uploaded_at || new Date().toISOString();
    minute.uploaded_by_name = labels.get(meetingActorKey(req.user.role, req.user.user_id)) || null;
    minute.version = minute.report_version || null;
    return res.status(existingMinute ? 200 : 201).json({ minute });
  } catch (err) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    if (uploadedPdf?.public_id) await cloudinary.uploader.destroy(uploadedPdf.public_id, { resource_type: 'raw' }).catch(() => {});
    console.error('Meeting report save error:', err);
    return res.status(500).json({ error: 'Failed to save the meeting report PDF' });
  } finally {
    client?.release();
  }
}

app.post('/api/meetings/:id/minute', authenticateToken, meetingReportMiddleware, requireProjectLifecycleWrite, (req, res) => saveMeetingMinutePdf(req, res, false));
app.put('/api/meetings/:id/minute', authenticateToken, meetingReportMiddleware, requireProjectLifecycleWrite, (req, res) => saveMeetingMinutePdf(req, res, true));

app.get('/api/meetings/:id/minute/pdf', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT m.id, m.project_id, m.scope, m.scope_value, a.url FROM meetings m
      JOIN meeting_minutes mm ON mm.meeting_id=m.id
      JOIN meeting_attachments a ON a.minute_id=mm.id
      WHERE m.id=$1 ORDER BY a.id DESC LIMIT 1
    `, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Meeting report not found' });
    if (!await canViewMeeting(req.user, rows[0])) return res.status(403).json({ error: 'Access denied to this meeting' });
    const fileResponse = await fetch(rows[0].url);
    if (!fileResponse.ok) return res.status(502).json({ error: 'Saved meeting report is unavailable' });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="meeting-${req.params.id}-report.pdf"`);
    return res.send(Buffer.from(await fileResponse.arrayBuffer()));
  } catch (err) {
    console.error('Meeting report download error:', err);
    return res.status(500).json({ error: 'Could not download the meeting report PDF' });
  }
});

// =============================================================================
//  SCHEDULE MODULE  (unchanged — all routes preserved)
// =============================================================================

app.get('/api/get-schedule', authenticateToken, async (req, res) => {
  const projectId = normalizeProjectId(req.query.projectId);
  if (!projectId) return res.status(400).json({ error: 'Valid projectId is required' });
  try {
    const scheduleClock = await getProjectScheduleClock(projectId);
    const schedRow = await pool.query('SELECT * FROM project_schedules WHERE project_id=$1 LIMIT 1', [projectId]);
    if (!schedRow.rows.length) return res.json({ schedule: null, effective_today: scheduleClock?.effective_today || null, schedule_paused: scheduleClock?.paused || false, pause_started_at: scheduleClock?.pause_started_at || null });
    const sched = schedRow.rows[0];
    const msRows = await pool.query(`SELECT m.*,COALESCE(json_agg(json_build_object('id',e.id,'date',e.report_date,'qty',e.qty_executed,'remarks',e.remarks,'cumulative',e.cumulative_after_entry) ORDER BY e.report_date) FILTER (WHERE e.id IS NOT NULL),'[]') AS entries,COALESCE(json_agg(DISTINCT jsonb_build_object('fileName',a.file_name,'url',a.cloudinary_url,'publicId',a.cloudinary_public_id)) FILTER (WHERE a.id IS NOT NULL),'[]') AS attachments FROM milestones m LEFT JOIN milestone_progress_entries e ON e.milestone_id=m.id LEFT JOIN milestone_attachments a ON a.milestone_id=m.id WHERE m.schedule_id=$1 GROUP BY m.id ORDER BY m.sort_order`, [sched.id]);
    const amRows = await pool.query(`SELECT am.*,COALESCE(json_agg(json_build_object('id',e.id,'date',e.report_date,'qty',e.qty_executed,'remarks',e.remarks,'cumulative',e.cumulative_after_entry) ORDER BY e.report_date) FILTER (WHERE e.id IS NOT NULL),'[]') AS entries,COALESCE(json_agg(DISTINCT jsonb_build_object('fileName',a.file_name,'url',a.cloudinary_url)) FILTER (WHERE a.id IS NOT NULL),'[]') AS attachments FROM additional_milestones am LEFT JOIN additional_milestone_progress_entries e ON e.additional_milestone_id=am.id LEFT JOIN additional_milestone_attachments a ON a.additional_milestone_id=am.id WHERE am.schedule_id=$1 GROUP BY am.id ORDER BY am.sort_order`, [sched.id]);
    
    const extRows = await pool.query(`SELECT id,extension_days,COALESCE(new_planned_start,new_planned_finish - (extension_days || ' days')::interval) as new_planned_start,new_planned_finish,reason,extension_type,status,created_at,supporting_file_name,supporting_file_url,supporting_file_mime,supporting_file_size FROM schedule_extensions WHERE schedule_id=$1 ORDER BY created_at ASC`, [sched.id]);
    
    const mapMs = (ms, isExt) => ({ id:ms.id,title:ms.title,description:ms.description,start:ms.planned_start,end:ms.planned_end,quantity:ms.quantity,unit:ms.unit,dep:ms.depends_on||ms.depends_on_baseline||'None',weight_pct:ms.weight_pct,float_days:ms.float_days,is_critical:ms.is_critical,executed:ms.executed,progress_pct:ms.progress_pct,activity_status:ms.activity_status,completed_at:ms.completed_at,entries:ms.entries,fileName:ms.attachments?.[0]?.fileName||null,attachmentUrl:ms.attachments?.[0]?.url||null,isExtension:isExt,extensionId:ms.schedule_extension_id||null });
    res.json({ schedule: { id:sched.id,timeline:{start:sched.planned_start,finish:sched.planned_finish,duration:sched.total_duration},location:sched.location||null,milestones:msRows.rows.map(ms=>mapMs(ms,false)),extension_milestones:amRows.rows.map(ms=>mapMs(ms,true)),extensions:extRows.rows,effective_today:scheduleClock?.effective_today||null,schedule_paused:scheduleClock?.paused||false,pause_started_at:scheduleClock?.pause_started_at||null } });
  } catch (err) { console.error('[GET /api/get-schedule]', err); res.status(500).json({ error: 'Failed to load schedule' }); }
});

app.post('/api/save-schedule', authenticateToken, upload.any(), requireProjectLifecycleWrite, async (req, res) => {
  const projectId = normalizeProjectId(req.body.projectId);
  if (!projectId) return res.status(400).json({ error: 'Valid projectId is required' });
  let tl, rawMilestones, newIds, editedIds, unchangedIds, deletedIds;
  let addlRawMs, newAddlIds, editedAddlIds, unchangedAddlIds, deletedAddlIds;
  const location = parseJsonSafe(req.body.location);
  try {
    tl = JSON.parse(req.body.timeline);
    rawMilestones = JSON.parse(req.body.milestones);
    newIds = new Set(JSON.parse(req.body.newIds||'[]'));
    editedIds = new Set(JSON.parse(req.body.editedIds||'[]'));
    unchangedIds = new Set(JSON.parse(req.body.unchangedIds||'[]'));
    deletedIds = JSON.parse(req.body.deletedIds||'[]');
    addlRawMs = JSON.parse(req.body.additionalMilestones||'[]');
    newAddlIds = new Set(JSON.parse(req.body.newAddlIds||'[]'));
    editedAddlIds = new Set(JSON.parse(req.body.editedAddlIds||'[]'));
    unchangedAddlIds = new Set(JSON.parse(req.body.unchangedAddlIds||'[]'));
    deletedAddlIds = JSON.parse(req.body.deletedAddlIds||'[]');
  } catch {
    return res.status(400).json({ error: 'Invalid JSON in timeline, milestones, or additional milestone lists' });
  }
  const fileMap = {};
  (req.files||[]).forEach(f => { fileMap[f.fieldname.replace(/^file_/,'')] = f; });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const schedRes = await client.query(`INSERT INTO project_schedules (project_id,planned_start,planned_finish,total_duration,location,created_by_user_id,created_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (project_id) DO UPDATE SET planned_start=EXCLUDED.planned_start,planned_finish=EXCLUDED.planned_finish,total_duration=EXCLUDED.total_duration,location=COALESCE(EXCLUDED.location, project_schedules.location),updated_at=now() RETURNING *`, [projectId,tl.start,tl.finish,tl.duration,location,req.user.user_id,req.user.role]);
    const schedId = schedRes.rows[0].id;
    for (const dbId of deletedIds) {
      const check = await client.query('SELECT executed FROM milestones WHERE id=$1 AND schedule_id=$2', [dbId, schedId]);
      if (!check.rows.length) continue;
      if (parseFloat(check.rows[0].executed) > 0) { console.warn(`[save-schedule] Skipping delete of milestone ${dbId}: has recorded progress`); continue; }
      await client.query('DELETE FROM milestones WHERE id=$1 AND schedule_id=$2', [dbId, schedId]);
    }
    for (const dbId of deletedAddlIds) {
      const check = await client.query('SELECT executed FROM additional_milestones WHERE id=$1 AND schedule_id=$2', [dbId, schedId]);
      if (!check.rows.length) continue;
      if (parseFloat(check.rows[0].executed) > 0) { console.warn(`[save-schedule] Skipping delete of additional milestone ${dbId}: has recorded progress`); continue; }
      await client.query('DELETE FROM additional_milestones WHERE id=$1 AND schedule_id=$2', [dbId, schedId]);
    }
    const totalDur = rawMilestones.reduce((sum, ms) => sum + Math.max(1, daysBetween(ms.start, ms.end)), 0);
    const tempToReal = {};
    for (const ms of rawMilestones) { if (!newIds.has(ms.id)) tempToReal[ms.id] = ms.id; }
    const needsAttachment = [];
    for (let i = 0; i < rawMilestones.length; i++) {
      const ms = rawMilestones[i];
      const dur = Math.max(1, daysBetween(ms.start, ms.end));
      const float = Math.max(0, daysBetween(ms.end, tl.finish));
      const w = totalDur > 0 ? (dur / totalDur) * 100 : 0;
      const depId = ms.dep && ms.dep !== 'None' && tempToReal[ms.dep] ? tempToReal[ms.dep] : null;
      if (newIds.has(ms.id)) {
        const ins = await client.query(`INSERT INTO milestones (schedule_id,project_id,title,description,sort_order,planned_start,planned_end,duration_days,float_days,is_critical,weight_pct,quantity,unit,depends_on,created_by_user_id,created_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id`, [schedId,projectId,ms.title,ms.desc||ms.description||null,i,ms.start,ms.end,dur,float,float===0,w.toFixed(2),parseFloat(ms.qty||ms.quantity)||0,ms.unit||null,depId,req.user.user_id,req.user.role]);
        const realId = ins.rows[0].id; tempToReal[ms.id] = realId;
        if (fileMap[ms.id]) needsAttachment.push({ realId, tempId: ms.id });
      } else if (editedIds.has(ms.id)) {
        await client.query(`UPDATE milestones SET title=$1,description=$2,sort_order=$3,planned_start=$4,planned_end=$5,duration_days=$6,float_days=$7,is_critical=$8,weight_pct=$9,quantity=$10,unit=$11,depends_on=$12,updated_at=now() WHERE id=$13 AND schedule_id=$14`, [ms.title,ms.desc||ms.description||null,i,ms.start,ms.end,dur,float,float===0,w.toFixed(2),parseFloat(ms.qty||ms.quantity)||0,ms.unit||null,depId,ms.id,schedId]);
        if (fileMap[ms.id]) needsAttachment.push({ realId: ms.id, tempId: ms.id });
      } else if (unchangedIds.has(ms.id)) {
        await client.query('UPDATE milestones SET sort_order=$1 WHERE id=$2 AND schedule_id=$3', [i, ms.id, schedId]);
      }
    }

    // Additional milestones created in the extension period
    const addlTempToReal = {};
    for (const ms of addlRawMs) { if (!newAddlIds.has(ms.id)) addlTempToReal[ms.id] = ms.id; }
    const addlNeedsAttachment = [];
    for (let i = 0; i < addlRawMs.length; i++) {
      const ms = addlRawMs[i];
      const dur = Math.max(1, daysBetween(ms.start, ms.end));
      const float = Math.max(0, daysBetween(ms.end, tl.finish));
      const depId = ms.dep && ms.dep !== 'None' ? ms.dep : null;
      const weight = parseFloat(ms.weight_pct || 0) || 0;
      const isCritical = ms.is_critical ? true : false;
      if (newAddlIds.has(ms.id)) {
        const ins = await client.query(`INSERT INTO additional_milestones (schedule_id,project_id,title,description,sort_order,planned_start,planned_end,duration_days,float_days,is_critical,weight_pct,quantity,unit,depends_on_baseline,added_by_user_id,added_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id`, [schedId,projectId,ms.title,ms.desc||ms.description||null,i,ms.start,ms.end,dur,float,isCritical,weight,parseFloat(ms.qty||ms.quantity)||0,ms.unit||null,depId,req.user.user_id,req.user.role]);
        const realId = ins.rows[0].id; addlTempToReal[ms.id] = realId;
        if (fileMap[ms.id]) addlNeedsAttachment.push({ realId, tempId: ms.id });
      } else if (editedAddlIds.has(ms.id)) {
        await client.query(`UPDATE additional_milestones SET title=$1,description=$2,sort_order=$3,planned_start=$4,planned_end=$5,duration_days=$6,float_days=$7,is_critical=$8,weight_pct=$9,quantity=$10,unit=$11,depends_on_baseline=$12,updated_at=now() WHERE id=$13 AND schedule_id=$14`, [ms.title,ms.desc||ms.description||null,i,ms.start,ms.end,dur,float,isCritical,weight,parseFloat(ms.qty||ms.quantity)||0,ms.unit||null,depId,ms.id,schedId]);
        if (fileMap[ms.id]) addlNeedsAttachment.push({ realId: ms.id, tempId: ms.id });
      } else if (unchangedAddlIds.has(ms.id)) {
        await client.query('UPDATE additional_milestones SET sort_order=$1 WHERE id=$2 AND schedule_id=$3', [i, ms.id, schedId]);
      }
    }

    for (const { realId, tempId } of needsAttachment) {
      const file = fileMap[tempId]; if (!file) continue;
      try {
        const cdResult = await scheduleCloudinaryUpload(file.buffer, file.originalname, `oneprojectapp/schedules/${projectId}/milestones`);
        await client.query(`INSERT INTO milestone_attachments (milestone_id,file_name,file_size,mime_type,cloudinary_public_id,cloudinary_url,uploaded_by_user_id,uploaded_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (cloudinary_public_id) DO NOTHING`, [realId,file.originalname,file.size,file.mimetype,cdResult.public_id,cdResult.secure_url,req.user.user_id,req.user.role]);
      } catch (cdErr) { console.error('[save-schedule] Cloudinary upload failed for milestone', realId, cdErr); }
    }
    for (const { realId, tempId } of addlNeedsAttachment) {
      const file = fileMap[tempId]; if (!file) continue;
      try {
        const cdResult = await scheduleCloudinaryUpload(file.buffer, file.originalname, `oneprojectapp/schedules/${projectId}/additional`);
        await client.query(`INSERT INTO additional_milestone_attachments (additional_milestone_id,file_name,file_size,mime_type,cloudinary_public_id,cloudinary_url,uploaded_by_user_id,uploaded_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (cloudinary_public_id) DO NOTHING`, [realId,file.originalname,file.size,file.mimetype,cdResult.public_id,cdResult.secure_url,req.user.user_id,req.user.role]);
      } catch (cdErr) { console.error('[save-schedule] Cloudinary upload failed for additional milestone', realId, cdErr); }
    }
    await client.query('COMMIT');

    // Notify project members that the schedule was edited
    try {
      const notifClient = await pool.connect();
      try {
        await notifClient.query('BEGIN');
        const notifMsg = `Schedule updated by ${req.user.role}`;
        const notifRes = await notifClient.query(
          `INSERT INTO notifications (project_id, entity_id, entity_type, message, added_by_id, added_by_role)
           VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
          [projectId, schedId, 'project_schedules', notifMsg, req.user.user_id, req.user.role]
        );
        const notificationId = notifRes.rows[0].id;
        const recipients = await getProjectRecipientKeys(projectId, req.user.user_id, req.user.role);
        await insertNotificationRecipients(notifClient, notificationId, recipients);
        await notifClient.query('COMMIT');
        console.log('[notifications] created schedule update notification', { notificationId, projectId, schedId, recipients: recipients.length });
      } catch (notifErr) {
        await notifClient.query('ROLLBACK');
        console.error('[notifications] failed to create schedule notification (non-fatal):', notifErr.message);
      } finally { notifClient.release(); }
    } catch (outerNotifErr) {
      console.error('[notifications] outer error creating schedule notification (non-fatal):', outerNotifErr.message);
    }

    const freshMs = await pool.query(`SELECT m.*,COALESCE(json_agg(json_build_object('date',e.report_date,'qty',e.qty_executed,'remarks',e.remarks,'cumulative',e.cumulative_after_entry) ORDER BY e.report_date) FILTER (WHERE e.id IS NOT NULL),'[]') AS entries,COALESCE(json_agg(DISTINCT jsonb_build_object('fileName',a.file_name,'url',a.cloudinary_url,'publicId',a.cloudinary_public_id)) FILTER (WHERE a.id IS NOT NULL),'[]') AS attachments FROM milestones m LEFT JOIN milestone_progress_entries e ON e.milestone_id=m.id LEFT JOIN milestone_attachments a ON a.milestone_id=m.id WHERE m.schedule_id=$1 GROUP BY m.id ORDER BY m.sort_order`, [schedId]);
    const savedLocation = schedRes.rows[0]?.location || location || null;
    const extRows2 = await pool.query(`SELECT id,extension_days,new_planned_start,new_planned_finish,reason,extension_type,status,created_at FROM schedule_extensions WHERE schedule_id=$1 ORDER BY created_at ASC`, [schedId]);
    const amRows2 = await pool.query(`SELECT am.*,COALESCE(json_agg(json_build_object('date',e.report_date,'qty',e.qty_executed,'remarks',e.remarks,'cumulative',e.cumulative_after_entry) ORDER BY e.report_date) FILTER (WHERE e.id IS NOT NULL),'[]') AS entries,COALESCE(json_agg(DISTINCT jsonb_build_object('fileName',a.file_name,'url',a.cloudinary_url)) FILTER (WHERE a.id IS NOT NULL),'[]') AS attachments FROM additional_milestones am LEFT JOIN additional_milestone_progress_entries e ON e.additional_milestone_id=am.id LEFT JOIN additional_milestone_attachments a ON a.additional_milestone_id=am.id WHERE am.schedule_id=$1 GROUP BY am.id ORDER BY am.sort_order`, [schedId]);
    const mapExtMs = ms => ({ id:ms.id,title:ms.title,description:ms.description,start:ms.planned_start,end:ms.planned_end,quantity:ms.quantity,unit:ms.unit,dep:ms.depends_on_baseline||null,weight_pct:ms.weight_pct,float_days:ms.float_days,is_critical:ms.is_critical,executed:ms.executed,progress_pct:ms.progress_pct,activity_status:ms.activity_status,entries:ms.entries,fileName:ms.attachments?.[0]?.fileName||null,attachmentUrl:ms.attachments?.[0]?.url||null,added_via_extension:true });
    res.json({ success:true,schedule:{ id:schedId,timeline:{start:tl.start,finish:tl.finish,duration:tl.duration},location:savedLocation,milestones:freshMs.rows.map(ms=>({id:ms.id,title:ms.title,description:ms.description,start:ms.planned_start,end:ms.planned_end,quantity:ms.quantity,unit:ms.unit,dep:ms.depends_on||'None',weight_pct:ms.weight_pct,float_days:ms.float_days,is_critical:ms.is_critical,executed:ms.executed,progress_pct:ms.progress_pct,activity_status:ms.activity_status,entries:ms.entries,fileName:ms.attachments?.[0]?.fileName||null,attachmentUrl:ms.attachments?.[0]?.url||null})),extension_milestones:amRows2.rows.map(mapExtMs),extensions:extRows2.rows } });
  } catch (err) { await client.query('ROLLBACK'); console.error('[POST /api/save-schedule]', err); res.status(500).json({ error: 'Failed to save schedule' }); } finally { client.release(); }
});

app.post('/api/report-progress', authenticateToken, upload.single('attachment'), requireProjectLifecycleWrite, async (req, res) => {
  const projectId = normalizeProjectId(req.body.projectId);
  const { milestoneId, reportDate, remarks } = req.body;
  const qty = parseFloat(req.body.qtyExecuted);
  if (!projectId||!milestoneId||!reportDate||!qty||qty<=0) return res.status(400).json({ error: 'Valid projectId, milestoneId, reportDate and positive qtyExecuted are required' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const msRes = await client.query('SELECT * FROM milestones WHERE id=$1 AND project_id=$2 FOR UPDATE', [milestoneId, projectId]);
    if (!msRes.rows.length) return res.status(404).json({ error: 'Milestone not found' });
    const ms = msRes.rows[0];
    if (ms.activity_status==='completed') return res.status(409).json({ error: 'Milestone is already completed' });
    const planned=parseFloat(ms.quantity)||0, prevExec=parseFloat(ms.executed)||0, newExecuted=prevExec+qty;
    if (planned>0&&newExecuted>planned) return res.status(422).json({ error: `Cannot exceed planned quantity of ${planned} ${ms.unit||''}. Remaining: ${(planned-prevExec).toFixed(3)}` });
    const newPct = planned>0?Math.min(100,(newExecuted/planned)*100):0;
    const entryRes = await client.query(`INSERT INTO milestone_progress_entries (milestone_id,project_id,report_date,qty_executed,cumulative_after_entry,progress_pct_after_entry,remarks,reported_by_user_id,reported_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (milestone_id,report_date) DO UPDATE SET qty_executed=milestone_progress_entries.qty_executed+EXCLUDED.qty_executed,cumulative_after_entry=EXCLUDED.cumulative_after_entry,progress_pct_after_entry=EXCLUDED.progress_pct_after_entry,remarks=COALESCE(EXCLUDED.remarks,milestone_progress_entries.remarks),reported_by_user_id=EXCLUDED.reported_by_user_id,reported_by_role=EXCLUDED.reported_by_role RETURNING *`, [milestoneId,projectId,reportDate,qty,newExecuted,newPct.toFixed(2),remarks||null,req.user.user_id,req.user.role]);
    await client.query(`UPDATE milestones SET executed=$1,progress_pct=$2,activity_status='in_progress',updated_at=now() WHERE id=$3`, [newExecuted,newPct.toFixed(2),milestoneId]);
    if (req.file) {
      try { const cdResult=await scheduleCloudinaryUpload(req.file.buffer,req.file.originalname,`oneprojectapp/schedules/${projectId}/progress`); await client.query(`INSERT INTO progress_entry_attachments (progress_entry_id,file_name,file_size,mime_type,cloudinary_public_id,cloudinary_url,uploaded_by_user_id,uploaded_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, [entryRes.rows[0].id,req.file.originalname,req.file.size,req.file.mimetype,cdResult.public_id,cdResult.secure_url,req.user.user_id,req.user.role]); } catch(cdErr){console.error('[report-progress] Attachment upload failed:',cdErr);}
    }
    await client.query('COMMIT');
    const allEntries=await pool.query(`SELECT report_date AS date,qty_executed AS qty,remarks,cumulative_after_entry AS cumulative FROM milestone_progress_entries WHERE milestone_id=$1 ORDER BY report_date`, [milestoneId]);
    res.json({ success:true,milestone:{id:milestoneId,executed:newExecuted,progress_pct:parseFloat(newPct.toFixed(2)),activity_status:'in_progress',entries:allEntries.rows} });
  } catch (err) { await client.query('ROLLBACK'); console.error('[POST /api/report-progress]', err); res.status(500).json({ error: 'Failed to save progress entry' }); } finally { client.release(); }
});

app.post('/api/report-additional-progress', authenticateToken, upload.single('attachment'), requireProjectLifecycleWrite, async (req, res) => {
  const projectId = normalizeProjectId(req.body.projectId);
  const { milestoneId, reportDate, remarks } = req.body;
  const qty = parseFloat(req.body.qtyExecuted);
  if (!projectId||!milestoneId||!reportDate||!qty||qty<=0) return res.status(400).json({ error: 'Valid projectId, milestoneId, reportDate and positive qtyExecuted are required' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const msRes=await client.query('SELECT * FROM additional_milestones WHERE id=$1 AND project_id=$2 FOR UPDATE',[milestoneId,projectId]);
    if (!msRes.rows.length) return res.status(404).json({ error: 'Additional milestone not found' });
    const ms=msRes.rows[0];
    if (ms.activity_status==='completed') return res.status(409).json({ error: 'Milestone is already completed' });
    const planned=parseFloat(ms.quantity)||0,prevExec=parseFloat(ms.executed)||0,newExecuted=prevExec+qty;
    if (planned>0&&newExecuted>planned) return res.status(422).json({ error:`Cannot exceed planned quantity. Remaining: ${(planned-prevExec).toFixed(3)} ${ms.unit||''}` });
    const newPct=planned>0?Math.min(100,(newExecuted/planned)*100):0;
    const entryRes=await client.query(`INSERT INTO additional_milestone_progress_entries (additional_milestone_id,project_id,report_date,qty_executed,cumulative_after_entry,progress_pct_after_entry,remarks,reported_by_user_id,reported_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (additional_milestone_id,report_date) DO UPDATE SET qty_executed=additional_milestone_progress_entries.qty_executed+EXCLUDED.qty_executed,cumulative_after_entry=EXCLUDED.cumulative_after_entry,progress_pct_after_entry=EXCLUDED.progress_pct_after_entry,remarks=COALESCE(EXCLUDED.remarks,additional_milestone_progress_entries.remarks),reported_by_user_id=EXCLUDED.reported_by_user_id,reported_by_role=EXCLUDED.reported_by_role RETURNING id`,[milestoneId,projectId,reportDate,qty,newExecuted,newPct.toFixed(2),remarks||null,req.user.user_id,req.user.role]);
    await client.query(`UPDATE additional_milestones SET executed=$1,progress_pct=$2,activity_status='in_progress',updated_at=now() WHERE id=$3`,[newExecuted,newPct.toFixed(2),milestoneId]);
    if (req.file) { try{const cdResult=await scheduleCloudinaryUpload(req.file.buffer,req.file.originalname,`oneprojectapp/schedules/${projectId}/additional-progress`);await client.query(`INSERT INTO additional_milestone_attachments (additional_milestone_id,file_name,file_size,mime_type,cloudinary_public_id,cloudinary_url,uploaded_by_user_id,uploaded_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,[milestoneId,req.file.originalname,req.file.size,req.file.mimetype,cdResult.public_id,cdResult.secure_url,req.user.user_id,req.user.role]);}catch(cdErr){console.error('[report-additional-progress] Attachment upload failed:',cdErr);} }
    await client.query('COMMIT');
    const allEntries=await pool.query(`SELECT report_date AS date,qty_executed AS qty,remarks,cumulative_after_entry AS cumulative FROM additional_milestone_progress_entries WHERE additional_milestone_id=$1 ORDER BY report_date`,[milestoneId]);
    res.json({ success:true,milestone:{id:milestoneId,executed:newExecuted,progress_pct:parseFloat(newPct.toFixed(2)),activity_status:'in_progress',entries:allEntries.rows} });
  } catch(err){await client.query('ROLLBACK');console.error('[POST /api/report-additional-progress]',err);res.status(500).json({error:'Failed to save additional progress entry'});}finally{client.release();}
});

app.patch('/api/schedule-progress/:entryId', authenticateToken, upload.none(), requireProjectLifecycleWrite, async (req, res) => {
  if (!canEditSchedule(req.user.role)) return res.status(403).json({ error: 'Schedule edit permission is required' });
  const projectId = normalizeProjectId(req.body.projectId);
  const qty = Number(req.body.qtyExecuted);
  const reportDate = String(req.body.reportDate || '').trim();
  const remarks = String(req.body.remarks || '').trim();
  if (!projectId || !reportDate || !Number.isFinite(qty) || qty <= 0) return res.status(400).json({ error: 'Project, report date, and positive quantity are required' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const base = await client.query('SELECT id,milestone_id FROM milestone_progress_entries WHERE id=$1 AND project_id=$2 FOR UPDATE', [req.params.entryId, projectId]);
    const ext = base.rows.length ? null : await client.query('SELECT id,additional_milestone_id FROM additional_milestone_progress_entries WHERE id=$1 AND project_id=$2 FOR UPDATE', [req.params.entryId, projectId]);
    const row = base.rows[0] || ext?.rows[0];
    if (!row) return res.status(404).json({ error: 'Progress entry not found' });
    const table = base.rows.length ? 'milestone_progress_entries' : 'additional_milestone_progress_entries';
    const foreignKey = base.rows.length ? 'milestone_id' : 'additional_milestone_id';
    const milestoneId = row[foreignKey];
    const milestoneTable = base.rows.length ? 'milestones' : 'additional_milestones';
    const milestone = await client.query(`SELECT quantity FROM ${milestoneTable} WHERE id=$1 AND project_id=$2`, [milestoneId, projectId]);
    const planned = Number(milestone.rows[0]?.quantity) || 0;
    const duplicate = await client.query(`SELECT 1 FROM ${table} WHERE ${foreignKey}=$1 AND report_date=$2 AND id<>$3`, [milestoneId, reportDate, req.params.entryId]);
    if (duplicate.rows.length) return res.status(409).json({ error: 'Another entry already exists for that date' });
    const totals = await client.query(`SELECT COALESCE(SUM(qty_executed),0) AS total FROM ${table} WHERE ${foreignKey}=$1 AND id<>$2`, [milestoneId, req.params.entryId]);
    if (planned > 0 && Number(totals.rows[0].total) + qty > planned) return res.status(422).json({ error: 'Edited quantity would exceed the planned quantity' });
    await client.query(`UPDATE ${table} SET report_date=$1,qty_executed=$2,remarks=$3 WHERE id=$4`, [reportDate, qty, remarks || null, req.params.entryId]);
    const summary = await recalculateScheduleProgress(client, table, foreignKey, milestoneId);
    await client.query('COMMIT');
    res.json({ success: true, milestone: summary });
  } catch (err) { await client.query('ROLLBACK'); console.error('[PATCH /api/schedule-progress]', err); res.status(500).json({ error: 'Failed to update progress entry' }); } finally { client.release(); }
});

app.delete('/api/schedule-progress/:entryId', authenticateToken, async (req, res) => {
  if (!canEditSchedule(req.user.role)) return res.status(403).json({ error: 'Schedule edit permission is required' });
  const projectId = normalizeProjectId(req.body.projectId);
  if (!projectId) return res.status(400).json({ error: 'Valid projectId is required' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const base = await client.query('SELECT id,milestone_id FROM milestone_progress_entries WHERE id=$1 AND project_id=$2 FOR UPDATE', [req.params.entryId, projectId]);
    const ext = base.rows.length ? null : await client.query('SELECT id,additional_milestone_id FROM additional_milestone_progress_entries WHERE id=$1 AND project_id=$2 FOR UPDATE', [req.params.entryId, projectId]);
    const row = base.rows[0] || ext?.rows[0];
    if (!row) return res.status(404).json({ error: 'Progress entry not found' });
    const table = base.rows.length ? 'milestone_progress_entries' : 'additional_milestone_progress_entries';
    const foreignKey = base.rows.length ? 'milestone_id' : 'additional_milestone_id';
    const milestoneId = row[foreignKey];
    await client.query(`DELETE FROM ${table} WHERE id=$1`, [req.params.entryId]);
    const summary = await recalculateScheduleProgress(client, table, foreignKey, milestoneId);
    await client.query('COMMIT');
    res.json({ success: true, milestone: summary });
  } catch (err) { await client.query('ROLLBACK'); console.error('[DELETE /api/schedule-progress]', err); res.status(500).json({ error: 'Failed to delete progress entry' }); } finally { client.release(); }
});

app.post('/api/complete-milestone', authenticateToken, async (req, res) => {
  const projectId = normalizeProjectId(req.body.projectId);
  const { milestoneId, isExtensionMilestone } = req.body;
  if (!projectId||!milestoneId) return res.status(400).json({ error: 'Valid projectId and milestoneId are required' });
  const isExt=isExtensionMilestone===true||isExtensionMilestone==='true';
  if (!canEditSchedule(req.user.role)) return res.status(403).json({ error: 'Schedule edit permission is required' });
  const table=isExt?'additional_milestones':'milestones';
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const msRes=await client.query(`SELECT * FROM ${table} WHERE id=$1 AND project_id=$2 FOR UPDATE`,[milestoneId,projectId]);
    if (!msRes.rows.length) return res.status(404).json({ error: 'Milestone not found' });
    const ms=msRes.rows[0];
    if (ms.activity_status==='completed') return res.status(409).json({ error: 'Milestone is already completed' });
    const planned=parseFloat(ms.quantity)||0,exec=parseFloat(ms.executed)||0;
    if (planned>0&&exec<planned) return res.status(422).json({ error:`Cannot complete: only ${exec} of ${planned} ${ms.unit||''} executed` });
    await client.query(`UPDATE ${table} SET activity_status='completed',progress_pct=100,completed_at=now(),updated_at=now() WHERE id=$1`,[milestoneId]);
    const notifMsg = `${isExt ? 'Additional milestone' : 'Milestone'} completed by ${req.user.role}: "${ms.title || `#${milestoneId}`}"`;
    console.log('[notifications] creating notification', { projectId, entity_id: milestoneId, entity_type: table, message: notifMsg, added_by_id: req.user.user_id, added_by_role: req.user.role });
    const notifRes = await client.query(
      `INSERT INTO notifications (project_id,entity_id,entity_type,message,added_by_id,added_by_role) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
      [projectId, milestoneId, table, notifMsg, req.user.user_id, req.user.role]
    );
    const notificationId = notifRes.rows[0].id;
    console.log('[notifications] created', { notificationId, projectId, entity_id: milestoneId });
    const recipients = await getProjectRecipientKeys(projectId, req.user.user_id, req.user.role);
    await insertNotificationRecipients(client, notificationId, recipients);
    await client.query('COMMIT');
    res.json({ success:true,completedAt:new Date().toISOString() });
  } catch(err){await client.query('ROLLBACK');console.error('[POST /api/complete-milestone]',err);res.status(500).json({error:'Failed to complete milestone'});}finally{client.release();}
});

app.post('/api/reopen-milestone', authenticateToken, async (req, res) => {
  if (!canEditSchedule(req.user.role)) return res.status(403).json({ error: 'Schedule edit permission is required' });
  const projectId = normalizeProjectId(req.body.projectId);
  const milestoneId = req.body.milestoneId;
  const isExt = req.body.isExtensionMilestone === true || req.body.isExtensionMilestone === 'true';
  if (!projectId || !milestoneId) return res.status(400).json({ error: 'Valid projectId and milestoneId are required' });
  const table = isExt ? 'additional_milestones' : 'milestones';
  const entryTable = isExt ? 'additional_milestone_progress_entries' : 'milestone_progress_entries';
  const foreignKey = isExt ? 'additional_milestone_id' : 'milestone_id';
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(`SELECT id FROM ${table} WHERE id=$1 AND project_id=$2 FOR UPDATE`, [milestoneId, projectId]);
    if (!result.rows.length) return res.status(404).json({ error: 'Milestone not found' });
    const count = await client.query(`SELECT COUNT(*)::int AS count FROM ${entryTable} WHERE ${foreignKey}=$1`, [milestoneId]);
    const status = count.rows[0].count > 0 ? 'in_progress' : 'planned';
    await client.query(`UPDATE ${table} SET activity_status=$1,progress_pct=LEAST(progress_pct,99.99),completed_at=NULL,updated_at=now() WHERE id=$2`, [status, milestoneId]);
    await client.query('COMMIT');
    res.json({ success: true, activity_status: status });
  } catch (err) { await client.query('ROLLBACK'); console.error('[POST /api/reopen-milestone]', err); res.status(500).json({ error: 'Failed to reopen milestone' }); } finally { client.release(); }
});

app.post('/api/save-extension', authenticateToken, upload.any(), requireProjectLifecycleWrite, async (req, res) => {
  const projectId = normalizeProjectId(req.body.projectId);
  if (!projectId) return res.status(400).json({ error: 'Valid projectId is required' });
  const extensionDays=parseInt(req.body.extensionDays,10),newPlannedFinish=req.body.newPlannedFinish,reason=(req.body.reason||'').trim(),extensionType=req.body.extensionType,scopeType=req.body.scopeType;
  let newMilestones=[];
  try{newMilestones=JSON.parse(req.body.newMilestones||'[]');}catch{return res.status(400).json({error:'Invalid JSON in newMilestones'});}
  if (!extensionDays||extensionDays<1) return res.status(400).json({error:'extensionDays must be a positive integer'});
  if (!newPlannedFinish) return res.status(400).json({error:'newPlannedFinish is required'});
  if (!reason) return res.status(400).json({error:'reason is required'});
  if (!['delay','scope_addition','force_majeure','design_change'].includes(extensionType)) return res.status(400).json({error:'Invalid extensionType'});
  const fileMap={};(req.files||[]).forEach(f=>{const m=f.fieldname.match(/^extFile_(\d+)$/);if(m)fileMap[parseInt(m[1],10)]=f;});
  const supportingDoc=(req.files||[]).find(f=>f.fieldname==='supportingDoc');
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const schedRes=await client.query('SELECT id,planned_finish FROM project_schedules WHERE project_id=$1 LIMIT 1',[projectId]);
    if (!schedRes.rows.length) return res.status(404).json({error:'No schedule found for this project'});
    const scheduleId=schedRes.rows[0].id;
    const lastExtRes=await client.query(`SELECT new_planned_finish FROM schedule_extensions WHERE schedule_id=$1 ORDER BY created_at DESC LIMIT 1`,[scheduleId]);
    const effectiveFinish=lastExtRes.rows[0]?.new_planned_finish||schedRes.rows[0].planned_finish;
    const newPlannedStart=new Date(effectiveFinish);newPlannedStart.setDate(newPlannedStart.getDate()+1);
    
    let supportingFile = null;
    if (supportingDoc) {
      const uploaded = await scheduleCloudinaryUpload(supportingDoc.buffer, supportingDoc.originalname, `oneprojectapp/schedules/${projectId}/extensions`);
      supportingFile = { name: supportingDoc.originalname, url: uploaded.secure_url || uploaded.url || null, publicId: uploaded.public_id || null, mime: supportingDoc.mimetype || null, size: supportingDoc.size || null };
    }
    const extRes = await client.query(`INSERT INTO schedule_extensions (schedule_id,project_id,extension_days,new_planned_start,new_planned_finish,reason,extension_type,requested_by_user_id,requested_by_role,supporting_file_name,supporting_file_url,supporting_file_public_id,supporting_file_mime,supporting_file_size) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id`,[scheduleId,projectId,extensionDays,newPlannedStart.toISOString().slice(0,10),newPlannedFinish,reason,extensionType,req.user.user_id,req.user.role,supportingFile?.name||null,supportingFile?.url||null,supportingFile?.publicId||null,supportingFile?.mime||null,supportingFile?.size||null]);
    
    const extensionId=extRes.rows[0].id;
    await client.query('UPDATE project_schedules SET planned_finish=$1,updated_at=now() WHERE id=$2',[newPlannedFinish,scheduleId]);
    const insertedAdditional=[];
    if (scopeType==='new'&&newMilestones.length>0) {
      for (let i=0;i<newMilestones.length;i++) {
        const ms=newMilestones[i],dur=Math.max(1,daysBetween(ms.planned_start,ms.planned_end)),floatD=Math.max(0,Math.round((new Date(newPlannedFinish)-new Date(ms.planned_end))/86400000)),depBaselineId=ms.depends_on_baseline&&ms.depends_on_baseline!=='None'?ms.depends_on_baseline:null;
        const amRes=await client.query(`INSERT INTO additional_milestones (schedule_id,project_id,schedule_extension_id,title,description,sort_order,planned_start,planned_end,duration_days,float_days,is_critical,weight_pct,quantity,unit,depends_on_baseline,added_by_user_id,added_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING id`,[scheduleId,projectId,extensionId,ms.title,ms.description||null,i,ms.planned_start,ms.planned_end,dur,floatD,floatD===0,0,parseFloat(ms.quantity)||0,ms.unit||null,depBaselineId,req.user.user_id,req.user.role]);
        const additionalId=amRes.rows[0].id;insertedAdditional.push({id:additionalId,index:i});
        const file=fileMap[i];
        if (file){try{const cdResult=await scheduleCloudinaryUpload(file.buffer,file.originalname,`oneprojectapp/schedules/${projectId}/additional`);await client.query(`INSERT INTO additional_milestone_attachments (additional_milestone_id,file_name,file_size,mime_type,cloudinary_public_id,cloudinary_url,uploaded_by_user_id,uploaded_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,[additionalId,file.originalname,file.size,file.mimetype,cdResult.public_id,cdResult.secure_url,req.user.user_id,req.user.role]);}catch(cdErr){console.error('[save-extension] Cloudinary upload failed for additional milestone',additionalId,cdErr);}}
      }
    }
    await client.query('COMMIT');

    // Create a notification for the extension so recipients are informed
    try {
      const notifClient = await pool.connect();
      try {
        await notifClient.query('BEGIN');
        const notifMsg = `Schedule extension requested by ${req.user.role}: "${reason}"`;
        const notifRes = await notifClient.query(
          `INSERT INTO notifications (project_id, entity_id, entity_type, message, added_by_id, added_by_role)
           VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
          [projectId, extensionId, 'schedule_extensions', notifMsg, req.user.user_id, req.user.role]
        );
        const notificationId = notifRes.rows[0].id;
        const recipients = await getProjectRecipientKeys(projectId, req.user.user_id, req.user.role);
        await insertNotificationRecipients(notifClient, notificationId, recipients);
        await notifClient.query('COMMIT');
        console.log('[notifications] created extension notification', { notificationId, projectId, extensionId, recipients: recipients.length });
      } catch (notifErr) {
        await notifClient.query('ROLLBACK');
        console.error('[notifications] failed to create extension notification (non-fatal):', notifErr.message);
      } finally { notifClient.release(); }
    } catch (outerNotifErr) {
      console.error('[notifications] outer error creating extension notification (non-fatal):', outerNotifErr.message);
    }

    res.json({success:true,extension:{id:extensionId,extensionDays,newPlannedFinish,reason,extensionType,status:'pending',newMilestonesAdded:insertedAdditional.length}});
  } catch(err){await client.query('ROLLBACK');console.error('[POST /api/save-extension]',err);res.status(500).json({error:'Failed to save extension'});}finally{client.release();}
});

app.patch('/api/schedule-extensions/:extensionId', authenticateToken, upload.single('supportingDoc'), requireProjectLifecycleWrite, async (req, res) => {
  if (!canEditSchedule(req.user.role)) return res.status(403).json({ error: 'Schedule edit permission is required' });
  const projectId = normalizeProjectId(req.body.projectId);
  const extensionId = req.params.extensionId;
  const extensionDays = parseInt(req.body.extensionDays, 10);
  const newPlannedFinish = String(req.body.newPlannedFinish || '').trim();
  const reason = String(req.body.reason || '').trim();
  const extensionType = String(req.body.extensionType || '').trim();
  const removeSupportingDoc = req.body.removeSupportingDoc === 'true';
  if (!projectId || !extensionId || !extensionDays || extensionDays < 1 || !newPlannedFinish || !reason || !['delay', 'scope_addition', 'force_majeure', 'design_change'].includes(extensionType)) {
    return res.status(400).json({ error: 'Valid extension details are required' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const current = await client.query('SELECT id,schedule_id FROM schedule_extensions WHERE id=$1 AND project_id=$2 FOR UPDATE', [extensionId, projectId]);
    if (!current.rows.length) return res.status(404).json({ error: 'Extension not found' });
    let attachmentSql = '';
    const attachmentValues = [];
    if (req.file) {
      const uploaded = await scheduleCloudinaryUpload(req.file.buffer, req.file.originalname, `oneprojectapp/schedules/${projectId}/extensions`);
      attachmentSql = ',supporting_file_name=$5,supporting_file_url=$6,supporting_file_public_id=$7,supporting_file_mime=$8,supporting_file_size=$9';
      attachmentValues.push(req.file.originalname, uploaded.secure_url || uploaded.url || null, uploaded.public_id || null, req.file.mimetype || null, req.file.size || null);
    } else if (removeSupportingDoc) {
      attachmentSql = ',supporting_file_name=NULL,supporting_file_url=NULL,supporting_file_public_id=NULL,supporting_file_mime=NULL,supporting_file_size=NULL';
    }
    const updateValues = [extensionDays, newPlannedFinish, reason, extensionType, ...attachmentValues, extensionId, projectId];
    const idPlaceholder = attachmentValues.length ? '$10' : '$5';
    const projectPlaceholder = attachmentValues.length ? '$11' : '$6';
    await client.query(`UPDATE schedule_extensions SET extension_days=$1,new_planned_finish=$2,reason=$3,extension_type=$4,updated_at=now()${attachmentSql} WHERE id=${idPlaceholder} AND project_id=${projectPlaceholder}`, updateValues);
    const latest = await client.query('SELECT new_planned_finish FROM schedule_extensions WHERE schedule_id=$1 ORDER BY new_planned_finish DESC,created_at DESC LIMIT 1', [current.rows[0].schedule_id]);
    await client.query('UPDATE project_schedules SET planned_finish=$1,updated_at=now() WHERE id=$2', [latest.rows[0]?.new_planned_finish || newPlannedFinish, current.rows[0].schedule_id]);
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (err) { await client.query('ROLLBACK'); console.error('[PATCH /api/schedule-extensions]', err); res.status(500).json({ error: 'Failed to update extension' }); } finally { client.release(); }
});

app.delete('/api/schedule-extensions/:extensionId', authenticateToken, async (req, res) => {
  if (!canEditSchedule(req.user.role)) return res.status(403).json({ error: 'Schedule edit permission is required' });
  const projectId = normalizeProjectId(req.body.projectId);
  const extensionId = req.params.extensionId;
  if (!projectId) return res.status(400).json({ error: 'Valid projectId is required' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const current = await client.query('SELECT id,schedule_id FROM schedule_extensions WHERE id=$1 AND project_id=$2 FOR UPDATE', [extensionId, projectId]);
    if (!current.rows.length) return res.status(404).json({ error: 'Extension not found' });
    const milestoneIds = await client.query('SELECT id FROM additional_milestones WHERE schedule_extension_id=$1', [extensionId]);
    for (const row of milestoneIds.rows) {
      await client.query('DELETE FROM milestone_photos WHERE additional_milestone_id=$1', [row.id]);
      await client.query('DELETE FROM additional_milestone_attachments WHERE additional_milestone_id=$1', [row.id]);
      await client.query('DELETE FROM additional_milestone_progress_entries WHERE additional_milestone_id=$1', [row.id]);
    }
    await client.query('DELETE FROM additional_milestones WHERE schedule_extension_id=$1', [extensionId]);
    await client.query('DELETE FROM schedule_extensions WHERE id=$1 AND project_id=$2', [extensionId, projectId]);
    const latest = await client.query('SELECT new_planned_finish FROM schedule_extensions WHERE schedule_id=$1 ORDER BY new_planned_finish DESC,created_at DESC LIMIT 1', [current.rows[0].schedule_id]);
    const baseline = await client.query('SELECT planned_finish FROM project_schedules WHERE id=$1', [current.rows[0].schedule_id]);
    await client.query('UPDATE project_schedules SET planned_finish=$1,updated_at=now() WHERE id=$2', [latest.rows[0]?.new_planned_finish || baseline.rows[0]?.planned_finish, current.rows[0].schedule_id]);
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (err) { await client.query('ROLLBACK'); console.error('[DELETE /api/schedule-extensions]', err); res.status(500).json({ error: 'Failed to delete extension' }); } finally { client.release(); }
});

// ─── Milestone Photos ────────────────────────────────────────────────────────
app.get('/api/milestone-photos', authenticateToken, async (req, res) => {
  const { milestoneId, additionalMilestoneId } = req.query;
  if (!milestoneId&&!additionalMilestoneId) return res.status(400).json({ error: 'milestoneId or additionalMilestoneId is required' });
  try {
    const col=milestoneId?'milestone_id':'additional_milestone_id', val=milestoneId??additionalMilestoneId;
    const { rows }=await pool.query(`SELECT id,file_name,cloudinary_url,uploaded_at FROM milestone_photos WHERE ${col}=$1 ORDER BY uploaded_at ASC`,[val]);
    res.json({ photos: rows });
  } catch(err){console.error('[GET /api/milestone-photos]',err);res.status(500).json({error:'Failed to fetch photos'});}
});

app.post('/api/milestone-photos', authenticateToken, photoUpload.array('photos',10), requireProjectLifecycleWrite, async (req, res) => {
  if (!canEditSchedule(req.user.role)) return res.status(403).json({error:'Schedule edit permission is required'});
  const { milestoneId, additionalMilestoneId } = req.body;
  const projectId = normalizeProjectId(req.body.projectId);
  if (!projectId) return res.status(400).json({error:'projectId is required'});
  if (!milestoneId&&!additionalMilestoneId) return res.status(400).json({error:'milestoneId or additionalMilestoneId is required'});
  if (!req.files||req.files.length===0) return res.status(400).json({error:'No files uploaded'});
  const col=milestoneId?'milestone_id':'additional_milestone_id', val=milestoneId??additionalMilestoneId;
  const folder=milestoneId?`oneprojectapp/schedules/${projectId}/milestone-photos`:`oneprojectapp/schedules/${projectId}/additional-photos`;
  const inserted=[];
  try {
    for (const file of req.files) {
      const cdResult=await new Promise((resolve,reject)=>{const stream=cloudinary.uploader.upload_stream({folder,resource_type:'image',public_id:`${Date.now()}_${file.originalname.replace(/\s+/g,'-')}`},(err,result)=>(err?reject(err):resolve(result)));Readable.from(file.buffer).pipe(stream);});
      const { rows }=await pool.query(`INSERT INTO milestone_photos (${col},project_id,file_name,cloudinary_public_id,cloudinary_url,uploaded_by_user_id,uploaded_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id,file_name,cloudinary_url,uploaded_at`,[val,projectId,file.originalname,cdResult.public_id,cdResult.secure_url,req.user.user_id,req.user.role]);
      inserted.push(rows[0]);
    }
    res.json({ success:true,photos:inserted });
  } catch(err){console.error('[POST /api/milestone-photos]',err);res.status(500).json({error:'Failed to upload photos'});}
});

app.delete('/api/milestone-photos/:id', authenticateToken, async (req, res) => {
  try {
    if (!canEditSchedule(req.user.role)) return res.status(403).json({error:'Schedule edit permission is required'});
    const { rows }=await pool.query('SELECT cloudinary_public_id,uploaded_by_user_id FROM milestone_photos WHERE id=$1',[req.params.id]);
    if (!rows.length) return res.status(404).json({error:'Photo not found'});
    try{await cloudinary.uploader.destroy(rows[0].cloudinary_public_id,{resource_type:'image'});}catch(cdErr){console.error('[DELETE /api/milestone-photos] Cloudinary destroy error (non-fatal):',cdErr);}
    await pool.query('DELETE FROM milestone_photos WHERE id=$1',[req.params.id]);
    res.json({ success:true });
  } catch(err){console.error('[DELETE /api/milestone-photos/:id]',err);res.status(500).json({error:'Failed to delete photo'});}
});

app.get('/api/project-summary', authenticateToken, async (req, res) => {
  const projectId = normalizeProjectId(req.query.projectId);
  if (!projectId) return res.status(400).json({error:'Valid projectId is required'});
  try {
    const scheduleClock=await getProjectScheduleClock(projectId);
    const schedRow=await pool.query('SELECT id,planned_start,planned_finish,total_duration,location FROM project_schedules WHERE project_id=$1 LIMIT 1',[projectId]);
    if (!schedRow.rows.length) return res.json({hasSchedule:false,milestones:[],photos:[],timeline:null,effective_today:scheduleClock?.effective_today||null,schedule_paused:scheduleClock?.paused||false,pause_started_at:scheduleClock?.pause_started_at||null});
    const sched=schedRow.rows[0];
    const location=sched.location || null;
    const msRows=await pool.query(`SELECT m.id,m.title,m.planned_start AS start,m.planned_end AS end,m.quantity,m.unit,m.weight_pct,m.float_days,m.is_critical,m.executed,m.progress_pct,m.activity_status,m.completed_at,(SELECT MAX(e.report_date)::timestamp FROM milestone_progress_entries e WHERE e.milestone_id=m.id) AS last_progress_date,m.depends_on AS dep FROM milestones m WHERE m.schedule_id=$1 ORDER BY m.sort_order`,[sched.id]);
    const amRows=await pool.query(`SELECT am.id,am.title,am.planned_start AS start,am.planned_end AS end,am.quantity,am.unit,am.weight_pct,am.float_days,am.is_critical,am.executed,am.progress_pct,am.activity_status,am.completed_at,(SELECT MAX(e.report_date)::timestamp FROM additional_milestone_progress_entries e WHERE e.additional_milestone_id=am.id) AS last_progress_date,am.depends_on_baseline AS dep,true AS is_extension FROM additional_milestones am WHERE am.schedule_id=$1 ORDER BY am.sort_order`,[sched.id]);
    const allMilestones=[...msRows.rows.map(m=>({...m,is_extension:false})),...amRows.rows.map(m=>({...m,is_extension:true}))];
    const totalWeight=allMilestones.reduce((s,m)=>s+Number(m.weight_pct||0),0);
    const overallPct=allMilestones.length===0?0:totalWeight>0?allMilestones.reduce((s,m)=>s+Number(m.weight_pct||0)*Number(m.progress_pct||0),0)/totalWeight:allMilestones.reduce((s,m)=>s+Number(m.progress_pct||0),0)/allMilestones.length;
    const [clockYear,clockMonth,clockDay]=(scheduleClock?.effective_today||new Date().toISOString().slice(0,10)).split('-').map(Number);
    const today=new Date(clockYear,clockMonth-1,clockDay);today.setHours(0,0,0,0);
    const projStart=new Date(sched.planned_start),projFinish=new Date(sched.planned_finish);
    const elapsed=Math.max(0,(today-projStart)/86400000),totalDays=Math.max(1,(projFinish-projStart)/86400000);
    const plannedPct=Math.min(100,(elapsed/totalDays)*100),variance=parseFloat((overallPct-plannedPct).toFixed(2));
    const completed=allMilestones.filter(m=>m.activity_status==='completed');
    const lastCompletedMilestone=completed.reduce((latest,milestone) => {
      if (!latest) return milestone;
      const milestoneDate = milestone.last_progress_date || milestone.completed_at;
      const latestDate = latest.last_progress_date || latest.completed_at;
      if (!milestoneDate) return latest;
      if (!latestDate) return milestone;
      return new Date(milestoneDate) > new Date(latestDate) ? milestone : latest;
    }, null);
    const lastCompleted=lastCompletedMilestone ? lastCompletedMilestone.title : null;
    const currentMsIndex = allMilestones.findIndex(m => m.activity_status !== 'completed');
    const currentMsForChart = currentMsIndex >= 0 ? allMilestones[currentMsIndex] : (allMilestones.length ? allMilestones[allMilestones.length - 1] : null);
    const chartMilestones = currentMsForChart ? [{
      id: currentMsForChart.id,
      title: currentMsForChart.title,
      start: currentMsForChart.start,
      end: currentMsForChart.end,
      planned_pct: (() => {
        const msStart = new Date(currentMsForChart.start), msEnd = new Date(currentMsForChart.end);
        if(today >= msEnd) return 100;
        if(today > msStart) return Math.min(100, ((today - msStart) / Math.max(1, msEnd - msStart)) * 100);
        return 0;
      })(),
      actual_pct: parseFloat(Number(currentMsForChart.progress_pct || 0).toFixed(2)),
      activity_status: currentMsForChart.activity_status,
      completed_at: currentMsForChart.completed_at,
      weight_pct: currentMsForChart.weight_pct,
      is_extension: currentMsForChart.is_extension,
    }] : [];
    const allChartMilestones = allMilestones.map((ms, idx) => {
      const msStart = new Date(ms.start), msEnd = new Date(ms.end);
      let msPlanPct = 0;
      if(today >= msEnd) msPlanPct = 100; else if(today > msStart) msPlanPct = Math.min(100, ((today - msStart) / Math.max(1, msEnd - msStart)) * 100);
      return {id: ms.id, title: ms.title, start: ms.start, end: ms.end, completed_at: ms.completed_at, actual_completed_at: ms.last_progress_date, planned_pct: parseFloat(msPlanPct.toFixed(2)), actual_pct: parseFloat(Number(ms.progress_pct || 0).toFixed(2)), activity_status: ms.activity_status, weight_pct: ms.weight_pct, is_extension: ms.is_extension, milestone_index: idx};
    });
    const msIds=msRows.rows.map(m=>m.id),amIds=amRows.rows.map(m=>m.id);
    let photos=[];
    if (msIds.length>0){const ph=msIds.map((_,i)=>`$${i+1}`).join(',');const photoRes=await pool.query(`SELECT mp.id,mp.file_name,mp.cloudinary_url,mp.uploaded_at,m.title AS ms_title FROM milestone_photos mp JOIN milestones m ON m.id=mp.milestone_id WHERE mp.milestone_id IN (${ph}) ORDER BY mp.uploaded_at ASC`,msIds);photos=photos.concat(photoRes.rows.map(p=>({...p,is_extension:false})));}
    if (amIds.length>0){const ph=amIds.map((_,i)=>`$${i+1}`).join(',');const amPhotoRes=await pool.query(`SELECT mp.id,mp.file_name,mp.cloudinary_url,mp.uploaded_at,am.title AS ms_title FROM milestone_photos mp JOIN additional_milestones am ON am.id=mp.additional_milestone_id WHERE mp.additional_milestone_id IN (${ph}) ORDER BY mp.uploaded_at ASC`,amIds);photos=photos.concat(amPhotoRes.rows.map(p=>({...p,is_extension:true})));}
    const extRow=await pool.query(`SELECT extension_days,new_planned_finish,status FROM schedule_extensions WHERE schedule_id=$1 AND status='approved' ORDER BY created_at DESC LIMIT 1`,[sched.id]);
    const latestExtension=extRow.rows[0]||null;
    const currentFinish = latestExtension ? new Date(latestExtension.new_planned_finish) : new Date(sched.planned_finish);
    const projectRemainingDays = Math.max(0, Math.ceil((currentFinish - today) / 86400000));
    const currentMs = allMilestones.find(m => m.activity_status !== 'completed') || (allMilestones.length ? allMilestones[allMilestones.length - 1] : null);
    const currentMilestone = currentMs ? {
      title: currentMs.title,
      start: currentMs.start,
      end: currentMs.end,
      status: currentMs.activity_status || 'pending',
      remaining_days: Math.max(0, Math.ceil((new Date(currentMs.end) - today) / 86400000)),
      is_extension: currentMs.is_extension,
    } : null;
    res.json({
      hasSchedule:true,
      effective_today:scheduleClock?.effective_today||null,
      schedule_paused:scheduleClock?.paused||false,
      pause_started_at:scheduleClock?.pause_started_at||null,
      location,
      timeline:{start:sched.planned_start,finish:sched.planned_finish,duration:sched.total_duration,current_finish:latestExtension?latestExtension.new_planned_finish:sched.planned_finish},
      progress:{overall_pct:parseFloat(overallPct.toFixed(2)),planned_pct:parseFloat(plannedPct.toFixed(2)),variance_pct:variance,last_completed:lastCompleted,total_milestones:allMilestones.length,completed_count:completed.length,in_progress_count:allMilestones.filter(m=>m.activity_status==='in_progress').length},
      project_remaining_days: projectRemainingDays,
      current_milestone: currentMilestone,
      chart_milestones: chartMilestones,
      all_milestones_for_modal: allChartMilestones,
      photos,
    });
  } catch(err){console.error('[GET /api/project-summary]',err);res.status(500).json({error:'Failed to load project summary'});}
});

// =============================================================================
//  HELPERS  (ensure these exist in your server.js before these routes)
// =============================================================================
//
//  function wcSide(role) {
//    if (['Contractor','ContractorPM'].includes(role))  return 'Contractor';
//    if (['Consultant','ConsultantPM'].includes(role))  return 'Consultant';
//    if (['Client','ClientPM'].includes(role))          return 'Client';
//    return null; // TeamMember — side must be looked up from team_member_assignments
//  }
//
//  function sideRoles(side) {
//    if (side === 'Contractor') return ['Contractor','ContractorPM'];
//    if (side === 'Consultant') return ['Consultant','ConsultantPM'];
//    if (side === 'Client')     return ['Client','ClientPM'];
//    return [];
//  }
//
//  function isWCLeader(role) {
//    return ['Contractor','ContractorPM','Consultant','ConsultantPM',
//            'Client','ClientPM'].includes(role);
//  }
//
// =============================================================================


// =============================================================================
//  SIDE RESOLUTION HELPER
//  For leaders/PMs → side from role.
//  For TeamMember  → side from team_member_assignments.assigned_part for this project.
// =============================================================================
async function resolveSide(role, user_id, projectId) {
  const direct = wcSide(role);
  if (direct) return direct;                         // leader / PM
  if (role !== 'TeamMember') return null;            // unknown role
  const r = await pool.query(
    `SELECT assigned_part FROM team_member_assignments
     WHERE team_member_id = $1 AND project_id = $2 LIMIT 1`,
    [user_id, projectId]
  );
  return r.rows.length ? r.rows[0].assigned_part : null;
}


// =============================================================================
//  PLANNING & EXECUTION ROUTES
// =============================================================================

// ── List all activities for the caller's side (leaders + PMs + TeamMembers) ──
app.post('/api/planning-execution', authenticateToken, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { projectId }     = req.body;
    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });

    const side = await resolveSide(role, user_id, projectId);
    if (!side) return res.status(403).json({ error: 'Access denied.' });

    const result = await pool.query(`
      SELECT
        pe.*,
        (pe.creator_id = $2)                           AS is_creator,
        COALESCE((
          SELECT ROUND(AVG(t.progress_pct)::numeric, 1)
          FROM   planning_execution_tracking t
          WHERE  t.activity_id = pe.id
        ), 0)                                          AS avg_progress,
        CASE WHEN pe.planned_quantity > 0 THEN LEAST(100, ROUND((COALESCE((
          SELECT SUM(t.actual_quantity)
          FROM   planning_execution_tracking t
          WHERE  t.activity_id = pe.id
        ), 0) / pe.planned_quantity * 100)::numeric, 1)) ELSE 0 END AS actual_progress,
        (SELECT COUNT(*)
         FROM   planning_execution_tracking t
         WHERE  t.activity_id = pe.id)                AS tracking_count
      FROM planning_execution pe
      WHERE pe.project_id = $1
        AND pe.side       = $3
      ORDER BY pe.milestone_name ASC NULLS LAST, pe.created_at DESC
    `, [projectId, user_id, side]);

    return res.json({ records: result.rows });
  } catch (err) {
    console.error('POST /api/planning-execution:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Simple list used by Work Center create-task form (leaders/PMs only) ──────
app.get('/api/planning-execution', authenticateToken, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { projectId }     = req.query;
    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });

    const side = await resolveSide(role, user_id, projectId);
    if (!side) return res.status(403).json({ error: 'Access denied.' });

    const result = await pool.query(`
      SELECT id, title, milestone_name, status, start_date, end_date,
             planned_quantity, unit,
             -- recommended (latest entry only):
             COALESCE((
               SELECT t.progress_pct
               FROM   planning_execution_tracking t
               WHERE  t.activity_id = pe.id
               ORDER  BY t.report_date DESC, t.created_at DESC
               LIMIT  1
             ), 0) AS avg_progress,
             LEAST(100, COALESCE((
               SELECT SUM(t.actual_quantity)
               FROM   planning_execution_tracking t
               WHERE  t.activity_id = pe.id
             ), 0) / NULLIF(planned_quantity, 0) * 100) AS actual_progress
      FROM   planning_execution pe
      WHERE  project_id = $1
        AND  side       = $2
      ORDER  BY milestone_name ASC NULLS LAST, created_at DESC
    `, [projectId, side]);

    return res.json({ records: result.rows, activities: result.rows });
  } catch (err) {
    console.error('GET /api/planning-execution:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Create activity (leaders/PMs only) ───────────────────────────────────────
app.post('/api/planning-execution/create', authenticateToken,
  upload.single('linked_file'), requireProjectLifecycleWrite, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    if (!isWCLeader(role))
      return res.status(403).json({ error: 'Only leaders and PMs can create activities.' });

    const {
      projectId,
      milestone_name    = '',
      title,
      description       = '',
      start_date,
      end_date,
      planned_quantity,
      unit,
      planned_work      = '',
      planned_manpower  = '',
      planned_equipment = '',
      planned_materials = '',
    } = req.body;

    if (!projectId)        return res.status(400).json({ error: 'projectId is required.' });
    if (!title?.trim())    return res.status(400).json({ error: 'title is required.' });
    if (!start_date)       return res.status(400).json({ error: 'start_date is required.' });
    if (!end_date)         return res.status(400).json({ error: 'end_date is required.' });
    if (!planned_quantity) return res.status(400).json({ error: 'planned_quantity is required.' });
    if (!unit?.trim())     return res.status(400).json({ error: 'unit is required.' });

    // side from JWT role — leaders always have a direct side
    const side = wcSide(role);
    if (!side) return res.status(403).json({ error: 'Cannot determine your side.' });

    // Verify membership in this project
    const projCheck = await pool.query(
      `SELECT 1 FROM assignments_view
       WHERE project_id = $1 AND role_id = $2 LIMIT 1`,
      [projectId, user_id]
    );
    if (!projCheck.rows.length)
      return res.status(403).json({ error: 'You are not a member of this project.' });

    let linkedFileName = null, linkedFileId = null, linkedFileUrl = null;
    if (req.file) {
      const uploaded = await scheduleCloudinaryUpload(
        req.file.buffer, req.file.originalname, 'planning_execution/plans'
      );
      linkedFileName = req.file.originalname;
      linkedFileId   = uploaded.public_id;
      linkedFileUrl  = uploaded.secure_url;
    }

    const result = await pool.query(`
      INSERT INTO planning_execution
        (project_id, side, milestone_name, title, description,
         start_date, end_date, planned_quantity, unit,
         planned_work, planned_manpower, planned_equipment, planned_materials,
         linked_file_name, linked_file_id, linked_file_url,
         status, creator_id, creator_role)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
              'not_yet_started',$17,$18)
      RETURNING *
    `, [
      projectId, side, milestone_name.trim(), title.trim(), description,
      start_date, end_date, planned_quantity, unit.trim(),
      planned_work, planned_manpower, planned_equipment, planned_materials,
      linkedFileName, linkedFileId, linkedFileUrl,
      user_id, role,
    ]);

    return res.status(201).json({ success: true, record: result.rows[0] });
  } catch (err) {
    console.error('POST /api/planning-execution/create:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Update activity plan fields (creating leader only) ───────────────────────
app.put('/api/planning-execution', authenticateToken,
  upload.single('linked_file'), requireProjectLifecycleWrite, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    if (!isWCLeader(role))
      return res.status(403).json({ error: 'Only leaders and PMs can update activities.' });

    const { id, projectId } = req.body;
    if (!id)        return res.status(400).json({ error: 'Activity id is required.' });
    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });

    const actCheck = await pool.query(
      `SELECT id, creator_id, linked_file_id
       FROM planning_execution WHERE id = $1 AND project_id = $2`,
      [id, projectId]
    );
    if (!actCheck.rows.length)
      return res.status(404).json({ error: 'Activity not found.' });
    if (String(actCheck.rows[0].creator_id) !== String(user_id))
      return res.status(403).json({ error: 'Only the creating leader can edit this activity.' });

    const {
      milestone_name, title, description,
      start_date, end_date, planned_quantity, unit,
      planned_work, planned_manpower, planned_equipment, planned_materials,
    } = req.body;
    // NOTE: status and side are NOT editable here — status is tracking-driven.

    const setClauses = [], values = []; let idx = 1;
    const push = (col, val) => { setClauses.push(`${col} = $${idx++}`); values.push(val); };

    if (milestone_name   !== undefined) push('milestone_name',    milestone_name.trim());
    if (title            !== undefined) push('title',             title.trim());
    if (description      !== undefined) push('description',       description);
    if (start_date       !== undefined) push('start_date',        start_date);
    if (end_date         !== undefined) push('end_date',          end_date);
    if (planned_quantity !== undefined) push('planned_quantity',  planned_quantity);
    if (unit             !== undefined) push('unit',              unit.trim());
    if (planned_work     !== undefined) push('planned_work',      planned_work);
    if (planned_manpower !== undefined) push('planned_manpower',  planned_manpower);
    if (planned_equipment!== undefined) push('planned_equipment', planned_equipment);
    if (planned_materials!== undefined) push('planned_materials', planned_materials);

    if (req.file) {
      if (actCheck.rows[0].linked_file_id)
        await cloudinary.uploader.destroy(
          actCheck.rows[0].linked_file_id, { resource_type: 'raw' }
        ).catch(() => {});
      const uploaded = await scheduleCloudinaryUpload(
        req.file.buffer, req.file.originalname, 'planning_execution/plans'
      );
      push('linked_file_name', req.file.originalname);
      push('linked_file_id',   uploaded.public_id);
      push('linked_file_url',  uploaded.secure_url);
    }

    if (!setClauses.length) return res.status(400).json({ error: 'No fields to update.' });
    values.push(id, projectId);

    const updated = await pool.query(
      `UPDATE planning_execution SET ${setClauses.join(', ')}
       WHERE id = $${idx} AND project_id = $${idx + 1} RETURNING *`,
      values
    );
    return res.json({ success: true, record: updated.rows[0] });
  } catch (err) {
    console.error('PUT /api/planning-execution:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Delete activity (creating leader only) ────────────────────────────────────
app.delete('/api/planning-execution/:activityId', authenticateToken, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { activityId }    = req.params;
    const { projectId }     = req.body;

    if (!isWCLeader(role))
      return res.status(403).json({ error: 'Only leaders and PMs can delete activities.' });
    if (!projectId)
      return res.status(400).json({ error: 'projectId is required.' });

    const actCheck = await pool.query(
      `SELECT id, creator_id, linked_file_id
       FROM planning_execution WHERE id = $1 AND project_id = $2`,
      [activityId, projectId]
    );
    if (!actCheck.rows.length)
      return res.status(404).json({ error: 'Activity not found.' });
    if (String(actCheck.rows[0].creator_id) !== String(user_id))
      return res.status(403).json({ error: 'Only the creating leader can delete this activity.' });

    if (actCheck.rows[0].linked_file_id)
      await cloudinary.uploader.destroy(
        actCheck.rows[0].linked_file_id, { resource_type: 'raw' }
      ).catch(() => {});

    const trackingFiles = await pool.query(
      `SELECT attachment_id FROM planning_execution_tracking
       WHERE activity_id = $1 AND attachment_id IS NOT NULL`,
      [activityId]
    );
    await Promise.allSettled(
      trackingFiles.rows.map(r =>
        cloudinary.uploader.destroy(r.attachment_id, { resource_type: 'raw' })
      )
    );

    await pool.query(
      `DELETE FROM planning_execution_tracking WHERE activity_id = $1`, [activityId]
    );
    await pool.query(
      `DELETE FROM planning_execution WHERE id = $1 AND project_id = $2`,
      [activityId, projectId]
    );

    return res.json({ success: true, message: 'Activity deleted.' });
  } catch (err) {
    console.error('DELETE /api/planning-execution/:activityId:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Download linked plan file ─────────────────────────────────────────────────
app.get('/api/planning-execution/:activityId/download', authenticateToken, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { activityId }    = req.params;
    const { projectId }     = req.query;
    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });

    const result = await pool.query(
      `SELECT linked_file_id, linked_file_url, linked_file_name, side
       FROM planning_execution WHERE id = $1 AND project_id = $2`,
      [activityId, projectId]
    );
    if (!result.rows.length)
      return res.status(404).json({ error: 'Activity not found.' });

    const act      = result.rows[0];
    const userSide = await resolveSide(role, user_id, projectId);

    if (!userSide || userSide !== act.side)
      return res.status(403).json({ error: 'Access denied.' });
    if (!act.linked_file_id)
      return res.status(404).json({ error: 'No file attached.' });

    return res.json({ url: act.linked_file_url, filename: act.linked_file_name });
  } catch (err) {
    console.error('GET /api/planning-execution/:activityId/download:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Get tracking entries (leaders + PMs + TeamMembers, same side) ─────────────
app.get('/api/planning-execution-tracking', authenticateToken, async (req, res) => {
  try {
    const { user_id, role }         = req.user;
    const { activityId, projectId } = req.query;
    if (!activityId) return res.status(400).json({ error: 'activityId is required.' });
    if (!projectId)  return res.status(400).json({ error: 'projectId is required.' });

    const actCheck = await pool.query(
      `SELECT id, side FROM planning_execution WHERE id = $1 AND project_id = $2`,
      [activityId, projectId]
    );
    if (!actCheck.rows.length)
      return res.status(404).json({ error: 'Activity not found.' });

    const userSide = await resolveSide(role, user_id, projectId);
    if (!userSide || userSide !== actCheck.rows[0].side)
      return res.status(403).json({ error: 'Access denied.' });

    const result = await pool.query(`
      SELECT
        t.*,
        CASE WHEN pe.planned_quantity > 0
          THEN LEAST(100, (t.actual_quantity / pe.planned_quantity) * 100)
          ELSE 0 END AS daily_progress_pct,
        SUM(t.actual_quantity) OVER (
          ORDER BY t.report_date ASC, t.created_at ASC
          ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
        ) AS cumulative_quantity
      FROM planning_execution_tracking t
      JOIN planning_execution pe ON pe.id = t.activity_id
      WHERE t.activity_id = $1
      ORDER BY t.report_date ASC, t.created_at ASC
    `, [activityId]);

    return res.json({ entries: result.rows });
  } catch (err) {
    console.error('GET /api/planning-execution-tracking:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Log execution entry (creating leader only) ────────────────────────────────
app.post('/api/planning-execution-tracking', authenticateToken,
  upload.single('attachment'), requireProjectLifecycleWrite, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    if (!isWCLeader(role))
      return res.status(403).json({ error: 'Only leaders and PMs can log execution entries.' });

    const {
      projectId,
      activity_id,
      report_date,
      actual_quantity,
      unit                    = '',
      manpower_used           = '',
      equipment_used          = '',
      materials_used          = '',
      progress_pct            = '0',
      day_remark              = '',
      issues                  = '',
      delay_days              = '0',
      delay_reason            = '',
      status_change_to_closed = '0',
    } = req.body;

    if (!projectId)           return res.status(400).json({ error: 'projectId is required.' });
    if (!activity_id)         return res.status(400).json({ error: 'activity_id is required.' });
    if (!report_date)         return res.status(400).json({ error: 'report_date is required.' });
    if (!actual_quantity)     return res.status(400).json({ error: 'actual_quantity is required.' });
    if (!day_remark.trim())   return res.status(400).json({ error: 'day_remark is required.' });

    const pct   = parseFloat(progress_pct);
    const delay = parseInt(delay_days, 10);
    if (isNaN(pct)   || pct < 0   || pct > 100)
      return res.status(400).json({ error: 'progress_pct must be 0–100.' });
    if (isNaN(delay) || delay < 0)
      return res.status(400).json({ error: 'delay_days must be 0 or more.' });

    const actCheck = await pool.query(
      `SELECT id, creator_id, unit AS planned_unit
       FROM planning_execution WHERE id = $1 AND project_id = $2`,
      [activity_id, projectId]
    );
    if (!actCheck.rows.length)
      return res.status(404).json({ error: 'Activity not found.' });
    if (String(actCheck.rows[0].creator_id) !== String(user_id))
      return res.status(403).json({
        error: 'Only the creating leader can log execution entries.'
      });
    const existingEntry = await pool.query(
      `SELECT id FROM planning_execution_tracking
       WHERE activity_id=$1 AND report_date=$2 LIMIT 1`,
      [activity_id, report_date]
    );
    if (existingEntry.rows.length)
      return res.status(409).json({ error: 'An execution entry already exists for this activity and date.' });

    let attachmentName = null, attachmentId = null, attachmentUrl = null;
    if (req.file) {
      const uploaded = await scheduleCloudinaryUpload(
        req.file.buffer, req.file.originalname, 'planning_execution/tracking'
      );
      attachmentName = req.file.originalname;
      attachmentId   = uploaded.public_id;
      attachmentUrl  = uploaded.secure_url;
    }

    const markClosed = status_change_to_closed === '1' || status_change_to_closed === true;

    const result = await pool.query(`
      INSERT INTO planning_execution_tracking
        (activity_id, report_date, actual_quantity, unit,
         manpower_used, equipment_used, materials_used,
         progress_pct, day_remark, issues,
         delay_days, delay_reason, status_change_to_closed,
         attachment_name, attachment_id, attachment_url,
         logged_by, logged_by_role)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
      RETURNING *
    `, [
      activity_id, report_date, actual_quantity,
      unit || actCheck.rows[0].planned_unit,
      manpower_used, equipment_used, materials_used,
      pct, day_remark.trim(), issues,
      delay, delay_reason, markClosed,
      attachmentName, attachmentId, attachmentUrl,
      user_id, role,
    ]);

    // ── Auto-update activity status based on entry ────────────────────────────
    if (markClosed) {
      await pool.query(
        `UPDATE planning_execution SET status = 'closed' WHERE id = $1`,
        [activity_id]
      );
    } else if (pct >= 100) {
      await pool.query(
        `UPDATE planning_execution SET status = 'completed' WHERE id = $1`,
        [activity_id]
      );
    } else {
      // First entry transitions not_yet_started → ongoing
      await pool.query(
        `UPDATE planning_execution SET status = 'ongoing'
         WHERE id = $1 AND status = 'not_yet_started'`,
        [activity_id]
      );
    }

    return res.status(201).json({ success: true, entry: result.rows[0] });
  } catch (err) {
    console.error('POST /api/planning-execution-tracking:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Delete tracking entry (creating leader only) ──────────────────────────────
app.delete('/api/planning-execution-tracking/:entryId', authenticateToken, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { entryId }       = req.params;
    const { projectId }     = req.body;

    if (!isWCLeader(role))
      return res.status(403).json({ error: 'Only leaders and PMs can delete tracking entries.' });
    if (!projectId)
      return res.status(400).json({ error: 'projectId is required.' });

    const entryCheck = await pool.query(`
      SELECT t.id, t.attachment_id, pe.creator_id
      FROM   planning_execution_tracking t
      JOIN   planning_execution pe ON pe.id = t.activity_id
      WHERE  t.id = $1 AND pe.project_id = $2
    `, [entryId, projectId]);

    if (!entryCheck.rows.length)
      return res.status(404).json({ error: 'Entry not found.' });
    if (String(entryCheck.rows[0].creator_id) !== String(user_id))
      return res.status(403).json({ error: 'Only the activity creator can delete entries.' });

    if (entryCheck.rows[0].attachment_id)
      await cloudinary.uploader.destroy(
        entryCheck.rows[0].attachment_id, { resource_type: 'raw' }
      ).catch(() => {});

    await pool.query(
      `DELETE FROM planning_execution_tracking WHERE id = $1`, [entryId]
    );
    return res.json({ success: true, message: 'Entry deleted.' });
  } catch (err) {
    console.error('DELETE /api/planning-execution-tracking/:entryId:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Download tracking attachment (same side) ──────────────────────────────────
app.get('/api/planning-execution-tracking/download/:entryId',
  authenticateToken, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { entryId }       = req.params;
    const { projectId }     = req.query;
    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });

    const result = await pool.query(`
      SELECT t.attachment_id, t.attachment_url, t.attachment_name, pe.side
      FROM   planning_execution_tracking t
      JOIN   planning_execution pe ON pe.id = t.activity_id
      WHERE  t.id = $1 AND pe.project_id = $2
    `, [entryId, projectId]);

    if (!result.rows.length)
      return res.status(404).json({ error: 'Entry not found.' });

    const userSide = await resolveSide(role, user_id, projectId);
    if (!userSide || userSide !== result.rows[0].side)
      return res.status(403).json({ error: 'Access denied.' });
    if (!result.rows[0].attachment_id)
      return res.status(404).json({ error: 'No attachment on this entry.' });

    return res.json({
      url:      result.rows[0].attachment_url,
      filename: result.rows[0].attachment_name,
    });
  } catch (err) {
    console.error('GET /api/planning-execution-tracking/download/:entryId:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});


// =============================================================================
//  WORK CENTER ROUTES
// =============================================================================

// ── Fetch all tasks for the caller (leaders see their side; TeamMembers see assigned) ──
app.post('/api/fetch-work-center-records', authenticateToken, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { projectId }     = req.body;
    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });

    console.log(`[WC] fetch-work-center-records projectId=${projectId} user=${user_id} role=${role}`);

    let records = [];

    if (isWCLeader(role)) {
      const side = wcSide(role);
      const r = await pool.query(`
        SELECT
          w.*,
          (w.creator_id = $2)                                        AS is_creator,
          EXISTS(
            SELECT 1 FROM work_center_views v
            WHERE v.task_id = w.id AND v.viewer_id = $2
          )                                                          AS is_viewed,
          pe.title       AS activity_title,
          pe.status      AS activity_status,
          pe.start_date  AS activity_start_date,
          pe.end_date    AS activity_end_date,
          COALESCE((
            SELECT ROUND(AVG(t.progress_pct)::numeric, 1)
            FROM   planning_execution_tracking t
            WHERE  t.activity_id = pe.id
          ), 0)                                                      AS activity_progress
        FROM workspace_work_center w
        LEFT JOIN planning_execution pe ON pe.id = w.activity_id
        WHERE w.project_id = $1
          AND w.side       = $3
        ORDER BY w.created_at DESC
      `, [projectId, user_id, side]);
      records = r.rows;

    } else if (role === 'TeamMember') {
      const r = await pool.query(`
        SELECT
          w.*,
          false                                                      AS is_creator,
          EXISTS(
            SELECT 1 FROM work_center_views v
            WHERE v.task_id = w.id AND v.viewer_id = $2
          )                                                          AS is_viewed,
          pe.title       AS activity_title,
          pe.status      AS activity_status,
          pe.start_date  AS activity_start_date,
          pe.end_date    AS activity_end_date,
          COALESCE((
            SELECT ROUND(AVG(t.progress_pct)::numeric, 1)
            FROM   planning_execution_tracking t
            WHERE  t.activity_id = pe.id
          ), 0)                                                      AS activity_progress
        FROM workspace_work_center w
        LEFT JOIN planning_execution pe ON pe.id = w.activity_id
        WHERE w.project_id = $1
          AND EXISTS(
            SELECT 1 FROM jsonb_array_elements(w.assigned_members) am
            WHERE (am->>'id')::text = $2::text
          )
        ORDER BY w.created_at DESC
      `, [projectId, user_id]);
      records = r.rows;

    } else {
      return res.status(403).json({ error: 'Access denied.' });
    }

    return res.json({ records });
  } catch (err) {
    console.error('POST /api/fetch-work-center-records:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Get team members for the caller's side ────────────────────────────────────
app.get('/api/work-center/team-members', authenticateToken, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { projectId }     = req.query;
    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });

    const side = wcSide(role);   // only leaders call this; TeamMember can't assign
    if (!side) return res.status(403).json({ error: 'Your role cannot manage tasks.' });

    const result = await pool.query(`
      SELECT t.id, t.email, tma.position, tma.name AS title, tma.telephone
      FROM   team_member_assignments tma
      JOIN   team_members t ON t.id = tma.team_member_id
      WHERE  tma.project_id   = $1
        AND  tma.assigned_part = $2
      ORDER  BY tma.position, t.email
    `, [projectId, side]);

    return res.json({ members: result.rows });
  } catch (err) {
    console.error('GET /api/work-center/team-members:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Create task (leaders/PMs only) ────────────────────────────────────────────
app.post('/api/work-center', authenticateToken,
  upload.single('linked_file'), requireProjectLifecycleWrite, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    if (!isWCLeader(role))
      return res.status(403).json({ error: 'Only leaders and PMs can create tasks.' });

    const side = wcSide(role);

    const {
      projectId,
      title,
      description  = '',
      work_package = '',
      assigned_members,
      priority     = 'normal',
      status       = 'ongoing',
      start_date,
      end_date,
      activity_id  = null,
    } = req.body;

    if (!projectId)              return res.status(400).json({ error: 'projectId is required.' });
    if (!title?.trim())          return res.status(400).json({ error: 'title is required.' });
    if (!start_date)             return res.status(400).json({ error: 'start_date is required.' });
    if (!end_date)               return res.status(400).json({ error: 'end_date is required.' });
    if (!['low','normal','high'].includes(priority))
      return res.status(400).json({ error: 'priority must be low, normal, or high.' });
    if (!['ongoing','completed','closed'].includes(status))
      return res.status(400).json({ error: 'status must be ongoing, completed, or closed.' });

    let members = [];
    try { members = JSON.parse(assigned_members || '[]'); }
    catch { return res.status(400).json({ error: 'assigned_members must be valid JSON.' }); }
    if (!members.length)
      return res.status(400).json({ error: 'At least one team member must be assigned.' });

    // Verify all members belong to the same side
    const memberIds = members.map(m => parseInt(m.id, 10)).filter(Boolean);
    const check = await pool.query(
      `SELECT COUNT(*) AS cnt FROM team_member_assignments
       WHERE project_id = $1 AND team_member_id = ANY($2::int[]) AND assigned_part = $3`,
      [projectId, memberIds, side]
    );
    if (parseInt(check.rows[0].cnt, 10) !== memberIds.length)
      return res.status(403).json({
        error: 'One or more assigned members do not belong to your side.'
      });

    // Validate activity_id belongs to the same side and project
    let resolvedActivityId = null;
    if (activity_id) {
      const actCheck = await pool.query(
        `SELECT id FROM planning_execution
         WHERE id = $1 AND project_id = $2 AND side = $3`,
        [activity_id, projectId, side]
      );
      if (actCheck.rows.length) resolvedActivityId = activity_id;
    }

    let linkedFileName = null, linkedFileId = null, linkedFileUrl = null;
    if (req.file) {
      const uploaded = await scheduleCloudinaryUpload(
        req.file.buffer, req.file.originalname, 'work_center/tasks'
      );
      linkedFileName = req.file.originalname;
      linkedFileId   = uploaded.public_id;
      linkedFileUrl  = uploaded.secure_url;
    }

    const result = await pool.query(`
      INSERT INTO workspace_work_center
        (project_id, title, description, work_package, assigned_members,
         priority, status, start_date, end_date,
         linked_file_name, linked_file_id, linked_file_url,
         creator_id, creator_role, side, activity_id)
      VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
      RETURNING *
    `, [
      projectId, title.trim(), description, work_package,
      JSON.stringify(members), priority, status, start_date, end_date,
      linkedFileName, linkedFileId, linkedFileUrl,
      user_id, role, side, resolvedActivityId,
    ]);

    return res.status(201).json({ success: true, task: result.rows[0] });
  } catch (err) {
    console.error('POST /api/work-center:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Update task (same-side leader only) ──────────────────────────────────────
app.put('/api/work-center/:taskId', authenticateToken,
  upload.single('linked_file'), requireProjectLifecycleWrite, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { taskId }        = req.params;
    const { projectId }     = req.body;

    if (!isWCLeader(role))
      return res.status(403).json({ error: 'Only leaders and PMs can update tasks.' });
    if (!projectId)
      return res.status(400).json({ error: 'projectId is required.' });

    const side = wcSide(role);
    const taskCheck = await pool.query(
      `SELECT id, side, linked_file_id FROM workspace_work_center
       WHERE id = $1 AND project_id = $2`,
      [taskId, projectId]
    );
    if (!taskCheck.rows.length)
      return res.status(404).json({ error: 'Task not found.' });
    if (taskCheck.rows[0].side !== side)
      return res.status(403).json({ error: 'You cannot edit tasks from another side.' });

    const {
      title, description, work_package, assigned_members,
      priority, status, start_date, end_date,
    } = req.body;

    if (priority !== undefined && !['low','normal','high'].includes(priority))
      return res.status(400).json({ error: 'priority must be low, normal, or high.' });
    if (status !== undefined && !['ongoing','completed','closed'].includes(status))
      return res.status(400).json({ error: 'status must be ongoing, completed, or closed.' });

    let members = null;
    if (assigned_members !== undefined) {
      try { members = JSON.parse(assigned_members); }
      catch { return res.status(400).json({ error: 'assigned_members must be valid JSON.' }); }
      if (members.length) {
        const memberIds = members.map(m => parseInt(m.id, 10)).filter(Boolean);
        const check = await pool.query(
          `SELECT COUNT(*) AS cnt FROM team_member_assignments
           WHERE project_id = $1 AND team_member_id = ANY($2::int[]) AND assigned_part = $3`,
          [projectId, memberIds, side]
        );
        if (parseInt(check.rows[0].cnt, 10) !== memberIds.length)
          return res.status(403).json({
            error: 'One or more members do not belong to your side.'
          });
      }
    }

    const setClauses = [], values = []; let idx = 1;
    const push = (col, val) => { setClauses.push(`${col} = $${idx++}`); values.push(val); };

    if (title            !== undefined) push('title',            title.trim());
    if (description      !== undefined) push('description',      description);
    if (work_package     !== undefined) push('work_package',     work_package);
    if (members          !== null)      push('assigned_members', JSON.stringify(members));
    if (priority         !== undefined) push('priority',         priority);
    if (status           !== undefined) push('status',           status);
    if (start_date       !== undefined) push('start_date',       start_date);
    if (end_date         !== undefined) push('end_date',         end_date);

    if (req.file) {
      if (taskCheck.rows[0].linked_file_id)
        await cloudinary.uploader.destroy(
          taskCheck.rows[0].linked_file_id, { resource_type: 'raw' }
        ).catch(() => {});
      const uploaded = await scheduleCloudinaryUpload(
        req.file.buffer, req.file.originalname, 'work_center/tasks'
      );
      push('linked_file_name', req.file.originalname);
      push('linked_file_id',   uploaded.public_id);
      push('linked_file_url',  uploaded.secure_url);
    }

    if (!setClauses.length) return res.status(400).json({ error: 'No fields to update.' });
    values.push(taskId, projectId);

    const updated = await pool.query(
      `UPDATE workspace_work_center SET ${setClauses.join(', ')}
       WHERE id = $${idx} AND project_id = $${idx + 1} RETURNING *`,
      values
    );
    return res.json({ success: true, task: updated.rows[0] });
  } catch (err) {
    console.error('PUT /api/work-center/:taskId:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Delete task (same-side leader only) ───────────────────────────────────────
app.delete('/api/work-center/:taskId', authenticateToken, async (req, res) => {
  try {
    const { role }      = req.user;
    const { taskId }    = req.params;
    const { projectId } = req.body;

    if (!isWCLeader(role))
      return res.status(403).json({ error: 'Only leaders and PMs can delete tasks.' });
    if (!projectId)
      return res.status(400).json({ error: 'projectId is required.' });

    const side = wcSide(role);
    const taskCheck = await pool.query(
      `SELECT id, side, linked_file_id FROM workspace_work_center
       WHERE id = $1 AND project_id = $2`,
      [taskId, projectId]
    );
    if (!taskCheck.rows.length)
      return res.status(404).json({ error: 'Task not found.' });
    if (taskCheck.rows[0].side !== side)
      return res.status(403).json({ error: 'You cannot delete tasks from another side.' });

    if (taskCheck.rows[0].linked_file_id)
      await cloudinary.uploader.destroy(
        taskCheck.rows[0].linked_file_id, { resource_type: 'raw' }
      ).catch(() => {});

    const progressFiles = await pool.query(
      `SELECT attachment_id FROM workspace_work_center_progress
       WHERE task_id = $1 AND attachment_id IS NOT NULL`,
      [taskId]
    );
    await Promise.allSettled(
      progressFiles.rows.map(r =>
        cloudinary.uploader.destroy(r.attachment_id, { resource_type: 'raw' })
      )
    );

    await pool.query(
      `DELETE FROM workspace_work_center WHERE id = $1 AND project_id = $2`,
      [taskId, projectId]
    );
    return res.json({ success: true, message: 'Task deleted.' });
  } catch (err) {
    console.error('DELETE /api/work-center/:taskId:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Download task linked file ──────────────────────────────────────────────────
app.get('/api/work-center/:taskId/download', authenticateToken, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { taskId }        = req.params;
    const { projectId }     = req.query;
    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });

    const taskCheck = await pool.query(
      `SELECT id, side, linked_file_id, linked_file_url, linked_file_name, assigned_members
       FROM workspace_work_center WHERE id = $1 AND project_id = $2`,
      [taskId, projectId]
    );
    if (!taskCheck.rows.length)
      return res.status(404).json({ error: 'Task not found.' });

    const task = taskCheck.rows[0];

    if (isWCLeader(role)) {
      if (task.side !== wcSide(role))
        return res.status(403).json({ error: 'Access denied.' });
    } else if (role === 'TeamMember') {
      const assigned = Array.isArray(task.assigned_members) ? task.assigned_members : [];
      if (!assigned.some(m => String(m.id) === String(user_id)))
        return res.status(403).json({ error: 'You are not assigned to this task.' });
    } else {
      return res.status(403).json({ error: 'Access denied.' });
    }

    if (!task.linked_file_id)
      return res.status(404).json({ error: 'No file attached to this task.' });

    return res.json({ url: task.linked_file_url, filename: task.linked_file_name });
  } catch (err) {
    console.error('GET /api/work-center/:taskId/download:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Get progress entries for a task ───────────────────────────────────────────
app.get('/api/work-center-progress/:taskId', authenticateToken, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { taskId }        = req.params;
    const { projectId }     = req.query;
    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });

    const taskCheck = await pool.query(
      `SELECT id, side, assigned_members FROM workspace_work_center
       WHERE id = $1 AND project_id = $2`,
      [taskId, projectId]
    );
    if (!taskCheck.rows.length)
      return res.status(404).json({ error: 'Task not found.' });

    const task = taskCheck.rows[0];

    if (isWCLeader(role)) {
      if (task.side !== wcSide(role))
        return res.status(403).json({ error: 'Access denied.' });
      const result = await pool.query(`
        SELECT p.*,
               t.email       AS member_email,
               tma.position  AS member_position,
               tma.name      AS member_title
        FROM   workspace_work_center_progress p
        JOIN   team_members t ON t.id = p.member_id
        LEFT JOIN LATERAL (
               SELECT position, name
               FROM   team_member_assignments
               WHERE  team_member_id = p.member_id
                 AND  project_id = $2
               ORDER  BY id DESC
               LIMIT 1
        ) tma ON true
        WHERE  p.task_id = $1
        ORDER  BY p.submitted_at DESC
      `, [taskId, projectId]);
      return res.json({ entries: result.rows });

    } else if (role === 'TeamMember') {
      const assigned = Array.isArray(task.assigned_members) ? task.assigned_members : [];
      if (!assigned.some(m => String(m.id) === String(user_id)))
        return res.status(403).json({ error: 'You are not assigned to this task.' });
      const result = await pool.query(
        `SELECT * FROM workspace_work_center_progress
         WHERE task_id = $1 AND member_id = $2 ORDER BY submitted_at DESC`,
        [taskId, user_id]
      );
      return res.json({ entries: result.rows });

    } else {
      return res.status(403).json({ error: 'Access denied.' });
    }
  } catch (err) {
    console.error('GET /api/work-center-progress/:taskId:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Submit progress (TeamMember only) ─────────────────────────────────────────
app.post('/api/work-center-progress', authenticateToken,
  upload.single('attachment'), requireProjectLifecycleWrite, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    if (role !== 'TeamMember')
      return res.status(403).json({
        error: 'Only assigned team members can submit progress reports.'
      });

    const {
      projectId, taskId, reportDate, workDone,
      manpower = '', equipment = '', materials = '',
      progressPct = '0', issues = '', notes = '',
    } = req.body;

    if (!projectId)  return res.status(400).json({ error: 'projectId is required.' });
    if (!taskId)     return res.status(400).json({ error: 'taskId is required.' });
    if (!reportDate) return res.status(400).json({ error: 'reportDate is required.' });
    if (!workDone)   return res.status(400).json({ error: 'workDone is required.' });

    const pct = parseInt(progressPct, 10);
    if (isNaN(pct) || pct < 0 || pct > 100)
      return res.status(400).json({ error: 'progressPct must be 0–100.' });

    const taskCheck = await pool.query(
      `SELECT id, assigned_members FROM workspace_work_center
       WHERE id = $1 AND project_id = $2`,
      [taskId, projectId]
    );
    if (!taskCheck.rows.length)
      return res.status(404).json({ error: 'Task not found.' });

    const assigned = Array.isArray(taskCheck.rows[0].assigned_members)
      ? taskCheck.rows[0].assigned_members : [];
    if (!assigned.some(m => String(m.id) === String(user_id)))
      return res.status(403).json({ error: 'You are not assigned to this task.' });

    let attachmentName = null, attachmentId = null, attachmentUrl = null;
    if (req.file) {
      const uploaded = await scheduleCloudinaryUpload(
        req.file.buffer, req.file.originalname, 'work_center/progress'
      );
      attachmentName = req.file.originalname;
      attachmentId   = uploaded.public_id;
      attachmentUrl  = uploaded.secure_url;
    }

    const result = await pool.query(`
      INSERT INTO workspace_work_center_progress
        (task_id, report_date, member_id, member_role,
         work_done, manpower, equipment, materials,
         progress_pct, issues, notes,
         attachment_name, attachment_id, attachment_url)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
      RETURNING *
    `, [
      taskId, reportDate, user_id, role,
      workDone, manpower, equipment, materials,
      pct, issues, notes,
      attachmentName, attachmentId, attachmentUrl,
    ]);

    return res.status(201).json({ success: true, entry: result.rows[0] });
  } catch (err) {
    console.error('POST /api/work-center-progress:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Validate progress entry (same-side leader only) ───────────────────────────
app.put('/api/work-center-progress/:progressId/validate',
  authenticateToken, async (req, res) => {
  try {
    const { user_id, role }                              = req.user;
    const { progressId }                                 = req.params;
    const { projectId, validation_status, validation_notes = '' } = req.body;

    if (!isWCLeader(role))
      return res.status(403).json({
        error: 'Only leaders and PMs can validate progress entries.'
      });
    if (!projectId)
      return res.status(400).json({ error: 'projectId is required.' });

    const isCommentOnly = !validation_status || validation_status === 'comment_only';
    if (!isCommentOnly && !['approved','rejected'].includes(validation_status))
      return res.status(400).json({
        error: 'validation_status must be approved, rejected, or comment_only.'
      });

    const entryCheck = await pool.query(`
      SELECT p.id, w.side
      FROM   workspace_work_center_progress p
      JOIN   workspace_work_center w ON w.id = p.task_id
      WHERE  p.id = $1 AND w.project_id = $2
    `, [progressId, projectId]);

    if (!entryCheck.rows.length)
      return res.status(404).json({ error: 'Progress entry not found.' });
    if (entryCheck.rows[0].side !== wcSide(role))
      return res.status(403).json({ error: 'You cannot validate progress from another side.' });

    let updated;
    if (isCommentOnly) {
      updated = await pool.query(
        `UPDATE workspace_work_center_progress
         SET validation_notes = $1 WHERE id = $2 RETURNING *`,
        [validation_notes, progressId]
      );
    } else {
      updated = await pool.query(
        `UPDATE workspace_work_center_progress
         SET validation_status = $1, validation_notes = $2,
             validated_by = $3, validated_at = NOW()
         WHERE id = $4 RETURNING *`,
        [validation_status, validation_notes, user_id, progressId]
      );
    }

    return res.json({ success: true, entry: updated.rows[0] });
  } catch (err) {
    console.error('PUT /api/work-center-progress/:progressId/validate:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Download progress attachment ───────────────────────────────────────────────
app.get('/api/work-center-progress/download/:progressId',
  authenticateToken, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { progressId }    = req.params;
    const { projectId }     = req.query;
    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });

    const result = await pool.query(`
      SELECT p.id, p.member_id, p.attachment_id, p.attachment_url,
             p.attachment_name, w.side
      FROM   workspace_work_center_progress p
      JOIN   workspace_work_center w ON w.id = p.task_id
      WHERE  p.id = $1 AND w.project_id = $2
    `, [progressId, projectId]);

    if (!result.rows.length)
      return res.status(404).json({ error: 'Progress entry not found.' });

    const entry = result.rows[0];
    const isOwner  = String(entry.member_id) === String(user_id);
    const isLeader = isWCLeader(role) && entry.side === wcSide(role);

    if (!isOwner && !isLeader)
      return res.status(403).json({ error: 'Access denied.' });
    if (!entry.attachment_id)
      return res.status(404).json({ error: 'No attachment on this entry.' });

    return res.json({ url: entry.attachment_url, filename: entry.attachment_name });
  } catch (err) {
    console.error('GET /api/work-center-progress/download/:progressId:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ── Mark task viewed ──────────────────────────────────────────────────────────
app.post('/api/mark-work-center-viewed', authenticateToken, async (req, res) => {
  try {
    const { user_id }         = req.user;
    const { projectId, recordId } = req.body;
    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });
    if (!recordId)  return res.status(400).json({ error: 'recordId is required.' });

    const check = await pool.query(
      `SELECT id FROM workspace_work_center WHERE id = $1 AND project_id = $2`,
      [recordId, projectId]
    );
    if (!check.rows.length)
      return res.status(404).json({ error: 'Task not found.' });

    await pool.query(
      `INSERT INTO work_center_views (task_id, viewer_id) VALUES ($1, $2)
       ON CONFLICT (task_id, viewer_id) DO NOTHING`,
      [recordId, user_id]
    );
    return res.json({ success: true });
  } catch (err) {
    console.error('POST /api/mark-work-center-viewed:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  PROJECT INFO PAGE ROUTES
// ─────────────────────────────────────────────────────────────────────────────

// ── GET /api/project-info/:projectId ─────────────────────────────────────────
// Loads all project data: project fields, client, contractor, consultant,
// all PMs, and team members. Used by project-information.html on page load.
app.get('/api/project-info/:projectId', authenticateToken, async (req, res) => {
  const projectId = normalizeProjectId(req.params.projectId);
  if (!projectId) return res.status(400).json({ success: false, error: 'Valid projectId is required.' });

  try {
    // Verify the requesting user has access to this project
    const hasAccess = await userHasProjectAccess(req.user.user_id, req.user.role, projectId);
    if (!hasAccess) return res.status(403).json({ success: false, error: 'Access denied to this project.' });

    // ── Project base fields ──────────────────────────────────────────────────
    const projRes = await pool.query(
      `SELECT id, name, location, contract_reference, time_zone, created_at
       FROM projects WHERE id = $1`,
      [projectId]
    );
    if (!projRes.rows.length)
      return res.status(404).json({ success: false, error: 'Project not found.' });
    const project = projRes.rows[0];

    // ── Client ───────────────────────────────────────────────────────────────
    // clients table: company_name, company_email, representative, title, telephone
    // No task column on clients — task comes from context, left null here
    const clientRes = await pool.query(
      `SELECT c.company_name, c.company_email AS email, c.telephone,
              c.representative, c.title
       FROM projects p
       JOIN clients c ON p.client_id = c.id
       WHERE p.id = $1`,
      [projectId]
    );
    const client = clientRes.rows[0] || null;

    // ── Contractor ───────────────────────────────────────────────────────────
    // contractor_assignments: company_name, telephone, task, representative,
    //                         title_position
    const contractorRes = await pool.query(
      `SELECT ca.company_name, c.email, ca.telephone,
              ca.representative, ca.title_position, ca.task
       FROM contractor_assignments ca
       JOIN contractors c ON ca.contractor_id = c.id
       WHERE ca.project_id = $1
       LIMIT 1`,
      [projectId]
    );
    const contractor = contractorRes.rows[0] || null;

    // ── Consultant ───────────────────────────────────────────────────────────
    const consultantRes = await pool.query(
      `SELECT co.company_name, c.email, co.telephone,
              co.representative, co.title_position, co.task
       FROM consultant_assignments co
       JOIN consultants c ON co.consultant_id = c.id
       WHERE co.project_id = $1
       LIMIT 1`,
      [projectId]
    );
    const consultant = consultantRes.rows[0] || null;

    // ── Client PM ────────────────────────────────────────────────────────────
    // client_pm_assignments: name, telephone, task
    // client_project_managers: email
    const clientPMRes = await pool.query(
      `SELECT cpa.name, pm.email, cpa.telephone, cpa.task
       FROM client_pm_assignments cpa
       JOIN client_project_managers pm ON cpa.client_pm_id = pm.id
       WHERE cpa.project_id = $1
       LIMIT 1`,
      [projectId]
    );
    const client_pm = clientPMRes.rows[0] || null;

    // ── Contractor PM ─────────────────────────────────────────────────────────
    const contractorPMRes = await pool.query(
      `SELECT cpa.name, pm.email, cpa.telephone, cpa.task
       FROM contractor_pm_assignments cpa
       JOIN contractor_project_managers pm ON cpa.contractor_pm_id = pm.id
       WHERE cpa.project_id = $1
       LIMIT 1`,
      [projectId]
    );
    const contractor_pm = contractorPMRes.rows[0] || null;

    // ── Consultant PM ─────────────────────────────────────────────────────────
    const consultantPMRes = await pool.query(
      `SELECT cpa.name, pm.email, cpa.telephone, cpa.task
       FROM consultant_pm_assignments cpa
       JOIN consultant_project_managers pm ON cpa.consultant_pm_id = pm.id
       WHERE cpa.project_id = $1
       LIMIT 1`,
      [projectId]
    );
    const consultant_pm = consultantPMRes.rows[0] || null;

    // ── Team Members ─────────────────────────────────────────────────────────
    // team_member_assignments: name, position, telephone, assigned_part
    // team_members: email
    const teamRes = await pool.query(
      `SELECT tma.id, tma.name, tm.email, tma.position,
              tma.telephone, tma.assigned_part
       FROM team_member_assignments tma
       JOIN team_members tm ON tma.team_member_id = tm.id
       WHERE tma.project_id = $1
       ORDER BY tma.assigned_part, tma.created_at`,
      [projectId]
    );
    const team_members = teamRes.rows;

    return res.json({
      success: true,
      project: {
        ...project,
        client,
        contractor,
        consultant,
        client_pm,
        contractor_pm,
        consultant_pm,
        team_members,
      },
    });
  } catch (err) {
    console.error('[GET /api/project-info/:projectId]', err);
    return res.status(500).json({ success: false, error: 'Server error loading project data.' });
  }
});


// ── POST /api/project-edit ────────────────────────────────────────────────────
// Edit project base fields (name, location, contract_reference).
// Only Client / ClientPM can call this (enforced in frontend + here).
app.post('/api/project-edit', authenticateToken, async (req, res) => {
  const { projectId, name, location, contract_reference, time_zone } = req.body;
  const pid = normalizeProjectId(projectId);
  if (!pid) return res.status(400).json({ success: false, error: 'Valid projectId is required.' });
  if (!name || !location || !contract_reference)
    return res.status(400).json({ success: false, error: 'name, location and contract_reference are required.' });
  if (time_zone && !isValidMeetingTimeZone(String(time_zone).trim()))
    return res.status(400).json({ success: false, error: 'Enter a valid IANA time zone, such as Europe/London.' });

  // Only client-side roles may edit project base fields
  const userSide = getSide(req.user.role);
  if (userSide !== 'client')
    return res.status(403).json({ success: false, error: 'Only the client side can edit project information.' });

  try {
    const hasAccess = await userHasProjectAccess(req.user.user_id, req.user.role, pid);
    if (!hasAccess) return res.status(403).json({ success: false, error: 'Access denied.' });

    // Ensure the new name doesn't clash with another project owned by the same client
    const clientRes = await pool.query('SELECT client_id FROM projects WHERE id = $1', [pid]);
    if (!clientRes.rows.length) return res.status(404).json({ success: false, error: 'Project not found.' });
    const clientId = clientRes.rows[0].client_id;

    const clash = await pool.query(
      `SELECT id FROM projects
       WHERE name = $1 AND client_id = $2 AND id != $3`,
      [name, clientId, pid]
    );
    if (clash.rows.length)
      return res.status(409).json({ success: false, error: 'Another project with this name already exists.' });

    await pool.query(
      `UPDATE projects SET name = $1, location = $2, contract_reference = $3, time_zone = $4
       WHERE id = $5`,
      [name, location, contract_reference, String(time_zone || '').trim() || null, pid]
    );

    return res.json({ success: true, message: 'Project info updated.' });
  } catch (err) {
    console.error('[POST /api/project-edit]', err);
    return res.status(500).json({ success: false, error: 'Server error updating project.' });
  }
});


// ── POST /api/project-edit-party ─────────────────────────────────────────────
// Edit client / contractor / consultant party fields.
// Each side can only edit their own party row.
// Columns differ: clients uses (company_email, title) not (email, title_position).
app.post('/api/project-edit-party', authenticateToken, async (req, res) => {
  const {
    projectId, side,
    company_name, email, telephone, representative,
    title_position, task,
    title,          // client-specific alias sent by frontend
  } = req.body;

  const pid = normalizeProjectId(projectId);
  if (!pid)   return res.status(400).json({ success: false, error: 'Valid projectId is required.' });
  if (!side)  return res.status(400).json({ success: false, error: 'side is required.' });
  if (!['client', 'contractor', 'consultant'].includes(side))
    return res.status(400).json({ success: false, error: 'side must be client, contractor or consultant.' });

  // Enforce: you can only edit your own side
  const userSide = getSide(req.user.role);
  if (userSide !== side)
    return res.status(403).json({ success: false, error: 'You can only edit your own party information.' });

  try {
    const hasAccess = await userHasProjectAccess(req.user.user_id, req.user.role, pid);
    if (!hasAccess) return res.status(403).json({ success: false, error: 'Access denied.' });

    if (side === 'client') {
      // clients row: update via projects.client_id join
      // company_email is the unique key so we do NOT let them change it here
      // title_position sent by frontend maps to clients.title for the client side
      const effectiveTitle = title || title_position || null;
      await pool.query(
        `UPDATE clients SET
           company_name   = $1,
           representative = $2,
           title          = $3,
           telephone      = $4
         WHERE id = (SELECT client_id FROM projects WHERE id = $5)`,
        [company_name, representative, effectiveTitle, telephone, pid]
      );
    } else if (side === 'contractor') {
      // contractor_assignments row
      await pool.query(
        `UPDATE contractor_assignments SET
           company_name   = $1,
           representative = $2,
           title_position = $3,
           telephone      = $4,
           task           = $5
         WHERE project_id = $6`,
        [company_name, representative, title_position, telephone, task, pid]
      );
      // Also update email on the contractors row if it changed
      if (email) {
        await pool.query(
          `UPDATE contractors SET email = $1
           WHERE id = (
             SELECT contractor_id FROM contractor_assignments WHERE project_id = $2
           )`,
          [email, pid]
        );
      }
    } else {
      // consultant_assignments row
      await pool.query(
        `UPDATE consultant_assignments SET
           company_name   = $1,
           representative = $2,
           title_position = $3,
           telephone      = $4,
           task           = $5
         WHERE project_id = $6`,
        [company_name, representative, title_position, telephone, task, pid]
      );
      if (email) {
        await pool.query(
          `UPDATE consultants SET email = $1
           WHERE id = (
             SELECT consultant_id FROM consultant_assignments WHERE project_id = $2
           )`,
          [email, pid]
        );
      }
    }

    return res.json({ success: true, message: `${side} info updated.` });
  } catch (err) {
    console.error('[POST /api/project-edit-party]', err);
    return res.status(500).json({ success: false, error: 'Server error updating party.' });
  }
});


// ── POST /api/project-delete-party ───────────────────────────────────────────
// Remove contractor or consultant (and their PM) from a project.
// Only client-side roles can do this. Client itself cannot be deleted.
app.post('/api/project-delete-party', authenticateToken, async (req, res) => {
  const { projectId, side } = req.body;
  const pid = normalizeProjectId(projectId);
  if (!pid)  return res.status(400).json({ success: false, error: 'Valid projectId is required.' });
  if (!side) return res.status(400).json({ success: false, error: 'side is required.' });
  if (!['contractor', 'consultant'].includes(side))
    return res.status(400).json({ success: false, error: 'Only contractor or consultant can be deleted.' });

  // Only client side may delete parties
  if (getSide(req.user.role) !== 'client')
    return res.status(403).json({ success: false, error: 'Only the client side can remove parties.' });

  try {
    const hasAccess = await userHasProjectAccess(req.user.user_id, req.user.role, pid);
    if (!hasAccess) return res.status(403).json({ success: false, error: 'Access denied.' });

    const dbClient = await pool.connect();
    try {
      await dbClient.query('BEGIN');

      if (side === 'contractor') {
        // Delete PM assignment first (FK cascade may handle it, but be explicit)
        await dbClient.query(
          `DELETE FROM contractor_pm_assignments WHERE project_id = $1`, [pid]
        );
        await dbClient.query(
          `DELETE FROM contractor_assignments WHERE project_id = $1`, [pid]
        );
      } else {
        await dbClient.query(
          `DELETE FROM consultant_pm_assignments WHERE project_id = $1`, [pid]
        );
        await dbClient.query(
          `DELETE FROM consultant_assignments WHERE project_id = $1`, [pid]
        );
      }

      await dbClient.query('COMMIT');
    } catch (e) {
      await dbClient.query('ROLLBACK');
      throw e;
    } finally {
      dbClient.release();
    }

    return res.json({ success: true, message: `${side} removed from project.` });
  } catch (err) {
    console.error('[POST /api/project-delete-party]', err);
    return res.status(500).json({ success: false, error: 'Server error deleting party.' });
  }
});


// ── POST /api/project-replace-pm ─────────────────────────────────────────────
// Replace (or create) the PM for a given side.
// Inserts into the *_project_managers table if email is new,
// then deletes the old *_pm_assignments row and inserts a fresh one.
// Auth: same-side leaders/PMs, or client-side for any party.
app.post('/api/project-replace-pm', authenticateToken, async (req, res) => {
  const { projectId, side, name, email, telephone, task } = req.body;
  const pid = normalizeProjectId(projectId);
  if (!pid)   return res.status(400).json({ success: false, error: 'Valid projectId is required.' });
  if (!side)  return res.status(400).json({ success: false, error: 'side is required.' });
  if (!name || !email || !task)
    return res.status(400).json({ success: false, error: 'name, email and task are required.' });
  if (!['client', 'contractor', 'consultant'].includes(side))
    return res.status(400).json({ success: false, error: 'side must be client, contractor or consultant.' });

  const userSide = getSide(req.user.role);
  // Must be the same side OR client-side (client can manage all PMs)
  if (userSide !== side && userSide !== 'client')
    return res.status(403).json({ success: false, error: 'You cannot manage PMs for another side.' });

  try {
    const hasAccess = await userHasProjectAccess(req.user.user_id, req.user.role, pid);
    if (!hasAccess) return res.status(403).json({ success: false, error: 'Access denied.' });

    // Map side → tables
    const map = {
      client:     { pmTable: 'client_project_managers',     assignTable: 'client_pm_assignments',     fk: 'client_pm_id' },
      contractor: { pmTable: 'contractor_project_managers', assignTable: 'contractor_pm_assignments', fk: 'contractor_pm_id' },
      consultant: { pmTable: 'consultant_project_managers', assignTable: 'consultant_pm_assignments', fk: 'consultant_pm_id' },
    }[side];

    const dbClient = await pool.connect();
    try {
      await dbClient.query('BEGIN');

      // Upsert PM user row
      await dbClient.query(
        `INSERT INTO ${map.pmTable} (email, verified)
         VALUES ($1, true)
         ON CONFLICT (email) DO NOTHING`,
        [email]
      );
      const pmRes = await dbClient.query(
        `SELECT id FROM ${map.pmTable} WHERE email = $1`, [email]
      );
      const pmId = pmRes.rows[0].id;

      // Remove old assignment for this project (there can only be one PM per side)
      await dbClient.query(
        `DELETE FROM ${map.assignTable} WHERE project_id = $1`, [pid]
      );

      // Insert new assignment
      await dbClient.query(
        `INSERT INTO ${map.assignTable} (project_id, ${map.fk}, name, telephone, task)
         VALUES ($1, $2, $3, $4, $5)`,
        [pid, pmId, name, telephone || null, task]
      );

      await dbClient.query('COMMIT');
    } catch (e) {
      await dbClient.query('ROLLBACK');
      throw e;
    } finally {
      dbClient.release();
    }

    return res.json({ success: true, message: `${side} PM replaced.` });
  } catch (err) {
    console.error('[POST /api/project-replace-pm]', err);
    return res.status(500).json({ success: false, error: 'Server error replacing PM.' });
  }
});


// ── POST /api/project-remove-pm ──────────────────────────────────────────────
// Remove the PM assignment for a given side from this project.
// The *_project_managers user row is kept (they may be on other projects).
app.post('/api/project-remove-pm', authenticateToken, async (req, res) => {
  const { projectId, side } = req.body;
  const pid = normalizeProjectId(projectId);
  if (!pid)  return res.status(400).json({ success: false, error: 'Valid projectId is required.' });
  if (!side) return res.status(400).json({ success: false, error: 'side is required.' });
  if (!['client', 'contractor', 'consultant'].includes(side))
    return res.status(400).json({ success: false, error: 'side must be client, contractor or consultant.' });

  const userSide = getSide(req.user.role);
  if (userSide !== side && userSide !== 'client')
    return res.status(403).json({ success: false, error: 'You cannot manage PMs for another side.' });

  try {
    const hasAccess = await userHasProjectAccess(req.user.user_id, req.user.role, pid);
    if (!hasAccess) return res.status(403).json({ success: false, error: 'Access denied.' });

    const assignTable = {
      client:     'client_pm_assignments',
      contractor: 'contractor_pm_assignments',
      consultant: 'consultant_pm_assignments',
    }[side];

    const result = await pool.query(
      `DELETE FROM ${assignTable} WHERE project_id = $1 RETURNING id`, [pid]
    );

    if (!result.rows.length)
      return res.status(404).json({ success: false, error: `No ${side} PM found on this project.` });

    return res.json({ success: true, message: `${side} PM removed.` });
  } catch (err) {
    console.error('[POST /api/project-remove-pm]', err);
    return res.status(500).json({ success: false, error: 'Server error removing PM.' });
  }
});


// ── POST /api/project-remove-member ──────────────────────────────────────────
// Remove a team member assignment from a project.
// Allowed if: the member themselves, same-side leader/PM, or client-side.
app.post('/api/project-remove-member', authenticateToken, async (req, res) => {
  const { projectId, memberId } = req.body;
  const pid = normalizeProjectId(projectId);
  if (!pid)      return res.status(400).json({ success: false, error: 'Valid projectId is required.' });
  if (!memberId) return res.status(400).json({ success: false, error: 'memberId is required.' });

  try {
    const hasAccess = await userHasProjectAccess(req.user.user_id, req.user.role, pid);
    if (!hasAccess) return res.status(403).json({ success: false, error: 'Access denied.' });

    // Fetch the assignment to check side and ownership
    const assignRes = await pool.query(
      `SELECT tma.id, tma.assigned_part, tm.email
       FROM team_member_assignments tma
       JOIN team_members tm ON tma.team_member_id = tm.id
       WHERE tma.id = $1 AND tma.project_id = $2`,
      [memberId, pid]
    );
    if (!assignRes.rows.length)
      return res.status(404).json({ success: false, error: 'Team member not found on this project.' });

    const assignment   = assignRes.rows[0];
    const memberSide   = (assignment.assigned_part || '').toLowerCase();
    const userSide     = getSide(req.user.role);
    const isSelf       = req.user.role === 'TeamMember' &&
                         req.user.email?.toLowerCase() === assignment.email?.toLowerCase();
    const isSameSide   = userSide === memberSide;
    const isClientSide = userSide === 'client';

    if (isSelf)
      return res.status(403).json({ success: false, error: 'Schedule your project exit from Project Settings. Membership is removed after 15 days.' });

    if (!isSelf && !isSameSide && !isClientSide)
      return res.status(403).json({ success: false, error: 'You do not have permission to remove this member.' });

    await pool.query(
      `DELETE FROM team_member_assignments WHERE id = $1 AND project_id = $2`,
      [memberId, pid]
    );

    return res.json({ success: true, message: 'Team member removed from project.' });
  } catch (err) {
    console.error('[POST /api/project-remove-member]', err);
    return res.status(500).json({ success: false, error: 'Server error removing team member.' });
  }
});


// ── POST /api/project-replace-member ─────────────────────────────────────────
// Replace a team member with a new one.
// Upserts the new person into team_members, removes old assignment,
// inserts new assignment inheriting the same assigned_part and assigned_by.
// Only same-side or client-side leaders/PMs can do this (not self).
app.post('/api/project-replace-member', authenticateToken, async (req, res) => {
  const { projectId, oldMemberId, name, email, position, telephone } = req.body;
  const pid = normalizeProjectId(projectId);
  if (!pid)         return res.status(400).json({ success: false, error: 'Valid projectId is required.' });
  if (!oldMemberId) return res.status(400).json({ success: false, error: 'oldMemberId is required.' });
  if (!name || !email || !position)
    return res.status(400).json({ success: false, error: 'name, email and position are required.' });

  // Only leaders/PMs can replace members (not team members themselves)
  const userSide = getSide(req.user.role);
  if (!userSide)
    return res.status(403).json({ success: false, error: 'Only leaders and PMs can replace team members.' });

  try {
    const hasAccess = await userHasProjectAccess(req.user.user_id, req.user.role, pid);
    if (!hasAccess) return res.status(403).json({ success: false, error: 'Access denied.' });

    // Fetch old assignment to inherit side + assigner info
    const oldRes = await pool.query(
      `SELECT id, assigned_part, assigned_by, assigned_by_role
       FROM team_member_assignments
       WHERE id = $1 AND project_id = $2`,
      [oldMemberId, pid]
    );
    if (!oldRes.rows.length)
      return res.status(404).json({ success: false, error: 'Original team member not found.' });

    const old            = oldRes.rows[0];
    const memberSide     = (old.assigned_part || '').toLowerCase();
    const isClientSide   = userSide === 'client';

    if (userSide !== memberSide && !isClientSide)
      return res.status(403).json({ success: false, error: 'You can only replace members on your own side.' });

    const dbClient = await pool.connect();
    try {
      await dbClient.query('BEGIN');

      // Upsert the new team member user row
      await dbClient.query(
        `INSERT INTO team_members (email, verified)
         VALUES ($1, true)
         ON CONFLICT (email) DO NOTHING`,
        [email]
      );
      const newTMRes = await dbClient.query(
        `SELECT id FROM team_members WHERE email = $1`, [email]
      );
      const newTMId = newTMRes.rows[0].id;

      // Check the new member isn't already assigned to this project
      const dupeCheck = await dbClient.query(
        `SELECT id FROM team_member_assignments
         WHERE project_id = $1 AND team_member_id = $2`,
        [pid, newTMId]
      );
      if (dupeCheck.rows.length) {
        await dbClient.query('ROLLBACK');
        return res.status(409).json({
          success: false,
          error: 'The replacement member is already assigned to this project.',
        });
      }

      // Remove old assignment
      await dbClient.query(
        `DELETE FROM team_member_assignments WHERE id = $1 AND project_id = $2`,
        [oldMemberId, pid]
      );

      // Insert new assignment, inheriting side/assigner from the old one
      await dbClient.query(
        `INSERT INTO team_member_assignments
           (project_id, team_member_id, name, position, telephone,
            assigned_part, assigned_by, assigned_by_role)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
          pid, newTMId, name, position, telephone || null,
          old.assigned_part,
          old.assigned_by     || req.user.user_id,
          old.assigned_by_role || req.user.role,
        ]
      );

      await dbClient.query('COMMIT');
    } catch (e) {
      await dbClient.query('ROLLBACK');
      throw e;
    } finally {
      dbClient.release();
    }

    return res.json({ success: true, message: 'Team member replaced.' });
  } catch (err) {
    console.error('[POST /api/project-replace-member]', err);
    return res.status(500).json({ success: false, error: 'Server error replacing team member.' });
  }
});

// ── POST /api/project-update-member ──────────────────────────────────────────
// Update name / position / telephone on a team_member_assignments row.
// The team_member_id (user) is NOT changed — only the assignment metadata.
app.post('/api/project-update-member', authenticateToken, async (req, res) => {
  const { projectId, memberId, name, position, telephone } = req.body;
  const pid = normalizeProjectId(projectId);
  if (!pid)      return res.status(400).json({ success: false, error: 'Valid projectId is required.' });
  if (!memberId) return res.status(400).json({ success: false, error: 'memberId is required.' });
  if (!position) return res.status(400).json({ success: false, error: 'position is required.' });

  try {
    const hasAccess = await userHasProjectAccess(req.user.user_id, req.user.role, pid);
    if (!hasAccess) return res.status(403).json({ success: false, error: 'Access denied.' });

    // Fetch assignment to check side-based permission
    const assignRes = await pool.query(
      `SELECT assigned_part FROM team_member_assignments WHERE id = $1 AND project_id = $2`,
      [memberId, pid]
    );
    if (!assignRes.rows.length)
      return res.status(404).json({ success: false, error: 'Team member not found.' });

    const memberSide = (assignRes.rows[0].assigned_part || '').toLowerCase();
    const userSide   = getSide(req.user.role);

    // Must be a leader/PM and same-side OR client-side
    if (!userSide)
      return res.status(403).json({ success: false, error: 'Team members cannot edit member info.' });
    if (userSide !== memberSide && userSide !== 'client')
      return res.status(403).json({ success: false, error: 'You can only edit members on your own side.' });

    await pool.query(
      `UPDATE team_member_assignments
       SET name = $1, position = $2, telephone = $3
       WHERE id = $4 AND project_id = $5`,
      [name || null, position, telephone || null, memberId, pid]
    );

    return res.json({ success: true, message: 'Member updated.' });
  } catch (err) {
    console.error('[POST /api/project-update-member]', err);
    return res.status(500).json({ success: false, error: 'Server error updating member.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  GLOBAL ERROR HANDLER
// ─────────────────────────────────────────────────────────────────────────────
// -----------------------------------------------------------------------------
//  DOCUMENT & APPROVAL  + CONTROL & REPORT API
// -----------------------------------------------------------------------------

function sideLabel(side) {
  if (!side) return null;
  if (side === 'contractor') return 'Contractor';
  if (side === 'consultant') return 'Consultant';
  if (side === 'client') return 'Client';
  return side;
}

// List document-approval items for a project
app.post('/api/document-approval', authenticateToken, async (req, res) => {
  const { projectId } = req.body || {};
  if (!projectId) return res.status(400).json({ error: 'Missing projectId' });
  try {
    const userId = req.user.user_id;
    const userRole = req.user.role;
    const userSide = await resolveSide(userRole, userId, projectId); // 'Contractor'|'Consultant'|'Client' or null
    const isLeader = getSide(userRole) !== null;

    // Visibility rules:
    // - Creator always sees their documents
    // - Side leader sees documents for their own side
    // - Shared documents appear in DA only for the same side
    // Build query requiring both creator id+role match, OR documents belonging
    // to the caller's resolved side. This prevents collisions where numeric
    // ids overlap across role tables.
    const params = [projectId, userId, userRole];
     let q = `SELECT id, project_id, title, description, category AS doc_type, document_date, file_name, file_url, creator_id, creator_role, side, approval_status AS status, approved_by_id, approved_by_role, approval_date AS reviewed_at, rejection_reason, is_shared, shared_at, created_at
       FROM documents WHERE project_id = $1 AND ((creator_id = $2 AND lower(creator_role) = lower($3))`;

    if (userSide) {
      params.push(userSide.toLowerCase());
      q += ` OR lower(side) = $4`;
    }

    q += `) ORDER BY created_at DESC`;

    const { rows } = await pool.query(q, params);
    const normalizedRows = rows.map(row => {
      if (row.is_shared) {
        row.status = 'shared';
      } else if (row.status === 'pending') {
        row.status = 'pending_approval';
      }
      return row;
    });
    return res.json({ documents: normalizedRows });
  } catch (err) {
    console.error('POST /api/document-approval:', err);
    return res.status(500).json({ error: 'Failed to load documents' });
  }
});

// Create a new document (draft for team members, auto-approved for side leaders)
app.post('/api/document-approval/create', authenticateToken, upload.single('file'), requireProjectLifecycleWrite, async (req, res) => {
  const projectId = req.body.projectId;
  if (!projectId) return res.status(400).json({ error: 'Missing projectId' });
  const { doc_type, title, description } = req.body;
  if (!doc_type || !title) return res.status(400).json({ error: 'Missing fields' });
  try {
    let fileUrl = null; let fileName = null; let fileId = null;
    if (req.file) {
      const uploaded = await scheduleCloudinaryUpload(req.file.buffer, req.file.originalname, 'documents');
      fileUrl = uploaded.secure_url || uploaded.url || null;
      fileName = req.file.originalname;
      fileId = uploaded.public_id || null;
    }
    // Resolve side: for leaders/PMs use role mapping, for TeamMember use assignment for this project
    const resolvedSide = await resolveSide(req.user.role, req.user.user_id, projectId);
    const side = sideLabel(resolvedSide);
    
    // Side leaders auto-approve their own documents; team members save drafts first
    const isLeader = getSide(req.user.role) !== null;
    // DB check constraint only allows 'draft','pending_approval','approved','rejected'
    const approvalStatus = isLeader ? 'approved' : 'draft';
    const approvedById = isLeader ? req.user.user_id : null;
    const approvedByRole = isLeader ? req.user.role : null;
    
    let q = `INSERT INTO documents(project_id, title, description, category, file_name, file_id, file_url, creator_id, creator_role, side, approval_status`;
    let params = [projectId, title, description || null, doc_type || null, fileName, fileId, fileUrl, req.user.user_id, req.user.role, side, approvalStatus];
    let paramIdx = 12;
    
    if (isLeader) {
      q += `, approved_by_id, approved_by_role, approval_date) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$${paramIdx},$${paramIdx+1},NOW())`;
      params.push(approvedById, approvedByRole);
    } else {
      q += `) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`;
    }
    
    console.log('CREATE DOCUMENT SQL:', q, params);
    console.log('CREATE DOCUMENT CONTEXT: user=', { id: req.user.user_id, role: req.user.role, isLeader }, 'file=', req.file ? req.file.originalname : null);
    const insert = await pool.query(q + ` RETURNING id`, params);
    return res.json({ success: true, id: insert.rows[0].id });
  } catch (err) {
    console.error('POST /api/document-approval/create:', err);
    return res.status(500).json({ error: 'Failed to create document' });
  }
});

// DEBUG: test the create flow without auth (local/dev only)
// Unauthenticated, so it must be switched on explicitly (ENABLE_DEBUG_ROUTES=true) and never in production.
// Previously only NODE_ENV === 'production' blocked it, which fails open if NODE_ENV is unset on the host.
app.post('/api/_debug/document-approval/create', async (req, res) => {
  if (process.env.NODE_ENV === 'production' || process.env.ENABLE_DEBUG_ROUTES !== 'true') {
    return res.status(403).json({ error: 'Disabled' });
  }
  const { projectId, doc_type, title, description, creator_id, creator_role, side } = req.body || {};
  if (!projectId || !doc_type || !title) return res.status(400).json({ error: 'Missing fields' });
  try {
    const fileName = null; const fileId = null; const fileUrl = req.body.file_url || null;
    const isLeader = false;
    const approvalStatus = 'draft';
    const params = [projectId, title, description || null, doc_type || null, fileName, fileId, fileUrl, creator_id || 99999, creator_role || 'TeamMember', side || null, approvalStatus];
    const q = `INSERT INTO documents(project_id, title, description, category, file_name, file_id, file_url, creator_id, creator_role, side, approval_status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`;
    console.log('DEBUG CREATE:', q, params);
    const insert = await pool.query(q, params);
    return res.json({ success: true, id: insert.rows[0].id });
  } catch (err) {
    console.error('DEBUG POST create error:', err);
    return res.status(500).json({ error: 'Debug create failed' });
  }
});

// Resubmit (update) existing document
app.put('/api/document-approval/:id/resubmit', authenticateToken, upload.single('file'), requireProjectLifecycleWrite, async (req, res) => {
  const docId = req.params.id;
  const { projectId } = req.body || {};
  if (!projectId) return res.status(400).json({ error: 'Missing projectId' });
  try {
    const { rows } = await pool.query('SELECT creator_id, creator_role FROM documents WHERE id=$1 AND project_id=$2', [docId, projectId]);
    if (!rows.length) return res.status(404).json({ error: 'Document not found' });
    const docCreatorId = String(rows[0].creator_id);
    const docCreatorRole = rows[0].creator_role;
    const isCreator = docCreatorId === String(req.user.user_id) && normalizeRole(docCreatorRole) === normalizeRole(req.user.role);
    let isAssignedBy = false;
    if (!isCreator && normalizeRole(docCreatorRole) === 'teammember') {
      const assignCheck = await pool.query('SELECT 1 FROM assignments_view WHERE project_id=$1 AND role_id=$2 AND role=$3 AND assigned_by=$4 LIMIT 1', [projectId, docCreatorId, 'TeamMember', req.user.user_id]);
      if (assignCheck.rows.length) isAssignedBy = true;
    }
    if (!isCreator && !isAssignedBy) return res.status(403).json({ error: 'Not allowed' });
    let fileUrl = null; let fileName = null; let fileId = null;
    if (req.file) {
      const uploaded = await scheduleCloudinaryUpload(req.file.buffer, req.file.originalname, 'documents');
      fileUrl = uploaded.secure_url || uploaded.url || null;
      fileName = req.file.originalname;
      fileId = uploaded.public_id || null;
    }
    const doc_type = req.body.doc_type || null;
    const title = req.body.title || null;
    const description = req.body.description || null;
    const updates = [];
    const params = [];
    let idx = 1;
    if (title) { updates.push(`title=$${idx++}`); params.push(title); }
    if (description) { updates.push(`description=$${idx++}`); params.push(description); }
    if (doc_type) { updates.push(`category=$${idx++}`); params.push(doc_type); }
    if (fileName) { updates.push(`file_name=$${idx++}`, `file_id=$${idx++}`, `file_url=$${idx++}`); params.push(fileName, fileId, fileUrl); }
    updates.push(`approval_status='pending_approval'`, `is_shared=false`, `rejection_reason=NULL`, `updated_at=NOW()`);
    const q = `UPDATE documents SET ${updates.join(', ')} WHERE id=$${idx} AND project_id=$${idx+1}`;
    params.push(docId, projectId);
    await pool.query(q, params);
    return res.json({ success: true });
  } catch (err) {
    console.error('PUT /api/document-approval/:id/resubmit:', err);
    return res.status(500).json({ error: 'Failed to resubmit' });
  }
});

// Review (approve/reject)
app.post('/api/document-approval/:id/review', authenticateToken, async (req, res) => {
  const docId = req.params.id;
  const { projectId, action, comment } = req.body || {};
  if (!projectId || !action) return res.status(400).json({ error: 'Missing fields' });
  if (!['approved','rejected'].includes(action)) return res.status(400).json({ error: 'Invalid action' });
  try {
    const { rows } = await pool.query('SELECT id, approval_status, side FROM documents WHERE id=$1 AND project_id=$2', [docId, projectId]);
    if (!rows.length) return res.status(404).json({ error: 'Document not found' });

    const docSide = (rows[0].side || '').toLowerCase();
    const userSide = getSide(req.user.role);
    if (!userSide) return res.status(403).json({ error: 'Only side leaders can review documents' });
    if (userSide !== docSide) return res.status(403).json({ error: 'You can only review documents for your side' });

    if (action === 'approved') {
      await pool.query(`UPDATE documents SET approval_status='approved', approved_by_id=$1, approved_by_role=$2, approval_date=NOW(), updated_at=NOW() WHERE id=$3`, [req.user.user_id, req.user.role, docId]);
    } else {
      await pool.query(`UPDATE documents SET approval_status='rejected', rejection_reason=$1, updated_at=NOW() WHERE id=$2`, [comment || null, docId]);
    }
    // Insert approval note
    await pool.query(`INSERT INTO document_approval_notes(document_id, note_text, created_by_id, created_by_role, is_visible_to_creator) VALUES($1,$2,$3,$4,$5)`, [docId, comment || (action === 'approved' ? 'Approved' : 'Rejected'), req.user.user_id, req.user.role, true]);
    return res.json({ success: true });
  } catch (err) {
    console.error('POST /api/document-approval/:id/review:', err);
    return res.status(500).json({ error: 'Failed to submit review' });
  }
});

// Share to Control & Report
app.post('/api/document-approval/:id/share', authenticateToken, async (req, res) => {
  const docId = req.params.id;
  const { projectId } = req.body || {};
  if (!projectId) return res.status(400).json({ error: 'Missing projectId' });
  try {
    const { rows } = await pool.query('SELECT approval_status, side FROM documents WHERE id=$1 AND project_id=$2', [docId, projectId]);
    if (!rows.length) return res.status(404).json({ error: 'Document not found' });
    if (rows[0].approval_status !== 'approved') return res.status(400).json({ error: 'Only approved documents can be shared' });

    const docSide = (rows[0].side || '').toLowerCase();
    const userSide = getSide(req.user.role);
    if (!userSide) return res.status(403).json({ error: 'Only side leaders can share documents' });
    if (userSide !== docSide) return res.status(403).json({ error: 'You can only share documents for your side' });

    await pool.query('UPDATE documents SET is_shared=true, shared_at=NOW(), updated_at=NOW() WHERE id=$1', [docId]);
    return res.json({ success: true });
  } catch (err) {
    console.error('POST /api/document-approval/:id/share:', err);
    return res.status(500).json({ error: 'Failed to share document' });
  }
});

// Submit draft for approval
app.post('/api/document-approval/:id/submit', authenticateToken, async (req, res) => {
  const docId = req.params.id;
  const { projectId } = req.body || {};
  if (!projectId) return res.status(400).json({ error: 'Missing projectId' });
  try {
    const { rows } = await pool.query('SELECT creator_id, creator_role FROM documents WHERE id=$1 AND project_id=$2', [docId, projectId]);
    if (!rows.length) return res.status(404).json({ error: 'Document not found' });
    const docCreatorId = String(rows[0].creator_id);
    const docCreatorRole = rows[0].creator_role;
    const isCreator = docCreatorId === String(req.user.user_id) && normalizeRole(docCreatorRole) === normalizeRole(req.user.role);
    let isAssignedBy = false;
    if (!isCreator && normalizeRole(docCreatorRole) === 'teammember') {
      const assignCheck = await pool.query('SELECT 1 FROM assignments_view WHERE project_id=$1 AND role_id=$2 AND role=$3 AND assigned_by=$4 LIMIT 1', [projectId, docCreatorId, 'TeamMember', req.user.user_id]);
      if (assignCheck.rows.length) isAssignedBy = true;
    }
    if (!isCreator && !isAssignedBy) return res.status(403).json({ error: 'Not allowed' });
    await pool.query("UPDATE documents SET approval_status='pending_approval', updated_at=NOW() WHERE id=$1", [docId]);
    return res.json({ success: true });
  } catch (err) {
    console.error('POST /api/document-approval/:id/submit:', err);
    return res.status(500).json({ error: 'Failed to submit' });
  }
});

// Delete document
app.delete('/api/document-approval/:id', authenticateToken, async (req, res) => {
  const docId = req.params.id;
  const projectId = req.body.projectId || req.query.projectId;
  if (!projectId) return res.status(400).json({ error: 'Missing projectId' });
  try {
    const { rows } = await pool.query('SELECT creator_id, creator_role, side FROM documents WHERE id=$1 AND project_id=$2', [docId, projectId]);
    if (!rows.length) return res.status(404).json({ error: 'Document not found' });
    const creatorId = String(rows[0].creator_id);
    const creatorRole = rows[0].creator_role;
    const docSide = (rows[0].side || '').toLowerCase();
    const userSide = getSide(req.user.role);

    // Allow deletion if creator, or if user is the team member's assigner,
    // or if user is a side leader for the same side
    const isCreator = String(req.user.user_id) === creatorId && normalizeRole(creatorRole) === normalizeRole(req.user.role);
    let isAssignedBy = false;
    if (!isCreator && normalizeRole(creatorRole) === 'teammember') {
      const assignCheck = await pool.query('SELECT 1 FROM assignments_view WHERE project_id=$1 AND role_id=$2 AND role=$3 AND assigned_by=$4 LIMIT 1', [projectId, creatorId, 'TeamMember', req.user.user_id]);
      if (assignCheck.rows.length) isAssignedBy = true;
    }
    if (!isCreator && !isAssignedBy) {
      if (!userSide || userSide !== docSide) return res.status(403).json({ error: 'Not allowed' });
    }
    await pool.query('DELETE FROM documents WHERE id=$1 AND project_id=$2', [docId, projectId]);
    return res.json({ success: true });
  } catch (err) {
    console.error('DELETE /api/document-approval/:id:', err);
    return res.status(500).json({ error: 'Failed to delete' });
  }
});

// Download document file (returns URL)
app.get('/api/document-approval/:id/download', authenticateToken, async (req, res) => {
  const docId = req.params.id;
  const projectId = req.query.projectId;
  if (!projectId) return res.status(400).json({ error: 'Missing projectId' });
  try {
    const { rows } = await pool.query('SELECT file_url, creator_id, creator_role, side, is_shared FROM documents WHERE id=$1 AND project_id=$2', [docId, projectId]);
    if (!rows.length) return res.status(404).json({ error: 'Document not found' });
    const row = rows[0];
    const docSide = (row.side || '').toLowerCase();
    const userSide = getSide(req.user.role);

    // Allow if creator or the team-member's assigner
    const isCreator = String(row.creator_id) === String(req.user.user_id) && normalizeRole(row.creator_role) === normalizeRole(req.user.role);
    let isAssignedBy = false;
    if (!isCreator && normalizeRole(row.creator_role) === 'teammember') {
      const assignCheck = await pool.query('SELECT 1 FROM assignments_view WHERE project_id=$1 AND role_id=$2 AND role=$3 AND assigned_by=$4 LIMIT 1', [projectId, String(row.creator_id), 'TeamMember', req.user.user_id]);
      if (assignCheck.rows.length) isAssignedBy = true;
    }
    if (isCreator || isAssignedBy) return res.json({ url: row.file_url || null });

    // Allow side leaders for same side
    if (userSide && userSide === docSide) return res.json({ url: row.file_url || null });

    // Allow if shared and user belongs to same side (resolve for TeamMember)
    if (row.is_shared) {
      const sideResolved = await resolveSide(req.user.role, req.user.user_id, projectId);
      if (sideResolved && sideResolved.toLowerCase() === docSide) return res.json({ url: row.file_url || null });
    }

    return res.status(403).json({ error: 'Access denied' });
  } catch (err) {
    console.error('GET /api/document-approval/:id/download:', err);
    return res.status(500).json({ error: 'Failed to download' });
  }
});

// CONTROL & REPORT — list shared documents
app.post('/api/control-reports', authenticateToken, async (req, res) => {
  const { projectId } = req.body || {};
  if (!projectId) return res.status(400).json({ error: 'Missing projectId' });
  try {
    const side = await resolveSide(req.user.role, req.user.user_id, projectId);
    if (!side) return res.status(403).json({ error: 'Access denied' });
    const { rows } = await pool.query(
      `SELECT id, project_id, title, description, category AS doc_type, file_name, file_url, creator_id, creator_role, side, is_shared, shared_at, approval_date AS reviewed_at, created_at
       FROM documents WHERE project_id=$1 AND is_shared = true AND lower(side) = $2 ORDER BY shared_at DESC NULLS LAST`,
      [projectId, side.toLowerCase()]
    );
    return res.json({ documents: rows });
  } catch (err) {
    console.error('POST /api/control-reports:', err);
    return res.status(500).json({ error: 'Failed to load control reports' });
  }
});

// CONTROL & REPORT — create (leader direct add)
app.post('/api/control-reports/create', authenticateToken, upload.single('file'), requireProjectLifecycleWrite, async (req, res) => {
  const projectId = req.body.projectId;
  if (!projectId) return res.status(400).json({ error: 'Missing projectId' });
  const { doc_type, title, description } = req.body;
  if (!doc_type || !title || !description) return res.status(400).json({ error: 'Missing fields' });
  try {
    // Only side leaders (Client/ClientPM, Contractor/ContractorPM, Consultant/ConsultantPM) can add direct C&R records
    const userSide = getSide(req.user.role);
    if (!userSide) return res.status(403).json({ error: 'Only side leaders can add control & report records' });
    let fileUrl = null; let fileName = null; let fileId = null;
    if (req.file) {
      const uploaded = await scheduleCloudinaryUpload(req.file.buffer, req.file.originalname, 'control_reports');
      fileUrl = uploaded.secure_url || uploaded.url || null;
      fileName = req.file.originalname;
      fileId = uploaded.public_id || null;
    }
    const side = sideLabel(getSide(req.user.role));
    const insert = await pool.query(
      `INSERT INTO documents(project_id, title, description, category, file_name, file_id, file_url, creator_id, creator_role, side, approval_status, approved_by_id, approved_by_role, approval_date, is_shared, shared_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'approved',$11,$12,NOW(),true,NOW()) RETURNING id`,
      [projectId, title, description, doc_type || null, fileName, fileId, fileUrl, req.user.user_id, req.user.role, side, req.user.user_id, req.user.role]
    );
    return res.json({ success: true, id: insert.rows[0].id });
  } catch (err) {
    console.error('POST /api/control-reports/create:', err);
    return res.status(500).json({ error: 'Failed to create control report' });
  }
});

// CONTROL & REPORT — download
app.get('/api/control-reports/:id/download', authenticateToken, async (req, res) => {
  const id = req.params.id;
  const projectId = req.query.projectId;
  if (!projectId) return res.status(400).json({ error: 'Missing projectId' });
  try {
    const { rows } = await pool.query('SELECT file_url, side FROM documents WHERE id=$1 AND project_id=$2', [id, projectId]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const docSide = (rows[0].side || '').toLowerCase();
    const side = await resolveSide(req.user.role, req.user.user_id, projectId);
    if (!side || side.toLowerCase() !== docSide) return res.status(403).json({ error: 'Access denied' });
    return res.json({ url: rows[0].file_url || null });
  } catch (err) {
    console.error('GET /api/control-reports/:id/download:', err);
    return res.status(500).json({ error: 'Failed to download' });
  }
});

app.use((err, _req, res, _next) => {
  console.error('Unexpected error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

async function sendDueMeetingReminders() {
  try {
    const { rows } = await pool.query(
      `SELECT r.id AS rsvp_id,r.participant_name,r.participant_email,r.participant_source,r.token_hash,
              m.id,m.title,m.scheduled_at,m.time_zone,m.location,m.virtual_link
         FROM meeting_rsvps r JOIN meetings m ON m.id=r.meeting_id
        WHERE m.is_draft=false AND m.status='scheduled' AND r.response='pending'
          AND r.reminder_sent_at IS NULL AND r.participant_email IS NOT NULL
          AND m.scheduled_at > NOW() + INTERVAL '23 hours'
          AND m.scheduled_at <= NOW() + INTERVAL '25 hours'
        ORDER BY m.scheduled_at LIMIT 100`
    );
    const apiBase = String(process.env.PUBLIC_API_URL || 'https://oneprojectapp-backend.onrender.com').replace(/\/$/, '');
    const frontendBase = String(process.env.FRONTEND_URL || 'https://oneprojectapp.onrender.com').replace(/\/$/, '');
    for (const invitee of rows) {
      const token = invitee.participant_source === 'manual' ? crypto.randomBytes(32).toString('hex') : null;
      if (token) {
        await pool.query('UPDATE meeting_rsvps SET token_hash=$1 WHERE id=$2',
          [crypto.createHash('sha256').update(token).digest('hex'), invitee.rsvp_id]);
      }
      const rsvpUrl = token
        ? `${apiBase}/api/meetings/rsvp?token=${encodeURIComponent(token)}`
        : `${frontendBase}/dashboard.html`;
      try {
        await transporter.sendMail({
          from: 'skyprincenkp16@gmail.com',
          to: invitee.participant_email,
          subject: `Reminder: ${invitee.title}`,
          text: `${invitee.title}\n${formatMeetingWhen(invitee)}\n${invitee.location || invitee.virtual_link || ''}\nRSVP: ${rsvpUrl}`,
          html: `<p>Reminder: <strong>${escapeMeetingEmail(invitee.title)}</strong></p><p>${escapeMeetingEmail(formatMeetingWhen(invitee) || '')}</p><p><a href="${escapeMeetingEmail(rsvpUrl)}">Respond to this invitation</a></p>`,
        });
        await pool.query('UPDATE meeting_rsvps SET reminder_sent_at=NOW() WHERE id=$1', [invitee.rsvp_id]);
      } catch (error) {
        console.error('Meeting reminder email failed:', invitee.participant_email, error);
      }
    }
  } catch (error) {
    console.error('Meeting reminder job failed:', error);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  START
// ─────────────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));

setTimeout(() => {
  sendDueMeetingReminders();
  setInterval(sendDueMeetingReminders, 15 * 60 * 1000);
}, 30 * 1000);

setInterval(() => {
  fetch('https://oneprojectapp-backend.onrender.com/')
    .then(r => console.log('Keep-alive ping:', r.status))
    .catch(err => console.error('Keep-alive error:', err));
}, 14 * 60 * 1000);