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
import { Readable } from 'stream';

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
    display_name: r.email || 'Unknown',  // raw fallback, overridden by enrichedMembers
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

app.post('/api/upload-attachment', authenticateToken, upload.single('attachment'), async (req, res) => {
  try {
    if (!req.file) {
      console.error('[POST /api/upload-attachment] No file in request');
      return res.status(400).json({ error: 'No file uploaded' });
    }
    console.log('[POST /api/upload-attachment] File received:', {name: req.file.originalname, mime: req.file.mimetype, size: req.file.size});
    const resourceType = req.file.mimetype?.startsWith('image/') ? 'image'
      : req.file.mimetype?.startsWith('video/') ? 'video'
      : req.file.mimetype?.startsWith('audio/') ? 'raw'
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
app.get('/api/me', authenticateToken, (req, res) => {
  res.json({ id: req.user.user_id, role: req.user.role, email: req.user.email });
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
// ─────────────────────────────────────────────────────────────────────────────
async function handleAddRecord(req, res) {
  try {
    const { user_id: userId, role } = req.user;
    const { title, description, projectId, noticeTiedId, recordKind } = req.body;
    const table = resolveTable(req.body.recordType);
    if (!table) return res.status(400).json({ success: false, message: 'Invalid or missing recordType.' });
    if (!projectId || !title) return res.status(400).json({ success: false, message: 'projectId and title are required.' });
    const memberCheck = await pool.query(
      `SELECT 1 FROM assignments_view WHERE project_id = $1 AND role_id = $2 AND role = $3
       UNION ALL SELECT 1 FROM projects WHERE id = $1 AND client_id = $2 AND $3 = 'Client'
       LIMIT 1`,
      [projectId, userId, role]
    );
    if (!memberCheck.rows.length) return res.status(403).json({ success: false, message: 'You are not assigned to this project.' });
    let filePath = null, attachmentId = null;
    if (req.file) {
      try {
        const r = await new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: 'oneproject/records', resource_type: 'auto', public_id: `${Date.now()}-${req.file.originalname.replace(/\s+/g, '-')}` },
            (err, result) => err ? reject(err) : resolve(result)
          );
          Readable.from(req.file.buffer).pipe(stream);
        });
        filePath = r.secure_url; attachmentId = r.public_id;
      } catch (uploadErr) {
        console.error('Cloudinary upload error:', uploadErr);
        return res.status(500).json({ success: false, message: 'File upload failed.' });
      }
    }
    const resolvedKind = recordKind || (noticeTiedId ? 'notice' : 'new');
    const noticeTied   = noticeTiedId ? Number(noticeTiedId) : null;
    if (noticeTied) {
      const parentCheck = await pool.query(`SELECT id FROM ${table} WHERE id = $1 AND project_id = $2`, [noticeTied, projectId]);
      if (!parentCheck.rows.length) return res.status(400).json({ success: false, message: 'The parent record this notice is tied to no longer exists.' });
    }
    const dbClient = await pool.connect();
    try {
      await dbClient.query('BEGIN');

      // 1. Insert the record
      const recRes = await dbClient.query(
        `INSERT INTO ${table} (project_id, title, description, file_path, attachment_id, uploaded_by, role, record_kind, notice_tied_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
        [projectId, title, description || null, filePath, attachmentId, userId, role, resolvedKind, noticeTied]
      );
      const recordId = recRes.rows[0].id;

      // 2. Commit the record first so it's never lost even if notification fails
      await dbClient.query('COMMIT');

      // 3. Create notification in a separate operation (non-fatal)
      let notificationId = null;
      try {
        const notifMsg = noticeTied
          ? `New ${resolvedKind === 'rejection_notice' ? 'rejection notice' : 'notice of determination'} issued by ${role} (tied to record #${noticeTied})`
          : `New record added by ${role}: "${title}"`;

        const notifClient = await pool.connect();
        try {
          await notifClient.query('BEGIN');
          const notifRes = await notifClient.query(
            `INSERT INTO notifications (project_id, entity_id, entity_type, message, added_by_id, added_by_role)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
            [projectId, recordId, table, notifMsg, userId, role]
          );
          notificationId = notifRes.rows[0].id;
          const recipients = await getProjectRecipientKeys(projectId, userId, role);
          await insertNotificationRecipients(notifClient, notificationId, recipients);
          await notifClient.query('COMMIT');
          console.log('[notifications] ✓ created notif', notificationId, 'with', recipients.length, 'recipients');
        } catch (notifErr) {
          await notifClient.query('ROLLBACK');
          console.error('[notifications] ✗ failed (non-fatal):', notifErr.message);
        } finally { notifClient.release(); }
      } catch (notifErr) {
        console.error('[notifications] ✗ outer error (non-fatal):', notifErr.message);
      }

      res.json({ success: true, message: 'Record saved.', recordId, notificationId, attachmentId, recordKind: resolvedKind });
    } catch (err) {
      await dbClient.query('ROLLBACK');
      console.error('Error saving record:', err);
      res.status(500).json({ success: false, message: 'Server error saving record.' });
    } finally { dbClient.release(); }
  } catch (err) {
    console.error('Add record route error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
}

app.post('/api/add-record', authenticateToken, upload.single('attachment'), handleAddRecord);
app.post('/records',        authenticateToken, upload.single('attachment'), handleAddRecord);

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

app.post('/api/arrets', authenticateToken, upload.array('attachments'), async (req, res) => {
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
    const { rows: records } = await pool.query(
      `SELECT r.id, r.title, r.description, r.file_path,
              r.issued_date, r.role AS uploader_role,
              r.uploaded_by, r.status, r.record_kind, r.notice_tied_id,
              r.signed_by_id, r.signed_by_role, r.signed_at,
              r.stamp_type, r.stamped_doc_url, r.signature_hash
       FROM ${table} r WHERE r.project_id = $1 ORDER BY r.issued_date DESC`,
      [projectId]
    );
    const enriched = await Promise.all(records.map(async rec => {
      const { rows: reviews } = await pool.query(
        `SELECT dr.reviewer_id, dr.reviewer_role, dr.action, dr.action_date,
                dr.comment, dr.reviewer_email, dr.reviewer_position, dr.reviewer_assigned_part
         FROM document_reviews dr WHERE dr.record_type = $1 AND dr.record_id = $2 ORDER BY dr.action_date ASC`,
        [table, rec.id]
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
      const isLocked      = rec.status === 'approved_record' || annotatedReviews.some(r => getSide(r.reviewer_role) === step2Side && r.action === 'accepted');
      const stepMap = {
        contractor: [{ side:'consultant',step:1,label:'Consultant Approval',action:'approved'},{side:'client',step:2,label:'Client Acceptance',action:'accepted'}],
        consultant: [{ side:'client',step:1,label:'Client Approval',action:'approved'},{side:'contractor',step:2,label:'Contractor Acceptance',action:'accepted'}],
        client:     [{ side:'consultant',step:1,label:'Consultant Approval',action:'approved'},{side:'contractor',step:2,label:'Contractor Acceptance',action:'accepted'}],
      };
      const steps = uploaderSide ? stepMap[uploaderSide] : null;
      const workflowSteps = steps ? steps.map(s => {
        const doneReview     = annotatedReviews.find(r => getSide(r.reviewer_role) === s.side && (r.action === 'approved' || r.action === 'accepted'));
        const rejectedReview = annotatedReviews.find(r => getSide(r.reviewer_role) === s.side && r.action === 'rejected');
        let status;
        if (isLocked) status = 'locked';
        else if (doneReview) status = 'done';
        else if (rejectedReview) status = 'rejected';
        else status = 'pending';
        return { label: s.label, status };
      }) : [];
      let btnState = 'none', pendingRole = null, approveLabel = null;
      if (isUploader) { btnState = 'uploader'; }
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
        `SELECT id, title, description, file_path, issued_date,
                role AS uploader_role, record_kind,
                signed_by_id, signed_by_role, signed_at, stamp_type, stamped_doc_url
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
      return {
        ...rec,
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
app.post('/api/review-record', authenticateToken, async (req, res) => {
  const { projectId, recordId, recordType, action, comment, actorType } = req.body;
  const reviewerId = req.user.user_id, reviewerRole = req.user.role;
  const table = resolveTable(recordType);
  if (!table) return res.status(400).json({ error: 'Invalid or missing recordType.' });
  const workflowActions = ['approved', 'accepted', 'rejected'];
  const isWorkflow = workflowActions.includes(action);
  const isDecisionMakerActor = isDecisionMaker(reviewerRole) && actorType !== 'team_member';
  if (!isWorkflow && action !== 'no_action') return res.status(400).json({ error: 'Invalid action.' });
  if (isWorkflow && !isDecisionMaker(reviewerRole) && actorType !== 'team_member') return res.status(403).json({ error: 'Only decision makers can run workflow actions.' });
  try {
    const { rows: recRows } = await pool.query(`SELECT id, role, uploaded_by FROM ${table} WHERE id=$1 AND project_id=$2`, [recordId, projectId]);
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
    if (isDecisionMakerActor && isWorkflow) {
      const uploaderSide = getSide(rec.role);
      let newStatus;
      if (action === 'rejected') { newStatus = 'rejected'; }
      else if (action === 'accepted') { newStatus = 'approved_record'; }
      else { const m = { contractor: 'pending_client_acceptance', consultant: 'pending_contractor_acceptance', client: 'pending_contractor_acceptance' }; newStatus = m[uploaderSide] || 'pending_review'; }
      await pool.query(`UPDATE ${table} SET status=$1 WHERE id=$2 AND project_id=$3`, [newStatus, recordId, projectId]);
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
  const { recordId, recordType } = req.query;
  const table = resolveTable(recordType);
  if (!table) return res.status(400).json({ error: 'Invalid or missing recordType.' });
  try {
    const { rows } = await pool.query(`SELECT file_path FROM ${table} WHERE id=$1`, [recordId]);
    if (!rows.length || !rows[0].file_path) return res.status(404).json({ error: 'File not found.' });
    const filePath = rows[0].file_path;
    if (filePath.startsWith('http')) return res.json({ url: filePath, fileName: filePath.split('/').pop() || 'download' });
    res.status(404).json({ error: 'File not accessible.' });
  } catch (err) { console.error('Download file error:', err); res.status(500).json({ error: 'Failed to download file.' }); }
});


// ─────────────────────────────────────────────────────────────────────────────
//  STAMP PROFILE   GET /api/my-stamp   POST /api/my-stamp
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/my-stamp', authenticateToken, async (req, res) => {
  const { user_id, role } = req.user;
  try {
    const { rows } = await pool.query(
      `SELECT id, signature_image, stamp_image_url, updated_at
       FROM user_stamps WHERE user_id=$1 AND user_role=$2 LIMIT 1`,
      [user_id, role]
    );
    res.json({ stamp: rows[0] || null });
  } catch (err) { console.error('GET my-stamp:', err); res.status(500).json({ error: 'Failed.' }); }
});

app.post('/api/my-stamp', authenticateToken, upload.single('stampImage'), async (req, res) => {
  const { user_id, role } = req.user;
  if (!isDecisionMaker(role)) return res.status(403).json({ error: 'Only decision makers can create a stamp.' });
  try {
    const { signatureBase64 } = req.body;
    let stampImageUrl = null;
    if (req.file) {
      const r = await uploadToCloudinary(req.file.buffer, 'oneproject/stamps', 'image');
      stampImageUrl = r.secure_url;
    }
    const { rows } = await pool.query(
      `INSERT INTO user_stamps (user_id, user_role, signature_image, stamp_image_url, updated_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT ON CONSTRAINT uniq_user_stamp
       DO UPDATE SET
         signature_image = COALESCE(EXCLUDED.signature_image, user_stamps.signature_image),
         stamp_image_url = COALESCE(EXCLUDED.stamp_image_url, user_stamps.stamp_image_url),
         updated_at      = NOW()
       RETURNING id, signature_image, stamp_image_url, updated_at`,
      [user_id, role, signatureBase64 || null, stampImageUrl]
    );
    res.json({ success: true, stamp: rows[0] });
  } catch (err) { console.error('POST my-stamp:', err); res.status(500).json({ error: 'Failed to save stamp.' }); }
});

// ─────────────────────────────────────────────────────────────────────────────
//  SIGN RECORD   POST /api/sign-record
//  Burns stamp onto PDF/image at upload time when user opts in.
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/sign-record', authenticateToken, async (req, res) => {
  const { user_id, role } = req.user;
  if (!isDecisionMaker(role)) return res.status(403).json({ error: 'Only decision makers can sign records.' });
  const { recordId, recordType, projectId, stampType } = req.body;
  const table = resolveTable(recordType);
  if (!table) return res.status(400).json({ error: 'Invalid recordType.' });
  try {
    const { rows: recRows } = await pool.query(
      `SELECT id, file_path, signed_at FROM ${table} WHERE id=$1 AND project_id=$2`,
      [recordId, projectId]
    );
    if (!recRows.length) return res.status(404).json({ error: 'Record not found.' });
    if (recRows[0].signed_at) return res.status(409).json({ error: 'Record already signed.' });

    const { rows: stampRows } = await pool.query(
      `SELECT signature_image, stamp_image_url FROM user_stamps WHERE user_id=$1 AND user_role=$2 LIMIT 1`,
      [user_id, role]
    );
    if (!stampRows.length) return res.status(400).json({ error: 'No stamp profile found. Set up your stamp first.' });
    const stampProfile = stampRows[0];

    let stampedDocUrl = null, signatureHash = null;

    if (recRows[0].file_path) {
      try {
        const { PDFDocument, rgb, StandardFonts } = await import('pdf-lib');
        const fetch2 = (await import('node-fetch')).default;

        const fileResp   = await fetch2(recRows[0].file_path);
        const fileBuffer = Buffer.from(await fileResp.arrayBuffer());
        const contentType = fileResp.headers.get('content-type') || '';

        let pdfBytes = null;

        if (contentType.includes('pdf') || /\.pdf$/i.test(recRows[0].file_path)) {
          pdfBytes = fileBuffer;
        } else if (contentType.startsWith('image/') || /\.(jpe?g|png)$/i.test(recRows[0].file_path)) {
          const tmpDoc = await PDFDocument.create();
          const img = contentType.includes('png') || /\.png$/i.test(recRows[0].file_path)
            ? await tmpDoc.embedPng(fileBuffer)
            : await tmpDoc.embedJpg(fileBuffer);
          const pg = tmpDoc.addPage([img.width, img.height]);
          pg.drawImage(img, { x: 0, y: 0, width: img.width, height: img.height });
          pdfBytes = await tmpDoc.save();
        }

        if (pdfBytes) {
          const pdfDoc = await PDFDocument.load(pdfBytes);
          const page   = pdfDoc.getPages()[pdfDoc.getPageCount() - 1];
          const { width, height } = page.getSize();
          const font = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

          const bx = width - 220, by = 20, bw = 200, bh = 110;
          page.drawRectangle({ x: bx, y: by, width: bw, height: bh,
            color: rgb(0.98, 0.98, 0.98), borderColor: rgb(0.2, 0.48, 0.53), borderWidth: 1.5 });

          const label = (stampType || 'SIGNED').toUpperCase();
          const lc = label === 'REJECTED' ? rgb(0.6,0.1,0.1)
                   : label === 'APPROVED'  ? rgb(0.04,0.37,0.27)
                   : rgb(0.07,0.44,0.52);
          page.drawText(label, { x: bx+8, y: by+bh-18, size: 13, font, color: lc });
          page.drawText(role,  { x: bx+8, y: by+bh-34, size: 9,  font, color: rgb(0.2,0.2,0.2) });
          page.drawText(new Date().toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'}),
            { x: bx+8, y: by+bh-46, size: 9, font, color: rgb(0.4,0.4,0.4) });

          if (stampProfile.stamp_image_url) {
            try {
              const si = await fetch2(stampProfile.stamp_image_url);
              const sb = Buffer.from(await si.arrayBuffer());
              const sc = si.headers.get('content-type') || '';
              const se = sc.includes('png') ? await pdfDoc.embedPng(sb) : await pdfDoc.embedJpg(sb);
              page.drawImage(se, { x: bx+8, y: by+4, width: 48, height: 48 });
            } catch(_) {}
          }
          if (stampProfile.signature_image) {
            try {
              const sd = stampProfile.signature_image.replace(/^data:image\/\w+;base64,/, '');
              const si2 = await pdfDoc.embedPng(Buffer.from(sd, 'base64'));
              page.drawImage(si2, { x: bx+70, y: by+4, width: 120, height: 50 });
            } catch(_) {}
          }

          const finalBytes = await pdfDoc.save();
          signatureHash = crypto.createHash('sha256').update(finalBytes).digest('hex');
          const cr = await uploadToCloudinary(Buffer.from(finalBytes), 'oneproject/stamped', 'raw');
          stampedDocUrl = cr.secure_url;
        }
      } catch (pdfErr) {
        console.error('[sign-record] PDF stamp failed (non-fatal):', pdfErr.message);
      }
    }

    await pool.query(
      `UPDATE ${table} SET signed_by_id=$1, signed_by_role=$2, signed_at=NOW(),
       stamp_type=$3, stamped_doc_url=$4, signature_hash=$5 WHERE id=$6 AND project_id=$7`,
      [user_id, role, stampType || null, stampedDocUrl, signatureHash, recordId, projectId]
    );

    res.json({ success: true, signed_at: new Date().toISOString(), stamped_doc_url: stampedDocUrl, signature_hash: signatureHash });
  } catch (err) {
    console.error('POST sign-record:', err);
    res.status(500).json({ error: 'Failed to sign record.' });
  }
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
app.get('/api/meetings', authenticateToken, async (req, res) => {
  const { view, scope, scope_value, project_id } = req.query;
  if (!project_id || !view || !scope) return res.status(400).json({ error: 'project_id, view and scope are required' });
  try {
    const params = [project_id, scope, new Date()];
    let scopeFilter = '';
    if (scope === 'side' && scope_value) { scopeFilter = ` AND m.scope_value = $4`; params.push(scope_value); }
    const { rows } = await pool.query(`
      SELECT m.*,
        EXISTS (SELECT 1 FROM meeting_minutes mm WHERE mm.meeting_id = m.id) AS has_minute,
        (SELECT json_build_object('id',mm.id,'attendees',mm.attendees,'agenda_discussed',mm.agenda_discussed,'decisions',mm.decisions,'action_items',mm.action_items,'next_meeting_date',mm.next_meeting_date,'attachments',(SELECT COALESCE(json_agg(json_build_object('name',a.name,'url',a.url)),'[]') FROM meeting_attachments a WHERE a.minute_id=mm.id)) FROM meeting_minutes mm WHERE mm.meeting_id=m.id LIMIT 1) AS minute,
        (SELECT COALESCE(json_agg(json_build_object('name',a.name,'url',a.url)),'[]') FROM meeting_attachments a WHERE a.meeting_id=m.id AND a.minute_id IS NULL) AS attachments
      FROM meetings m
      WHERE m.project_id=$1 AND m.scope=$2 AND m.date_time ${view==='scheduled'?'>=':'<'} $3
      ${scopeFilter}
      ORDER BY m.date_time ${view==='scheduled'?'ASC':'DESC'}
    `, params);
    res.json(rows);
  } catch (err) { console.error('GET /api/meetings:', err); res.status(500).json({ error: 'Failed to load meetings' }); }
});

app.post('/api/meetings', authenticateToken, upload.array('attachments'), async (req, res) => {
  const { project_id, meeting_type, title, date_time, location, participants, agenda, scope, scope_value } = req.body;
  if (!project_id||!meeting_type||!title||!date_time||!location||!participants||!agenda||!scope) return res.status(400).json({ error: 'All required fields must be provided' });
  if (normalizeRole(req.user.role) === 'TeamMember') return res.status(403).json({ error: 'Team members cannot schedule meetings.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(`INSERT INTO meetings (project_id,meeting_type,title,date_time,location,participants,agenda,scope,scope_value,created_by,created_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`, [project_id,meeting_type,title,date_time,location,participants,agenda,scope,scope_value||null,req.user.user_id,req.user.role]);
    const meeting = rows[0];
    if (req.files?.length) {
      for (const file of req.files) {
        const result = await uploadToCloudinary(file.buffer, 'meeting_attachments');
        await client.query(`INSERT INTO meeting_attachments (meeting_id,name,url,public_id) VALUES ($1,$2,$3,$4)`, [meeting.id,file.originalname,result.secure_url,result.public_id]);
      }
    }
    const notifMsg = scope === 'side'
      ? `New ${meeting_type} meeting scheduled by ${req.user.role} for ${scope_value || 'your'} side: "${title}" on ${date_time}`
      : `New ${meeting_type} meeting scheduled by ${req.user.role}: "${title}" on ${date_time}`;
    console.log('[notifications] creating notification', { projectId: project_id, entity_id: meeting.id, entity_type: 'meetings', message: notifMsg, added_by_id: req.user.user_id, added_by_role: req.user.role, scope, scope_value });
    const notifRes = await client.query(
      `INSERT INTO notifications (project_id,entity_id,entity_type,message,added_by_id,added_by_role) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
      [project_id, meeting.id, 'meetings', notifMsg, req.user.user_id, req.user.role]
    );
    const notificationId = notifRes.rows[0].id;
    console.log('[notifications] created', { notificationId, projectId: project_id, entity_id: meeting.id });
    const recipients = await getProjectRecipientKeys(project_id, req.user.user_id, req.user.role, scope, scope_value);
    await insertNotificationRecipients(client, notificationId, recipients);
    await client.query('COMMIT');
    res.status(201).json(meeting);
  } catch (err) { await client.query('ROLLBACK'); console.error('POST /api/meetings:', err); res.status(500).json({ error: 'Failed to create meeting' }); } finally { client.release(); }
});

app.post('/api/meetings/:id/minute', authenticateToken, upload.array('attachments'), async (req, res) => {
  const meetingId = req.params.id;
  const { project_id, attendees, agenda_discussed, decisions, action_items, scope, scope_value, next_meeting_date } = req.body;
  if (!project_id||!attendees||!agenda_discussed||!decisions||!action_items||!scope) return res.status(400).json({ error: 'All required fields must be provided' });
  if (normalizeRole(req.user.role) === 'TeamMember') return res.status(403).json({ error: 'Team members cannot add meeting minutes.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: meeting } = await client.query(`SELECT id, title FROM meetings WHERE id=$1 AND project_id=$2`, [meetingId, project_id]);
    if (!meeting.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Meeting not found' }); }
    const { rows: existing } = await client.query(`SELECT id FROM meeting_minutes WHERE meeting_id=$1`, [meetingId]);
    if (existing.length) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'Minute already recorded for this meeting' }); }
    const { rows } = await client.query(`INSERT INTO meeting_minutes (meeting_id,project_id,attendees,agenda_discussed,decisions,action_items,next_meeting_date,scope,scope_value,created_by,created_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`, [meetingId,project_id,attendees,agenda_discussed,decisions,action_items,next_meeting_date||null,scope,scope_value||null,req.user.user_id,req.user.role]);
    const minute = rows[0];
    if (req.files?.length) {
      for (const file of req.files) {
        const result = await uploadToCloudinary(file.buffer, 'meeting_attachments');
        await client.query(`INSERT INTO meeting_attachments (minute_id,name,url,public_id) VALUES ($1,$2,$3,$4)`, [minute.id,file.originalname,result.secure_url,result.public_id]);
      }
    }
    const { rows: attachments } = await client.query(`SELECT name, url FROM meeting_attachments WHERE minute_id=$1`, [minute.id]);
    minute.attachments = attachments;
    const meetingTitle = meeting[0]?.title || `#${meetingId}`;
    const notifMsg = scope === 'side'
      ? `Meeting minutes recorded by ${req.user.role} for ${scope_value || 'your'} side: "${meetingTitle}"`
      : `Meeting minutes recorded by ${req.user.role}: "${meetingTitle}"`;
    const notifRes = await client.query(
      `INSERT INTO notifications (project_id,entity_id,entity_type,message,added_by_id,added_by_role) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
      [project_id, minute.id, 'meeting_minutes', notifMsg, req.user.user_id, req.user.role]
    );
    const notificationId = notifRes.rows[0].id;
    const recipients = await getProjectRecipientKeys(project_id, req.user.user_id, req.user.role, scope, scope_value);
    await insertNotificationRecipients(client, notificationId, recipients);
    await client.query('COMMIT');
    res.status(201).json({ minute });
  } catch (err) { await client.query('ROLLBACK'); console.error('POST /api/meetings/:id/minute:', err); res.status(500).json({ error: 'Failed to save minute' }); } finally { client.release(); }
});

// =============================================================================
//  SCHEDULE MODULE  (unchanged — all routes preserved)
// =============================================================================

app.get('/api/get-schedule', authenticateToken, async (req, res) => {
  const projectId = normalizeProjectId(req.query.projectId);
  if (!projectId) return res.status(400).json({ error: 'Valid projectId is required' });
  try {
    const schedRow = await pool.query('SELECT * FROM project_schedules WHERE project_id=$1 LIMIT 1', [projectId]);
    if (!schedRow.rows.length) return res.json({ schedule: null });
    const sched = schedRow.rows[0];
    const msRows = await pool.query(`SELECT m.*,COALESCE(json_agg(json_build_object('date',e.report_date,'qty',e.qty_executed,'remarks',e.remarks,'cumulative',e.cumulative_after_entry) ORDER BY e.report_date) FILTER (WHERE e.id IS NOT NULL),'[]') AS entries,COALESCE(json_agg(DISTINCT jsonb_build_object('fileName',a.file_name,'url',a.cloudinary_url,'publicId',a.cloudinary_public_id)) FILTER (WHERE a.id IS NOT NULL),'[]') AS attachments FROM milestones m LEFT JOIN milestone_progress_entries e ON e.milestone_id=m.id LEFT JOIN milestone_attachments a ON a.milestone_id=m.id WHERE m.schedule_id=$1 GROUP BY m.id ORDER BY m.sort_order`, [sched.id]);
    const amRows = await pool.query(`SELECT am.*,COALESCE(json_agg(json_build_object('date',e.report_date,'qty',e.qty_executed,'remarks',e.remarks,'cumulative',e.cumulative_after_entry) ORDER BY e.report_date) FILTER (WHERE e.id IS NOT NULL),'[]') AS entries,COALESCE(json_agg(DISTINCT jsonb_build_object('fileName',a.file_name,'url',a.cloudinary_url)) FILTER (WHERE a.id IS NOT NULL),'[]') AS attachments FROM additional_milestones am LEFT JOIN additional_milestone_progress_entries e ON e.additional_milestone_id=am.id LEFT JOIN additional_milestone_attachments a ON a.additional_milestone_id=am.id WHERE am.schedule_id=$1 GROUP BY am.id ORDER BY am.sort_order`, [sched.id]);
    
    const extRows = await pool.query(`SELECT id,extension_days,COALESCE(new_planned_start,new_planned_finish - (extension_days || ' days')::interval) as new_planned_start,new_planned_finish,reason,extension_type,status,created_at FROM schedule_extensions WHERE schedule_id=$1 ORDER BY created_at ASC`, [sched.id]);
    
    const mapMs = (ms, isExt) => ({ id:ms.id,title:ms.title,description:ms.description,start:ms.planned_start,end:ms.planned_end,quantity:ms.quantity,unit:ms.unit,dep:ms.depends_on||ms.depends_on_baseline||'None',weight_pct:ms.weight_pct,float_days:ms.float_days,is_critical:ms.is_critical,executed:ms.executed,progress_pct:ms.progress_pct,activity_status:ms.activity_status,completed_at:ms.completed_at,entries:ms.entries,fileName:ms.attachments?.[0]?.fileName||null,attachmentUrl:ms.attachments?.[0]?.url||null,isExtension:isExt });
    res.json({ schedule: { id:sched.id,timeline:{start:sched.planned_start,finish:sched.planned_finish,duration:sched.total_duration},location:sched.location||null,milestones:msRows.rows.map(ms=>mapMs(ms,false)),extension_milestones:amRows.rows.map(ms=>mapMs(ms,true)),extensions:extRows.rows } });
  } catch (err) { console.error('[GET /api/get-schedule]', err); res.status(500).json({ error: 'Failed to load schedule' }); }
});

app.post('/api/save-schedule', authenticateToken, upload.any(), async (req, res) => {
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

app.post('/api/report-progress', authenticateToken, upload.single('attachment'), async (req, res) => {
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

app.post('/api/report-additional-progress', authenticateToken, upload.single('attachment'), async (req, res) => {
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

app.post('/api/complete-milestone', authenticateToken, async (req, res) => {
  const projectId = normalizeProjectId(req.body.projectId);
  const { milestoneId, isExtensionMilestone } = req.body;
  if (!projectId||!milestoneId) return res.status(400).json({ error: 'Valid projectId and milestoneId are required' });
  const isExt=isExtensionMilestone===true||isExtensionMilestone==='true';
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

app.post('/api/save-extension', authenticateToken, upload.any(), async (req, res) => {
  const projectId = normalizeProjectId(req.body.projectId);
  if (!projectId) return res.status(400).json({ error: 'Valid projectId is required' });
  const extensionDays=parseInt(req.body.extensionDays,10),newPlannedFinish=req.body.newPlannedFinish,reason=(req.body.reason||'').trim(),extensionType=req.body.extensionType,scopeType=req.body.scopeType;
  let newMilestones=[];
  try{newMilestones=JSON.parse(req.body.newMilestones||'[]');}catch{return res.status(400).json({error:'Invalid JSON in newMilestones'});}
  if (!extensionDays||extensionDays<1) return res.status(400).json({error:'extensionDays must be a positive integer'});
  if (!newPlannedFinish) return res.status(400).json({error:'newPlannedFinish is required'});
  if (!reason) return res.status(400).json({error:'reason is required'});
  if (!['delay','scope_addition','force_majeure'].includes(extensionType)) return res.status(400).json({error:'Invalid extensionType'});
  const fileMap={};(req.files||[]).forEach(f=>{const m=f.fieldname.match(/^extFile_(\d+)$/);if(m)fileMap[parseInt(m[1],10)]=f;});
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const schedRes=await client.query('SELECT id,planned_finish FROM project_schedules WHERE project_id=$1 LIMIT 1',[projectId]);
    if (!schedRes.rows.length) return res.status(404).json({error:'No schedule found for this project'});
    const scheduleId=schedRes.rows[0].id;
    const lastExtRes=await client.query(`SELECT new_planned_finish FROM schedule_extensions WHERE schedule_id=$1 ORDER BY created_at DESC LIMIT 1`,[scheduleId]);
    const effectiveFinish=lastExtRes.rows[0]?.new_planned_finish||schedRes.rows[0].planned_finish;
    const newPlannedStart=new Date(effectiveFinish);newPlannedStart.setDate(newPlannedStart.getDate()+1);
    
    const extRes = await client.query(`INSERT INTO schedule_extensions (schedule_id,project_id,extension_days,new_planned_start,new_planned_finish,reason,extension_type,requested_by_user_id,requested_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,[scheduleId,projectId,extensionDays,newPlannedStart.toISOString().slice(0,10),newPlannedFinish,reason,extensionType,req.user.user_id,req.user.role]);
    
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

app.post('/api/milestone-photos', authenticateToken, photoUpload.array('photos',10), async (req, res) => {
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
    const { rows }=await pool.query('SELECT cloudinary_public_id,uploaded_by_user_id FROM milestone_photos WHERE id=$1',[req.params.id]);
    if (!rows.length) return res.status(404).json({error:'Photo not found'});
    if (rows[0].uploaded_by_user_id!==req.user.user_id) return res.status(403).json({error:'Only the uploader can delete this photo'});
    try{await cloudinary.uploader.destroy(rows[0].cloudinary_public_id,{resource_type:'image'});}catch(cdErr){console.error('[DELETE /api/milestone-photos] Cloudinary destroy error (non-fatal):',cdErr);}
    await pool.query('DELETE FROM milestone_photos WHERE id=$1',[req.params.id]);
    res.json({ success:true });
  } catch(err){console.error('[DELETE /api/milestone-photos/:id]',err);res.status(500).json({error:'Failed to delete photo'});}
});

app.get('/api/project-summary', authenticateToken, async (req, res) => {
  const projectId = normalizeProjectId(req.query.projectId);
  if (!projectId) return res.status(400).json({error:'Valid projectId is required'});
  try {
    const schedRow=await pool.query('SELECT id,planned_start,planned_finish,total_duration,location FROM project_schedules WHERE project_id=$1 LIMIT 1',[projectId]);
    if (!schedRow.rows.length) return res.json({hasSchedule:false,milestones:[],photos:[],timeline:null});
    const sched=schedRow.rows[0];
    const location=sched.location || null;
    const msRows=await pool.query(`SELECT m.id,m.title,m.planned_start AS start,m.planned_end AS end,m.quantity,m.unit,m.weight_pct,m.float_days,m.is_critical,m.executed,m.progress_pct,m.activity_status,m.completed_at,m.depends_on AS dep FROM milestones m WHERE m.schedule_id=$1 ORDER BY m.sort_order`,[sched.id]);
    const amRows=await pool.query(`SELECT am.id,am.title,am.planned_start AS start,am.planned_end AS end,am.quantity,am.unit,am.weight_pct,am.float_days,am.is_critical,am.executed,am.progress_pct,am.activity_status,am.completed_at,am.depends_on_baseline AS dep,true AS is_extension FROM additional_milestones am WHERE am.schedule_id=$1 ORDER BY am.sort_order`,[sched.id]);
    const allMilestones=[...msRows.rows.map(m=>({...m,is_extension:false})),...amRows.rows.map(m=>({...m,is_extension:true}))];
    const totalWeight=allMilestones.reduce((s,m)=>s+Number(m.weight_pct||0),0);
    const overallPct=allMilestones.length===0?0:totalWeight>0?allMilestones.reduce((s,m)=>s+Number(m.weight_pct||0)*Number(m.progress_pct||0),0)/totalWeight:allMilestones.reduce((s,m)=>s+Number(m.progress_pct||0),0)/allMilestones.length;
    const today=new Date();today.setHours(0,0,0,0);
    const projStart=new Date(sched.planned_start),projFinish=new Date(sched.planned_finish);
    const elapsed=Math.max(0,(today-projStart)/86400000),totalDays=Math.max(1,(projFinish-projStart)/86400000);
    const plannedPct=Math.min(100,(elapsed/totalDays)*100),variance=parseFloat((overallPct-plannedPct).toFixed(2));
    const completed=allMilestones.filter(m=>m.activity_status==='completed'),lastCompleted=completed.length?completed[completed.length-1].title:null;
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
      weight_pct: currentMsForChart.weight_pct,
      is_extension: currentMsForChart.is_extension,
    }] : [];
    const allChartMilestones = allMilestones.map((ms, idx) => {
      const msStart = new Date(ms.start), msEnd = new Date(ms.end);
      let msPlanPct = 0;
      if(today >= msEnd) msPlanPct = 100; else if(today > msStart) msPlanPct = Math.min(100, ((today - msStart) / Math.max(1, msEnd - msStart)) * 100);
      return {id: ms.id, title: ms.title, start: ms.start, end: ms.end, planned_pct: parseFloat(msPlanPct.toFixed(2)), actual_pct: parseFloat(Number(ms.progress_pct || 0).toFixed(2)), activity_status: ms.activity_status, weight_pct: ms.weight_pct, is_extension: ms.is_extension, milestone_index: idx};
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
             ), 0) AS avg_progress
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
  upload.single('linked_file'), async (req, res) => {
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
  upload.single('linked_file'), async (req, res) => {
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
        SUM(t.actual_quantity) OVER (
          ORDER BY t.report_date ASC, t.created_at ASC
          ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
        ) AS cumulative_quantity
      FROM planning_execution_tracking t
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
  upload.single('attachment'), async (req, res) => {
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
  upload.single('linked_file'), async (req, res) => {
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
  upload.single('linked_file'), async (req, res) => {
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
  upload.single('attachment'), async (req, res) => {
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
      `SELECT id, name, location, contract_reference, created_at
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
  const { projectId, name, location, contract_reference } = req.body;
  const pid = normalizeProjectId(projectId);
  if (!pid) return res.status(400).json({ success: false, error: 'Valid projectId is required.' });
  if (!name || !location || !contract_reference)
    return res.status(400).json({ success: false, error: 'name, location and contract_reference are required.' });

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
      `UPDATE projects SET name = $1, location = $2, contract_reference = $3
       WHERE id = $4`,
      [name, location, contract_reference, pid]
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
app.post('/api/document-approval/create', authenticateToken, upload.single('file'), async (req, res) => {
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

// DEBUG: allow testing the create flow without auth in non-production environments
app.post('/api/_debug/document-approval/create', async (req, res) => {
  if (process.env.NODE_ENV === 'production') return res.status(403).json({ error: 'Disabled in production' });
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
app.put('/api/document-approval/:id/resubmit', authenticateToken, upload.single('file'), async (req, res) => {
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
app.post('/api/control-reports/create', authenticateToken, upload.single('file'), async (req, res) => {
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

// ─────────────────────────────────────────────────────────────────────────────
//  START
// ─────────────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));

setInterval(() => {
  fetch('https://oneprojectapp-backend.onrender.com/')
    .then(r => console.log('Keep-alive ping:', r.status))
    .catch(err => console.error('Keep-alive error:', err));
}, 14 * 60 * 1000);

export default app;