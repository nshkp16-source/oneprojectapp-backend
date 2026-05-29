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

// ─── Cloudinary ───────────────────────────────────────────────────────────────
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ─── Multer ───────────────────────────────────────────────────────────────────
const upload = multer({
  limits: { fileSize: 10 * 1024 * 1024 },
  storage: multer.memoryStorage(),
  fileFilter: (_req, file, cb) => {
    const allowed = [
      'image/png','image/jpeg','image/jpg','application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ];
    cb(allowed.includes(file.mimetype) ? null : new Error('Unsupported file type'),
       allowed.includes(file.mimetype));
  },
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
      role:    decoded.role,
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
  const r = role.toLowerCase().replace(/[\s_-]+/g, '_');
  if (r === 'contractor' || r === 'contractor_project_manager') return 'contractor';
  if (r === 'consultant' || r === 'consultant_project_manager') return 'consultant';
  if (r === 'client'     || r === 'client_project_manager')     return 'client';
  return null;
}

function isDecisionMaker(role) { return getSide(role) !== null; }

function daysBetween(startStr, endStr) {
  if (!startStr || !endStr) return 0;
  return Math.max(0, Math.round((new Date(endStr) - new Date(startStr)) / 86400000) + 1);
}

function roleTableMap(role) {
  switch (role) {
    case 'Client':                      return { table: 'clients',                    emailCol: 'company_email' };
    case 'Client Project Manager':      return { table: 'client_project_managers',    emailCol: 'email' };
    case 'Consultant':                  return { table: 'consultants',                emailCol: 'email' };
    case 'Consultant Project Manager':  return { table: 'consultant_project_managers',emailCol: 'email' };
    case 'Contractor':                  return { table: 'contractors',                emailCol: 'email' };
    case 'Contractor Project Manager':  return { table: 'contractor_project_managers',emailCol: 'email' };
    case 'Team Member':                 return { table: 'team_members',               emailCol: 'email' };
    default:                            return null;
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
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const result = await uploadToCloudinary(req.file.buffer, 'oneprojectapp/attachments');
    res.json({ success: true, url: result.secure_url });
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
       ON CONFLICT (company_email) DO UPDATE SET company_name=EXCLUDED.company_name,representative=EXCLUDED.representative,title=EXCLUDED.title,telephone=EXCLUDED.telephone,password_hash=EXCLUDED.password_hash,profile_picture=EXCLUDED.profile_picture,profile_picture_id=EXCLUDED.profile_picture_id,verified=true
       RETURNING id,company_email`,
      [client?.company_name||null,client?.company_email||null,client?.representative||null,client?.title||null,client?.telephone||null,hashedPassword,clientPictureUrl,clientPictureId]
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
        `INSERT INTO ${assignmentTable} (project_id,${fkColumn},company_name,title,position,telephone,task,representative,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW()) ON CONFLICT (project_id,${fkColumn}) DO NOTHING`,
        [project_id,role_id,user.company_name||null,user.title||null,user.position||null,user.telephone||null,user.task||null,user.representative||null]
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
    const {user_id,role,expires_at}=tokenRes.rows[0];
    if (new Date(expires_at)<new Date()) return res.status(403).json({success:false,error:'Refresh token expired.'});
    const map=roleTableMap(role);
    if (!map) return res.status(400).json({success:false,error:'Invalid role.'});
    const userRes=await pool.query(`SELECT id,${map.emailCol} AS email FROM ${map.table} WHERE id=$1`,[user_id]);
    if (!userRes.rows.length) return res.status(404).json({success:false,error:'User not found.'});
    const user=userRes.rows[0];
    const assignmentInfo={
      'Client':{table:'projects',fk:'client_id'},
      'Client Project Manager':{table:'client_pm_assignments',fk:'client_pm_id'},
      'Consultant':{table:'consultant_assignments',fk:'consultant_id'},
      'Consultant Project Manager':{table:'consultant_pm_assignments',fk:'consultant_pm_id'},
      'Contractor':{table:'contractor_assignments',fk:'contractor_id'},
      'Contractor Project Manager':{table:'contractor_pm_assignments',fk:'contractor_pm_id'},
      'Team Member':{table:'team_member_assignments',fk:'team_member_id'},
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
//  PROFILE ROUTES (Cloudinary-ready, works for all roles)
// ─────────────────────────────────────────────────────────────────────────────
function buildProfileRoutes({
  routePrefix,
  jwtRole,
  dbTable,
  emailCol,
  cloudFolder,
  assignmentTable,
  assignmentFk,
  isClientRole,
  extraProfileFields
}) {
  // Fetch profile
  app.get(`${routePrefix}/profile`, authenticateToken, async (req, res) => {
    if (req.user.role !== jwtRole) return res.status(403).json({ error: `Access denied: ${jwtRole} only` });
    try {
      const fields = [emailCol, 'profile_picture', ...(extraProfileFields || [])].join(',');
      const result = await pool.query(
        `SELECT ${fields} FROM ${dbTable} WHERE id=$1 AND ${emailCol}=$2`,
        [req.user.user_id, req.user.companyEmail || req.user.email]
      );
      if (!result.rows.length) return res.status(404).json({ error: `${jwtRole} not found` });

      const row = result.rows[0];
      res.json({
        email: row[emailCol], // normalize to "email" for frontend
        profile_picture: row.profile_picture,
        ...extraProfileFields?.reduce((acc, f) => { acc[f] = row[f]; return acc; }, {}),
        role: jwtRole
      });
    } catch (err) {
      console.error(`Fetch ${jwtRole} profile error:`, err);
      res.status(500).json({ error: 'Failed to fetch profile' });
    }
  });

  // Upload profile picture
  app.post(`${routePrefix}/upload-picture`, authenticateToken, upload.single('profile_picture'), async (req, res) => {
    if (req.user.role !== jwtRole) return res.status(403).json({ error: `Access denied: ${jwtRole} only` });
    try {
      if (!req.file) return res.status(400).json({ error: 'No file uploaded or file too large.' });
      if (!req.file.mimetype.startsWith('image/')) return res.status(400).json({ error: 'Only image files allowed.' });

      const cdResult = await uploadToCloudinary(req.file.buffer, cloudFolder, 'image');
      await pool.query(
        `UPDATE ${dbTable} SET profile_picture=$1, profile_picture_id=$2 WHERE id=$3 AND ${emailCol}=$4`,
        [cdResult.secure_url, cdResult.public_id, req.user.user_id, req.user.companyEmail || req.user.email]
      );
      res.json({ success: true, url: cdResult.secure_url });
    } catch (err) {
      console.error(`Upload ${jwtRole} picture error:`, err);
      res.status(500).json({ error: 'Failed to upload picture' });
    }
  });

  // Delete profile picture
  app.post(`${routePrefix}/delete-picture`, authenticateToken, async (req, res) => {
    if (req.user.role !== jwtRole) return res.status(403).json({ error: `Access denied: ${jwtRole} only` });
    try {
      const result = await pool.query(
        `SELECT profile_picture_id FROM ${dbTable} WHERE id=$1 AND ${emailCol}=$2`,
        [req.user.user_id, req.user.companyEmail || req.user.email]
      );
      if (result.rows.length > 0 && result.rows[0].profile_picture_id) {
        await cloudinary.uploader.destroy(result.rows[0].profile_picture_id);
      }
      await pool.query(
        `UPDATE ${dbTable} SET profile_picture=NULL, profile_picture_id=NULL WHERE id=$1 AND ${emailCol}=$2`,
        [req.user.user_id, req.user.companyEmail || req.user.email]
      );
      res.json({ success: true });
    } catch (err) {
      console.error(`Delete ${jwtRole} picture error:`, err);
      res.status(500).json({ error: 'Failed to delete picture' });
    }
  });

  // Fetch projects
  app.post(`${routePrefix}/projects`, authenticateToken, async (req, res) => {
    if (req.user.role !== jwtRole) return res.status(403).json({ error: `Access denied: ${jwtRole} only` });
    try {
      let rows;
      if (isClientRole) {
        const r = await pool.query(
          'SELECT id,name,location,contract_reference,created_at FROM projects WHERE client_id=$1',
          [req.user.user_id]
        );
        rows = r.rows;
      } else {
        const r = await pool.query(
          `SELECT p.id,p.name,p.location,p.contract_reference,p.created_at 
           FROM ${assignmentTable} a 
           JOIN projects p ON a.project_id=p.id 
           WHERE a.${assignmentFk}=$1`,
          [req.user.user_id]
        );
        rows = r.rows;
      }
      res.json({ projects: rows });
    } catch (err) {
      console.error(`Fetch ${jwtRole} projects error:`, err);
      res.status(500).json({ error: 'Failed to fetch projects' });
    }
  });

  // Fetch project details
  app.post(`${routePrefix}/project-details`, authenticateToken, async (req, res) => {
    if (req.user.role !== jwtRole) return res.status(403).json({ error: `Access denied: ${jwtRole} only` });
    try {
      const { projectId } = req.body;
      let project;
      if (isClientRole) {
        const r = await pool.query(
          'SELECT id,name,location,contract_reference,created_at FROM projects WHERE id=$1 AND client_id=$2',
          [projectId, req.user.user_id]
        );
        if (!r.rows.length) return res.status(404).json({ error: 'Project not found or not owned by client' });
        project = r.rows[0];
      } else {
        const r = await pool.query(
          `SELECT p.id,p.name,p.location,p.contract_reference,p.created_at 
           FROM ${assignmentTable} a 
           JOIN projects p ON a.project_id=p.id 
           WHERE a.${assignmentFk}=$1 AND p.id=$2`,
          [req.user.user_id, projectId]
        );
        if (!r.rows.length) return res.status(404).json({ error: 'Project not found or not assigned' });
        project = r.rows[0];
      }
      res.json({ project });
    } catch (err) {
      console.error(`Fetch ${jwtRole} project-details error:`, err);
      res.status(500).json({ error: 'Failed to fetch project details' });
    }
  });
}

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
      await pool.query(`INSERT INTO ${assignTable} (project_id,${fk},company_name,representative,title,position,telephone,task,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW()) ON CONFLICT (project_id,${fk}) DO NOTHING`,[project_id,id,party.company_name||null,party.representative||null,party.title||null,party.position||null,party.telephone||null,party.task||null]);
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
    const side=getSide(role);
    if (!side) return res.status(400).json({success:false,error:'Unsupported role'});
    const projectCheckMap={client:'SELECT 1 FROM projects WHERE id=$1 AND client_id=$2',contractor:'SELECT 1 FROM contractor_assignments WHERE project_id=$1 AND contractor_id=$2',consultant:'SELECT 1 FROM consultant_assignments WHERE project_id=$1 AND consultant_id=$2'};
    const check=await pool.query(projectCheckMap[side],[projectId,userId]);
    if (!check.rows.length) return res.status(403).json({success:false,error:'Project not linked to this user'});
    const client=await pool.connect();
    try {
      for (const a of assignments) {
        if (a.role==='Project Manager'){
          const pmTableMap={client:{pmTable:'client_project_managers',aTable:'client_pm_assignments',fk:'client_pm_id'},contractor:{pmTable:'contractor_project_managers',aTable:'contractor_pm_assignments',fk:'contractor_pm_id'},consultant:{pmTable:'consultant_project_managers',aTable:'consultant_pm_assignments',fk:'consultant_pm_id'}};
          const pm=pmTableMap[side];
          await client.query(`INSERT INTO ${pm.aTable} (project_id,${pm.fk},company_name,title,position,telephone,task,representative) VALUES ($1,(SELECT id FROM ${pm.pmTable} WHERE email=$2),$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,[projectId,a.email,a.company_name,a.title,a.position,a.telephone,a.task,a.representative]);
        } else if (a.role==='Team Member'){
          const assignedPart=a.assigned_part||(side==='client'?'Client':side==='contractor'?'Contractor':'Consultant');
          await client.query(`INSERT INTO team_member_assignments (project_id,team_member_id,company_name,title,position,telephone,task,representative,assigned_part,assigned_by) VALUES ($1,(SELECT id FROM team_members WHERE email=$2),$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`,[projectId,a.email,a.company_name,a.title,a.position,a.telephone,a.task,a.representative,assignedPart,a.assigned_by||userId]);
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
    const client=await pool.connect();
    try {
      let insertQuery,params,roleLabel;
      if (assignment.role==='Client Project Manager'){
        await client.query(`INSERT INTO client_project_managers (email,verified) VALUES ($1,true) ON CONFLICT (email) DO NOTHING`,[assignment.email]);
        insertQuery=`INSERT INTO client_pm_assignments (project_id,client_pm_id,company_name,title,position,telephone,task,representative) VALUES ($1,(SELECT id FROM client_project_managers WHERE email=$2),$3,$4,$5,$6,$7,$8) RETURNING client_pm_id AS assigned_id`;
        params=[projectId,assignment.email,assignment.company_name,assignment.title,assignment.position,assignment.telephone,assignment.task,assignment.representative]; roleLabel='Client';
      } else if (assignment.role==='Contractor Project Manager'){
        await client.query(`INSERT INTO contractor_project_managers (email,verified) VALUES ($1,true) ON CONFLICT (email) DO NOTHING`,[assignment.email]);
        insertQuery=`INSERT INTO contractor_pm_assignments (project_id,contractor_pm_id,company_name,title,position,telephone,task,representative) VALUES ($1,(SELECT id FROM contractor_project_managers WHERE email=$2),$3,$4,$5,$6,$7,$8) RETURNING contractor_pm_id AS assigned_id`;
        params=[projectId,assignment.email,assignment.company_name,assignment.title,assignment.position,assignment.telephone,assignment.task,assignment.representative]; roleLabel='Contractor';
      } else if (assignment.role==='Consultant Project Manager'){
        await client.query(`INSERT INTO consultant_project_managers (email,verified) VALUES ($1,true) ON CONFLICT (email) DO NOTHING`,[assignment.email]);
        insertQuery=`INSERT INTO consultant_pm_assignments (project_id,consultant_pm_id,company_name,title,position,telephone,task,representative) VALUES ($1,(SELECT id FROM consultant_project_managers WHERE email=$2),$3,$4,$5,$6,$7,$8) RETURNING consultant_pm_id AS assigned_id`;
        params=[projectId,assignment.email,assignment.company_name,assignment.title,assignment.position,assignment.telephone,assignment.task,assignment.representative]; roleLabel='Consultant';
      } else if (assignment.role==='Team Member'){
        await client.query(`INSERT INTO team_members (email,verified) VALUES ($1,true) ON CONFLICT (email) DO NOTHING`,[assignment.email]);
        const side=getSide(jwtRole);
        const assignedPart=assignment.assigned_part||(side==='client'?'Client':side==='contractor'?'Contractor':'Consultant');
        insertQuery=`INSERT INTO team_member_assignments (project_id,team_member_id,company_name,title,position,telephone,task,representative,assigned_part,assigned_by) VALUES ($1,(SELECT id FROM team_members WHERE email=$2),$3,$4,$5,$6,$7,$8,$9,$10) RETURNING team_member_id AS assigned_id`;
        params=[projectId,assignment.email,assignment.company_name,assignment.title,assignment.position,assignment.telephone,assignment.task,assignment.representative,assignedPart,assignment.assigned_by||userId]; roleLabel='TeamMember';
      } else {
        return res.status(400).json({success:false,error:'Unsupported role'});
      }
      const result=await client.query(insertQuery,params);
      res.json({success:true,message:'Assignment saved',role:roleLabel,projectId,assignedId:result.rows[0]?.assigned_id});
    } finally{client.release();}
  } catch(err){console.error('Assign route error:',err);res.status(500).json({success:false,error:'Server error'});}
});

// ─────────────────────────────────────────────────────────────────────────────
//  /api/me
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/me', authenticateToken, (req, res) => {
  res.json({ id: req.user.user_id, role: req.user.role, email: req.user.email });
});

// ─────────────────────────────────────────────────────────────────────────────
//  NOTIFICATIONS
// ─────────────────────────────────────────────────────────────────────────────
app.get('/notifications/unread-count', authenticateToken, async (req, res) => {
  const { projectId } = req.query;
  const userId = req.user.user_id;
  try {
    const result = await pool.query(
      `SELECT COUNT(*) AS count
       FROM notifications n
       LEFT JOIN notification_recipients nr
         ON nr.notification_id = n.id AND nr.user_id = $2
       WHERE n.project_id = $1
         AND n.added_by_id != $2
         AND (nr.is_read = false OR nr.id IS NULL)`,
      [projectId, userId]
    );
    res.json({ count: parseInt(result.rows[0].count, 10) });
  } catch (err) {
    console.error('Unread count error:', err);
    res.status(500).json({ count: 0 });
  }
});

app.get('/notifications', authenticateToken, async (req, res) => {
  const { projectId } = req.query;
  const userId = req.user.user_id;
  try {
    const { rows: notifs } = await pool.query(
      `SELECT n.id, n.entity_type, n.entity_id, n.message,
              n.added_by_role, n.created_at,
              COALESCE(nr.is_read, false) AS is_read
       FROM notifications n
       LEFT JOIN notification_recipients nr
         ON nr.notification_id = n.id AND nr.user_id = $2
       WHERE n.project_id = $1
         AND n.added_by_id != $2
       ORDER BY n.created_at DESC`,
      [projectId, userId]
    );
    for (const n of notifs) {
      await pool.query(
        `INSERT INTO notification_recipients (notification_id, user_id, is_read)
         VALUES ($1, $2, false)
         ON CONFLICT (notification_id, user_id) DO NOTHING`,
        [n.id, userId]
      );
    }
    res.json({ notifications: notifs });
  } catch (err) {
    console.error('Fetch notifications error:', err);
    res.status(500).json({ notifications: [] });
  }
});

app.put('/notifications/:id/read', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.user_id;
  try {
    await pool.query(
      `INSERT INTO notification_recipients (notification_id, user_id, is_read, read_at)
       VALUES ($1, $2, true, NOW())
       ON CONFLICT (notification_id, user_id)
       DO UPDATE SET is_read = true, read_at = NOW()`,
      [id, userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Mark read error:', err);
    res.status(500).json({ success: false });
  }
});

app.post('/notifications/mark-all-read', authenticateToken, async (req, res) => {
  const { notificationIds } = req.body;
  const userId = req.user.user_id;
  if (!Array.isArray(notificationIds) || !notificationIds.length) {
    return res.json({ success: true, updated: 0 });
  }
  try {
    for (const notifId of notificationIds) {
      await pool.query(
        `INSERT INTO notification_recipients (notification_id, user_id, is_read, read_at)
         VALUES ($1, $2, true, NOW())
         ON CONFLICT (notification_id, user_id)
         DO UPDATE SET is_read = true, read_at = NOW()`,
        [notifId, userId]
      );
    }
    res.json({ success: true, updated: notificationIds.length });
  } catch (err) {
    console.error('Mark all read error:', err);
    res.status(500).json({ success: false });
  }
});

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
       UNION ALL
       SELECT 1 FROM projects WHERE id = $1 AND client_id = $2 AND $3 = 'Client'
       LIMIT 1`,
      [projectId, userId, role]
    );
    if (!memberCheck.rows.length) {
      return res.status(403).json({ success: false, message: 'You are not assigned to this project.' });
    }
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
      const parentCheck = await pool.query(
        `SELECT id FROM ${table} WHERE id = $1 AND project_id = $2`,
        [noticeTied, projectId]
      );
      if (!parentCheck.rows.length) {
        return res.status(400).json({ success: false, message: 'The parent record this notice is tied to no longer exists.' });
      }
    }
    const dbClient = await pool.connect();
    try {
      await dbClient.query('BEGIN');
      const recRes = await dbClient.query(
        `INSERT INTO ${table} (project_id, title, description, file_path, attachment_id, uploaded_by, role, record_kind, notice_tied_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
        [projectId, title, description || null, filePath, attachmentId, userId, role, resolvedKind, noticeTied]
      );
      const recordId = recRes.rows[0].id;
      const notifMsg = noticeTied
        ? `New ${resolvedKind === 'rejection_notice' ? 'rejection notice' : 'notice of determination'} issued by ${role} (tied to record #${noticeTied})`
        : `New record added by ${role}: "${title}"`;
      const notifRes = await dbClient.query(
        `INSERT INTO notifications (project_id, entity_id, entity_type, message, added_by_id, added_by_role)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
        [projectId, recordId, table, notifMsg, userId, role]
      );
      const notificationId = notifRes.rows[0].id;
      const recipientIds = await getProjectMemberUserIds(projectId, userId);
      if (recipientIds.length > 0) {
        const recipientValues = recipientIds.map((uid, i) => `($1, $${i + 2})`).join(', ');
        await dbClient.query(
          `INSERT INTO notification_recipients (notification_id, user_id)
           VALUES ${recipientValues}
           ON CONFLICT (notification_id, user_id) DO NOTHING`,
          [notificationId, ...recipientIds]
        );
      }
      await dbClient.query('COMMIT');
      res.json({ success: true, message: 'Record saved.', recordId, notificationId, attachmentId, recordKind: resolvedKind });
    } catch (err) {
      await dbClient.query('ROLLBACK');
      console.error('Error saving record:', err);
      res.status(500).json({ success: false, message: 'Server error saving record.' });
    } finally {
      dbClient.release();
    }
  } catch (err) {
    console.error('Add record route error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
}

app.post('/api/add-record', authenticateToken, upload.single('attachment'), handleAddRecord);
app.post('/records',        authenticateToken, upload.single('attachment'), handleAddRecord);

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
              r.uploaded_by, r.status, r.record_kind, r.notice_tied_id
       FROM ${table} r
       WHERE r.project_id = $1
       ORDER BY r.issued_date DESC`,
      [projectId]
    );
    const enriched = await Promise.all(records.map(async rec => {
      const { rows: reviews } = await pool.query(
        `SELECT dr.reviewer_id, dr.reviewer_role, dr.action, dr.action_date,
                dr.comment, dr.reviewer_email, dr.reviewer_position
         FROM document_reviews dr
         WHERE dr.record_type = $1 AND dr.record_id = $2
         ORDER BY dr.action_date ASC`,
        [table, rec.id]
      );
      const annotatedReviews = reviews.map(r => ({
        ...r,
        is_decision_maker: isDecisionMaker(r.reviewer_role),
      }));
      const isUploader = String(rec.uploaded_by) === String(userId)
                      && getSide(rec.uploader_role) === getSide(userRole);
      let isViewed = isUploader;
      if (!isUploader) {
        // ── FIX: scope viewed check by reviewer_role too ──
        const { rows: viewed } = await pool.query(
          `SELECT 1 FROM document_reviews
           WHERE record_type = $1 AND record_id = $2
           AND reviewer_id = $3 AND reviewer_role = $4 LIMIT 1`,
          [table, rec.id, userId, userRole]
        );
        isViewed = viewed.length > 0;
      }
      const myReviewRow = reviews.find(r => String(r.reviewer_id) === String(userId)
                                         && getSide(r.reviewer_role) === getSide(userRole));
      const myReview    = myReviewRow
        ? { action: myReviewRow.action, comment: myReviewRow.comment || '' }
        : {};
      const uploaderSide  = getSide(rec.uploader_role);
      const step2SideMap  = { contractor: 'client', consultant: 'contractor', client: 'contractor' };
      const step2Side     = step2SideMap[uploaderSide];
      const isLocked      =
        rec.status === 'approved_record' ||
        annotatedReviews.some(r => getSide(r.reviewer_role) === step2Side && r.action === 'accepted');
      const stepMap = {
        contractor: [
          { side: 'consultant', step: 1, label: 'Consultant Approval', action: 'approved' },
          { side: 'client',     step: 2, label: 'Client Acceptance',   action: 'accepted' },
        ],
        consultant: [
          { side: 'client',     step: 1, label: 'Client Approval',      action: 'approved' },
          { side: 'contractor', step: 2, label: 'Contractor Acceptance', action: 'accepted' },
        ],
        client: [
          { side: 'consultant', step: 1, label: 'Consultant Approval',   action: 'approved' },
          { side: 'contractor', step: 2, label: 'Contractor Acceptance', action: 'accepted' },
        ],
      };
      const steps = uploaderSide ? stepMap[uploaderSide] : null;
      const workflowSteps = steps
        ? steps.map(s => {
            const doneReview     = annotatedReviews.find(r => getSide(r.reviewer_role) === s.side && (r.action === 'approved' || r.action === 'accepted'));
            const rejectedReview = annotatedReviews.find(r => getSide(r.reviewer_role) === s.side && r.action === 'rejected');
            let status;
            if (isLocked)            status = 'locked';
            else if (doneReview)     status = 'done';
            else if (rejectedReview) status = 'rejected';
            else                     status = 'pending';
            return { label: s.label, status };
          })
        : [];
      let btnState = 'none', pendingRole = null, approveLabel = null;
      if (isUploader) {
        btnState = 'uploader';
      } else if (isLocked) {
        btnState = 'locked';
      } else if (!userIsDM) {
        btnState = 'team_member';
      } else if (userSide === uploaderSide) {
        btnState = 'none';
      } else {
        const workflowActions = ['approved', 'accepted', 'rejected'];
        const alreadyActed    = myReviewRow && workflowActions.includes(myReviewRow.action);
        if (alreadyActed) {
          btnState = 'acted';
        } else if (steps) {
          const myStep = steps.find(s => s.side === userSide);
          if (!myStep) {
            btnState = 'none';
          } else if (myStep.step === 2) {
            const step1     = steps.find(s => s.step === 1);
            const step1Done = annotatedReviews.some(r => getSide(r.reviewer_role) === step1.side && (r.action === 'approved' || r.action === 'accepted'));
            if (!step1Done) {
              btnState = 'awaiting'; pendingRole = step1.side;
            } else {
              btnState = 'can_approve'; approveLabel = myStep.action === 'accepted' ? 'Accept' : 'Approve';
            }
          } else {
            btnState = 'can_approve'; approveLabel = myStep.action === 'accepted' ? 'Accept' : 'Approve';
          }
        }
      }
      const { rows: myNotices } = await pool.query(
        `SELECT id, title FROM ${table}
         WHERE notice_tied_id = $1 AND project_id = $2 AND uploaded_by = $3 AND role = $4`,
        [rec.id, projectId, userId, userRole]
      );
      const myIssuedNotice = myNotices.length > 0 ? myNotices[0] : null;
      let tiedRecordTitle = null;
      if (rec.notice_tied_id) {
        const { rows: tied } = await pool.query(`SELECT title FROM ${table} WHERE id = $1`, [rec.notice_tied_id]);
        tiedRecordTitle = tied[0]?.title || null;
      }
      return {
        ...rec,
        reviews:           annotatedReviews,
        is_uploader:       isUploader,
        is_viewed:         isViewed,
        is_locked:         isLocked,
        is_decision_maker: userIsDM,
        btn_state:         btnState,
        pending_role:      pendingRole,
        approve_label:     approveLabel,
        my_review:         myReview,
        workflow_steps:    workflowSteps,
        my_issued_notice:  myIssuedNotice,
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
  const reviewerId   = req.user.user_id;
  const reviewerRole = req.user.role;
  const table = resolveTable(recordType);
  if (!table) return res.status(400).json({ error: 'Invalid or missing recordType.' });
  try {
    const { rows: rec } = await pool.query(
      `SELECT uploaded_by, role FROM ${table} WHERE id = $1 AND project_id = $2`,
      [recordId, projectId]
    );
    if (!rec.length) return res.status(400).json({ error: 'Record not found.' });
    if (String(rec[0].uploaded_by) === String(reviewerId) && getSide(rec[0].role) === getSide(reviewerRole)) {
      return res.json({ success: true, skipped: true });
    }
    const assignRow = await pool.query(
      `SELECT av.role_email AS email, av.position FROM assignments_view av
       WHERE av.project_id = $1 AND av.role_id = $2 AND av.role = $3 LIMIT 1`,
      [projectId, reviewerId, reviewerRole]
    );
    const reviewerEmail    = assignRow.rows[0]?.email    || null;
    const reviewerPosition = assignRow.rows[0]?.position || null;
    // ── FIX: conflict target now includes reviewer_role ──
    await pool.query(
      `INSERT INTO document_reviews
         (record_type, record_id, record_kind, reviewer_id, reviewer_role,
          reviewer_email, reviewer_position, action)
       VALUES ($1, $2, 'new', $3, $4, $5, $6, 'no_action')
       ON CONFLICT (record_type, record_id, reviewer_id, reviewer_role) DO NOTHING`,
      [table, recordId, reviewerId, reviewerRole, reviewerEmail, reviewerPosition]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Mark viewed error:', err);
    res.status(500).json({ error: 'Failed to mark as viewed.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  REVIEW RECORD
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/review-record', authenticateToken, async (req, res) => {
  const { projectId, recordId, recordType, action, comment, actorType } = req.body;
  const reviewerId   = req.user.user_id;
  const reviewerRole = req.user.role;
  const table = resolveTable(recordType);
  if (!table) return res.status(400).json({ error: 'Invalid or missing recordType.' });
  const workflowActions      = ['approved', 'accepted', 'rejected'];
  const isWorkflow           = workflowActions.includes(action);
  const isDecisionMakerActor = isDecisionMaker(reviewerRole) && actorType !== 'team_member';
  if (!isWorkflow && action !== 'no_action') return res.status(400).json({ error: 'Invalid action.' });
  if (isWorkflow && !isDecisionMaker(reviewerRole) && actorType !== 'team_member') {
    return res.status(403).json({ error: 'Only decision makers can run workflow actions.' });
  }
  try {
    const { rows: recRows } = await pool.query(
      `SELECT id, role, uploaded_by FROM ${table} WHERE id = $1 AND project_id = $2`,
      [recordId, projectId]
    );
    if (!recRows.length) return res.status(400).json({ error: 'Record not found. It may have been deleted.' });
    const rec = recRows[0];
    if (String(rec.uploaded_by) === String(reviewerId) && getSide(rec.role) === getSide(reviewerRole)) {
      return res.status(403).json({ error: 'You cannot review your own record.' });
    }
    const assignRow = await pool.query(
      `SELECT av.role_email AS email, av.position FROM assignments_view av
       WHERE av.project_id = $1 AND av.role_id = $2 AND av.role = $3 LIMIT 1`,
      [projectId, reviewerId, reviewerRole]
    );
    const reviewerEmail    = assignRow.rows[0]?.email    || null;
    const reviewerPosition = assignRow.rows[0]?.position || null;

    // ── FIX: scope existing-row lookup by reviewer_role so a user acting
    //         in two different roles (e.g. Consultant then Contractor)
    //         gets a separate row per role and is never falsely blocked ──
    const { rows: existing } = await pool.query(
      `SELECT id, action FROM document_reviews
       WHERE record_type = $1 AND record_id = $2
       AND reviewer_id = $3 AND reviewer_role = $4 LIMIT 1`,
      [table, recordId, reviewerId, reviewerRole]
    );

    if (action === 'no_action' && comment?.trim()) {
      if (existing.length > 0) {
        await pool.query(
          `UPDATE document_reviews SET comment = $1, action_date = NOW() WHERE id = $2`,
          [comment.trim(), existing[0].id]
        );
      } else {
        await pool.query(
          `INSERT INTO document_reviews
             (record_type, record_id, record_kind, reviewer_id, reviewer_role,
              reviewer_email, reviewer_position, action, comment)
           VALUES ($1, $2, 'new', $3, $4, $5, $6, 'no_action', $7)`,
          [table, recordId, reviewerId, reviewerRole, reviewerEmail, reviewerPosition, comment.trim()]
        );
      }
      return res.json({ success: true, message: 'Comment saved.' });
    }

    if (existing.length > 0) {
      if (isDecisionMakerActor && workflowActions.includes(existing[0].action)) {
        return res.status(409).json({ error: `You already ${existing[0].action} this record.` });
      }
      await pool.query(
        `UPDATE document_reviews
         SET action = $1, action_date = NOW(), comment = COALESCE($2, comment)
         WHERE id = $3`,
        [action, comment?.trim() || null, existing[0].id]
      );
    } else {
      await pool.query(
        `INSERT INTO document_reviews
           (record_type, record_id, record_kind, reviewer_id, reviewer_role,
            reviewer_email, reviewer_position, action, comment)
         VALUES ($1, $2, 'new', $3, $4, $5, $6, $7, $8)`,
        [table, recordId, reviewerId, reviewerRole, reviewerEmail, reviewerPosition, action, comment?.trim() || null]
      );
    }

    if (isDecisionMakerActor && isWorkflow) {
      const uploaderSide = getSide(rec.role);
      let newStatus;
      if (action === 'rejected') {
        newStatus = 'rejected';
      } else if (action === 'accepted') {
        newStatus = 'approved_record';
      } else {
        const step2StatusMap = {
          contractor: 'pending_client_acceptance',
          consultant: 'pending_contractor_acceptance',
          client:     'pending_contractor_acceptance',
        };
        newStatus = step2StatusMap[uploaderSide] || 'pending_review';
      }
      await pool.query(
        `UPDATE ${table} SET status = $1 WHERE id = $2 AND project_id = $3`,
        [newStatus, recordId, projectId]
      );
      const notifMsg = `${reviewerRole} ${action} record "${rec.role}" #${recordId}`;
      const dbClient = await pool.connect();
      try {
        await dbClient.query('BEGIN');
        const notifRes = await dbClient.query(
          `INSERT INTO notifications
             (project_id, entity_id, entity_type, message, added_by_id, added_by_role)
           VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
          [projectId, recordId, table, notifMsg, reviewerId, reviewerRole]
        );
        const notificationId = notifRes.rows[0].id;
        const recipientIds   = await getProjectMemberUserIds(projectId, reviewerId);
        if (recipientIds.length > 0) {
          const vals = recipientIds.map((uid, i) => `($1, $${i + 2})`).join(', ');
          await dbClient.query(
            `INSERT INTO notification_recipients (notification_id, user_id)
             VALUES ${vals}
             ON CONFLICT (notification_id, user_id) DO NOTHING`,
            [notificationId, ...recipientIds]
          );
        }
        await dbClient.query('COMMIT');
      } catch (notifErr) {
        await dbClient.query('ROLLBACK');
        console.error('Notification insert error (non-fatal):', notifErr);
      } finally {
        dbClient.release();
      }
    }
    res.json({ success: true, message: `Action '${action}' recorded successfully.` });
  } catch (err) {
    console.error('Review record error:', err);
    res.status(500).json({ error: 'Failed to process review.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  DOWNLOAD FILE
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/download-file', authenticateToken, async (req, res) => {
  const { recordId, recordType } = req.query;
  const table = resolveTable(recordType);
  if (!table) return res.status(400).json({ error: 'Invalid or missing recordType.' });
  try {
    const { rows } = await pool.query(`SELECT file_path FROM ${table} WHERE id = $1`, [recordId]);
    if (!rows.length || !rows[0].file_path) return res.status(404).json({ error: 'File not found.' });
    const filePath = rows[0].file_path;
    const fileName = filePath.split('/').pop() || 'download';
    if (filePath.startsWith('http')) return res.json({ url: filePath, fileName });
    res.status(404).json({ error: 'File not accessible.' });
  } catch (err) {
    console.error('Download file error:', err);
    res.status(500).json({ error: 'Failed to download file.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  DELETE RECORD
// ─────────────────────────────────────────────────────────────────────────────
app.delete('/api/delete-record', authenticateToken, async (req, res) => {
  const { projectId, recordId, recordType } = req.body;
  const userId = req.user.user_id;
  const table  = resolveTable(recordType);
  if (!table) return res.status(400).json({ error: 'Invalid or missing recordType.' });
  try {
    const { rows } = await pool.query(
      `SELECT uploaded_by, role FROM ${table} WHERE id = $1 AND project_id = $2`,
      [recordId, projectId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Record not found.' });
    if (String(rows[0].uploaded_by) !== String(userId) || getSide(rows[0].role) !== getSide(req.user.role)) {
      return res.status(403).json({ error: 'Only the uploader can delete this record.' });
    }
    await pool.query(
      `DELETE FROM notification_recipients WHERE notification_id IN (SELECT id FROM notifications WHERE entity_id = $1 AND entity_type = $2)`,
      [recordId, table]
    );
    await pool.query('DELETE FROM notifications WHERE entity_id = $1 AND entity_type = $2', [recordId, table]);
    await pool.query('DELETE FROM document_reviews WHERE record_type = $1 AND record_id = $2', [table, recordId]);
    await pool.query(`DELETE FROM ${table} WHERE id = $1 AND project_id = $2`, [recordId, projectId]);
    res.json({ success: true, message: 'Record deleted successfully.' });
  } catch (err) {
    console.error('Delete record error:', err);
    res.status(500).json({ error: 'Failed to delete record.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  MEETING ROUTES
// ─────────────────────────────────────────────────────────────────────────────
app.post('/records/schedule-meeting', authenticateToken, async (req, res) => {
  const {projectId,title,dateTime,participants,agenda}=req.body;
  if (!projectId||!title||!dateTime||!participants||!agenda)
    return res.status(400).json({success:false,message:'All fields are required.'});
  try {
    const result=await pool.query(
      `INSERT INTO meetings (project_id,title,meeting_date,participants,agenda,type,created_by,created_at)
       VALUES ($1,$2,$3,$4,$5,'scheduled',$6,NOW()) RETURNING id`,
      [projectId,title,new Date(dateTime),participants,agenda,req.user.user_id]
    );
    res.json({success:true,meetingId:result.rows[0].id,message:'Meeting scheduled successfully.'});
  } catch(err){console.error('Schedule meeting error:',err);res.status(500).json({success:false,message:'Failed to schedule meeting.'});}
});

app.post('/records/meetings', authenticateToken, async (req, res) => {
  const {projectId,type}=req.body;
  if (!projectId) return res.status(400).json({success:false,message:'projectId is required.'});
  try {
    const meetingType = type==='scheduled' ? 'scheduled' : 'minutes';
    const result=await pool.query(
      `SELECT id,title,meeting_date AS date,description,type FROM meetings
       WHERE project_id=$1 AND type=$2 ORDER BY meeting_date DESC`,
      [projectId,meetingType]
    );
    res.json({success:true,meetings:result.rows});
  } catch(err){console.error('Meetings list error:',err);res.status(500).json({success:false,message:'Failed to fetch meetings.'});}
});

app.post('/records/meeting-detail', authenticateToken, async (req, res) => {
  const {meetingId,projectId}=req.body;
  if (!meetingId) return res.status(400).json({success:false,message:'meetingId is required.'});
  try {
    const result=await pool.query(
      `SELECT id,title,meeting_date AS date,participants,description AS minutes,agenda,type FROM meetings WHERE id=$1 AND project_id=$2`,
      [meetingId,projectId]
    );
    if (!result.rows.length) return res.status(404).json({success:false,message:'Meeting not found.'});
    res.json({success:true,...result.rows[0]});
  } catch(err){console.error('Meeting detail error:',err);res.status(500).json({success:false,message:'Failed to fetch meeting detail.'});}
});

app.post('/records/add-meeting-minute', authenticateToken, upload.array('documents', 5), async (req, res) => {
  const {title,details,projectId,date}=req.body;
  if (!title||!details||!projectId) return res.status(400).json({success:false,message:'title, details and projectId are required.'});
  try {
    const attachmentUrls=[];
    for (const file of (req.files||[])) {
      try {
        const r=await uploadToCloudinary(file.buffer,'oneprojectapp/meetings');
        attachmentUrls.push(r.secure_url);
      } catch(cdErr){console.error('Meeting attachment upload error:',cdErr);}
    }
    const result=await pool.query(
      `INSERT INTO meetings (project_id,title,description,meeting_date,type,attachments,created_by,created_at)
       VALUES ($1,$2,$3,$4,'minutes',$5,$6,NOW()) RETURNING id`,
      [projectId,title,details,date?new Date(date):new Date(),JSON.stringify(attachmentUrls),req.user.user_id]
    );
    res.json({success:true,meetingId:result.rows[0].id,message:'Meeting minute added successfully.'});
  } catch(err){console.error('Add meeting minute error:',err);res.status(500).json({success:false,message:'Failed to add meeting minute.'});}
});

// =============================================================================
//  SCHEDULE MODULE
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
//  GET /api/get-schedule
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/get-schedule', authenticateToken, async (req, res) => {
  const projectId = parseInt(req.query.projectId, 10);
  if (!projectId) return res.status(400).json({ error: 'Valid integer projectId is required' });
  try {
    const schedRow = await pool.query(
      'SELECT * FROM project_schedules WHERE project_id = $1 LIMIT 1',
      [projectId]
    );
    if (!schedRow.rows.length) return res.json({ schedule: null });
    const sched = schedRow.rows[0];
    const msRows = await pool.query(
      `SELECT m.*,
         COALESCE(json_agg(json_build_object('date',e.report_date,'qty',e.qty_executed,'remarks',e.remarks,'cumulative',e.cumulative_after_entry) ORDER BY e.report_date) FILTER (WHERE e.id IS NOT NULL),'[]') AS entries,
         COALESCE(json_agg(DISTINCT jsonb_build_object('fileName',a.file_name,'url',a.cloudinary_url,'publicId',a.cloudinary_public_id)) FILTER (WHERE a.id IS NOT NULL),'[]') AS attachments
       FROM milestones m
       LEFT JOIN milestone_progress_entries e ON e.milestone_id = m.id
       LEFT JOIN milestone_attachments      a ON a.milestone_id = m.id
       WHERE m.schedule_id = $1
       GROUP BY m.id ORDER BY m.sort_order`,
      [sched.id]
    );
    const amRows = await pool.query(
      `SELECT am.*,
         COALESCE(json_agg(json_build_object('date',e.report_date,'qty',e.qty_executed,'remarks',e.remarks,'cumulative',e.cumulative_after_entry) ORDER BY e.report_date) FILTER (WHERE e.id IS NOT NULL),'[]') AS entries,
         COALESCE(json_agg(DISTINCT jsonb_build_object('fileName',a.file_name,'url',a.cloudinary_url)) FILTER (WHERE a.id IS NOT NULL),'[]') AS attachments
       FROM additional_milestones am
       LEFT JOIN additional_milestone_progress_entries e ON e.additional_milestone_id = am.id
       LEFT JOIN additional_milestone_attachments a ON a.additional_milestone_id = am.id
       WHERE am.schedule_id = $1
       GROUP BY am.id ORDER BY am.sort_order`,
      [sched.id]
    );
    const extRows = await pool.query(
      `SELECT id, extension_days, new_planned_finish, reason, extension_type, status, created_at
       FROM schedule_extensions WHERE schedule_id = $1 ORDER BY created_at ASC`,
      [sched.id]
    );
    const mapMs = (ms, isExt) => ({
      id: ms.id, title: ms.title, description: ms.description,
      start: ms.planned_start, end: ms.planned_end,
      quantity: ms.quantity, unit: ms.unit,
      dep: ms.depends_on || ms.depends_on_baseline || 'None',
      weight_pct: ms.weight_pct, float_days: ms.float_days, is_critical: ms.is_critical,
      executed: ms.executed, progress_pct: ms.progress_pct,
      activity_status: ms.activity_status, completed_at: ms.completed_at,
      entries: ms.entries,
      fileName: ms.attachments?.[0]?.fileName || null,
      attachmentUrl: ms.attachments?.[0]?.url || null,
      isExtension: isExt,
    });
    res.json({
      schedule: {
        id: sched.id,
        timeline: { start: sched.planned_start, finish: sched.planned_finish, duration: sched.total_duration },
        milestones:           msRows.rows.map(ms => mapMs(ms, false)),
        extension_milestones: amRows.rows.map(ms => mapMs(ms, true)),
        extensions:           extRows.rows,
      },
    });
  } catch (err) {
    console.error('[GET /api/get-schedule]', err);
    res.status(500).json({ error: 'Failed to load schedule' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  POST /api/save-schedule
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/save-schedule', authenticateToken, upload.any(), async (req, res) => {
  const projectId = parseInt(req.body.projectId, 10);
  if (!projectId) return res.status(400).json({ error: 'Valid integer projectId is required' });
  let tl, rawMilestones, newIds, editedIds, unchangedIds, deletedIds;
  try {
    tl            = JSON.parse(req.body.timeline);
    rawMilestones = JSON.parse(req.body.milestones);
    newIds        = new Set(JSON.parse(req.body.newIds       || '[]'));
    editedIds     = new Set(JSON.parse(req.body.editedIds    || '[]'));
    unchangedIds  = new Set(JSON.parse(req.body.unchangedIds || '[]'));
    deletedIds    =          JSON.parse(req.body.deletedIds  || '[]');
  } catch {
    return res.status(400).json({ error: 'Invalid JSON in timeline, milestones, or id lists' });
  }
  const fileMap = {};
  (req.files || []).forEach(f => { fileMap[f.fieldname.replace(/^file_/, '')] = f; });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const schedRes = await client.query(
      `INSERT INTO project_schedules (project_id, planned_start, planned_finish, total_duration, created_by_user_id, created_by_role)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (project_id) DO UPDATE
         SET planned_start = EXCLUDED.planned_start, planned_finish = EXCLUDED.planned_finish,
             total_duration = EXCLUDED.total_duration, updated_at = now()
       RETURNING *`,
      [projectId, tl.start, tl.finish, tl.duration, req.user.user_id, req.user.role]
    );
    const schedId = schedRes.rows[0].id;
    for (const dbId of deletedIds) {
      const check = await client.query('SELECT executed FROM milestones WHERE id = $1 AND schedule_id = $2', [dbId, schedId]);
      if (!check.rows.length) continue;
      if (parseFloat(check.rows[0].executed) > 0) { console.warn(`[save-schedule] Skipping delete of milestone ${dbId}: has recorded progress`); continue; }
      await client.query('DELETE FROM milestones WHERE id = $1 AND schedule_id = $2', [dbId, schedId]);
    }
    const totalDur = rawMilestones.reduce((sum, ms) => sum + Math.max(1, daysBetween(ms.start, ms.end)), 0);
    const tempToReal = {};
    for (const ms of rawMilestones) { if (!newIds.has(ms.id)) tempToReal[ms.id] = ms.id; }
    const needsAttachment = [];
    for (let i = 0; i < rawMilestones.length; i++) {
      const ms    = rawMilestones[i];
      const dur   = Math.max(1, daysBetween(ms.start, ms.end));
      const float = Math.max(0, daysBetween(ms.end, tl.finish));
      const w     = totalDur > 0 ? (dur / totalDur) * 100 : 0;
      const depId = ms.dep && ms.dep !== 'None' && tempToReal[ms.dep] ? tempToReal[ms.dep] : null;
      if (newIds.has(ms.id)) {
        const ins = await client.query(
          `INSERT INTO milestones (schedule_id, project_id, title, description, sort_order, planned_start, planned_end, duration_days, float_days, is_critical, weight_pct, quantity, unit, depends_on, created_by_user_id, created_by_role)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id`,
          [schedId, projectId, ms.title, ms.desc || ms.description || null, i, ms.start, ms.end, dur, float, float === 0, w.toFixed(2), parseFloat(ms.qty || ms.quantity) || 0, ms.unit || null, depId, req.user.user_id, req.user.role]
        );
        const realId = ins.rows[0].id;
        tempToReal[ms.id] = realId;
        if (fileMap[ms.id]) needsAttachment.push({ realId, tempId: ms.id });
      } else if (editedIds.has(ms.id)) {
        await client.query(
          `UPDATE milestones SET title=$1, description=$2, sort_order=$3, planned_start=$4, planned_end=$5, duration_days=$6, float_days=$7, is_critical=$8, weight_pct=$9, quantity=$10, unit=$11, depends_on=$12, updated_at=now()
           WHERE id = $13 AND schedule_id = $14`,
          [ms.title, ms.desc || ms.description || null, i, ms.start, ms.end, dur, float, float === 0, w.toFixed(2), parseFloat(ms.qty || ms.quantity) || 0, ms.unit || null, depId, ms.id, schedId]
        );
        if (fileMap[ms.id]) needsAttachment.push({ realId: ms.id, tempId: ms.id });
      } else if (unchangedIds.has(ms.id)) {
        await client.query('UPDATE milestones SET sort_order = $1 WHERE id = $2 AND schedule_id = $3', [i, ms.id, schedId]);
      }
    }
    for (const { realId, tempId } of needsAttachment) {
      const file = fileMap[tempId];
      if (!file) continue;
      try {
        const cdResult = await scheduleCloudinaryUpload(file.buffer, file.originalname, `oneprojectapp/schedules/${projectId}/milestones`);
        await client.query(
          `INSERT INTO milestone_attachments (milestone_id, file_name, file_size, mime_type, cloudinary_public_id, cloudinary_url, uploaded_by_user_id, uploaded_by_role)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (cloudinary_public_id) DO NOTHING`,
          [realId, file.originalname, file.size, file.mimetype, cdResult.public_id, cdResult.secure_url, req.user.user_id, req.user.role]
        );
      } catch (cdErr) { console.error('[save-schedule] Cloudinary upload failed for milestone', realId, cdErr); }
    }
    await client.query('COMMIT');
    const freshMs = await pool.query(
      `SELECT m.*,
         COALESCE(json_agg(json_build_object('date',e.report_date,'qty',e.qty_executed,'remarks',e.remarks,'cumulative',e.cumulative_after_entry) ORDER BY e.report_date) FILTER (WHERE e.id IS NOT NULL),'[]') AS entries,
         COALESCE(json_agg(DISTINCT jsonb_build_object('fileName',a.file_name,'url',a.cloudinary_url,'publicId',a.cloudinary_public_id)) FILTER (WHERE a.id IS NOT NULL),'[]') AS attachments
       FROM milestones m
       LEFT JOIN milestone_progress_entries e ON e.milestone_id = m.id
       LEFT JOIN milestone_attachments      a ON a.milestone_id = m.id
       WHERE m.schedule_id = $1
       GROUP BY m.id ORDER BY m.sort_order`,
      [schedId]
    );
    res.json({
      success: true,
      schedule: {
        id: schedId,
        timeline: { start: tl.start, finish: tl.finish, duration: tl.duration },
        milestones: freshMs.rows.map(ms => ({
          id: ms.id, title: ms.title, description: ms.description,
          start: ms.planned_start, end: ms.planned_end,
          quantity: ms.quantity, unit: ms.unit, dep: ms.depends_on || 'None',
          weight_pct: ms.weight_pct, float_days: ms.float_days, is_critical: ms.is_critical,
          executed: ms.executed, progress_pct: ms.progress_pct, activity_status: ms.activity_status,
          entries: ms.entries,
          fileName: ms.attachments?.[0]?.fileName || null,
          attachmentUrl: ms.attachments?.[0]?.url || null,
        })),
        extension_milestones: [],
      },
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[POST /api/save-schedule]', err);
    res.status(500).json({ error: 'Failed to save schedule' });
  } finally {
    client.release();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  POST /api/report-progress
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/report-progress', authenticateToken, upload.single('attachment'), async (req, res) => {
  const projectId = parseInt(req.body.projectId, 10);
  const { milestoneId, reportDate, remarks } = req.body;
  const qty = parseFloat(req.body.qtyExecuted);
  if (!projectId || !milestoneId || !reportDate || !qty || qty <= 0) {
    return res.status(400).json({ error: 'Valid projectId, milestoneId, reportDate and positive qtyExecuted are required' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const msRes = await client.query('SELECT * FROM milestones WHERE id = $1 AND project_id = $2 FOR UPDATE', [milestoneId, projectId]);
    if (!msRes.rows.length) return res.status(404).json({ error: 'Milestone not found' });
    const ms = msRes.rows[0];
    if (ms.activity_status === 'completed') return res.status(409).json({ error: 'Milestone is already completed' });
    const planned    = parseFloat(ms.quantity) || 0;
    const prevExec   = parseFloat(ms.executed) || 0;
    const newExecuted = prevExec + qty;
    if (planned > 0 && newExecuted > planned) {
      return res.status(422).json({ error: `Cannot exceed planned quantity of ${planned} ${ms.unit || ''}. Remaining: ${(planned - prevExec).toFixed(3)}` });
    }
    const newPct = planned > 0 ? Math.min(100, (newExecuted / planned) * 100) : 0;
    const entryRes = await client.query(
      `INSERT INTO milestone_progress_entries (milestone_id, project_id, report_date, qty_executed, cumulative_after_entry, progress_pct_after_entry, remarks, reported_by_user_id, reported_by_role)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (milestone_id, report_date) DO UPDATE
         SET qty_executed = milestone_progress_entries.qty_executed + EXCLUDED.qty_executed,
             cumulative_after_entry = EXCLUDED.cumulative_after_entry,
             progress_pct_after_entry = EXCLUDED.progress_pct_after_entry,
             remarks = COALESCE(EXCLUDED.remarks, milestone_progress_entries.remarks),
             reported_by_user_id = EXCLUDED.reported_by_user_id,
             reported_by_role = EXCLUDED.reported_by_role
       RETURNING *`,
      [milestoneId, projectId, reportDate, qty, newExecuted, newPct.toFixed(2), remarks || null, req.user.user_id, req.user.role]
    );
    await client.query(
      `UPDATE milestones SET executed=$1, progress_pct=$2, activity_status='in_progress', updated_at=now() WHERE id=$3`,
      [newExecuted, newPct.toFixed(2), milestoneId]
    );
    if (req.file) {
      try {
        const cdResult = await scheduleCloudinaryUpload(req.file.buffer, req.file.originalname, `oneprojectapp/schedules/${projectId}/progress`);
        await client.query(
          `INSERT INTO progress_entry_attachments (progress_entry_id, file_name, file_size, mime_type, cloudinary_public_id, cloudinary_url, uploaded_by_user_id, uploaded_by_role)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [entryRes.rows[0].id, req.file.originalname, req.file.size, req.file.mimetype, cdResult.public_id, cdResult.secure_url, req.user.user_id, req.user.role]
        );
      } catch (cdErr) { console.error('[report-progress] Attachment upload failed:', cdErr); }
    }
    await client.query('COMMIT');
    const allEntries = await pool.query(
      `SELECT report_date AS date, qty_executed AS qty, remarks, cumulative_after_entry AS cumulative
       FROM milestone_progress_entries WHERE milestone_id = $1 ORDER BY report_date`,
      [milestoneId]
    );
    res.json({ success: true, milestone: { id: milestoneId, executed: newExecuted, progress_pct: parseFloat(newPct.toFixed(2)), activity_status: 'in_progress', entries: allEntries.rows } });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[POST /api/report-progress]', err);
    res.status(500).json({ error: 'Failed to save progress entry' });
  } finally {
    client.release();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  POST /api/report-additional-progress
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/report-additional-progress', authenticateToken, upload.single('attachment'), async (req, res) => {
  const projectId = parseInt(req.body.projectId, 10);
  const { milestoneId, reportDate, remarks } = req.body;
  const qty = parseFloat(req.body.qtyExecuted);
  if (!projectId || !milestoneId || !reportDate || !qty || qty <= 0) {
    return res.status(400).json({ error: 'Valid projectId, milestoneId, reportDate and positive qtyExecuted are required' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const msRes = await client.query('SELECT * FROM additional_milestones WHERE id = $1 AND project_id = $2 FOR UPDATE', [milestoneId, projectId]);
    if (!msRes.rows.length) return res.status(404).json({ error: 'Additional milestone not found' });
    const ms = msRes.rows[0];
    if (ms.activity_status === 'completed') return res.status(409).json({ error: 'Milestone is already completed' });
    const planned    = parseFloat(ms.quantity) || 0;
    const prevExec   = parseFloat(ms.executed) || 0;
    const newExecuted = prevExec + qty;
    if (planned > 0 && newExecuted > planned) {
      return res.status(422).json({ error: `Cannot exceed planned quantity. Remaining: ${(planned - prevExec).toFixed(3)} ${ms.unit || ''}` });
    }
    const newPct = planned > 0 ? Math.min(100, (newExecuted / planned) * 100) : 0;
    const entryRes = await client.query(
      `INSERT INTO additional_milestone_progress_entries (additional_milestone_id, project_id, report_date, qty_executed, cumulative_after_entry, progress_pct_after_entry, remarks, reported_by_user_id, reported_by_role)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (additional_milestone_id, report_date) DO UPDATE
         SET qty_executed = additional_milestone_progress_entries.qty_executed + EXCLUDED.qty_executed,
             cumulative_after_entry = EXCLUDED.cumulative_after_entry,
             progress_pct_after_entry = EXCLUDED.progress_pct_after_entry,
             remarks = COALESCE(EXCLUDED.remarks, additional_milestone_progress_entries.remarks),
             reported_by_user_id = EXCLUDED.reported_by_user_id,
             reported_by_role = EXCLUDED.reported_by_role
       RETURNING id`,
      [milestoneId, projectId, reportDate, qty, newExecuted, newPct.toFixed(2), remarks || null, req.user.user_id, req.user.role]
    );
    await client.query(
      `UPDATE additional_milestones SET executed=$1, progress_pct=$2, activity_status='in_progress', updated_at=now() WHERE id=$3`,
      [newExecuted, newPct.toFixed(2), milestoneId]
    );
    if (req.file) {
      try {
        const cdResult = await scheduleCloudinaryUpload(req.file.buffer, req.file.originalname, `oneprojectapp/schedules/${projectId}/additional-progress`);
        await client.query(
          `INSERT INTO additional_milestone_attachments (additional_milestone_id, file_name, file_size, mime_type, cloudinary_public_id, cloudinary_url, uploaded_by_user_id, uploaded_by_role)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [milestoneId, req.file.originalname, req.file.size, req.file.mimetype, cdResult.public_id, cdResult.secure_url, req.user.user_id, req.user.role]
        );
      } catch (cdErr) { console.error('[report-additional-progress] Attachment upload failed:', cdErr); }
    }
    await client.query('COMMIT');
    const allEntries = await pool.query(
      `SELECT report_date AS date, qty_executed AS qty, remarks, cumulative_after_entry AS cumulative
       FROM additional_milestone_progress_entries WHERE additional_milestone_id = $1 ORDER BY report_date`,
      [milestoneId]
    );
    res.json({ success: true, milestone: { id: milestoneId, executed: newExecuted, progress_pct: parseFloat(newPct.toFixed(2)), activity_status: 'in_progress', entries: allEntries.rows } });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[POST /api/report-additional-progress]', err);
    res.status(500).json({ error: 'Failed to save additional progress entry' });
  } finally {
    client.release();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  POST /api/complete-milestone
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/complete-milestone', authenticateToken, async (req, res) => {
  const projectId = parseInt(req.body.projectId, 10);
  const { milestoneId, isExtensionMilestone } = req.body;
  if (!projectId || !milestoneId) return res.status(400).json({ error: 'Valid projectId and milestoneId are required' });
  const isExt  = isExtensionMilestone === true || isExtensionMilestone === 'true';
  const table  = isExt ? 'additional_milestones' : 'milestones';
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const msRes = await client.query(`SELECT * FROM ${table} WHERE id = $1 AND project_id = $2 FOR UPDATE`, [milestoneId, projectId]);
    if (!msRes.rows.length) return res.status(404).json({ error: 'Milestone not found' });
    const ms = msRes.rows[0];
    if (ms.activity_status === 'completed') return res.status(409).json({ error: 'Milestone is already completed' });
    const planned = parseFloat(ms.quantity) || 0;
    const exec    = parseFloat(ms.executed)  || 0;
    if (planned > 0 && exec < planned) {
      return res.status(422).json({ error: `Cannot complete: only ${exec} of ${planned} ${ms.unit || ''} executed` });
    }
    await client.query(
      `UPDATE ${table} SET activity_status='completed', progress_pct=100, completed_at=now(), updated_at=now() WHERE id=$1`,
      [milestoneId]
    );
    await client.query('COMMIT');
    res.json({ success: true, completedAt: new Date().toISOString() });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[POST /api/complete-milestone]', err);
    res.status(500).json({ error: 'Failed to complete milestone' });
  } finally {
    client.release();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  POST /api/save-extension
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/save-extension', authenticateToken, upload.any(), async (req, res) => {
  const projectId = parseInt(req.body.projectId, 10);
  if (!projectId) return res.status(400).json({ error: 'Valid integer projectId is required' });
  const extensionDays    = parseInt(req.body.extensionDays, 10);
  const newPlannedFinish = req.body.newPlannedFinish;
  const reason           = (req.body.reason || '').trim();
  const extensionType    = req.body.extensionType;
  const scopeType        = req.body.scopeType;
  let newMilestones = [];
  try { newMilestones = JSON.parse(req.body.newMilestones || '[]'); }
  catch { return res.status(400).json({ error: 'Invalid JSON in newMilestones' }); }
  if (!extensionDays || extensionDays < 1) return res.status(400).json({ error: 'extensionDays must be a positive integer' });
  if (!newPlannedFinish) return res.status(400).json({ error: 'newPlannedFinish is required' });
  if (!reason) return res.status(400).json({ error: 'reason is required' });
  if (!['delay', 'scope_addition', 'force_majeure'].includes(extensionType)) return res.status(400).json({ error: 'Invalid extensionType' });
  const fileMap = {};
  (req.files || []).forEach(f => { const m = f.fieldname.match(/^extFile_(\d+)$/); if (m) fileMap[parseInt(m[1], 10)] = f; });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const schedRes = await client.query('SELECT id, planned_finish FROM project_schedules WHERE project_id = $1 LIMIT 1', [projectId]);
    if (!schedRes.rows.length) return res.status(404).json({ error: 'No schedule found for this project' });
    const scheduleId = schedRes.rows[0].id;
    const extRes = await client.query(
      `INSERT INTO schedule_extensions (schedule_id, project_id, extension_days, new_planned_finish, reason, extension_type, requested_by_user_id, requested_by_role)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [scheduleId, projectId, extensionDays, newPlannedFinish, reason, extensionType, req.user.user_id, req.user.role]
    );
    const extensionId = extRes.rows[0].id;
    await client.query('UPDATE project_schedules SET planned_finish=$1, updated_at=now() WHERE id=$2', [newPlannedFinish, scheduleId]);
    const insertedAdditional = [];
    if (scopeType === 'new' && newMilestones.length > 0) {
      for (let i = 0; i < newMilestones.length; i++) {
        const ms     = newMilestones[i];
        const dur    = Math.max(1, daysBetween(ms.planned_start, ms.planned_end));
        const floatD = Math.max(0, Math.round((new Date(newPlannedFinish) - new Date(ms.planned_end)) / 86400000));
        const depBaselineId = ms.depends_on_baseline && ms.depends_on_baseline !== 'None' ? ms.depends_on_baseline : null;
        const amRes = await client.query(
          `INSERT INTO additional_milestones (schedule_id, project_id, schedule_extension_id, title, description, sort_order, planned_start, planned_end, duration_days, float_days, is_critical, weight_pct, quantity, unit, depends_on_baseline, added_by_user_id, added_by_role)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING id`,
          [scheduleId, projectId, extensionId, ms.title, ms.description || null, i, ms.planned_start, ms.planned_end, dur, floatD, floatD === 0, 0, parseFloat(ms.quantity) || 0, ms.unit || null, depBaselineId, req.user.user_id, req.user.role]
        );
        const additionalId = amRes.rows[0].id;
        insertedAdditional.push({ id: additionalId, index: i });
        const file = fileMap[i];
        if (file) {
          try {
            const cdResult = await scheduleCloudinaryUpload(file.buffer, file.originalname, `oneprojectapp/schedules/${projectId}/additional`);
            await client.query(
              `INSERT INTO additional_milestone_attachments (additional_milestone_id, file_name, file_size, mime_type, cloudinary_public_id, cloudinary_url, uploaded_by_user_id, uploaded_by_role)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
              [additionalId, file.originalname, file.size, file.mimetype, cdResult.public_id, cdResult.secure_url, req.user.user_id, req.user.role]
            );
          } catch (cdErr) { console.error('[save-extension] Cloudinary upload failed for additional milestone', additionalId, cdErr); }
        }
      }
    }
    await client.query('COMMIT');
    res.json({ success: true, extension: { id: extensionId, extensionDays, newPlannedFinish, reason, extensionType, status: 'pending', newMilestonesAdded: insertedAdditional.length } });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[POST /api/save-extension]', err);
    res.status(500).json({ error: 'Failed to save extension' });
  } finally {
    client.release();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  MILESTONE PHOTOS
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/milestone-photos', authenticateToken, async (req, res) => {
  const { milestoneId, additionalMilestoneId } = req.query;
  if (!milestoneId && !additionalMilestoneId) return res.status(400).json({ error: 'milestoneId or additionalMilestoneId is required' });
  try {
    const col = milestoneId ? 'milestone_id' : 'additional_milestone_id';
    const val = milestoneId ?? additionalMilestoneId;
    const { rows } = await pool.query(
      `SELECT id, file_name, file_size, mime_type, cloudinary_url, uploaded_at FROM milestone_photos WHERE ${col} = $1 ORDER BY uploaded_at ASC`,
      [val]
    );
    res.json({ photos: rows });
  } catch (err) {
    console.error('[GET /api/milestone-photos]', err);
    res.status(500).json({ error: 'Failed to fetch photos' });
  }
});

app.post('/api/milestone-photos', authenticateToken, photoUpload.array('photos', 10), async (req, res) => {
  const { milestoneId, additionalMilestoneId } = req.body;
  const projectId = parseInt(req.body.projectId, 10);
  if (!projectId) return res.status(400).json({ error: 'projectId is required' });
  if (!milestoneId && !additionalMilestoneId) return res.status(400).json({ error: 'milestoneId or additionalMilestoneId is required' });
  if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'No files uploaded' });
  const col    = milestoneId ? 'milestone_id' : 'additional_milestone_id';
  const val    = milestoneId ?? additionalMilestoneId;
  const folder = milestoneId
    ? `oneprojectapp/schedules/${projectId}/milestone-photos`
    : `oneprojectapp/schedules/${projectId}/additional-photos`;
  const inserted = [];
  try {
    for (const file of req.files) {
      const cdResult = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder, resource_type: 'image', public_id: `${Date.now()}_${file.originalname.replace(/\s+/g, '-')}` },
          (err, result) => (err ? reject(err) : resolve(result))
        );
        Readable.from(file.buffer).pipe(stream);
      });
      const { rows } = await pool.query(
        `INSERT INTO milestone_photos (${col}, project_id, file_name, file_size, mime_type, cloudinary_public_id, cloudinary_url, uploaded_by_user_id, uploaded_by_role)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         RETURNING id, file_name, cloudinary_url, uploaded_at`,
        [val, projectId, file.originalname, file.size, file.mimetype, cdResult.public_id, cdResult.secure_url, req.user.user_id, req.user.role]
      );
      inserted.push(rows[0]);
    }
    res.json({ success: true, photos: inserted });
  } catch (err) {
    console.error('[POST /api/milestone-photos]', err);
    res.status(500).json({ error: 'Failed to upload photos' });
  }
});

app.delete('/api/milestone-photos/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query(
      'SELECT cloudinary_public_id, uploaded_by_user_id FROM milestone_photos WHERE id = $1',
      [id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Photo not found' });
    if (rows[0].uploaded_by_user_id !== req.user.user_id) {
      return res.status(403).json({ error: 'Only the uploader can delete this photo' });
    }
    try {
      await cloudinary.uploader.destroy(rows[0].cloudinary_public_id, { resource_type: 'image' });
    } catch (cdErr) { console.error('[DELETE /api/milestone-photos] Cloudinary destroy error (non-fatal):', cdErr); }
    await pool.query('DELETE FROM milestone_photos WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error('[DELETE /api/milestone-photos/:id]', err);
    res.status(500).json({ error: 'Failed to delete photo' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  GET /api/project-summary
//  Single-call endpoint for the summary panel
//  Returns: timeline, progress stats, per-milestone chart data, all photos
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/project-summary', authenticateToken, async (req, res) => {
  const projectId = parseInt(req.query.projectId, 10);
  if (!projectId) return res.status(400).json({ error: 'Valid integer projectId is required' });

  try {
    // ── 1. Schedule ──
    const schedRow = await pool.query(
      'SELECT id, planned_start, planned_finish, total_duration FROM project_schedules WHERE project_id = $1 LIMIT 1',
      [projectId]
    );
    if (!schedRow.rows.length) {
      return res.json({ hasSchedule: false, milestones: [], photos: [], timeline: null });
    }
    const sched = schedRow.rows[0];

    // ── 2. Baseline milestones ──
    const msRows = await pool.query(
      `SELECT
         m.id, m.title, m.planned_start AS start, m.planned_end AS end,
         m.quantity, m.unit, m.weight_pct, m.float_days, m.is_critical,
         m.executed, m.progress_pct, m.activity_status, m.completed_at,
         m.depends_on AS dep
       FROM milestones m
       WHERE m.schedule_id = $1
       ORDER BY m.sort_order`,
      [sched.id]
    );

    // ── 3. Extension milestones ──
    const amRows = await pool.query(
      `SELECT
         am.id, am.title, am.planned_start AS start, am.planned_end AS end,
         am.quantity, am.unit, am.weight_pct, am.float_days, am.is_critical,
         am.executed, am.progress_pct, am.activity_status, am.completed_at,
         am.depends_on_baseline AS dep,
         true AS is_extension
       FROM additional_milestones am
       WHERE am.schedule_id = $1
       ORDER BY am.sort_order`,
      [sched.id]
    );

    const allMilestones = [
      ...msRows.rows.map(m => ({ ...m, is_extension: false })),
      ...amRows.rows.map(m => ({ ...m, is_extension: true  })),
    ];

    // ── 4. Overall progress (weight-aware) ──
    const totalWeight = allMilestones.reduce((s, m) => s + Number(m.weight_pct || 0), 0);
    const overallPct  = allMilestones.length === 0 ? 0
      : totalWeight > 0
        ? allMilestones.reduce((s, m) => s + Number(m.weight_pct || 0) * Number(m.progress_pct || 0), 0) / totalWeight
        : allMilestones.reduce((s, m) => s + Number(m.progress_pct || 0), 0) / allMilestones.length;

    // ── 5. Planned % today ──
    const today      = new Date(); today.setHours(0, 0, 0, 0);
    const projStart  = new Date(sched.planned_start);
    const projFinish = new Date(sched.planned_finish);
    const elapsed    = Math.max(0, (today - projStart) / 86400000);
    const totalDays  = Math.max(1, (projFinish - projStart) / 86400000);
    const plannedPct = Math.min(100, (elapsed / totalDays) * 100);
    const variance   = parseFloat((overallPct - plannedPct).toFixed(2));

    // ── 6. Last completed milestone ──
    const completed     = allMilestones.filter(m => m.activity_status === 'completed');
    const lastCompleted = completed.length ? completed[completed.length - 1].title : null;

    // ── 7. Per-milestone chart data (max 7) ──
    const chartMilestones = allMilestones.slice(0, 7).map(ms => {
      const msStart = new Date(ms.start);
      const msEnd   = new Date(ms.end);
      let msPlanPct = 0;
      if (today >= msEnd)        msPlanPct = 100;
      else if (today > msStart)  msPlanPct = Math.min(100, ((today - msStart) / Math.max(1, msEnd - msStart)) * 100);
      return {
        id:              ms.id,
        title:           ms.title,
        start:           ms.start,
        end:             ms.end,
        planned_pct:     parseFloat(msPlanPct.toFixed(2)),
        actual_pct:      parseFloat(Number(ms.progress_pct || 0).toFixed(2)),
        activity_status: ms.activity_status,
        weight_pct:      ms.weight_pct,
        is_extension:    ms.is_extension,
      };
    });

    // ── 8. All photos — bulk queries ──
    const msIds = msRows.rows.map(m => m.id);
    const amIds = amRows.rows.map(m => m.id);
    let photos  = [];

    if (msIds.length > 0) {
      const placeholders = msIds.map((_, i) => `$${i + 1}`).join(', ');
      const photoRes = await pool.query(
        `SELECT
           mp.id, mp.file_name, mp.cloudinary_url, mp.uploaded_at,
           m.title AS ms_title
         FROM milestone_photos mp
         JOIN milestones m ON m.id = mp.milestone_id
         WHERE mp.milestone_id IN (${placeholders})
         ORDER BY mp.uploaded_at ASC`,
        msIds
      );
      photos = photos.concat(photoRes.rows.map(p => ({ ...p, is_extension: false })));
    }

    if (amIds.length > 0) {
      const placeholders = amIds.map((_, i) => `$${i + 1}`).join(', ');
      const amPhotoRes = await pool.query(
        `SELECT
           mp.id, mp.file_name, mp.cloudinary_url, mp.uploaded_at,
           am.title AS ms_title
         FROM milestone_photos mp
         JOIN additional_milestones am ON am.id = mp.additional_milestone_id
         WHERE mp.additional_milestone_id IN (${placeholders})
         ORDER BY mp.uploaded_at ASC`,
        amIds
      );
      photos = photos.concat(amPhotoRes.rows.map(p => ({ ...p, is_extension: true })));
    }

    // ── 9. Latest approved extension ──
    const extRow = await pool.query(
      `SELECT extension_days, new_planned_finish, status
       FROM schedule_extensions
       WHERE schedule_id = $1 AND status = 'approved'
       ORDER BY created_at DESC LIMIT 1`,
      [sched.id]
    );
    const latestExtension = extRow.rows[0] || null;

    res.json({
      hasSchedule: true,
      timeline: {
        start:          sched.planned_start,
        finish:         sched.planned_finish,
        duration:       sched.total_duration,
        current_finish: latestExtension ? latestExtension.new_planned_finish : sched.planned_finish,
      },
      progress: {
        overall_pct:       parseFloat(overallPct.toFixed(2)),
        planned_pct:       parseFloat(plannedPct.toFixed(2)),
        variance_pct:      variance,
        last_completed:    lastCompleted,
        total_milestones:  allMilestones.length,
        completed_count:   completed.length,
        in_progress_count: allMilestones.filter(m => m.activity_status === 'in_progress').length,
      },
      chart_milestones: chartMilestones,
      photos,
    });

  } catch (err) {
    console.error('[GET /api/project-summary]', err);
    res.status(500).json({ error: 'Failed to load project summary' });
  }
});

// =============================================================================
//  WORK CENTER ROUTES
//  Paste these directly into your server.js (after your existing helpers).
//  Uses: authenticateToken, pool, upload, uploadToCloudinary,
//        scheduleCloudinaryUpload, cloudinary  — already defined above.
// =============================================================================

// ─── local helper (work-center only) ─────────────────────────────────────────
function wcSide(role) {
  // Works with the role strings stored in JWT:
  // Contractor | ContractorPM | Consultant | ConsultantPM | Client | ClientPM
  if (['Contractor',  'ContractorPM'].includes(role)) return 'Contractor';
  if (['Consultant',  'ConsultantPM'].includes(role)) return 'Consultant';
  if (['Client',      'ClientPM'].includes(role))     return 'Client';
  return null;
}

function isWCLeader(role) {
  return wcSide(role) !== null;
}

// ─── SQL: run once ────────────────────────────────────────────────────────────
// CREATE TABLE IF NOT EXISTS work_center_views (
//   id         SERIAL PRIMARY KEY,
//   task_id    INTEGER NOT NULL REFERENCES workspace_work_center(id) ON DELETE CASCADE,
//   viewer_id  INTEGER NOT NULL,
//   viewed_at  TIMESTAMP DEFAULT NOW(),
//   UNIQUE(task_id, viewer_id)
// );

// =============================================================================
//  1.  GET /api/work-center/team-members
//      Returns team members on the same side as the requesting PM/leader.
//      JWT → role determines side.  Query → ?projectId=...
// =============================================================================
app.get('/api/work-center/team-members', authenticateToken, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { projectId }     = req.query;

    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });

    const side = wcSide(role);
    if (!side) return res.status(403).json({ error: 'Your role cannot manage tasks.' });

    const result = await pool.query(
      `SELECT
         t.id,
         t.email,
         tma.position,
         tma.title,
         tma.telephone
       FROM team_member_assignments tma
       JOIN team_members t ON t.id = tma.team_member_id
       WHERE tma.project_id   = $1
         AND tma.assigned_part = $2
       ORDER BY tma.position, t.email`,
      [projectId, side]
    );

    return res.json({ members: result.rows });
  } catch (err) {
    console.error('GET /api/work-center/team-members:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// =============================================================================
//  2.  POST /api/work-center
//      Create a task.  PM / Leader only.
//      Body (multipart/form-data):
//        projectId, title, description, work_package,
//        assigned_members (JSON string), priority,
//        start_date, end_date, linked_file (optional)
// =============================================================================
app.post('/api/work-center', authenticateToken, upload.single('linked_file'), async (req, res) => {
  try {
    const { user_id, role } = req.user;

    if (!isWCLeader(role)) {
      return res.status(403).json({ error: 'Only leaders and PMs can create tasks.' });
    }

    const side = wcSide(role);
    const {
      projectId,
      title,
      description    = '',
      work_package   = '',
      assigned_members,
      priority       = 'normal',
      start_date,
      end_date,
    } = req.body;

    if (!projectId)  return res.status(400).json({ error: 'projectId is required.' });
    if (!title)      return res.status(400).json({ error: 'title is required.' });
    if (!start_date) return res.status(400).json({ error: 'start_date is required.' });
    if (!end_date)   return res.status(400).json({ error: 'end_date is required.' });
    if (!['low','normal','high'].includes(priority)) {
      return res.status(400).json({ error: 'priority must be low, normal, or high.' });
    }

    // Parse assigned members
    let members = [];
    try   { members = JSON.parse(assigned_members || '[]'); }
    catch { return res.status(400).json({ error: 'assigned_members must be valid JSON.' }); }
    if (!Array.isArray(members) || !members.length) {
      return res.status(400).json({ error: 'At least one team member must be assigned.' });
    }

    // Verify all members belong to this project and the same side
    const memberIds = members.map(m => parseInt(m.id, 10)).filter(Boolean);
    const check = await pool.query(
      `SELECT COUNT(*) AS cnt
       FROM team_member_assignments
       WHERE project_id    = $1
         AND team_member_id = ANY($2::int[])
         AND assigned_part  = $3`,
      [projectId, memberIds, side]
    );
    if (parseInt(check.rows[0].cnt, 10) !== memberIds.length) {
      return res.status(403).json({
        error: 'One or more assigned members do not belong to your side on this project.'
      });
    }

    // Upload linked file to Cloudinary if provided
    let linkedFileName = null;
    let linkedFileId   = null;
    let linkedFileUrl  = null;

    if (req.file) {
      const result = await scheduleCloudinaryUpload(
        req.file.buffer, req.file.originalname, 'work_center/tasks'
      );
      linkedFileName = req.file.originalname;
      linkedFileId   = result.public_id;
      linkedFileUrl  = result.secure_url;
    }

    const insertResult = await pool.query(
      `INSERT INTO workspace_work_center
         (project_id, title, description, work_package,
          assigned_members, priority, start_date, end_date,
          linked_file_name, linked_file_id, linked_file_url,
          creator_id, creator_role, side)
       VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$11,$12,$13,$14)
       RETURNING *`,
      [
        projectId, title, description, work_package,
        JSON.stringify(members), priority, start_date, end_date,
        linkedFileName, linkedFileId, linkedFileUrl,
        user_id, role, side,
      ]
    );

    return res.status(201).json({ success: true, task: insertResult.rows[0] });
  } catch (err) {
    console.error('POST /api/work-center:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// =============================================================================
//  3.  PUT /api/work-center/:taskId
//      Update a task.  PM / Leader (same side) only.
//      Body (multipart/form-data): any subset of task fields + optional linked_file
// =============================================================================
app.put('/api/work-center/:taskId', authenticateToken, upload.single('linked_file'), async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { taskId }        = req.params;
    const { projectId }     = req.body;

    if (!isWCLeader(role)) {
      return res.status(403).json({ error: 'Only leaders and PMs can update tasks.' });
    }
    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });

    const side = wcSide(role);

    // Confirm task belongs to this project and same side
    const taskCheck = await pool.query(
      `SELECT id, side, linked_file_id
       FROM workspace_work_center
       WHERE id = $1 AND project_id = $2`,
      [taskId, projectId]
    );
    if (!taskCheck.rows.length) return res.status(404).json({ error: 'Task not found.' });
    if (taskCheck.rows[0].side !== side) {
      return res.status(403).json({ error: 'You cannot edit tasks from another side.' });
    }

    const {
      title, description, work_package,
      assigned_members, priority, start_date, end_date,
    } = req.body;

    // Parse members if provided
    let members = null;
    if (assigned_members !== undefined) {
      try   { members = JSON.parse(assigned_members); }
      catch { return res.status(400).json({ error: 'assigned_members must be valid JSON.' }); }

      // Validate members belong to same side
      if (members && members.length > 0) {
        const memberIds = members.map(m => parseInt(m.id, 10)).filter(Boolean);
        const check = await pool.query(
          `SELECT COUNT(*) AS cnt
           FROM team_member_assignments
           WHERE project_id    = $1
             AND team_member_id = ANY($2::int[])
             AND assigned_part  = $3`,
          [projectId, memberIds, side]
        );
        if (parseInt(check.rows[0].cnt, 10) !== memberIds.length) {
          return res.status(403).json({ error: 'One or more members do not belong to your side.' });
        }
      }
    }

    // Build dynamic SET clause
    const setClauses = [];
    const values     = [];
    let   idx        = 1;

    const push = (col, val) => { setClauses.push(`${col} = $${idx++}`); values.push(val); };

    if (title           !== undefined) push('title',            title);
    if (description     !== undefined) push('description',      description);
    if (work_package    !== undefined) push('work_package',     work_package);
    if (members         !== null)      push('assigned_members', JSON.stringify(members));
    if (priority        !== undefined) push('priority',         priority);
    if (start_date      !== undefined) push('start_date',       start_date);
    if (end_date        !== undefined) push('end_date',         end_date);

    // Replace linked file if new one uploaded
    if (req.file) {
      // Delete old Cloudinary file (non-fatal)
      if (taskCheck.rows[0].linked_file_id) {
        await cloudinary.uploader.destroy(taskCheck.rows[0].linked_file_id, { resource_type: 'raw' })
          .catch(() => {});
      }
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
      `UPDATE workspace_work_center
       SET ${setClauses.join(', ')}
       WHERE id = $${idx} AND project_id = $${idx + 1}
       RETURNING *`,
      values
    );

    return res.json({ success: true, task: updated.rows[0] });
  } catch (err) {
    console.error('PUT /api/work-center/:taskId:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// =============================================================================
//  4.  DELETE /api/work-center/:taskId
//      Delete a task and all its progress entries (CASCADE handles DB rows).
//      Cleans up Cloudinary files too.
//      Body: { projectId }
// =============================================================================
app.delete('/api/work-center/:taskId', authenticateToken, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { taskId }        = req.params;
    const { projectId }     = req.body;

    if (!isWCLeader(role)) {
      return res.status(403).json({ error: 'Only leaders and PMs can delete tasks.' });
    }
    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });

    const side = wcSide(role);

    const taskCheck = await pool.query(
      `SELECT id, side, linked_file_id
       FROM workspace_work_center
       WHERE id = $1 AND project_id = $2`,
      [taskId, projectId]
    );
    if (!taskCheck.rows.length) return res.status(404).json({ error: 'Task not found.' });
    if (taskCheck.rows[0].side !== side) {
      return res.status(403).json({ error: 'You cannot delete tasks from another side.' });
    }

    // Clean up Cloudinary files (all non-fatal)
    const task = taskCheck.rows[0];
    if (task.linked_file_id) {
      await cloudinary.uploader.destroy(task.linked_file_id, { resource_type: 'raw' })
        .catch(() => {});
    }

    // Clean up progress attachment files
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

    // Delete task (progress rows cascade)
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

// =============================================================================
//  5.  GET /api/work-center-progress/:taskId
//      PM / Leader  → all entries with member info
//      Team Member  → only their own entries
//      Query: ?projectId=...
// =============================================================================
app.get('/api/work-center-progress/:taskId', authenticateToken, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { taskId }        = req.params;
    const { projectId }     = req.query;

    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });

    // Fetch task to check access
    const taskCheck = await pool.query(
      `SELECT id, side, assigned_members
       FROM workspace_work_center
       WHERE id = $1 AND project_id = $2`,
      [taskId, projectId]
    );
    if (!taskCheck.rows.length) return res.status(404).json({ error: 'Task not found.' });

    const task = taskCheck.rows[0];
    const side = wcSide(role);

    if (isWCLeader(role)) {
      // Must be on the same side
      if (task.side !== side) return res.status(403).json({ error: 'Access denied.' });

      // Return all entries with member details
      const result = await pool.query(
        `SELECT
           p.*,
           t.email          AS member_email,
           tma.position     AS member_position,
           tma.title        AS member_title
         FROM workspace_work_center_progress p
         JOIN team_members t ON t.id = p.member_id
         LEFT JOIN team_member_assignments tma
           ON tma.team_member_id = p.member_id
          AND tma.project_id    = $2
         WHERE p.task_id = $1
         ORDER BY p.submitted_at DESC`,
        [taskId, projectId]
      );
      return res.json({ entries: result.rows });

    } else if (role === 'TeamMember') {
      // Must be assigned to this task
      const assignedMembers = Array.isArray(task.assigned_members)
        ? task.assigned_members : [];
      const isAssigned = assignedMembers.some(m => String(m.id) === String(user_id));
      if (!isAssigned) return res.status(403).json({ error: 'You are not assigned to this task.' });

      // Return only their own entries
      const result = await pool.query(
        `SELECT * FROM workspace_work_center_progress
         WHERE task_id = $1 AND member_id = $2
         ORDER BY submitted_at DESC`,
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

// =============================================================================
//  6.  POST /api/work-center-progress
//      Submit a progress entry.  Assigned team members only.
//      Body (multipart/form-data):
//        projectId, taskId, reportDate, workDone,
//        manpower, equipment, materials, progressPct,
//        issues, notes, attachment (optional file)
// =============================================================================
app.post('/api/work-center-progress', authenticateToken, upload.single('attachment'), async (req, res) => {
  try {
    const { user_id, role } = req.user;

    if (role !== 'TeamMember') {
      return res.status(403).json({
        error: 'Only assigned team members can submit progress reports.'
      });
    }

    const {
      projectId,
      taskId,
      reportDate,
      workDone,
      manpower    = '',
      equipment   = '',
      materials   = '',
      progressPct = '0',
      issues      = '',
      notes       = '',
    } = req.body;

    if (!projectId)  return res.status(400).json({ error: 'projectId is required.' });
    if (!taskId)     return res.status(400).json({ error: 'taskId is required.' });
    if (!reportDate) return res.status(400).json({ error: 'reportDate is required.' });
    if (!workDone)   return res.status(400).json({ error: 'workDone is required.' });

    const pct = parseInt(progressPct, 10);
    if (isNaN(pct) || pct < 0 || pct > 100) {
      return res.status(400).json({ error: 'progressPct must be between 0 and 100.' });
    }

    // Confirm task exists and member is assigned
    const taskCheck = await pool.query(
      `SELECT id, assigned_members
       FROM workspace_work_center
       WHERE id = $1 AND project_id = $2`,
      [taskId, projectId]
    );
    if (!taskCheck.rows.length) return res.status(404).json({ error: 'Task not found.' });

    const assignedMembers = Array.isArray(taskCheck.rows[0].assigned_members)
      ? taskCheck.rows[0].assigned_members : [];
    const isAssigned = assignedMembers.some(m => String(m.id) === String(user_id));
    if (!isAssigned) {
      return res.status(403).json({
        error: 'You are not assigned to this task and cannot submit progress.'
      });
    }

    // Upload attachment to Cloudinary if provided
    let attachmentName = null;
    let attachmentId   = null;
    let attachmentUrl  = null;

    if (req.file) {
      const uploaded = await scheduleCloudinaryUpload(
        req.file.buffer, req.file.originalname, 'work_center/progress'
      );
      attachmentName = req.file.originalname;
      attachmentId   = uploaded.public_id;
      attachmentUrl  = uploaded.secure_url;
    }

    const result = await pool.query(
      `INSERT INTO workspace_work_center_progress
         (task_id, report_date, member_id, member_role,
          work_done, manpower, equipment, materials,
          progress_pct, issues, notes,
          attachment_name, attachment_id, attachment_url)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
       RETURNING *`,
      [
        taskId, reportDate, user_id, role,
        workDone, manpower, equipment, materials,
        pct, issues, notes,
        attachmentName, attachmentId, attachmentUrl,
      ]
    );

    return res.status(201).json({ success: true, entry: result.rows[0] });
  } catch (err) {
    console.error('POST /api/work-center-progress:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// =============================================================================
//  7.  PUT /api/work-center-progress/:progressId/validate
//      Approve or reject a progress entry.  PM / Leader (same side) only.
//      Body: { projectId, validation_status, validation_notes }
// =============================================================================
app.put('/api/work-center-progress/:progressId/validate', authenticateToken, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { progressId }    = req.params;
    const { projectId, validation_status, validation_notes = '' } = req.body;

    if (!isWCLeader(role)) {
      return res.status(403).json({ error: 'Only leaders and PMs can validate progress entries.' });
    }
    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });
    if (!['approved','rejected'].includes(validation_status)) {
      return res.status(400).json({ error: 'validation_status must be "approved" or "rejected".' });
    }

    const side = wcSide(role);

    // Confirm entry exists and task belongs to same project + side
    const check = await pool.query(
      `SELECT p.id, w.side, w.project_id
       FROM workspace_work_center_progress p
       JOIN workspace_work_center w ON w.id = p.task_id
       WHERE p.id = $1`,
      [progressId]
    );
    if (!check.rows.length) return res.status(404).json({ error: 'Progress entry not found.' });

    const row = check.rows[0];
    if (String(row.project_id) !== String(projectId)) {
      return res.status(403).json({ error: 'Access denied.' });
    }
    if (row.side !== side) {
      return res.status(403).json({ error: 'You cannot validate entries from another side.' });
    }

    const result = await pool.query(
      `UPDATE workspace_work_center_progress
       SET
         validation_status = $1,
         validation_notes  = $2,
         validated_by      = $3,
         validated_at      = NOW()
       WHERE id = $4
       RETURNING *`,
      [validation_status, validation_notes, user_id, progressId]
    );

    return res.json({ success: true, entry: result.rows[0] });
  } catch (err) {
    console.error('PUT /api/work-center-progress/:progressId/validate:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// =============================================================================
//  8.  GET /api/work-center-progress/download/:progressId
//      Returns a signed Cloudinary URL for the progress attachment.
//      Accessible by: the submitting member OR the PM of the same side.
//      Query: ?projectId=...
// =============================================================================
app.get('/api/work-center-progress/download/:progressId', authenticateToken, async (req, res) => {
  try {
    const { user_id, role } = req.user;
    const { progressId }    = req.params;
    const { projectId }     = req.query;

    if (!projectId) return res.status(400).json({ error: 'projectId is required.' });

    const result = await pool.query(
      `SELECT
         p.member_id, p.attachment_id, p.attachment_name, p.attachment_url,
         w.side, w.project_id
       FROM workspace_work_center_progress p
       JOIN workspace_work_center w ON w.id = p.task_id
       WHERE p.id = $1`,
      [progressId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Entry not found.' });

    const entry = result.rows[0];
    if (String(entry.project_id) !== String(projectId)) {
      return res.status(403).json({ error: 'Access denied.' });
    }

    const side     = wcSide(role);
    const isOwner  = role === 'TeamMember' && String(entry.member_id) === String(user_id);
    const isPMSide = isWCLeader(role) && entry.side === side;

    if (!isOwner && !isPMSide) return res.status(403).json({ error: 'Access denied.' });
    if (!entry.attachment_id)  return res.status(404).json({ error: 'No attachment for this entry.' });

    // Generate a signed URL valid for 1 hour
    const url = cloudinary.url(entry.attachment_id, {
      resource_type: 'raw',
      type:          'upload',
      sign_url:      true,
      expires_at:    Math.floor(Date.now() / 1000) + 3600,
    });

    return res.json({ url, filename: entry.attachment_name });
  } catch (err) {
    console.error('GET /api/work-center-progress/download/:progressId:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// =============================================================================
//  9.  EXTEND your existing  POST /api/fetch-tab-records
//      Inside your switch/if on recordType, add this block:
// =============================================================================
//
//  if (recordType === 'workspace_work_center') {
//    const { user_id, role } = req.user;
//    const side = wcSide(role);          // 'Contractor' | 'Consultant' | 'Client' | null
//
//    let records = [];
//
//    if (isWCLeader(role)) {
//      // PM / Leader: all tasks on their side for this project
//      const r = await pool.query(
//        `SELECT
//           w.*,
//           true AS is_creator,
//           EXISTS (
//             SELECT 1 FROM work_center_views v
//             WHERE v.task_id = w.id AND v.viewer_id = $2
//           ) AS is_viewed
//         FROM workspace_work_center w
//         WHERE w.project_id = $1
//           AND w.side       = $3
//         ORDER BY w.created_at DESC`,
//        [projectId, user_id, side]
//      );
//      records = r.rows;
//
//    } else if (role === 'TeamMember') {
//      // Team Member: only tasks where their id is in assigned_members JSONB
//      const r = await pool.query(
//        `SELECT
//           w.*,
//           false AS is_creator,
//           EXISTS (
//             SELECT 1 FROM work_center_views v
//             WHERE v.task_id = w.id AND v.viewer_id = $2
//           ) AS is_viewed
//         FROM workspace_work_center w
//         WHERE w.project_id      = $1
//           AND w.assigned_members @> $3::jsonb
//         ORDER BY w.created_at DESC`,
//        [projectId, user_id, JSON.stringify([{ id: String(user_id) }])]
//      );
//      records = r.rows;
//    }
//
//    return res.json({ records });
//  }

// =============================================================================
//  10. EXTEND your existing  POST /api/mark-record-viewed
//      Add this block when recordType === 'workspace_work_center':
// =============================================================================
//
//  if (recordType === 'workspace_work_center') {
//    await pool.query(
//      `INSERT INTO work_center_views (task_id, viewer_id)
//       VALUES ($1, $2)
//       ON CONFLICT (task_id, viewer_id) DO NOTHING`,
//      [recordId, req.user.user_id]
//    );
//    return res.json({ success: true });
//  }

// =============================================================================
//  SQL — run once in your database
// =============================================================================
//
//  -- Add attachment_url column if not already present:
//  ALTER TABLE workspace_work_center
//    ADD COLUMN IF NOT EXISTS linked_file_url TEXT;
//
//  ALTER TABLE workspace_work_center_progress
//    ADD COLUMN IF NOT EXISTS attachment_url TEXT;
//
//  -- Views tracking table:
//  CREATE TABLE IF NOT EXISTS work_center_views (
//    id         SERIAL PRIMARY KEY,
//    task_id    INTEGER NOT NULL REFERENCES workspace_work_center(id) ON DELETE CASCADE,
//    viewer_id  INTEGER NOT NULL,
//    viewed_at  TIMESTAMP DEFAULT NOW(),
//    UNIQUE(task_id, viewer_id)
//  );

// ─────────────────────────────────────────────────────────────────────────────
//  GLOBAL ERROR HANDLER
// ─────────────────────────────────────────────────────────────────────────────
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