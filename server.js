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

// ─── Multer (memory storage) ──────────────────────────────────────────────────
const upload = multer({
  limits: { fileSize: 10 * 1024 * 1024 },
  storage: multer.memoryStorage(),
  fileFilter: (_req, file, cb) => {
    const allowed = [
      'image/png', 'image/jpeg', 'image/jpg',
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ];
    cb(allowed.includes(file.mimetype) ? null : new Error('Unsupported file type'),
       allowed.includes(file.mimetype));
  },
});

// ─── Cloudinary upload helper ─────────────────────────────────────────────────
function uploadToCloudinary(buffer, folder, resourceType = 'auto') {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder, resource_type: resourceType },
      (err, result) => (err ? reject(err) : resolve(result))
    );
    Readable.from(buffer).pipe(stream);
  });
}

// Schedule-scoped Cloudinary helper
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
      user_id: decoded.sub,
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

// ─── Helpers ──────────────────────────────────────────────────────────────────
const TABLE_MAP = {
  contractual:    'contractual_records',
  administrative: 'administrative_records',
  safety:         'safety_records',
  operational:    'operational_records',
  financial:      'financial_records',
};

function getSide(role) {
  const r = (role || '').toLowerCase().replace(/\s/g, '_');
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

// ─────────────────────────────────────────────────────────────────────────────
//  ROOT
// ─────────────────────────────────────────────────────────────────────────────
app.get('/', (_req, res) => res.send('Backend is running successfully!'));

// ─────────────────────────────────────────────────────────────────────────────
//  GENERIC PROFILE PICTURE / ATTACHMENT ROUTES
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

setInterval(async()=>{
  try{const r=await pool.query('DELETE FROM email_tokens WHERE expires_at<NOW() AND verified=false');if(r.rowCount>0)console.log(`Scheduled cleanup: ${r.rowCount} expired tokens deleted.`);}
  catch(err){console.error('Scheduled cleanup error:',err);}
},3*60*1000);

// ─────────────────────────────────────────────────────────────────────────────
//  PROFILE ROUTES
// ─────────────────────────────────────────────────────────────────────────────
function buildProfileRoutes({routePrefix,jwtRole,dbTable,emailCol,cloudFolder,assignmentTable,assignmentFk,isClientRole,extraProfileFields}) {
  app.get(`${routePrefix}/profile`, authenticateToken, async (req, res) => {
    if (req.user.role!==jwtRole) return res.status(403).json({error:`Access denied: ${jwtRole} only`});
    try {
      const fields=['email','profile_picture',...(extraProfileFields||[])].join(',');
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
        const r=await pool.query(`SELECT p.id,p.name,p.location,p.contract_reference,p.created_at FROM ${assignmentTable} a JOIN projects p ON a.project_id=p.id WHERE a.${assignmentFk}=$1`,[req.user.user_id]);
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
        const r=await pool.query(`SELECT p.id,p.name,p.location,p.contract_reference,p.created_at FROM ${assignmentTable} a JOIN projects p ON a.project_id=p.id WHERE a.${assignmentFk}=$1 AND p.id=$2`,[req.user.user_id,projectId]);
        if (!r.rows.length) return res.status(404).json({error:'Project not found or not assigned'});
        project=r.rows[0];
      }
      res.json({project});
    } catch(err){console.error(`Fetch ${jwtRole} project-details error:`,err);res.status(500).json({error:'Failed to fetch project details'});}
  });
}

buildProfileRoutes({routePrefix:'/client',jwtRole:'Client',dbTable:'clients',emailCol:'company_email',cloudFolder:'oneprojectapp/clients',isClientRole:true,extraProfileFields:['representative','title','telephone','company_name']});
buildProfileRoutes({routePrefix:'/contractor',jwtRole:'Contractor',dbTable:'contractors',emailCol:'email',cloudFolder:'oneprojectapp/contractors',assignmentTable:'contractor_assignments',assignmentFk:'contractor_id'});
buildProfileRoutes({routePrefix:'/consultant',jwtRole:'Consultant',dbTable:'consultants',emailCol:'email',cloudFolder:'oneprojectapp/consultants',assignmentTable:'consultant_assignments',assignmentFk:'consultant_id'});
buildProfileRoutes({routePrefix:'/client-project-manager',jwtRole:'Client Project Manager',dbTable:'client_project_managers',emailCol:'email',cloudFolder:'oneprojectapp/client_project_managers',assignmentTable:'client_pm_assignments',assignmentFk:'client_pm_id'});
buildProfileRoutes({routePrefix:'/contractor-project-manager',jwtRole:'Contractor Project Manager',dbTable:'contractor_project_managers',emailCol:'email',cloudFolder:'oneprojectapp/contractor_project_managers',assignmentTable:'contractor_pm_assignments',assignmentFk:'contractor_pm_id'});
buildProfileRoutes({routePrefix:'/consultant-project-manager',jwtRole:'Consultant Project Manager',dbTable:'consultant_project_managers',emailCol:'email',cloudFolder:'oneprojectapp/consultant_project_managers',assignmentTable:'consultant_pm_assignments',assignmentFk:'consultant_pm_id'});
buildProfileRoutes({routePrefix:'/team-member',jwtRole:'Team Member',dbTable:'team_members',emailCol:'email',cloudFolder:'oneprojectapp/team_members',assignmentTable:'team_member_assignments',assignmentFk:'team_member_id'});

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
  res.json({id:req.user.user_id,role:req.user.role,email:req.user.email});
});

// ─────────────────────────────────────────────────────────────────────────────
//  NOTIFICATIONS
//  Frontend calls:
//    GET /notifications?projectId=&userId=
//    PUT /notifications/:id/read?projectId=&userId=&userRole=
//    GET /notifications/unreadCount?projectId=       ← NEW
// ─────────────────────────────────────────────────────────────────────────────
app.get('/notifications', authenticateToken, async (req, res) => {
  const {projectId,userId}=req.query;
  try {
    const result=await pool.query(
      `SELECT n.id,n.entity_type AS concept,n.entity_id AS record_id,n.message,n.added_by_id,n.added_by_role,
              COALESCE(nv.viewed_at IS NOT NULL,false) AS read
       FROM notifications n
       LEFT JOIN notification_views nv ON nv.notification_id=n.id AND nv.user_id=$2
       WHERE n.project_id=$1 AND n.added_by_id<>$2 ORDER BY n.id DESC`,
      [projectId,userId]
    );
    res.json({success:true,notifications:result.rows});
  } catch(err){console.error('Fetch notifications error:',err);res.status(500).json({success:false,message:'Server error fetching notifications.'});}
});

app.put('/notifications/:id/read', authenticateToken, async (req, res) => {
  const {id}=req.params;
  const {projectId,userId,userRole}=req.query;
  try {
    await pool.query(`INSERT INTO notification_views (notification_id,project_id,user_id,user_role,viewed_at) VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT DO NOTHING`,[id,projectId,userId,userRole]);
    res.json({success:true,message:'Notification marked as read.'});
  } catch(err){console.error('Mark as read error:',err);res.status(500).json({success:false,message:'Server error.'});}
});

// NEW: unread count for notification badge
app.get('/notifications/unreadCount', authenticateToken, async (req, res) => {
  const {projectId}=req.query;
  const userId=req.user.user_id;
  try {
    const result=await pool.query(
      `SELECT COUNT(*) AS count FROM notifications n
       WHERE n.project_id=$1 AND n.added_by_id<>$2
         AND NOT EXISTS (
           SELECT 1 FROM notification_views nv
           WHERE nv.notification_id=n.id AND nv.user_id=$2
         )`,
      [projectId,userId]
    );
    res.json({success:true,count:parseInt(result.rows[0].count,10)});
  } catch(err){console.error('Unread count error:',err);res.status(500).json({success:false,count:0});}
});

// ─────────────────────────────────────────────────────────────────────────────
//  RECORDS
//  Frontend calls:
//    POST /api/add-record      ← tabs.js record form
//    POST /records/add-record  ← tabs.js meeting minutes
//    POST /records             ← original route (kept for compat)
// ─────────────────────────────────────────────────────────────────────────────

// Shared record-save logic extracted so both /api/add-record and /records can use it
async function handleAddRecord(req, res) {
  try {
    const {user_id:userId,role}=req.user;
    const {title,description,projectId,category,noticeTiedId}=req.body;
    if (!projectId||!title||!category) return res.status(400).json({success:false,message:'projectId, title and category are required'});

    const categoryMap={
      'contractual-legal':            {table:'contractual_records',    type:'contractual'},
      'administrative-instructional': {table:'administrative_records', type:'administrative'},
      'safety-compliance':            {table:'safety_records',         type:'safety'},
      'operational-performance':      {table:'operational_records',    type:'operational'},
      'financial':                    {table:'financial_records',      type:'financial'},
      // tabs.js sends shorthand keys too
      'contractual':                  {table:'contractual_records',    type:'contractual'},
      'administrative':               {table:'administrative_records', type:'administrative'},
      'safety':                       {table:'safety_records',         type:'safety'},
      'operational':                  {table:'operational_records',    type:'operational'},
    };
    const resolved=categoryMap[category];
    if (!resolved) return res.status(400).json({success:false,message:'Invalid category'});

    let filePath=null, attachmentId=null;
    if (req.file) {
      try {
        const r=await new Promise((resolve,reject)=>{
          const stream=cloudinary.uploader.upload_stream(
            {folder:'oneproject/records',resource_type:'auto',public_id:`${Date.now()}-${req.file.originalname.replace(/\s+/g,'-')}`},
            (err,result)=>err?reject(err):resolve(result)
          );
          Readable.from(req.file.buffer).pipe(stream);
        });
        filePath=r.secure_url; attachmentId=r.public_id;
      } catch(uploadErr){console.error('Cloudinary upload error:',uploadErr);return res.status(500).json({success:false,message:'File upload failed'});}
    }

    const recordKind=noticeTiedId?'notice':'new';
    const noticeTied=noticeTiedId?Number(noticeTiedId):null;
    const notifMsg=noticeTiedId?`New notice of determination issued by ${role} (tied to record #${noticeTied})`:`New ${resolved.type} record added by ${role}: "${title}"`;

    const client=await pool.connect();
    try {
      await client.query('BEGIN');
      const recRes=await client.query(
        `INSERT INTO ${resolved.table} (project_id,title,description,file_path,attachment_id,uploaded_by,role,record_kind,notice_tied_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
        [projectId,title,description||null,filePath,attachmentId,userId,role,recordKind,noticeTied]
      );
      const recordId=recRes.rows[0].id;
      const notifRes=await client.query(
        `INSERT INTO notifications (project_id,entity_id,entity_type,message,added_by_id,added_by_role) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
        [projectId,recordId,resolved.type,notifMsg,userId,role]
      );
      await client.query('COMMIT');
      res.json({success:true,message:'Record saved.',recordId,notificationId:notifRes.rows[0].id,attachmentId,recordKind});
    } catch(err){await client.query('ROLLBACK');console.error('Error saving record:',err);res.status(500).json({success:false,message:'Server error saving record'});}
    finally{client.release();}
  } catch(err){console.error('Add record route error:',err);res.status(500).json({success:false,message:'Server error'});}
}

// POST /api/add-record  ← used by tabs.js openAddRecordPanel form submission
app.post('/api/add-record', authenticateToken, upload.single('attachment'), handleAddRecord);

// POST /records  ← original route kept for backward compatibility
app.post('/records', authenticateToken, upload.single('attachment'), handleAddRecord);

// ─── Fetch tab records ────────────────────────────────────────────────────────
app.post('/api/fetch-tab-records', authenticateToken, async (req, res) => {
  const {projectId,category}=req.body;
  const table=TABLE_MAP[category];
  if (!table) return res.status(400).json({error:'Invalid category'});
  try {
    const {rows:records}=await pool.query(
      `SELECT r.id,r.title,r.description,r.file_path,r.issued_date AS date_recorded,r.role AS uploader_role,r.uploaded_by,r.status,r.record_kind,r.notice_tied_id
       FROM ${table} r WHERE r.project_id=$1 AND r.record_kind IN ('new','notice','rejection_notice') ORDER BY r.issued_date DESC`,
      [projectId]
    );
    const userId=req.user.user_id||req.user.id;
    const enriched=await Promise.all(records.map(async rec=>{
      const {rows:reviews}=await pool.query(
        `SELECT reviewer_id,reviewer_role,action,action_date,comment FROM document_reviews WHERE record_type=$1 AND record_id=$2 AND action IN ('approved','accepted','rejected','comment','no_action') ORDER BY action_date ASC`,
        [category,rec.id]
      );
      const isUploader=String(rec.uploaded_by)===String(userId);
      let isViewed=isUploader;
      if (!isUploader){const {rows:viewed}=await pool.query('SELECT 1 FROM document_reviews WHERE record_type=$1 AND record_id=$2 AND reviewer_id=$3 LIMIT 1',[category,rec.id,userId]);isViewed=viewed.length>0;}
      return {...rec,reviews,is_viewed:isViewed};
    }));
    res.json({records:enriched});
  } catch(err){console.error('Fetch tab records error:',err);res.status(500).json({error:'Failed to fetch records'});}
});

// ─── Mark record viewed ───────────────────────────────────────────────────────
app.post('/api/mark-record-viewed', authenticateToken, async (req, res) => {
  const {recordId,category}=req.body;
  const reviewerId=req.user.user_id||req.user.id;
  const reviewerRole=req.user.role;
  if (!TABLE_MAP[category]) return res.status(400).json({error:'Invalid category'});
  try {
    const {rows:rec}=await pool.query(`SELECT uploaded_by FROM ${TABLE_MAP[category]} WHERE id=$1`,[recordId]);
    if (rec.length>0&&String(rec[0].uploaded_by)===String(reviewerId)) return res.json({success:true,skipped:true});
    await pool.query(`INSERT INTO document_reviews (record_type,record_id,record_kind,reviewer_id,reviewer_role,action) VALUES ($1,$2,'new',$3,$4,'no_action') ON CONFLICT (record_type,record_id,reviewer_id) DO NOTHING`,[category,recordId,reviewerId,reviewerRole]);
    res.json({success:true});
  } catch(err){console.error('Mark viewed error:',err);res.status(500).json({error:'Failed to mark as viewed.'});}
});

// ─── Review record ────────────────────────────────────────────────────────────
app.post('/api/review-record', authenticateToken, async (req, res) => {
  const { projectId, recordId, category, action, comment, actorType } = req.body;
  const reviewerId   = req.user.user_id || req.user.id;
  const reviewerRole = req.user.role;
  const table        = TABLE_MAP[category];
  if (!table) return res.status(400).json({ error: 'Invalid category' });

  // Allowed workflow actions in the DB constraint
  const workflowActions = ['approved', 'accepted', 'rejected'];
  const isComment       = action === 'comment';
  const isWorkflow      = workflowActions.includes(action);

  if (!isWorkflow && !isComment)
    return res.status(400).json({ error: 'Invalid action.' });

  // Decision makers do workflow; team members do action col without status change
  const isDecisionMakerActor = isDecisionMaker(reviewerRole) && actorType !== 'team_member';

  // Team members and non-decision-makers cannot trigger status changes
  if (isWorkflow && !isDecisionMakerActor && !isDecisionMaker(reviewerRole))
    return res.status(403).json({ error: 'Only decision makers can run workflow actions.' });

  try {
    const { rows: existing } = await pool.query(
      'SELECT id, action, comment FROM document_reviews WHERE record_type=$1 AND record_id=$2 AND reviewer_id=$3 LIMIT 1',
      [category, recordId, reviewerId]
    );

    if (isComment) {
      // Save/update comment text only — never changes action or record status
      if (!comment?.trim()) return res.status(400).json({ error: 'Comment text is required.' });
      if (existing.length > 0) {
        await pool.query(
          'UPDATE document_reviews SET comment=$1, action_date=NOW() WHERE id=$2',
          [comment.trim(), existing[0].id]
        );
      } else {
        // Insert with action='no_action' — satisfies DB constraint, comment stored separately
        await pool.query(
          `INSERT INTO document_reviews (record_type, record_id, record_kind, reviewer_id, reviewer_role, action, comment)
           VALUES ($1, $2, 'new', $3, $4, 'no_action', $5)`,
          [category, recordId, reviewerId, reviewerRole, comment.trim()]
        );
      }
      return res.json({ success: true, message: 'Comment saved.' });
    }

    // ── Workflow / team action ──
    if (existing.length > 0) {
      // Prevent double workflow actions from decision makers
      if (isDecisionMakerActor && workflowActions.includes(existing[0].action)) {
        return res.status(409).json({ error: `You already ${existing[0].action} this record.` });
      }
      await pool.query(
        'UPDATE document_reviews SET action=$1, action_date=NOW() WHERE id=$2',
        [action, existing[0].id]
      );
    } else {
      await pool.query(
        `INSERT INTO document_reviews (record_type, record_id, record_kind, reviewer_id, reviewer_role, action)
         VALUES ($1, $2, 'new', $3, $4, $5)`,
        [category, recordId, reviewerId, reviewerRole, action]
      );
    }

    // ── Update record status — ONLY for decision maker workflow actions ──
    if (isDecisionMakerActor) {
      const { rows: recRows } = await pool.query(
        `SELECT role FROM ${table} WHERE id=$1 AND project_id=$2`,
        [recordId, projectId]
      );
      if (!recRows.length) return res.status(404).json({ error: 'Record not found.' });

      const uploaderSide = getSide(recRows[0].role);
      let newStatus;
      if (action === 'rejected') {
        newStatus = 'rejected';
      } else if (action === 'accepted') {
        newStatus = 'approved_record';
      } else {
        // 'approved' — step 1 done, advance to step 2 pending
        const step2Map = {
          contractor: 'pending_client_acceptance',
          consultant: 'pending_contractor_acceptance',
          client:     'pending_contractor_acceptance',
        };
        newStatus = step2Map[uploaderSide] || 'pending_review';
      }

      await pool.query(
        `UPDATE ${table} SET status=$1 WHERE id=$2 AND project_id=$3`,
        [newStatus, recordId, projectId]
      );
    }
    // Team member actions: action column updated above, status column untouched

    res.json({ success: true, message: `Action '${action}' recorded successfully.` });
  } catch (err) {
    console.error('Review record error:', err);
    res.status(500).json({ error: 'Failed to process review.' });
  }
});

// ─── Download file ────────────────────────────────────────────────────────────
app.get('/api/download-file', authenticateToken, async (req, res) => {
  const {recordId,category}=req.query;
  const table=TABLE_MAP[category];
  if (!table) return res.status(400).json({error:'Invalid category'});
  try {
    const {rows}=await pool.query(`SELECT file_path FROM ${table} WHERE id=$1`,[recordId]);
    if (!rows.length||!rows[0].file_path) return res.status(404).json({error:'File not found.'});
    const filePath=rows[0].file_path;
    const fileName=filePath.split('/').pop()||'download';
    if (filePath.startsWith('http')) return res.json({url:filePath,fileName});
    res.status(404).json({error:'File not accessible.'});
  } catch(err){console.error('Download file error:',err);res.status(500).json({error:'Failed to download file.'});}
});

// ─── Delete record ────────────────────────────────────────────────────────────
app.delete('/api/delete-record', authenticateToken, async (req, res) => {
  const {projectId,recordId,category}=req.body;
  const userId=req.user.user_id||req.user.id;
  const table=TABLE_MAP[category];
  if (!table) return res.status(400).json({error:'Invalid category'});
  try {
    const {rows}=await pool.query(`SELECT uploaded_by FROM ${table} WHERE id=$1 AND project_id=$2`,[recordId,projectId]);
    if (!rows.length) return res.status(404).json({error:'Record not found.'});
    if (String(rows[0].uploaded_by)!==String(userId)) return res.status(403).json({error:'Only the uploader can delete this record.'});
    await pool.query('DELETE FROM document_reviews WHERE record_type=$1 AND record_id=$2',[category,recordId]);
    await pool.query('DELETE FROM notifications WHERE entity_id=$1 AND entity_type=$2',[recordId,category]);
    await pool.query(`DELETE FROM ${table} WHERE id=$1 AND project_id=$2`,[recordId,projectId]);
    res.json({success:true,message:'Record deleted successfully.'});
  } catch(err){console.error('Delete record error:',err);res.status(500).json({error:'Failed to delete record.'});}
});

// ─────────────────────────────────────────────────────────────────────────────
//  MEETING ROUTES
//  Frontend calls:
//    POST /records/schedule-meeting
//    POST /records/meetings
//    POST /records/meeting-detail
//    POST /records/add-record  (meeting minutes)
// ─────────────────────────────────────────────────────────────────────────────

// POST /records/schedule-meeting
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

// POST /records/meetings
app.post('/records/meetings', authenticateToken, async (req, res) => {
  const {projectId,type}=req.body;  // type: 'minutes' | 'scheduled'
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

// POST /records/meeting-detail
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

// POST /records/add-record  ← meeting minutes
app.post('/records/add-record', authenticateToken, upload.array('documents', 5), async (req, res) => {
  const {title,details,projectId,category,date}=req.body;
  if (!title||!details||!projectId) return res.status(400).json({success:false,message:'title, details and projectId are required.'});
  try {
    // Upload any attached files to Cloudinary
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

// ─────────────────────────────────────────────────────────────────────────────
//  SCHEDULE MODULE
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/get-schedule  — returns baseline + extension milestones
app.get('/api/get-schedule', authenticateToken, async (req, res) => {
  const projectId=parseInt(req.query.projectId,10);
  if (!projectId) return res.status(400).json({error:'Valid integer projectId is required'});
  try {
    const schedRow=await pool.query('SELECT * FROM project_schedules WHERE project_id=$1 LIMIT 1',[projectId]);
    if (!schedRow.rows.length) return res.json({schedule:null});
    const sched=schedRow.rows[0];

    // Baseline milestones
    const msRows=await pool.query(
      `SELECT m.*,
         COALESCE(json_agg(json_build_object('date',e.report_date,'qty',e.qty_executed,'remarks',e.remarks,'cumulative',e.cumulative_after_entry) ORDER BY e.report_date) FILTER (WHERE e.id IS NOT NULL),'[]') AS entries,
         COALESCE(json_agg(DISTINCT jsonb_build_object('fileName',a.file_name,'url',a.cloudinary_url,'publicId',a.cloudinary_public_id)) FILTER (WHERE a.id IS NOT NULL),'[]') AS attachments
       FROM milestones m
       LEFT JOIN milestone_progress_entries e ON e.milestone_id=m.id
       LEFT JOIN milestone_attachments a ON a.milestone_id=m.id
       WHERE m.schedule_id=$1 GROUP BY m.id ORDER BY m.sort_order`,
      [sched.id]
    );

    // Extension (additional) milestones
    const amRows=await pool.query(
      `SELECT am.*,
         COALESCE(json_agg(json_build_object('date',e.report_date,'qty',e.qty_executed,'remarks',e.remarks,'cumulative',e.cumulative_after_entry) ORDER BY e.report_date) FILTER (WHERE e.id IS NOT NULL),'[]') AS entries,
         COALESCE(json_agg(DISTINCT jsonb_build_object('fileName',a.file_name,'url',a.cloudinary_url)) FILTER (WHERE a.id IS NOT NULL),'[]') AS attachments
       FROM additional_milestones am
       LEFT JOIN additional_milestone_progress_entries e ON e.additional_milestone_id=am.id
       LEFT JOIN additional_milestone_attachments a ON a.additional_milestone_id=am.id
       WHERE am.schedule_id=$1 GROUP BY am.id ORDER BY am.sort_order`,
      [sched.id]
    );

    const mapMs=(ms,isExt)=>({
      id:ms.id, title:ms.title, description:ms.description,
      start:ms.planned_start, end:ms.planned_end,
      quantity:ms.quantity, unit:ms.unit,
      dep:ms.depends_on||ms.depends_on_baseline||'None',
      weight_pct:ms.weight_pct, float_days:ms.float_days, is_critical:ms.is_critical,
      executed:ms.executed, progress_pct:ms.progress_pct,
      activity_status:ms.activity_status, completed_at:ms.completed_at,
      entries:ms.entries,
      fileName:ms.attachments?.[0]?.fileName||null,
      attachmentUrl:ms.attachments?.[0]?.url||null,
      isExtension:isExt,
    });

    res.json({
      schedule:{
        id:sched.id,
        timeline:{start:sched.planned_start,finish:sched.planned_finish,duration:sched.total_duration},
        milestones:           msRows.rows.map(ms=>mapMs(ms,false)),
        extension_milestones: amRows.rows.map(ms=>mapMs(ms,true)),
      },
    });
  } catch(err){console.error('[GET /api/get-schedule]',err);res.status(500).json({error:'Failed to load schedule'});}
});

// POST /api/save-schedule
app.post('/api/save-schedule', authenticateToken, upload.any(), async (req, res) => {
  const projectId=parseInt(req.body.projectId,10);
  if (!projectId) return res.status(400).json({error:'Valid integer projectId is required'});
  let tl,rawMilestones;
  try{tl=JSON.parse(req.body.timeline);rawMilestones=JSON.parse(req.body.milestones);}
  catch{return res.status(400).json({error:'Invalid JSON in timeline or milestones'});}
  const fileMap={};
  (req.files||[]).forEach(f=>{fileMap[f.fieldname.replace(/^file_/,'')]=f;});
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const schedRes=await client.query(
      `INSERT INTO project_schedules (project_id,planned_start,planned_finish,total_duration,created_by_user_id,created_by_role)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (project_id) DO UPDATE SET planned_start=EXCLUDED.planned_start,planned_finish=EXCLUDED.planned_finish,total_duration=EXCLUDED.total_duration,updated_at=now()
       RETURNING *`,
      [projectId,tl.start,tl.finish,tl.duration,req.user.user_id,req.user.role]
    );
    const schedId=schedRes.rows[0].id;
    await client.query('DELETE FROM milestones WHERE schedule_id=$1',[schedId]);
    const totalDur=rawMilestones.reduce((sum,ms)=>sum+Math.max(1,daysBetween(ms.start,ms.end)),0);
    const tempToReal={};
    const insertedMs=[];
    for (let i=0;i<rawMilestones.length;i++) {
      const ms=rawMilestones[i];
      const dur=Math.max(1,daysBetween(ms.start,ms.end));
      const floatD=Math.max(0,daysBetween(ms.end,tl.finish));
      const weight=totalDur>0?(dur/totalDur)*100:0;
      const depId=ms.dep&&ms.dep!=='None'&&tempToReal[ms.dep]?tempToReal[ms.dep]:null;
      const msRes=await client.query(
        `INSERT INTO milestones (schedule_id,project_id,title,description,sort_order,planned_start,planned_end,duration_days,float_days,is_critical,weight_pct,quantity,unit,depends_on,created_by_user_id,created_by_role)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *`,
        [schedId,projectId,ms.title,ms.desc||ms.description||null,i,ms.start,ms.end,dur,floatD,floatD===0,weight.toFixed(2),parseFloat(ms.qty||ms.quantity)||0,ms.unit||null,depId,req.user.user_id,req.user.role]
      );
      const realId=msRes.rows[0].id;
      tempToReal[ms.id]=realId;
      insertedMs.push({...msRes.rows[0],tempId:ms.id});
    }
    for (const ms of insertedMs) {
      const file=fileMap[ms.tempId];
      if (!file) continue;
      try {
        const cdResult=await scheduleCloudinaryUpload(file.buffer,file.originalname,`oneprojectapp/schedules/${projectId}/milestones`);
        await client.query(
          `INSERT INTO milestone_attachments (milestone_id,file_name,file_size,mime_type,cloudinary_public_id,cloudinary_url,uploaded_by_user_id,uploaded_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [ms.id,file.originalname,file.size,file.mimetype,cdResult.public_id,cdResult.secure_url,req.user.user_id,req.user.role]
        );
      } catch(cdErr){console.error('Cloudinary upload failed for milestone',ms.id,cdErr);}
    }
    await client.query('COMMIT');
    const freshMs=await pool.query(
      `SELECT m.*,'[]'::json AS entries,
         COALESCE(json_agg(DISTINCT jsonb_build_object('fileName',a.file_name,'url',a.cloudinary_url)) FILTER (WHERE a.id IS NOT NULL),'[]') AS attachments
       FROM milestones m LEFT JOIN milestone_attachments a ON a.milestone_id=m.id
       WHERE m.schedule_id=$1 GROUP BY m.id ORDER BY m.sort_order`,
      [schedId]
    );
    res.json({
      success:true,
      schedule:{
        id:schedId,
        timeline:{start:tl.start,finish:tl.finish,duration:tl.duration},
        milestones:freshMs.rows.map(ms=>({id:ms.id,title:ms.title,description:ms.description,start:ms.planned_start,end:ms.planned_end,quantity:ms.quantity,unit:ms.unit,dep:ms.depends_on||'None',weight_pct:ms.weight_pct,float_days:ms.float_days,is_critical:ms.is_critical,executed:ms.executed,progress_pct:ms.progress_pct,activity_status:ms.activity_status,entries:[],fileName:ms.attachments?.[0]?.fileName||null,attachmentUrl:ms.attachments?.[0]?.url||null})),
        extension_milestones:[],
      },
    });
  } catch(err){await client.query('ROLLBACK');console.error('[POST /api/save-schedule]',err);res.status(500).json({error:'Failed to save schedule'});}
  finally{client.release();}
});

// POST /api/report-progress  — baseline milestones
app.post('/api/report-progress', authenticateToken, upload.single('attachment'), async (req, res) => {
  const projectId=parseInt(req.body.projectId,10);
  const {milestoneId,reportDate,remarks}=req.body;
  const qty=parseFloat(req.body.qtyExecuted);
  if (!projectId||!milestoneId||!reportDate||!qty||qty<=0)
    return res.status(400).json({error:'Valid projectId, milestoneId, reportDate and positive qtyExecuted are required'});
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const msRes=await client.query('SELECT * FROM milestones WHERE id=$1 AND project_id=$2 FOR UPDATE',[milestoneId,projectId]);
    if (!msRes.rows.length) return res.status(404).json({error:'Milestone not found'});
    const ms=msRes.rows[0];
    if (ms.activity_status==='completed') return res.status(409).json({error:'Milestone is already completed'});
    const planned=parseFloat(ms.quantity)||0, prevExec=parseFloat(ms.executed)||0, newExecuted=prevExec+qty;
    if (planned>0&&newExecuted>planned) return res.status(422).json({error:`Cannot exceed planned quantity. Remaining: ${(planned-prevExec).toFixed(3)} ${ms.unit||''}`});
    const newPct=planned>0?Math.min(100,(newExecuted/planned)*100):0;
    const entryRes=await client.query(
      `INSERT INTO milestone_progress_entries (milestone_id,project_id,report_date,qty_executed,cumulative_after_entry,progress_pct_after_entry,remarks,reported_by_user_id,reported_by_role)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (milestone_id,report_date) DO UPDATE SET
         qty_executed=milestone_progress_entries.qty_executed+EXCLUDED.qty_executed,
         cumulative_after_entry=EXCLUDED.cumulative_after_entry,
         progress_pct_after_entry=EXCLUDED.progress_pct_after_entry,
         remarks=COALESCE(EXCLUDED.remarks,milestone_progress_entries.remarks),
         reported_by_user_id=EXCLUDED.reported_by_user_id,reported_by_role=EXCLUDED.reported_by_role
       RETURNING *`,
      [milestoneId,projectId,reportDate,qty,newExecuted,newPct.toFixed(2),remarks||null,req.user.user_id,req.user.role]
    );
    await client.query(`UPDATE milestones SET executed=$1,progress_pct=$2,activity_status='in_progress',updated_at=now() WHERE id=$3`,[newExecuted,newPct.toFixed(2),milestoneId]);
    if (req.file) {
      try {
        const cdResult=await scheduleCloudinaryUpload(req.file.buffer,req.file.originalname,`oneprojectapp/schedules/${projectId}/progress`);
        await client.query(`INSERT INTO progress_entry_attachments (progress_entry_id,file_name,file_size,mime_type,cloudinary_public_id,cloudinary_url,uploaded_by_user_id,uploaded_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,[entryRes.rows[0].id,req.file.originalname,req.file.size,req.file.mimetype,cdResult.public_id,cdResult.secure_url,req.user.user_id,req.user.role]);
      } catch(cdErr){console.error('Progress attachment upload failed:',cdErr);}
    }
    await client.query('COMMIT');
    const allEntries=await pool.query(`SELECT report_date AS date,qty_executed AS qty,remarks,cumulative_after_entry AS cumulative FROM milestone_progress_entries WHERE milestone_id=$1 ORDER BY report_date`,[milestoneId]);
    res.json({success:true,milestone:{id:milestoneId,executed:newExecuted,progress_pct:parseFloat(newPct.toFixed(2)),activity_status:'in_progress',entries:allEntries.rows}});
  } catch(err){await client.query('ROLLBACK');console.error('[POST /api/report-progress]',err);res.status(500).json({error:'Failed to save progress entry'});}
  finally{client.release();}
});

// POST /api/complete-milestone
app.post('/api/complete-milestone', authenticateToken, async (req, res) => {
  const projectId=parseInt(req.body.projectId,10);
  const {milestoneId,isExtensionMilestone}=req.body;
  if (!projectId||!milestoneId) return res.status(400).json({error:'Valid projectId and milestoneId are required'});
  const isExt=isExtensionMilestone===true||isExtensionMilestone==='true';
  const table=isExt?'additional_milestones':'milestones';
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const msRes=await client.query(`SELECT * FROM ${table} WHERE id=$1 AND project_id=$2 FOR UPDATE`,[milestoneId,projectId]);
    if (!msRes.rows.length) return res.status(404).json({error:'Milestone not found'});
    const ms=msRes.rows[0];
    if (ms.activity_status==='completed') return res.status(409).json({error:'Milestone is already completed'});
    const planned=parseFloat(ms.quantity)||0, exec=parseFloat(ms.executed)||0;
    if (planned>0&&exec<planned) return res.status(422).json({error:`Cannot complete: only ${exec} of ${planned} ${ms.unit||''} executed`});
    await client.query(`UPDATE ${table} SET activity_status='completed',progress_pct=100,completed_at=now(),updated_at=now() WHERE id=$1`,[milestoneId]);
    await client.query('COMMIT');
    res.json({success:true,completedAt:new Date().toISOString()});
  } catch(err){await client.query('ROLLBACK');console.error('[POST /api/complete-milestone]',err);res.status(500).json({error:'Failed to complete milestone'});}
  finally{client.release();}
});

// POST /api/save-extension
app.post('/api/save-extension', authenticateToken, upload.any(), async (req, res) => {
  const projectId=parseInt(req.body.projectId,10);
  if (!projectId) return res.status(400).json({error:'Valid integer projectId is required'});
  const extensionDays=parseInt(req.body.extensionDays,10);
  const newPlannedFinish=req.body.newPlannedFinish;
  const reason=(req.body.reason||'').trim();
  const extensionType=req.body.extensionType;
  const scopeType=req.body.scopeType;
  let newMilestones=[];
  try{newMilestones=JSON.parse(req.body.newMilestones||'[]');}
  catch{return res.status(400).json({error:'Invalid JSON in newMilestones'});}
  if (!extensionDays||extensionDays<1) return res.status(400).json({error:'extensionDays must be a positive integer'});
  if (!newPlannedFinish) return res.status(400).json({error:'newPlannedFinish is required'});
  if (!reason) return res.status(400).json({error:'reason is required'});
  if (!['delay','scope_addition','force_majeure'].includes(extensionType)) return res.status(400).json({error:'Invalid extensionType'});
  const fileMap={};
  (req.files||[]).forEach(f=>{const m=f.fieldname.match(/^extFile_(\d+)$/);if(m)fileMap[parseInt(m[1],10)]=f;});
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const schedRes=await client.query('SELECT id,planned_finish FROM project_schedules WHERE project_id=$1 LIMIT 1',[projectId]);
    if (!schedRes.rows.length) return res.status(404).json({error:'No schedule found for this project'});
    const scheduleId=schedRes.rows[0].id;
    const extRes=await client.query(
      `INSERT INTO schedule_extensions (schedule_id,project_id,extension_days,new_planned_finish,reason,extension_type,requested_by_user_id,requested_by_role)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [scheduleId,projectId,extensionDays,newPlannedFinish,reason,extensionType,req.user.user_id,req.user.role]
    );
    const extensionId=extRes.rows[0].id;
    await client.query(`UPDATE project_schedules SET planned_finish=$1,updated_at=now() WHERE id=$2`,[newPlannedFinish,scheduleId]);
    const insertedAdditional=[];
    if (scopeType==='new'&&newMilestones.length>0) {
      for (let i=0;i<newMilestones.length;i++) {
        const ms=newMilestones[i];
        const dur=Math.max(1,daysBetween(ms.start,ms.end));
        const floatD=Math.max(0,Math.round((new Date(newPlannedFinish)-new Date(ms.end))/86400000));
        const depBaselineId=(ms.dep&&ms.dep!=='None')?ms.dep:null;
        const amRes=await client.query(
          `INSERT INTO additional_milestones (schedule_id,project_id,schedule_extension_id,title,description,sort_order,planned_start,planned_end,duration_days,float_days,is_critical,weight_pct,quantity,unit,depends_on_baseline,added_by_user_id,added_by_role)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING id`,
          [scheduleId,projectId,extensionId,ms.title,ms.desc||ms.description||null,i,ms.start,ms.end,dur,floatD,floatD===0,0,parseFloat(ms.qty||ms.quantity)||0,ms.unit||null,depBaselineId,req.user.user_id,req.user.role]
        );
        const additionalId=amRes.rows[0].id;
        insertedAdditional.push({id:additionalId,index:i,ms});
        const file=fileMap[i];
        if (file) {
          try {
            const cdResult=await scheduleCloudinaryUpload(file.buffer,file.originalname,`oneprojectapp/schedules/${projectId}/additional`);
            await client.query(`INSERT INTO additional_milestone_attachments (additional_milestone_id,file_name,file_size,mime_type,cloudinary_public_id,cloudinary_url,uploaded_by_user_id,uploaded_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,[additionalId,file.originalname,file.size,file.mimetype,cdResult.public_id,cdResult.secure_url,req.user.user_id,req.user.role]);
          } catch(cdErr){console.error('Cloudinary upload failed for additional milestone',additionalId,cdErr);}
        }
      }
    }
    await client.query('COMMIT');
    res.json({success:true,extension:{id:extensionId,extensionDays,newPlannedFinish,reason,extensionType,status:'pending',newMilestonesAdded:insertedAdditional.length}});
  } catch(err){await client.query('ROLLBACK');console.error('[POST /api/save-extension]',err);res.status(500).json({error:'Failed to save extension'});}
  finally{client.release();}
});

// POST /api/report-additional-progress  — extension milestones
app.post('/api/report-additional-progress', authenticateToken, upload.single('attachment'), async (req, res) => {
  const projectId=parseInt(req.body.projectId,10);
  const {milestoneId,reportDate,remarks}=req.body;
  const qty=parseFloat(req.body.qtyExecuted);
  if (!projectId||!milestoneId||!reportDate||!qty||qty<=0)
    return res.status(400).json({error:'Valid projectId, milestoneId, reportDate and positive qtyExecuted are required'});
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const msRes=await client.query('SELECT * FROM additional_milestones WHERE id=$1 AND project_id=$2 FOR UPDATE',[milestoneId,projectId]);
    if (!msRes.rows.length) return res.status(404).json({error:'Additional milestone not found'});
    const ms=msRes.rows[0];
    if (ms.activity_status==='completed') return res.status(409).json({error:'Milestone is already completed'});
    const planned=parseFloat(ms.quantity)||0, prevExec=parseFloat(ms.executed)||0, newExecuted=prevExec+qty;
    if (planned>0&&newExecuted>planned) return res.status(422).json({error:`Cannot exceed planned quantity. Remaining: ${(planned-prevExec).toFixed(3)} ${ms.unit||''}`});
    const newPct=planned>0?Math.min(100,(newExecuted/planned)*100):0;
    const entryRes=await client.query(
      `INSERT INTO additional_milestone_progress_entries (additional_milestone_id,project_id,report_date,qty_executed,cumulative_after_entry,progress_pct_after_entry,remarks,reported_by_user_id,reported_by_role)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (additional_milestone_id,report_date) DO UPDATE SET
         qty_executed=additional_milestone_progress_entries.qty_executed+EXCLUDED.qty_executed,
         cumulative_after_entry=EXCLUDED.cumulative_after_entry,
         progress_pct_after_entry=EXCLUDED.progress_pct_after_entry,
         remarks=COALESCE(EXCLUDED.remarks,additional_milestone_progress_entries.remarks),
         reported_by_user_id=EXCLUDED.reported_by_user_id,reported_by_role=EXCLUDED.reported_by_role
       RETURNING id`,
      [milestoneId,projectId,reportDate,qty,newExecuted,newPct.toFixed(2),remarks||null,req.user.user_id,req.user.role]
    );
    await client.query(`UPDATE additional_milestones SET executed=$1,progress_pct=$2,activity_status='in_progress',updated_at=now() WHERE id=$3`,[newExecuted,newPct.toFixed(2),milestoneId]);
    if (req.file) {
      try {
        const cdResult=await scheduleCloudinaryUpload(req.file.buffer,req.file.originalname,`oneprojectapp/schedules/${projectId}/additional-progress`);
        await client.query(`INSERT INTO additional_milestone_attachments (additional_milestone_id,file_name,file_size,mime_type,cloudinary_public_id,cloudinary_url,uploaded_by_user_id,uploaded_by_role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,[milestoneId,req.file.originalname,req.file.size,req.file.mimetype,cdResult.public_id,cdResult.secure_url,req.user.user_id,req.user.role]);
      } catch(cdErr){console.error('Progress attachment upload failed:',cdErr);}
    }
    await client.query('COMMIT');
    const allEntries=await pool.query(`SELECT report_date AS date,qty_executed AS qty,remarks,cumulative_after_entry AS cumulative FROM additional_milestone_progress_entries WHERE additional_milestone_id=$1 ORDER BY report_date`,[milestoneId]);
    res.json({success:true,milestone:{id:milestoneId,executed:newExecuted,progress_pct:parseFloat(newPct.toFixed(2)),activity_status:'in_progress',entries:allEntries.rows}});
  } catch(err){await client.query('ROLLBACK');console.error('[POST /api/report-additional-progress]',err);res.status(500).json({error:'Failed to save additional progress entry'});}
  finally{client.release();}
});

// ─────────────────────────────────────────────────────────────────────────────
//  GLOBAL ERROR HANDLER
// ─────────────────────────────────────────────────────────────────────────────
app.use((err,_req,res,_next)=>{
  console.error('Unexpected error:',err);
  res.status(500).json({error:'Internal server error'});
});

// ─────────────────────────────────────────────────────────────────────────────
//  START
// ─────────────────────────────────────────────────────────────────────────────
const PORT=process.env.PORT||3000;
app.listen(PORT,()=>console.log(`Backend running on port ${PORT}`));

setInterval(()=>{
  fetch('https://oneprojectapp-backend.onrender.com/')
    .then(r=>console.log('Keep-alive ping:',r.status))
    .catch(err=>console.error('Keep-alive error:',err));
},14*60*1000);

export default app;