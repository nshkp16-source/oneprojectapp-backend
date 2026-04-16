// server.js
import express from 'express';
import multer from "multer";
import { Pool } from 'pg';
import nodemailer from 'nodemailer';
import cors from 'cors';
import nodemailerSendgrid from 'nodemailer-sendgrid';
import fetch from "node-fetch";
import pkg from 'uuid';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from "crypto";

const { v4: uuidv4 } = pkg;

const app = express();
app.use(express.json());
app.use(cors());

// ✅ Multer setup
const upload = multer({
  limits: { fileSize: 500 * 1024 },
  storage: multer.diskStorage({
    destination: "uploads/",
    filename: (req, file, cb) => {
      cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "-"));
    }
  })
});

// ✅ Serve uploads folder publicly
app.use("/uploads", express.static("uploads"));

// ✅ JWT middleware (corrected)
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {   // <-- changed here
    if (err) {
      console.error("JWT verification error:", err);
      return res.status(403).json({ error: "Invalid or expired token" });
    }

    // Attach decoded payload to request
    req.user = {
      user_id: decoded.sub,   // JWT "sub" is the user id
      role: decoded.role,
      // Use company_email for Clients, email for others
      email: decoded.companyEmail || decoded.email
    };

    next();
  });
}

// 🔹 Neon DB connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// 🔹 SendGrid setup
const transporter = nodemailer.createTransport(
  nodemailerSendgrid({ apiKey: process.env.SENDGRID_API_KEY })
);

// -------------------- ROUTES --------------------
// Root route
app.get('/', (req, res) => {
  res.send('Backend is running successfully!');
});

// 1. Finalize Account (send verification only)
app.post("/finalize-account", async (req, res) => {
  const { clientEmail } = req.body;

  try {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = uuidv4();

    await pool.query(
      `INSERT INTO email_tokens 
       (email, token, expires_at, attempts, session_id, verified, pending_password, reset_flow, created_at, project_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',0,$3,false,false,false,NOW(),false)`,
      [clientEmail, code, sessionId]
    );

    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: clientEmail,
      subject: "Verify your OneProjectApp account",
      html: `<p>Your verification code is: <b>${code}</b></p>
             <p>This code will expire in 3 minutes.</p>`
    });

    res.json({ success: true, message: "Verification email sent.", sessionId });
  } catch (err) {
    console.error("Finalize error:", err);
    res.status(500).json({ success: false, error: "Server error finalizing account." });
  }
});

// 2. Verify Code (only mark token verified)
app.post("/verify-code", async (req, res) => {
  const { email, code } = req.body;

  try {
    const result = await pool.query(
      `SELECT * FROM email_tokens 
       WHERE email=$1 AND token=$2 AND expires_at > NOW() AND verified=false
       ORDER BY expires_at DESC LIMIT 1`,
      [email, code]
    );

    if (result.rows.length === 0) {
      return res.json({ success: false, verified: false, error: "Invalid or expired code." });
    }

    // ✅ Mark token as verified
    await pool.query(`UPDATE email_tokens SET verified=true WHERE id=$1`, [
      result.rows[0].id
    ]);

    return res.json({
      success: true,
      verified: true,
      message: "Verification successful. You may now commit account data."
    });
  } catch (err) {
    console.error("Verification error:", err.message);
    res.status(500).json({ success: false, verified: false, error: "Server error verifying code." });
  }
});

// 3. Commit Account (save client, project, role users, assignments)
app.post("/commit-account", async (req, res) => {
  const { client, project, contractor, consultant, teamMember, contractorPM, consultantPM } = req.body;

  try {
    const hashedPassword = client.password_hash
      ? await bcrypt.hash(client.password_hash, 10)
      : null;

    const clientResult = await pool.query(
      `INSERT INTO clients (company_name, company_email, representative, title, telephone, password_hash, verified, created_at, profile_picture) 
       VALUES ($1,$2,$3,$4,$5,$6,true,NOW(),$7)
       ON CONFLICT (company_email) DO UPDATE SET 
         company_name=EXCLUDED.company_name,
         representative=EXCLUDED.representative,
         title=EXCLUDED.title,
         telephone=EXCLUDED.telephone,
         password_hash=EXCLUDED.password_hash,
         profile_picture=EXCLUDED.profile_picture,
         verified=true
       RETURNING id, company_email;`,
      [
        client.company_name,
        client.company_email,
        client.representative,
        client.title,
        client.telephone,
        hashedPassword,
        client.profile_picture || null
      ]
    );
    const client_id = clientResult.rows[0].id;

    const projectResult = await pool.query(
      `INSERT INTO projects (name, location, contract_reference, client_id, created_at)
       VALUES ($1,$2,$3,$4,NOW())
       ON CONFLICT (name, client_id) DO NOTHING RETURNING id;`,
      [project.name, project.location, project.contract_reference, client_id]
    );

    let project_id =
      projectResult.rows[0]?.id ||
      (
        await pool.query(
          `SELECT id FROM projects WHERE name=$1 AND client_id=$2`,
          [project.name, client_id]
        )
      ).rows[0].id;

    async function addRoleUser(user, tableName, assignmentTable, fkColumn) {
      if (!user?.email) return;

      const existing = await pool.query(
        `SELECT id FROM ${tableName} WHERE email=$1`,
        [user.email]
      );

      let role_id;
      if (existing.rows.length > 0) {
        role_id = existing.rows[0].id;
      } else {
        const roleResult = await pool.query(
          `INSERT INTO ${tableName} (email, password_hash, verified, profile_picture, created_at)
           VALUES ($1,$2,true,$3,NOW())
           RETURNING id;`,
          [user.email, user.password_hash || null, user.profile_picture || null]
        );
        role_id = roleResult.rows[0].id;
      }

      await pool.query(
        `INSERT INTO ${assignmentTable} (project_id, ${fkColumn}, company_name, title, position, telephone, task, representative, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
         ON CONFLICT (project_id, ${fkColumn}) DO NOTHING;`,
        [
          project_id,
          role_id,
          user.company_name || null,
          user.title || null,
          user.position || null,
          user.telephone || null,
          user.task || null,
          user.representative || null
        ]
      );
    }

    await addRoleUser(contractor, "contractors", "contractor_assignments", "contractor_id");
    await addRoleUser(consultant, "consultants", "consultant_assignments", "consultant_id");
    await addRoleUser(teamMember, "team_members", "team_member_assignments", "team_member_id");
    await addRoleUser(contractorPM, "contractor_project_managers", "contractor_pm_assignments", "contractor_pm_id");
    await addRoleUser(consultantPM, "consultant_project_managers", "consultant_pm_assignments", "consultant_pm_id");

    // ✅ Generate JWT for client
    const SECRET = process.env.JWT_SECRET || "supersecretkey";
    const payload = {
      sub: client_id,
      companyEmail: clientResult.rows[0].company_email,
      role: "Client",
      projects: [project_id]
    };

    const accessToken = jwt.sign(payload, SECRET, { expiresIn: "15m" });

    const refreshToken = crypto.randomBytes(64).toString("hex");
    await pool.query(
      `INSERT INTO refresh_tokens (user_id, role, token, expires_at)
       VALUES ($1, $2, $3, NOW() + interval '24 hours')`,
      [client_id, "Client", refreshToken]
    );

    return res.json({
      success: true,
      message: "Account, project, and assignments saved successfully.",
      clientId: client_id,
      projectId: project_id,
      accessToken,
      refreshToken
    });
  } catch (err) {
    console.error("Commit error:", err.message);
    res.status(500).json({ success: false, error: "Server error committing account." });
  }
});

// 3. Resend Verification (replace old token with new one)
app.post("/resend-verification", async (req, res) => {
  const { email } = req.body;
  try {
    // Delete old unverified tokens for this email
    await pool.query(
      `DELETE FROM email_tokens WHERE email=$1 AND verified=false`,
      [email]
    );

    // Generate new code and session
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = uuidv4();

    // Insert new token
    await pool.query(
      `INSERT INTO email_tokens 
       (email, token, expires_at, attempts, session_id, verified, pending_password, reset_flow, created_at, project_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',0,$3,false,false,false,NOW(),false)`,
      [email, code, sessionId]
    );

    // Send new verification email
    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: "Resend Verification Code - OneProjectApp",
      html: `<p>Your new verification code is: <b>${code}</b></p>
             <p>This code will expire in 3 minutes.</p>`
    });

    res.json({ success: true, message: "Verification code resent.", sessionId });
  } catch (err) {
    console.error("Resend error:", err.message);
    res.status(500).json({ success: false, error: "Failed to resend verification." });
  }
});

// 4. First Login (send verification code only)
app.post("/firstlogin-send", async (req, res) => {
  const { email } = req.body;
  try {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = uuidv4();

    await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, session_id, verified, reset_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',$3,false,false)`,
      [email, code, sessionId]
    );

    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: "OneProjectApp Verification Code",
      html: `<p>Your verification code is: <b>${code}</b></p>
             <p>This code will expire in 3 minutes.</p>`
    });

    res.json({ success: true, message: "Verification code sent.", sessionId });
  } catch (err) {
    console.error("First login send error:", err);
    res.status(500).json({ success: false, error: "Failed to send verification." });
  }
});

// 5. Resend verification code (first login)
app.post("/firstlogin-resend", async (req, res) => {
  const { email } = req.body;
  try {
    await pool.query(
      `DELETE FROM email_tokens 
       WHERE email=$1 AND verified=false AND reset_flow=false`,
      [email]
    );

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = uuidv4();

    await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, session_id, verified, reset_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',$3,false,false)`,
      [email, code, sessionId]
    );

    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: "OneProjectApp Verification Code (Resend)",
      html: `<p>Your new verification code is: <b>${code}</b></p>
             <p>This code will expire in 3 minutes.</p>`
    });

    res.json({ success: true, message: "New verification code sent.", sessionId });
  } catch (err) {
    console.error("First login resend error:", err);
    res.status(500).json({ success: false, error: "Failed to resend verification." });
  }
});

// 6. Verify code only (no password commit here)
app.post('/verify-password-code', async (req, res) => {
  const { email, token } = req.body;
  try {
    const tokenCheck = await pool.query(
      `SELECT * FROM email_tokens 
       WHERE email=$1 AND token=$2 
       AND expires_at > NOW() 
       AND verified=false AND reset_flow=false
       ORDER BY expires_at DESC LIMIT 1`,
      [email, token]
    );

    if (tokenCheck.rows.length === 0) {
      return res.json({ success: false, verified: false, error: "Invalid or expired code." });
    }

    await pool.query(`UPDATE email_tokens SET verified=true WHERE id=$1`, [
      tokenCheck.rows[0].id
    ]);

    res.json({ success: true, verified: true, message: "Code verified. You may now set your password." });
  } catch (err) {
    console.error("Verify password code error:", err);
    res.status(500).json({ success: false, verified: false, error: "Failed to verify code." });
  }
});

// 7. Set password after verification (issue JWT + refresh token)
app.post("/set-password", async (req, res) => {
  const { email, password, role } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);

    let table, emailColumn;
    switch (role) {
      case "Client": table = "clients"; emailColumn = "company_email"; break;
      case "Client Project Manager": table = "client_project_managers"; emailColumn = "email"; break;
      case "Consultant": table = "consultants"; emailColumn = "email"; break;
      case "Consultant Project Manager": table = "consultant_project_managers"; emailColumn = "email"; break;
      case "Contractor": table = "contractors"; emailColumn = "email"; break;
      case "Contractor Project Manager": table = "contractor_project_managers"; emailColumn = "email"; break;
      case "Team Member": table = "team_members"; emailColumn = "email"; break;
      default: return res.json({ success: false, error: "Invalid role." });
    }

    const updateRes = await pool.query(
      `UPDATE ${table} SET password_hash=$1, verified=true WHERE ${emailColumn}=$2 RETURNING id, ${emailColumn} AS email`,
      [hash, email]
    );

    if (updateRes.rows.length === 0) {
      return res.json({ success: false, error: "Account not found." });
    }

    const user = updateRes.rows[0];

    // ✅ Generate JWT + refresh token
    const SECRET = process.env.JWT_SECRET || "supersecretkey";
    const payload = role === "Client"
      ? { sub: user.id, role, companyEmail: user.email }
      : { sub: user.id, role, email: user.email };

    const accessToken = jwt.sign(payload, SECRET, { expiresIn: "15m" });
    const refreshToken = crypto.randomBytes(64).toString("hex");

    await pool.query(
      `INSERT INTO refresh_tokens (user_id, role, token, expires_at)
       VALUES ($1, $2, $3, NOW() + interval '24 hours')`,
      [user.id, role, refreshToken]
    );

    console.log(`Password set for ${role}:`, email);
    return res.json({
      success: true,
      role,
      message: "Password set successfully.",
      accessToken,
      refreshToken
    });
  } catch (err) {
    console.error("Set password error:", err);
    res.status(500).json({ success: false, error: "Failed to set password." });
  }
});

// 8. Reset Password (send verification code)
app.post('/reset-send', async (req, res) => {
  const { email, role } = req.body;
  try {
    let table, emailColumn;

    // ✅ Match frontend role strings exactly
    switch (role) {
      case "Client":
        table = "clients";
        emailColumn = "company_email";   // clients use company_email
        break;
      case "Client Project Manager":
        table = "client_project_managers";
        emailColumn = "email";
        break;
      case "Consultant":
        table = "consultants";
        emailColumn = "email";
        break;
      case "Consultant Project Manager":
        table = "consultant_project_managers";
        emailColumn = "email";
        break;
      case "Contractor":
        table = "contractors";
        emailColumn = "email";
        break;
      case "Contractor Project Manager":
        table = "contractor_project_managers";
        emailColumn = "email";
        break;
      case "Team Member":
        table = "team_members";
        emailColumn = "email";
        break;
      default:
        return res.json({ success: false, error: "Invalid role." });
    }

    // 1. Check if user has an existing password
    const result = await pool.query(
      `SELECT password_hash FROM ${table} WHERE ${emailColumn}=$1`,
      [email]
    );

    if (result.rows.length === 0 || !result.rows[0].password_hash) {
      return res.json({
        success: false,
        error: "This account has no password yet. Please follow the first‑login flow to set your password."
      });
    }

    // 2. Delete any existing reset tokens
    await pool.query(`DELETE FROM email_tokens WHERE email=$1 AND reset_flow=true`, [email]);

    // 3. Create new token
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = uuidv4();

    const insertResult = await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, session_id, verified, reset_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',$3,false,true)
       RETURNING *`,
      [email, code, sessionId]
    );

    // 4. Send email immediately
    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: 'Reset your password - OneProjectApp',
      html: `<p>Your reset code is: <b>${code}</b></p>
             <p>This code will expire in 3 minutes.</p>`
    });

    // 5. Return success + expiry timestamp
    res.json({
      success: true,
      message: "Reset code sent.",
      sessionId,
      expiresAt: insertResult.rows[0].expires_at
    });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ success: false, error: "Failed to send reset code." });
  }
});

// 9. Resend reset code
app.post('/reset-resend', async (req, res) => {
  const { email, role } = req.body;
  try {
    let table, emailColumn;

    switch (role) {
      case "Client":
        table = "clients";
        emailColumn = "company_email";
        break;
      case "Client Project Manager":
        table = "client_project_managers";
        emailColumn = "email";
        break; // ✅ added break to prevent fall-through
      case "Consultant":
        table = "consultants";
        emailColumn = "email";
        break;
      case "Consultant Project Manager":
        table = "consultant_project_managers";
        emailColumn = "email";
        break;
      case "Contractor":
        table = "contractors";
        emailColumn = "email";
        break;
      case "Contractor Project Manager":
        table = "contractor_project_managers";
        emailColumn = "email";
        break;
      case "Team Member":
        table = "team_members";
        emailColumn = "email";
        break;
      default:
        return res.json({ success: false, error: "Invalid role." });
    }

    // 1. Check if user has an existing password
    const result = await pool.query(
      `SELECT password_hash FROM ${table} WHERE ${emailColumn}=$1`,
      [email]
    );

    if (result.rows.length === 0 || !result.rows[0].password_hash) {
      return res.json({
        success: false,
        error: "This account has no password yet. Please follow the first‑login flow to set your password."
      });
    }

    // 2. Delete any existing reset tokens
    await pool.query(`DELETE FROM email_tokens WHERE email=$1 AND reset_flow=true`, [email]);

    // 3. Create new token
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = uuidv4();

    const insertResult = await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, session_id, verified, reset_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',$3,false,true)
       RETURNING *`,
      [email, code, sessionId]
    );

    // 4. Send email immediately
    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: "Resend reset code - OneProjectApp",
      html: `<p>Your new reset code is: <b>${code}</b></p>
             <p>This code will expire in 3 minutes.</p>`
    });

    res.json({
      success: true,
      message: "New reset code sent.",
      sessionId,
      expiresAt: insertResult.rows[0].expires_at
    });
  } catch (err) {
    console.error("Resend reset error:", err);
    res.status(500).json({ success: false, error: "Failed to resend reset code." });
  }
});

// 10. Verify reset password code (unchanged, works with email_tokens)
app.post('/reset-verify', async (req, res) => {
  const { email, token } = req.body;
  try {
    const tokenCheck = await pool.query(
      `SELECT * FROM email_tokens 
       WHERE email=$1 AND token=$2 
       AND expires_at > NOW() 
       AND verified=false 
       AND reset_flow=true
       ORDER BY expires_at DESC LIMIT 1`,
      [email, token]
    );

    if (tokenCheck.rows.length === 0) {
      return res.json({ success: false, verified: false, error: "Invalid or expired code." });
    }

    await pool.query(`UPDATE email_tokens SET verified=true WHERE id=$1`, [
      tokenCheck.rows[0].id
    ]);

    res.json({
      success: true,
      verified: true,
      message: "Code verified. You may now set your new password."
    });
  } catch (err) {
    console.error("Verify reset code error:", err);
    res.status(500).json({
      success: false,
      verified: false,
      error: "Failed to verify reset code."
    });
  }
});

// 11. Save new password after verification
app.post('/reset-set-password', async (req, res) => {
  const { email, password, role } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);

    let table, emailColumn;
    switch (role) {
      case "Client":
        table = "clients";
        emailColumn = "company_email";
        break;
      case "Client Project Manager":
        table = "client_project_managers";
        emailColumn = "email";
        break;
      case "Consultant":
        table = "consultants";
        emailColumn = "email";
        break;
      case "Consultant Project Manager":
        table = "consultant_project_managers";
        emailColumn = "email";
        break;
      case "Contractor":
        table = "contractors";
        emailColumn = "email";
        break;
      case "Contractor Project Manager":
        table = "contractor_project_managers";
        emailColumn = "email";
        break;
      case "Team Member":
        table = "team_members";
        emailColumn = "email";
        break;
      default:
        return res.json({ success: false, error: "Invalid role." });
    }

    // Update password and mark verified
    const updateRes = await pool.query(
      `UPDATE ${table} SET password_hash=$1, verified=true 
       WHERE ${emailColumn}=$2 RETURNING id, ${emailColumn} AS email`,
      [hash, email]
    );

    if (updateRes.rows.length === 0) {
      return res.json({ success: false, error: "Account not found." });
    }

    const user = updateRes.rows[0];

    // ✅ Generate JWT + Refresh Token
    const SECRET = process.env.JWT_SECRET || "supersecretkey";

    const payload =
      role === "Client"
        ? { sub: user.id, companyEmail: user.email, role }
        : { sub: user.id, email: user.email, role };

    const accessToken = jwt.sign(payload, SECRET, { expiresIn: "15m" });

    const refreshToken = crypto.randomBytes(64).toString("hex");
    await pool.query(
      `INSERT INTO refresh_tokens (user_id, role, token, expires_at)
       VALUES ($1, $2, $3, NOW() + interval '24 hours')`,
      [user.id, role, refreshToken]
    );

    console.log(`Password reset for ${role}:`, email);

    return res.json({
      success: true,
      role,
      message: "Password reset successfully.",
      accessToken,
      refreshToken
    });
  } catch (err) {
    console.error("Reset set password error:", err);
    res.status(500).json({ success: false, error: "Failed to reset password." });
  }
});

// LOGIN route (role-specific tables with JWT + Refresh Token)
app.post("/login", async (req, res) => {
  const { email, company_email, password, role } = req.body;
  try {
    let table, assignmentTable, foreignKey, emailColumn, selectFields;

    switch (role) {
      case "Client":
        table = "clients";
        assignmentTable = "projects";
        foreignKey = "client_id";
        emailColumn = "company_email";
        selectFields = `
          id, company_name, company_email,
          representative, title, telephone,
          password_hash, verified, profile_picture, created_at
        `;
        break;
      case "Contractor":
        table = "contractors";
        assignmentTable = "contractor_assignments";
        foreignKey = "contractor_id";
        emailColumn = "email";
        selectFields = "id, email, password_hash, verified, profile_picture, created_at";
        break;
      case "Consultant":
        table = "consultants";
        assignmentTable = "consultant_assignments";
        foreignKey = "consultant_id";
        emailColumn = "email";
        selectFields = "id, email, password_hash, verified, profile_picture, created_at";
        break;
      case "Team Member":
        table = "team_members";
        assignmentTable = "team_member_assignments";
        foreignKey = "team_member_id";
        emailColumn = "email";
        selectFields = "id, email, password_hash, verified, profile_picture, created_at";
        break;
      case "Client Project Manager":
        table = "client_project_managers";
        assignmentTable = "client_pm_assignments";
        foreignKey = "client_pm_id";
        emailColumn = "email";
        selectFields = "id, email, password_hash, verified, profile_picture, created_at";
        break;
      case "Contractor Project Manager":
        table = "contractor_project_managers";
        assignmentTable = "contractor_pm_assignments";
        foreignKey = "contractor_pm_id";
        emailColumn = "email";
        selectFields = "id, email, password_hash, verified, profile_picture, created_at";
        break;
      case "Consultant Project Manager":
        table = "consultant_project_managers";
        assignmentTable = "consultant_pm_assignments";
        foreignKey = "consultant_pm_id";
        emailColumn = "email";
        selectFields = "id, email, password_hash, verified, profile_picture, created_at";
        break;
      default:
        return res.json({ success: false, error: "Invalid role." });
    }

    const loginEmail = role === "Client" ? company_email : email;

    const result = await pool.query(
      `SELECT ${selectFields} 
       FROM ${table} 
       WHERE TRIM(LOWER(${emailColumn}))=TRIM(LOWER($1))`,
      [loginEmail]
    );
    if (result.rows.length === 0) return res.json({ success: false, error: "Account not found." });

    const user = result.rows[0];
    if (!user.password_hash) return res.json({ success: false, error: "No password set yet. Follow the first-login guideline." });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.json({ success: false, error: "Invalid password." });

    if (!user.verified) return res.json({ success: false, error: "Account not verified. Please check your email." });

    let projectAssignments = [];
    if (role === "Client") {
      const projectsRes = await pool.query("SELECT id FROM projects WHERE client_id=$1", [user.id]);
      projectAssignments = projectsRes.rows.map(r => r.id);
    } else {
      const projectsRes = await pool.query(
        `SELECT project_id FROM ${assignmentTable} WHERE ${foreignKey}=$1`,
        [user.id]
      );
      projectAssignments = projectsRes.rows.map(r => r.project_id);
    }

    const SECRET = process.env.JWT_SECRET || "supersecretkey";

    // ✅ Payload distinction
    const payload =
      role === "Client"
        ? { sub: user.id, companyEmail: user.company_email, role, projects: projectAssignments }
        : { sub: user.id, email: user.email, role, projects: projectAssignments };

    const accessToken = jwt.sign(payload, SECRET, { expiresIn: "15m" });

    const refreshToken = crypto.randomBytes(64).toString("hex");
    await pool.query(
      `INSERT INTO refresh_tokens (user_id, role, token, expires_at)
       VALUES ($1, $2, $3, NOW() + interval '24 hours')`,
      [user.id, role, refreshToken]
    );

    res.json({
      success: true,
      message: "Login successful.",
      accessToken,
      refreshToken,
      role,
      projects: projectAssignments
    });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ success: false, error: "Server error logging in." });
  }
});

// REFRESH route (issue new access token using refresh token)
app.post("/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(401).json({ success: false, error: "No refresh token provided." });
    }

    const tokenRes = await pool.query(
      "SELECT user_id, role, expires_at FROM refresh_tokens WHERE token=$1",
      [refreshToken]
    );
    if (tokenRes.rows.length === 0) {
      return res.status(401).json({ success: false, error: "Refresh token not recognized." });
    }

    const { user_id, role, expires_at } = tokenRes.rows[0];
    if (new Date(expires_at) < new Date()) {
      return res.status(403).json({ success: false, error: "Refresh token expired." });
    }

    let emailColumn, table, foreignKey, assignmentTable;
    switch (role) {
      case "Client": table = "clients"; emailColumn = "company_email"; assignmentTable = "projects"; foreignKey = "client_id"; break;
      case "Contractor": table = "contractors"; emailColumn = "email"; assignmentTable = "contractor_assignments"; foreignKey = "contractor_id"; break;
      case "Consultant": table = "consultants"; emailColumn = "email"; assignmentTable = "consultant_assignments"; foreignKey = "consultant_id"; break;
      case "Team Member": table = "team_members"; emailColumn = "email"; assignmentTable = "team_member_assignments"; foreignKey = "team_member_id"; break;
      case "Client Project Manager": table = "client_project_managers"; emailColumn = "email"; assignmentTable = "client_pm_assignments"; foreignKey = "client_pm_id"; break;
      case "Contractor Project Manager": table = "contractor_project_managers"; emailColumn = "email"; assignmentTable = "contractor_pm_assignments"; foreignKey = "contractor_pm_id"; break;
      case "Consultant Project Manager": table = "consultant_project_managers"; emailColumn = "email"; assignmentTable = "consultant_pm_assignments"; foreignKey = "consultant_pm_id"; break;
      default: return res.status(400).json({ success: false, error: "Invalid role." });
    }

    const userRes = await pool.query(`SELECT id, ${emailColumn} FROM ${table} WHERE id=$1`, [user_id]);
    if (userRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found." });
    }
    const user = userRes.rows[0];

    let projectAssignments = [];
    if (role === "Client") {
      const projectsRes = await pool.query("SELECT id FROM projects WHERE client_id=$1", [user_id]);
      projectAssignments = projectsRes.rows.map(r => r.id);
    } else {
      const projectsRes = await pool.query(
        `SELECT project_id FROM ${assignmentTable} WHERE ${foreignKey}=$1`,
        [user_id]
      );
      projectAssignments = projectsRes.rows.map(r => r.project_id);
    }

    const SECRET = process.env.JWT_SECRET || "supersecretkey";

    // ✅ Payload distinction
    const payload =
      role === "Client"
        ? { sub: user_id, companyEmail: user.company_email, role, projects: projectAssignments }
        : { sub: user_id, email: user.email, role, projects: projectAssignments };

    const newAccessToken = jwt.sign(payload, SECRET, { expiresIn: "15m" });

    // Optionally rotate refresh token
    // const newRefreshToken = crypto.randomBytes(64).toString("hex");
    // await pool.query(`UPDATE refresh_tokens SET token=$1, expires_at=NOW() + interval '24 hours' WHERE user_id=$2 AND role=$3`, [newRefreshToken, user_id, role]);

    res.json({
      success: true,
      accessToken: newAccessToken,
      refreshToken, // reuse existing until expiry
      role,
      projects: projectAssignments
    });
  } catch (err) {
    console.error("Refresh error:", err.message);
    res.status(500).json({ success: false, error: "Server error refreshing token." });
  }
});

// Global logout route (invalidate refresh token for any role)
app.post("/logout", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ success: false, error: "No refresh token provided." });
    }

    // Delete the refresh token from DB
    const result = await pool.query(
      "DELETE FROM refresh_tokens WHERE token=$1 RETURNING id",
      [refreshToken]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Refresh token not found." });
    }

    res.json({ success: true, message: "Logged out successfully. Refresh token revoked." });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ success: false, error: "Server error during logout." });
  }
});

// 13. SendGrid Event Webhook
app.post("/sendgrid-events", async (req, res) => {
  const events = req.body;
  for (const e of events) {
    if (e.event === "bounce" || e.event === "dropped" || e.event === "blocked") {
      console.log("Email failed:", e.email);

      await pool.query(
        `UPDATE clients SET verified=false WHERE company_email=$1`,
        [e.email]
      );

      await pool.query(
        `UPDATE users SET verified=false WHERE email=$1`,
        [e.email]
      );
    }
  }
  res.status(200).send("OK");
});

// 14. Check Email Exists (role-specific tables)
app.post("/check-email", async (req, res) => {
  const { email, role } = req.body;
  try {
    let table, emailColumn;

    switch (role) {
      case "Client":
        table = "clients";
        emailColumn = "company_email";
        break;
      case "Client Project Manager":
        table = "client_project_managers";
        emailColumn = "email";
        break;
      case "Consultant":
        table = "consultants";
        emailColumn = "email";
        break;
      case "Consultant Project Manager":
        table = "consultant_project_managers";
        emailColumn = "email";
        break;
      case "Contractor":
        table = "contractors";
        emailColumn = "email";
        break;
      case "Contractor Project Manager":
        table = "contractor_project_managers";
        emailColumn = "email";
        break;
      case "Team Member":
        table = "team_members";
        emailColumn = "email";
        break;
      default:
        return res.json({ success: false, exists: false, error: "Invalid role." });
    }

    const result = await pool.query(
      `SELECT id FROM ${table} WHERE ${emailColumn}=$1`,
      [email]
    );

    res.json({ success: true, exists: result.rows.length > 0 });
  } catch (err) {
    console.error("Check email error:", err.message);
    res.status(500).json({ success: false, error: "Server error checking email." });
  }
});

// 15. Cleanup expired tokens (manual trigger)
app.post("/cleanup-tokens", async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM email_tokens 
       WHERE expires_at < NOW() 
       AND verified=false`
    );

    res.json({
      success: true,
      message: "Expired tokens cleaned up.",
      deletedCount: result.rowCount
    });
  } catch (err) {
    console.error("Cleanup error:", err.message);
    res.status(500).json({ success: false, error: "Failed to cleanup tokens." });
  }
});

// 🔹 Automatic cleanup every 3 minutes
setInterval(async () => {
  try {
    const result = await pool.query(
      `DELETE FROM email_tokens 
       WHERE expires_at < NOW() 
       AND verified=false`
    );
    if (result.rowCount > 0) {
      console.log(`Scheduled cleanup: ${result.rowCount} expired tokens deleted.`);
    }
  } catch (err) {
    console.error("Scheduled cleanup error:", err.message);
  }
}, 3 * 60 * 1000); // 3 minutes

// ============ CLIENT PROFILE ROUTES (JWT-based, aligned with clients table) =============

// Fetch client profile basics (company_email + profile picture + role)
app.get("/client/profile", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "Client") {
      return res.status(403).json({ error: "Access denied: Client only route" });
    }

    const clientEmail = req.user.email;   // unified field from JWT
    const clientId = req.user.user_id;    // mapped from JWT sub

    const clientResult = await pool.query(
      "SELECT company_email, representative, title, telephone, profile_picture FROM clients WHERE id=$1 AND company_email=$2",
      [clientId, clientEmail]
    );
    if (clientResult.rows.length === 0) {
      return res.status(404).json({ error: "Client not found" });
    }

    const client = clientResult.rows[0];
    res.json({
      email: client.company_email,
      role: req.user.role,
      representative: client.representative,
      title: client.title,
      telephone: client.telephone,
      profile_picture: client.profile_picture
    });
  } catch (err) {
    console.error("Fetch client profile error:", err);
    res.status(500).json({ error: "Failed to fetch client profile" });
  }
});

// Upload client profile picture
app.post("/client/upload-picture", authenticateToken, upload.single("profile_picture"), async (req, res) => {
  try {
    if (req.user.role !== "Client") {
      return res.status(403).json({ error: "Access denied: Client only route" });
    }

    const clientEmail = req.user.email;
    const clientId = req.user.user_id;

    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded or file too large." });
    }
    if (!req.file.mimetype.startsWith("image/")) {
      return res.status(400).json({ error: "Only image files allowed." });
    }

    const fileUrl = `https://oneprojectapp-backend.onrender.com/uploads/${req.file.filename}`;
    await pool.query(
      "UPDATE clients SET profile_picture=$1 WHERE id=$2 AND company_email=$3",
      [fileUrl, clientId, clientEmail]
    );

    res.json({ success: true, url: fileUrl });
  } catch (err) {
    console.error("Upload client picture error:", err);
    res.status(500).json({ error: "Failed to upload client picture" });
  }
});

// Delete client profile picture
app.post("/client/delete-picture", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "Client") {
      return res.status(403).json({ error: "Access denied: Client only route" });
    }

    const clientEmail = req.user.email;
    const clientId = req.user.user_id;

    await pool.query(
      "UPDATE clients SET profile_picture=NULL WHERE id=$1 AND company_email=$2",
      [clientId, clientEmail]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Delete client picture error:", err);
    res.status(500).json({ error: "Failed to delete client picture" });
  }
});

// Fetch all projects for this client
app.post("/client/projects", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "Client") {
      return res.status(403).json({ error: "Access denied: Client only route" });
    }

    const clientId = req.user.user_id;

    const projectsResult = await pool.query(
      "SELECT id, name, location, contract_reference, created_at FROM projects WHERE client_id=$1",
      [clientId]
    );

    res.json({ projects: projectsResult.rows });
  } catch (err) {
    console.error("Fetch client projects error:", err);
    res.status(500).json({ error: "Failed to fetch client projects" });
  }
});

// Fetch project details for a specific client project
app.post("/client/project-details", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "Client") {
      return res.status(403).json({ error: "Access denied: Client only route" });
    }

    const clientId = req.user.user_id;
    const clientEmail = req.user.email;
    const { projectId } = req.body;

    // Verify client exists
    const clientResult = await pool.query(
      "SELECT id, profile_picture FROM clients WHERE id=$1 AND company_email=$2",
      [clientId, clientEmail]
    );
    if (clientResult.rows.length === 0) {
      return res.status(404).json({ error: "Client not found" });
    }
    const client = clientResult.rows[0];

    // Verify project belongs to client
    const projectResult = await pool.query(
      "SELECT id, name, location, contract_reference, created_at FROM projects WHERE id=$1 AND client_id=$2",
      [projectId, clientId]
    );
    if (projectResult.rows.length === 0) {
      return res.status(404).json({ error: "Project not found or not owned by client" });
    }
    const project = projectResult.rows[0];

    res.json({
      client: {
        email: clientEmail,
        role: req.user.role,
        profile_picture: client.profile_picture
      },
      project
    });
  } catch (err) {
    console.error("Fetch project details error:", err);
    res.status(500).json({ error: "Failed to fetch project details" });
  }
});

// ============ CONTRACTOR PROFILE ROUTES (JWT-based, Schema-Aligned) =============

// Fetch contractor profile + projects (via contractor_assignments)
app.post("/contractor/profile", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;

    const contractorResult = await pool.query(
      "SELECT id, email, 'Contractor' AS role, profile_picture FROM contractors WHERE email=$1",
      [email]
    );
    if (contractorResult.rows.length === 0) {
      return res.status(404).json({ error: "Contractor not found" });
    }
    const contractor = contractorResult.rows[0];

    const projectsResult = await pool.query(
      `SELECT p.id, p.name, p.location, p.contract_reference, p.created_at
       FROM contractor_assignments ca
       JOIN projects p ON ca.project_id = p.id
       WHERE ca.contractor_id=$1`,
      [contractor.id]
    );
    contractor.projects = projectsResult.rows;

    if (contractor.projects.length === 1) {
      contractor.defaultProject = contractor.projects[0];
    }

    res.json(contractor);
  } catch (err) {
    console.error("Fetch contractor profile error:", err);
    res.status(500).json({ error: "Failed to fetch contractor profile" });
  }
});

// Upload contractor profile picture
app.post("/contractor/upload-picture", authenticateToken, upload.single("profile_picture"), async (req, res) => {
  try {
    const email = req.user.email;
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded or file too large." });
    }

    const fileUrl = `https://oneprojectapp-backend.onrender.com/uploads/${req.file.filename}`;
    await pool.query("UPDATE contractors SET profile_picture=$1 WHERE email=$2", [fileUrl, email]);

    res.json({ success: true, url: fileUrl });
  } catch (err) {
    console.error("Upload contractor picture error:", err);
    res.status(500).json({ error: "Failed to upload contractor picture" });
  }
});

// Delete contractor profile picture
app.post("/contractor/delete-picture", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    await pool.query("UPDATE contractors SET profile_picture=NULL WHERE email=$1", [email]);
    res.json({ success: true });
  } catch (err) {
    console.error("Delete contractor picture error:", err);
    res.status(500).json({ error: "Failed to delete contractor picture" });
  }
});

// Fetch project details for a specific contractor project
app.post("/contractor/project-details", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    const { projectId } = req.body;

    const contractorResult = await pool.query(
      "SELECT id, email, 'Contractor' AS role, profile_picture FROM contractors WHERE email=$1",
      [email]
    );
    if (contractorResult.rows.length === 0) {
      return res.status(404).json({ error: "Contractor not found" });
    }
    const contractor = contractorResult.rows[0];

    // Ensure contractor is assigned to the requested project
    const assignmentCheck = await pool.query(
      "SELECT 1 FROM contractor_assignments WHERE contractor_id=$1 AND project_id=$2",
      [contractor.id, projectId]
    );
    if (assignmentCheck.rows.length === 0) {
      return res.status(404).json({ error: "Project not found or not linked to contractor" });
    }

    const projectResult = await pool.query(
      "SELECT id, name, location, contract_reference, created_at FROM projects WHERE id=$1",
      [projectId]
    );
    if (projectResult.rows.length === 0) {
      return res.status(404).json({ error: "Project not found" });
    }
    const project = projectResult.rows[0];

    res.json({
      contractor: {
        email: contractor.email,
        role: contractor.role,
        profile_picture: contractor.profile_picture
      },
      project: project
    });
  } catch (err) {
    console.error("Fetch contractor project details error:", err);
    res.status(500).json({ error: "Failed to fetch contractor project details" });
  }
});

// ============ CONSULTANT PROFILE ROUTES (JWT-based, Schema-Aligned) =============

// Fetch consultant profile + projects (via consultant_assignments)
app.post("/consultant/profile", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;

    const consultantResult = await pool.query(
      "SELECT id, email, 'Consultant' AS role, profile_picture, verified, created_at FROM consultants WHERE email=$1",
      [email]
    );
    if (consultantResult.rows.length === 0) {
      return res.status(404).json({ error: "Consultant not found" });
    }
    const consultant = consultantResult.rows[0];

    const projectsResult = await pool.query(
      `SELECT p.id, p.name, p.location, p.contract_reference, p.created_at
       FROM consultant_assignments ca
       JOIN projects p ON ca.project_id = p.id
       WHERE ca.consultant_id=$1`,
      [consultant.id]
    );
    consultant.projects = projectsResult.rows;

    if (consultant.projects.length === 1) {
      consultant.defaultProject = consultant.projects[0];
    }

    res.json(consultant);
  } catch (err) {
    console.error("Fetch consultant profile error:", err);
    res.status(500).json({ error: "Failed to fetch consultant profile" });
  }
});

// Upload consultant profile picture
app.post("/consultant/upload-picture", authenticateToken, upload.single("profile_picture"), async (req, res) => {
  try {
    const email = req.user.email;
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded or file too large." });
    }

    const fileUrl = `https://oneprojectapp-backend.onrender.com/uploads/${req.file.filename}`;
    await pool.query("UPDATE consultants SET profile_picture=$1 WHERE email=$2", [fileUrl, email]);

    res.json({ success: true, url: fileUrl });
  } catch (err) {
    console.error("Upload consultant picture error:", err);
    res.status(500).json({ error: "Failed to upload consultant picture" });
  }
});

// Delete consultant profile picture
app.post("/consultant/delete-picture", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    await pool.query("UPDATE consultants SET profile_picture=NULL WHERE email=$1", [email]);
    res.json({ success: true });
  } catch (err) {
    console.error("Delete consultant picture error:", err);
    res.status(500).json({ error: "Failed to delete consultant picture" });
  }
});

// Fetch project details for a specific consultant project
app.post("/consultant/project-details", authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    const { projectId } = req.body;

    const consultantResult = await pool.query(
      "SELECT id, email, 'Consultant' AS role, profile_picture FROM consultants WHERE email=$1",
      [email]
    );
    if (consultantResult.rows.length === 0) {
      return res.status(404).json({ error: "Consultant not found" });
    }
    const consultant = consultantResult.rows[0];

    // Ensure consultant is assigned to the requested project
    const assignmentCheck = await pool.query(
      "SELECT 1 FROM consultant_assignments WHERE consultant_id=$1 AND project_id=$2",
      [consultant.id, projectId]
    );
    if (assignmentCheck.rows.length === 0) {
      return res.status(404).json({ error: "Project not found or not linked to consultant" });
    }

    const projectResult = await pool.query(
      "SELECT id, name, location, contract_reference, created_at FROM projects WHERE id=$1",
      [projectId]
    );
    if (projectResult.rows.length === 0) {
      return res.status(404).json({ error: "Project not found" });
    }
    const project = projectResult.rows[0];

    res.json({
      consultant: {
        email: consultant.email,
        role: consultant.role,
        profile_picture: consultant.profile_picture
      },
      project: project
    });
  } catch (err) {
    console.error("Fetch consultant project details error:", err);
    res.status(500).json({ error: "Failed to fetch consultant project details" });
  }
});

// 19. ============ CLIENT ROUTES =============

// Check if client email exists (for new account creation)
app.post("/client/check-email", async (req, res) => {
  const { email } = req.body;

  try {
    // ✅ Only check company_email in clients table
    const result = await pool.query(
      "SELECT company_email FROM clients WHERE company_email = $1",
      [email]
    );

    if (result.rows.length > 0) {
      return res.json({
        exists: true,
        message: "This email is already registered. Please use 'Existing Account' option."
      });
    }

    res.json({ exists: false });
  } catch (err) {
    console.error("Check email error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Client login (for existing account)
app.post("/client/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // ✅ Only fetch company_email and password_hash
    const result = await pool.query(
      "SELECT company_email, password_hash FROM clients WHERE company_email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: "Client not found. Please use 'New Account' option."
      });
    }

    const client = result.rows[0];
    const match = await bcrypt.compare(password, client.password_hash);

    if (!match) {
      return res.status(401).json({
        success: false,
        error: "Invalid password. Please use 'New Account' option."
      });
    }

    // ✅ Valid login → return only email for frontend
    res.json({
      success: true,
      clientEmail: client.company_email
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ============ FETCH CLIENT PROFILE PICTURE ============
app.post("/client/profile-picture", async (req, res) => {
  const { email } = req.body;
  try {
    const result = await pool.query(
      `SELECT profile_picture 
       FROM clients 
       WHERE TRIM(LOWER(company_email)) = TRIM(LOWER($1))`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.json({ success: false, error: "Client not found." });
    }

    const profilePicture = result.rows[0].profile_picture;

    if (!profilePicture) {
      // Explicitly tell frontend there is no picture
      return res.json({ success: true, profile_picture: null });
    }

    // Return the stored picture URL
    res.json({ success: true, profile_picture: profilePicture });
  } catch (err) {
    console.error("Profile picture fetch error:", err);
    res.status(500).json({ success: false, error: "Server error fetching profile picture." });
  }
});

// 1. Send project verification code
app.post('/project-send', async (req, res) => {
  const { email } = req.body;
  try {
    await pool.query(
      `DELETE FROM email_tokens WHERE email=$1 AND project_flow=true`,
      [email]
    );

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = uuidv4();

    const insertResult = await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, session_id, verified, project_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',$3,false,true)
       RETURNING *`,
      [email, code, sessionId]
    );

    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: "Project Verification - OneProjectApp",
      html: `<p>Your project verification code is: <b>${code}</b></p>
             <p>This code will expire in 3 minutes.</p>`
    });

    res.json({
      success: true,
      message: "Project verification code sent.",
      sessionId,
      expiresAt: insertResult.rows[0].expires_at
    });
  } catch (err) {
    console.error("Project send error:", err);
    res.status(500).json({ success: false, error: "Failed to send project code." });
  }
});

// 2. Resend project verification code
app.post('/project-resend', async (req, res) => {
  const { email } = req.body;
  try {
    await pool.query(
      `DELETE FROM email_tokens WHERE email=$1 AND project_flow=true`,
      [email]
    );

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = uuidv4();

    const insertResult = await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, session_id, verified, project_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',$3,false,true)
       RETURNING *`,
      [email, code, sessionId]
    );

    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: "Resend Project Verification Code - OneProjectApp",
      html: `<p>Your new project verification code is: <b>${code}</b></p>
             <p>This code will expire in 3 minutes.</p>`
    });

    res.json({
      success: true,
      message: "New project verification code sent.",
      sessionId,
      expiresAt: insertResult.rows[0].expires_at
    });
  } catch (err) {
    console.error("Project resend error:", err);
    res.status(500).json({ success: false, error: "Failed to resend project code." });
  }
});

// 3. Verify project code
app.post('/project-verify', async (req, res) => {
  const { email, token } = req.body;
  try {
    const tokenCheck = await pool.query(
      `SELECT * FROM email_tokens 
       WHERE email=$1 
       AND token=$2 
       AND expires_at > NOW() 
       AND verified=false 
       AND project_flow=true
       ORDER BY expires_at DESC LIMIT 1`,
      [email, token]
    );

    if (tokenCheck.rows.length === 0) {
      return res.json({ success: false, error: "Invalid or expired project code." });
    }

    await pool.query(`UPDATE email_tokens SET verified=true WHERE id=$1`, [
      tokenCheck.rows[0].id
    ]);

    res.json({ success: true, message: "Project code verified." });
  } catch (err) {
    console.error("Project verify error:", err);
    res.status(500).json({ success: false, error: "Failed to verify project code." });
  }
});

// 4. Save project after verification (issue JWT + Refresh Token)
app.post('/project-save', async (req, res) => {
  const { project, contractor, consultant, clientEmail } = req.body;

  try {
    // ✅ Ensure client exists and is verified
    const clientResult = await pool.query(
      `SELECT id, company_email FROM clients 
       WHERE TRIM(LOWER(company_email)) = TRIM(LOWER($1)) AND verified=true`,
      [clientEmail]
    );

    if (clientResult.rows.length === 0) {
      return res.json({ success: false, error: "Client not found or not verified." });
    }

    const client_id = clientResult.rows[0].id;

    // ✅ Insert project or fetch existing
    const projectResult = await pool.query(
      `INSERT INTO projects (name, location, contract_reference, client_id, created_at)
       VALUES ($1,$2,$3,$4,NOW())
       ON CONFLICT (name, client_id) DO NOTHING RETURNING id;`,
      [project.name, project.location, project.contract_reference, client_id]
    );

    let project_id =
      projectResult.rows[0]?.id ||
      (
        await pool.query(
          `SELECT id FROM projects WHERE name=$1 AND client_id=$2`,
          [project.name, client_id]
        )
      ).rows[0].id;

    // ✅ Ensure contractor exists and assign
    if (contractor?.email) {
      let contractorResult = await pool.query(
        `SELECT id FROM contractors WHERE TRIM(LOWER(email))=TRIM(LOWER($1))`,
        [contractor.email]
      );

      let contractor_id;
      if (contractorResult.rows.length === 0) {
        const insertResult = await pool.query(
          `INSERT INTO contractors (email, verified, created_at)
           VALUES ($1, true, NOW())
           RETURNING id;`,
          [contractor.email]
        );
        contractor_id = insertResult.rows[0].id;
      } else {
        contractor_id = contractorResult.rows[0].id;
      }

      await pool.query(
        `INSERT INTO contractor_assignments
         (project_id, contractor_id, company_name, representative, title, position, telephone, task, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
         ON CONFLICT (project_id, contractor_id) DO NOTHING;`,
        [
          project_id,
          contractor_id,
          contractor.company_name || null,
          contractor.representative || null,
          contractor.title || null,
          contractor.position || null,
          contractor.telephone || null,
          contractor.task || null
        ]
      );
    }

    // ✅ Ensure consultant exists and assign
    if (consultant?.email) {
      let consultantResult = await pool.query(
        `SELECT id FROM consultants WHERE TRIM(LOWER(email))=TRIM(LOWER($1))`,
        [consultant.email]
      );

      let consultant_id;
      if (consultantResult.rows.length === 0) {
        const insertResult = await pool.query(
          `INSERT INTO consultants (email, verified, created_at)
           VALUES ($1, true, NOW())
           RETURNING id;`,
          [consultant.email]
        );
        consultant_id = insertResult.rows[0].id;
      } else {
        consultant_id = consultantResult.rows[0].id;
      }

      await pool.query(
        `INSERT INTO consultant_assignments
         (project_id, consultant_id, company_name, representative, title, position, telephone, task, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
         ON CONFLICT (project_id, consultant_id) DO NOTHING;`,
        [
          project_id,
          consultant_id,
          consultant.company_name || null,
          consultant.representative || null,
          consultant.title || null,
          consultant.position || null,
          consultant.telephone || null,
          consultant.task || null
        ]
      );
    }

    // ✅ Generate JWT + Refresh Token for client
    const SECRET = process.env.JWT_SECRET || "supersecretkey";
    const payload = {
      sub: client_id,
      companyEmail: clientResult.rows[0].company_email,
      role: "Client",
      projects: [project_id]
    };

    const accessToken = jwt.sign(payload, SECRET, { expiresIn: "15m" });

    const refreshToken = crypto.randomBytes(64).toString("hex");
    await pool.query(
      `INSERT INTO refresh_tokens (user_id, role, token, expires_at)
       VALUES ($1, $2, $3, NOW() + interval '24 hours')`,
      [client_id, "Client", refreshToken]
    );

    return res.json({
      success: true,
      message: "Project and team saved successfully.",
      projectId: project_id,
      accessToken,
      refreshToken
    });
  } catch (err) {
    console.error("Project save error:", err.message);
    res.status(500).json({ success: false, error: "Server error saving project." });
  }
});

// ============ UNIFIED PROJECT DETAILS ROUTE (JWT-based) ============
app.post("/profile/project-details", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: "Authorization header missing" });
    }

    const token = authHeader.split(" ")[1];
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET || "supersecretkey");
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    const { sub: userId, role } = decoded;
    const { projectId } = req.body;

    let userResult, projectResult;

    switch (role) {
      case "Client":
      case "Client Project Manager":
        userResult = await pool.query(
          "SELECT id, company_email AS email, $2 AS role, profile_picture FROM clients WHERE id=$1",
          [userId, role]
        );
        if (userResult.rows.length === 0) return res.status(404).json({ error: "Client not found" });
        const client = userResult.rows[0];
        projectResult = await pool.query(
          "SELECT id, name, location, contract_reference, created_at FROM projects WHERE id=$1 AND client_id=$2",
          [projectId, client.id]
        );
        if (projectResult.rows.length === 0) return res.status(404).json({ error: "Project not found or not owned by client" });
        return res.json({ user: client, project: projectResult.rows[0] });

      case "Contractor":
      case "Contractor Project Manager":
        userResult = await pool.query(
          "SELECT id, email, $2 AS role, profile_picture FROM contractors WHERE id=$1",
          [userId, role]
        );
        if (userResult.rows.length === 0) return res.status(404).json({ error: "Contractor not found" });
        const contractor = userResult.rows[0];
        const assignmentCheck = await pool.query(
          "SELECT 1 FROM contractor_assignments WHERE contractor_id=$1 AND project_id=$2",
          [contractor.id, projectId]
        );
        if (assignmentCheck.rows.length === 0) return res.status(403).json({ error: "Project not linked to contractor" });
        projectResult = await pool.query("SELECT id, name, location, contract_reference, created_at FROM projects WHERE id=$1", [projectId]);
        return res.json({ user: contractor, project: projectResult.rows[0] });

      case "Consultant":
      case "Consultant Project Manager":
        userResult = await pool.query(
          "SELECT id, email, $2 AS role, profile_picture FROM consultants WHERE id=$1",
          [userId, role]
        );
        if (userResult.rows.length === 0) return res.status(404).json({ error: "Consultant not found" });
        const consultant = userResult.rows[0];
        const consultantCheck = await pool.query(
          "SELECT 1 FROM consultant_assignments WHERE consultant_id=$1 AND project_id=$2",
          [consultant.id, projectId]
        );
        if (consultantCheck.rows.length === 0) return res.status(403).json({ error: "Project not linked to consultant" });
        projectResult = await pool.query("SELECT id, name, location, contract_reference, created_at FROM projects WHERE id=$1", [projectId]);
        return res.json({ user: consultant, project: projectResult.rows[0] });

      default:
        return res.status(400).json({ error: "Unsupported role" });
    }
  } catch (err) {
    console.error("Unified project-details error:", err);
    res.status(500).json({ error: "Failed to fetch project details" });
  }
});

// ============ ASSIGN TEAM ROUTE (JWT-based) ============
app.post("/assign-team", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ success: false, error: "Authorization header missing" });
    }

    const token = authHeader.split(" ")[1];
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET || "supersecretkey");
    } catch (err) {
      return res.status(401).json({ success: false, error: "Invalid or expired token" });
    }

    const { sub: userId, role } = decoded;
    const { projectId, assignments } = req.body;

    if (!projectId || !Array.isArray(assignments)) {
      return res.status(400).json({ success: false, error: "Invalid payload" });
    }

    // Verify project ownership/assignment
    let projectCheck;
    if (role.startsWith("Client")) {
      projectCheck = await pool.query("SELECT 1 FROM projects WHERE id=$1 AND client_id=$2", [projectId, userId]);
    } else if (role.startsWith("Contractor")) {
      projectCheck = await pool.query("SELECT 1 FROM contractor_assignments WHERE project_id=$1 AND contractor_id=$2", [projectId, userId]);
    } else if (role.startsWith("Consultant")) {
      projectCheck = await pool.query("SELECT 1 FROM consultant_assignments WHERE project_id=$1 AND consultant_id=$2", [projectId, userId]);
    } else {
      return res.status(400).json({ success: false, error: "Unsupported role" });
    }

    if (projectCheck.rows.length === 0) {
      return res.status(403).json({ success: false, error: "Project not linked to this user" });
    }

    const client = await pool.connect();
    try {
      for (const a of assignments) {
        if (a.role === "Project Manager") {
          if (role.startsWith("Client")) {
            await client.query(
              `INSERT INTO client_pm_assignments 
               (project_id, client_pm_id, company_name, title, position, telephone, task, representative) 
               VALUES ($1, (SELECT id FROM client_project_managers WHERE email=$2), $3,$4,$5,$6,$7,$8)
               ON CONFLICT DO NOTHING`,
              [projectId, a.email, a.company_name, a.title, a.position, a.telephone, a.task, a.representative]
            );
          } else if (role.startsWith("Contractor")) {
            await client.query(
              `INSERT INTO contractor_pm_assignments 
               (project_id, contractor_pm_id, company_name, title, position, telephone, task, representative) 
               VALUES ($1, (SELECT id FROM contractor_project_managers WHERE email=$2), $3,$4,$5,$6,$7,$8)
               ON CONFLICT DO NOTHING`,
              [projectId, a.email, a.company_name, a.title, a.position, a.telephone, a.task, a.representative]
            );
          } else if (role.startsWith("Consultant")) {
            await client.query(
              `INSERT INTO consultant_pm_assignments 
               (project_id, consultant_pm_id, company_name, title, position, telephone, task, representative) 
               VALUES ($1, (SELECT id FROM consultant_project_managers WHERE email=$2), $3,$4,$5,$6,$7,$8)
               ON CONFLICT DO NOTHING`,
              [projectId, a.email, a.company_name, a.title, a.position, a.telephone, a.task, a.representative]
            );
          }
        } else {
          // Team Member assignment
          await client.query(
            `INSERT INTO team_member_assignments 
             (project_id, team_member_id, company_name, title, position, telephone, task, representative) 
             VALUES ($1, (SELECT id FROM team_members WHERE email=$2), $3,$4,$5,$6,$7,$8)
             ON CONFLICT DO NOTHING`,
            [projectId, a.email, a.company_name, a.title, a.position, a.telephone, a.task, a.representative]
          );
        }
      }
      res.json({ success: true, message: "Assignments saved" });
    } catch (err) {
      console.error("Error saving assignments:", err);
      res.status(500).json({ success: false, error: "Server error" });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error("Assign team error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// -------------------- ERROR HANDLING --------------------
app.use((err, req, res, next) => {
  console.error('Unexpected error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// -------------------- SERVER --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});

// 🔹 Keep-alive ping
setInterval(() => {
  fetch("https://oneprojectapp-backend.onrender.com/")
    .then(res => console.log("Keep-alive ping:", res.status))
    .catch(err => console.error("Keep-alive error:", err));
}, 14 * 60 * 1000);

export default app;

