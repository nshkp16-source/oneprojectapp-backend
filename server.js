// server.js
import express from 'express';
import crypto from 'crypto';
import { Pool } from 'pg';
import nodemailer from 'nodemailer';
import cors from 'cors';
import nodemailerSendgrid from 'nodemailer-sendgrid';
import fetch from "node-fetch";
import { v4 as uuidv4 } from 'uuid';

const app = express();

app.use(express.json());
app.use(cors());

// 🔹 Neon DB connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// 🔹 SendGrid setup
const transporter = nodemailer.createTransport(
  nodemailerSendgrid({
    apiKey: process.env.SENDGRID_API_KEY
  })
);

// -------------------- ROUTES --------------------

// Root route
app.get('/', (req, res) => {
  res.send('Backend is running successfully!');
});

// 1. Create Client (verification only)
app.post('/create-client', async (req, res) => {
  const { company_email } = req.body;

  try {
    if (!company_email || !company_email.includes("@") || !company_email.includes(".")) {
      return res.status(400).json({ error: "Invalid email address." });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const sessionId = uuidv4();

    await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, attempts, session_id, verified)
       VALUES ($1, $2, NOW() + interval '1 hour', 0, $3, false)`,
      [company_email, token, sessionId]
    );

    const verifyUrl = `https://oneprojectapp-backend.onrender.com/verify?token=${token}`;
    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: company_email,
      subject: "Verify your OneProjectApp account",
      html: `<p>Click <a href="${verifyUrl}">here</a> to verify your account.</p>`
    });

    res.json({ success: true, message: 'Verification email sent.', sessionId });
  } catch (err) {
    console.error("Error sending verification:", err.stack);
    res.status(500).json({ error: 'Failed to send verification.' });
  }
});

// 2. Verify Client
app.get('/verify', async (req, res) => {
  const { token } = req.query;
  try {
    const result = await pool.query(
      `SELECT email, session_id, expires_at, attempts FROM email_tokens WHERE token=$1`,
      [token]
    );

    if (result.rows.length === 0) {
      return res.json({ verified: "failed" });
    }

    const { email, session_id, expires_at, attempts } = result.rows[0];

    if (new Date() > expires_at || attempts >= 2) {
      return res.json({ verified: "failed" });
    }

    await pool.query(`UPDATE clients SET verified=true WHERE company_email=$1`, [email]);
    await pool.query(`UPDATE email_tokens SET verified=true WHERE token=$1`, [token]);

    console.log("Verified email:", email);
    return res.json({ verified: true, sessionId: session_id });
  } catch (err) {
    console.error("Verification error:", err.message);
    res.json({ verified: "failed" });
  }
});

// 9. Resend Verification (max 2 attempts)
app.post('/resend-verification', async (req, res) => {
  const { email } = req.body;
  try {
    const check = await pool.query(
      `SELECT attempts, session_id FROM email_tokens WHERE email=$1 ORDER BY expires_at DESC LIMIT 1`,
      [email]
    );

    if (check.rows.length > 0 && check.rows[0].attempts >= 2) {
      return res.json({ success: false, redirect: "https://oneprojectapp.netlify.app/verify-failed.html" });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const newAttempts = check.rows.length ? check.rows[0].attempts + 1 : 1;
    const sessionId = check.rows.length ? check.rows[0].session_id : uuidv4();

    await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, attempts, session_id, verified)
       VALUES ($1, $2, NOW() + interval '1 hour', $3, $4, false)`,
      [email, token, newAttempts, sessionId]
    );

    const verifyUrl = `https://oneprojectapp-backend.onrender.com/verify?token=${token}`;
    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: "Resend Verification - OneProjectApp",
      html: `<p>Click <a href="${verifyUrl}">here</a> to verify your account.</p>`
    });

    res.json({ success: true, message: "Verification email resent.", sessionId });
  } catch (err) {
    console.error("Resend error:", err.message);
    res.status(500).json({ error: "Failed to resend verification." });
  }
});

// 3. Create Project
app.post('/create-project', async (req, res) => {
  const { name, location, contract_reference } = req.body;
  try {
    res.json({ success: true, message: 'Project details captured temporarily.' });
  } catch (err) {
    console.error("Error capturing project:", err);
    res.status(500).json({ error: 'Failed to capture project.' });
  }
});

// 4. Assign Team Members
app.post('/assign-team', async (req, res) => {
  const { members } = req.body;
  try {
    res.json({ success: true, message: 'Team members captured temporarily.' });
  } catch (err) {
    console.error("Error capturing team:", err);
    res.status(500).json({ error: 'Failed to capture team members.' });
  }
});

// 5. Finalize Account
app.post('/finalize-account', async (req, res) => {
  const { client, project, team_members } = req.body;

  try {
    const clientResult = await pool.query(
      `INSERT INTO clients 
       (company_name, company_email, representative_name, title, phone_number, password_hash, verified) 
       VALUES ($1, $2, $3, $4, $5, $6, true) 
       RETURNING id`,
      [
        client.company_name,
        client.company_email,
        client.representative_name,
        client.title,
        client.phone_number,
        client.password_hash
      ]
    );

    const client_id = clientResult.rows[0].id;

    const projectResult = await pool.query(
      `INSERT INTO projects (name, location, contract_reference, client_id, created_at)
       VALUES ($1, $2, $3, $4, NOW())
       RETURNING id`,
      [project.name, project.location, project.contract_reference, client_id]
    );

    const project_id = projectResult.rows[0].id;

    if (Array.isArray(team_members)) {
      for (const m of team_members) {
        await pool.query(
          `INSERT INTO team_members (name, position, task, email, project_id)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (email, project_id) DO NOTHING`,
          [m.name, m.position, m.task, m.email, project_id]
        );
      }
    }

    res.json({ success: true, message: "Account finalized successfully." });
  } catch (err) {
    console.error("Finalize error:", err);
    res.status(500).json({ success: false, error: "Server error finalizing account." });
  }
});

// 6. Verify Login
app.post('/verify-login', async (req, res) => {
  const { role, email, password } = req.body;

  try {
    let table, emailField;
    switch (role) {
      case "client": table = "clients"; emailField = "company_email"; break;
      case "consultant":
      case "contractor": table = "users"; emailField = "email"; break;
      case "consultant_pm":
      case "contractor_pm":
      case "team_member": table = "team_members"; emailField = "email"; break;
      default: return res.status(400).json({ success: false, error: "Invalid role." });
    }

    const result = await pool.query(`SELECT * FROM ${table} WHERE ${emailField}=$1`, [email]);
    if (result.rows.length === 0) return res.json({ success: false, error: "User not found." });

    const user = result.rows[0];
    if (!user.password_hash) {
      return res.json({ success: false, firstLogin: true });
    }

    if (user.password_hash !== password) {
      return res.json({ success: false, error: "Incorrect password." });
    }

        res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Server error." });
  }
});

// 7. First Login (send verification, store pending password)
app.post('/send-verification', async (req, res) => {
  const { email, role, password } = req.body;

  try {
    const token = crypto.randomBytes(32).toString('hex');
    const sessionId = uuidv4();

    await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, pending_password, session_id, verified)
       VALUES ($1, $2, NOW() + interval '1 hour', $3, $4, false)`,
      [email, token, password, sessionId]
    );

    const verifyUrl = `https://oneprojectapp-backend.onrender.com/verify?token=${token}&flow=reset`;
    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: 'Set your password',
      html: `<p>Click <a href="${verifyUrl}">here</a> to confirm and set your password.</p>`
    });

    res.json({ success: true, message: "Verification email sent.", sessionId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Failed to send verification." });
  }
});

// 8. Reset Password
app.post('/reset-password', async (req, res) => {
  const { email, role, token, password } = req.body;

  try {
    const tokenCheck = await pool.query(
      `SELECT * FROM email_tokens WHERE email=$1 AND token=$2 AND expires_at > NOW()`,
      [email, token]
    );
    if (tokenCheck.rows.length === 0) {
      return res.json({ success: false, error: "Invalid or expired token." });
    }

    const table = role === "client" ? "clients" :
                  (role === "consultant" || role === "contractor") ? "users" : "team_members";
    const emailField = role === "client" ? "company_email" : "email";

    await pool.query(
      `UPDATE ${table} SET password_hash=$1 WHERE ${emailField}=$2`,
      [password, email]
    );

    await pool.query(`DELETE FROM email_tokens WHERE email=$1`, [email]);

    res.json({ success: true, message: "Password reset successfully." });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ success: false, error: "Failed to reset password." });
  }
});

// 11. SendGrid Event Webhook (detect bounced/invalid emails)
app.post("/sendgrid-events", async (req, res) => {
  const events = req.body;
  for (const e of events) {
    if (e.event === "bounce" || e.event === "dropped" || e.event === "blocked") {
      console.log("Email failed:", e.email);
      await pool.query(
        `UPDATE clients SET verified=false WHERE company_email=$1`,
        [e.email]
      );
    }
  }
  res.status(200).send("OK");
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
