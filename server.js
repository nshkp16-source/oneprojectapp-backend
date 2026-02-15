// server.js
import express from 'express';
import crypto from 'crypto';
import { Pool } from 'pg';
import nodemailer from 'nodemailer';
import cors from 'cors';
import nodemailerSendgrid from 'nodemailer-sendgrid';
import fetch from "node-fetch";

const app = express();

// ✅ Built-in JSON parser
app.use(express.json());
app.use(cors()); // allow Netlify frontend to call backend

// 🔹 Neon DB connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // set this in Render
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
    if (!company_email) {
      return res.status(400).json({ error: "Company email is required." });
    }

    const token = crypto.randomBytes(32).toString('hex');
    await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at)
       VALUES ($1, $2, NOW() + interval '1 hour')`,
      [company_email, token]
    );

    const verifyUrl = `https://oneprojectapp-backend.onrender.com/verify?token=${token}`;
    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com", // must match verified sender
      to: company_email,
      subject: "Verify your OneProjectApp account",
      text: "Click the link to verify your account...",
      html: `<p>Click <a href="${verifyUrl}">here</a> to verify your account.</p>`
    });

    res.json({ success: true, message: 'Verification email sent.' });
  } catch (err) {
    console.error("Error sending verification:", err);
    res.status(500).json({ error: 'Failed to send verification.' });
  }
});

// 2. Verify Client (handles normal + reset flows)
app.get('/verify', async (req, res) => {
  const { token, flow } = req.query;

  try {
    const result = await pool.query(
      `SELECT email FROM email_tokens WHERE token=$1 AND expires_at > NOW()`,
      [token]
    );

    if (result.rows.length === 0) {
      return res.redirect('/verify-failed.html');
    }

    const email = result.rows[0].email;
    console.log(`Verified email: ${email}`);

    if (flow === "reset") {
      return res.redirect('/reset-password.html?token=' + token);
    } else {
      return res.redirect('/verify-success.html');
    }
  } catch (err) {
    console.error("Verification error:", err);
    res.redirect('/verify-failed.html');
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

// 7. First Login (send verification)
app.post('/send-verification', async (req, res) => {
  const { email, role, password } = req.body;

  try {
    const token = crypto.randomBytes(32).toString('hex');
    await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at)
       VALUES ($1, $2, NOW() + interval '1 hour')`,
      [email, token]
    );

    const verifyUrl = `https://oneprojectapp-backend.onrender.com/verify?token=${token}&flow=reset`;
    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com", // must match verified sender
      to: email,
      subject: 'Set your password',
      text: "Click the link to set your password...",
      html: `<p>Click <a href="${verifyUrl}">here</a> to confirm and set your password.</p>`
    });

    const table = role === "client" ? "clients" :
                  (role === "consultant" || role === "contractor") ? "users" : "team_members";
    const emailField = role === "client" ? "company_email" : "email";

    await pool.query(
      `UPDATE ${table} SET password_hash=$1 WHERE ${emailField}=$2`,
      [password, email]
    );

    res.json({ success: true, message: "Verification email sent." });
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

    // ✅ Clean up token after successful reset
    await pool.query(`DELETE FROM email_tokens WHERE email=$1`, [email]);

    res.json({ success: true, message: "Password reset successfully." });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ success: false, error: "Failed to reset password." });
  }
});

// 9. Resend Verification (max 2 attempts, then redirect to verify-failed.html)
app.post('/resend-verification', async (req, res) => {
  const { email, resendCount } = req.body;

  try {
    if (resendCount >= 2) {
      return res.json({ success: false, redirect: "/verify-failed.html" });
    }

    const token = crypto.randomBytes(32).toString('hex');
    await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at)
       VALUES ($1, $2, NOW() + interval '1 hour')`,
      [email, token]
    );

    const verifyUrl = `https://oneprojectapp-backend.onrender.com/verify?token=${token}`;
    await transporter.sendMail({
      from: "skyprincekp16@gmail.com",
      to: email,
      subject: "Resend Verification - OneProjectApp",
      text: "Click the link to verify your account...",
      html: `<p>Click <a href="${verifyUrl}">here</a> to verify your account.</p>`
    });

    res.json({ success: true, message: "Verification email resent." });
  } catch (err) {
    console.error("Resend error:", err);
    res.status(500).json({ error: "Failed to resend verification." });
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

// 🔹 Keep-alive ping to prevent Render free tier sleep
setInterval(() => {
  fetch("https://oneprojectapp-backend.onrender.com/")
    .then(res => console.log("Keep-alive ping:", res.status))
    .catch(err => console.error("Keep-alive error:", err));
}, 14 * 60 * 1000); // every 14 minutes

export default app; // optional for testing
