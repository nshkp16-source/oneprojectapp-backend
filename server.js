// server.js
import express from 'express';
import { Pool } from 'pg';
import nodemailer from 'nodemailer';
import cors from 'cors';
import nodemailerSendgrid from 'nodemailer-sendgrid';
import fetch from "node-fetch";
import pkg from 'uuid';
import bcrypt from 'bcryptjs';
const { v4: uuidv4 } = pkg;

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
  nodemailerSendgrid({ apiKey: process.env.SENDGRID_API_KEY })
);

// -------------------- ROUTES --------------------

// Root route
app.get('/', (req, res) => res.send('Backend is running successfully!'));

// 1. Finalize Account (send verification only)
app.post("/finalize-account", async (req, res) => {
  const { clientEmail } = req.body;
  try {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = uuidv4();

    await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, attempts, session_id, verified, reset_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',0,$3,false,false)`,
      [clientEmail, code, sessionId]
    );

    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: clientEmail,
      subject: "Verify your OneProjectApp account",
      html: `<p>Your verification code is: <b>${code}</b></p><p>This code will expire in 3 minutes.</p>`
    });

    res.json({ success: true, message: "Verification email sent.", sessionId });
  } catch (err) {
    console.error("Finalize error:", err);
    res.status(500).json({ success: false, error: "Server error finalizing account." });
  }
});

// 2. Verify Code (commit staged data)
app.post("/verify-code", async (req, res) => {
  const { email, sessionId, code, client, project, contractor, consultant, team_members } = req.body;
  try {
    const result = await pool.query(
      `SELECT * FROM email_tokens WHERE email=$1 AND session_id=$2 AND token=$3 AND expires_at > NOW() AND verified=false`,
      [email, sessionId, code]
    );
    if (result.rows.length === 0) return res.json({ success: false, verified: false, error: "Invalid or expired code." });

    const hashedPassword = client.password_hash ? await bcrypt.hash(client.password_hash, 10) : null;

    const clientResult = await pool.query(
      `INSERT INTO clients (company_name, company_email, representative_name, title, phone_number, password_hash, verified, created_at) 
       VALUES ($1,$2,$3,$4,$5,$6,true,NOW())
       ON CONFLICT (company_email) DO UPDATE SET 
         company_name=EXCLUDED.company_name,
         representative_name=EXCLUDED.representative_name,
         title=EXCLUDED.title,
         phone_number=EXCLUDED.phone_number,
         password_hash=EXCLUDED.password_hash,
         verified=true
       RETURNING id;`,
      [client.company_name, client.company_email, client.representative_name, client.title, client.phone_number, hashedPassword]
    );
    const client_id = clientResult.rows[0].id;

    const projectResult = await pool.query(
      `INSERT INTO projects (name, location, contract_reference, client_id, created_at, verified)
       VALUES ($1,$2,$3,$4,NOW(),true)
       ON CONFLICT (name, client_id) DO NOTHING RETURNING id;`,
      [project.name, project.location, project.contract_reference, client_id]
    );
    let project_id = projectResult.rows[0]?.id || (await pool.query(
      `SELECT id FROM projects WHERE name=$1 AND client_id=$2`, [project.name, client_id]
    )).rows[0].id;

    async function addUser(user) {
      if (!user?.email) return;
      const userResult = await pool.query(
        `INSERT INTO users (email, representative_name, title, phone_number, created_at, verified, project_id)
         VALUES ($1,$2,$3,$4,NOW(),true,$5)
         ON CONFLICT (email) DO UPDATE SET 
           representative_name=EXCLUDED.representative_name,
           title=EXCLUDED.title,
           phone_number=EXCLUDED.phone_number,
           verified=true
         RETURNING id;`,
        [user.email, user.repName || user.name, user.repTitle || user.position, user.tel || null, project_id]
      );
      const user_id = userResult.rows[0].id;
      await pool.query(
        `INSERT INTO user_projects (user_id, project_id, created_at) VALUES ($1,$2,NOW())
         ON CONFLICT (user_id, project_id) DO NOTHING;`,
        [user_id, project_id]
      );
    }
    await addUser(contractor);
    await addUser(consultant);
    if (Array.isArray(team_members)) for (const m of team_members) await addUser(m);

    await pool.query(`UPDATE email_tokens SET verified=true WHERE email=$1 AND session_id=$2`, [email, sessionId]);

    return res.json({ success: true, verified: true, message: "Account verified and data committed." });
  } catch (err) {
    console.error("Verification error:", err.message);
    res.status(500).json({ success: false, verified: false, error: "Server error verifying code." });
  }
});

// 3. Resend Verification (with cleanup)
app.post("/resend-verification", async (req, res) => {
  const { email } = req.body;
  try {
    const check = await pool.query(
      `SELECT attempts, session_id FROM email_tokens WHERE email=$1 ORDER BY expires_at DESC LIMIT 1`,
      [email]
    );
    if (check.rows.length > 0 && check.rows[0].attempts >= 2) {
      await pool.query(`DELETE FROM team_members WHERE project_id IN (SELECT id FROM projects WHERE client_id IN (SELECT id FROM clients WHERE company_email=$1 AND verified=false))`, [email]);
      await pool.query(`DELETE FROM users WHERE project_id IN (SELECT id FROM projects WHERE client_id IN (SELECT id FROM clients WHERE company_email=$1 AND verified=false))`, [email]);
      await pool.query(`DELETE FROM projects WHERE client_id IN (SELECT id FROM clients WHERE company_email=$1 AND verified=false)`, [email]);
      await pool.query(`DELETE FROM clients WHERE company_email=$1 AND verified=false`, [email]);
      return res.json({ success: false, error: "Resend attempts exceeded. Please restart account creation." });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const newAttempts = check.rows.length ? check.rows[0].attempts + 1 : 1;
    const sessionId = check.rows.length ? check.rows[0].session_id : uuidv4();

    await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, attempts, session_id, verified)
       VALUES ($1,$2,NOW() + interval '3 minutes',$3,$4,false)`,
      [email, code, newAttempts, sessionId]
    );

    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: "Resend Verification Code - OneProjectApp",
      html: `<p>Your new verification code is: <b>${code}</b></p><p>This code will expire in 3 minutes.</p>`
    });

    res.json({ success: true, message: "Verification code resent.", sessionId });
  } catch (err) {
    console.error("Resend error:", err.message);
    res.status(500).json({ success: false, error: "Failed to resend verification." });
  }
});

// 4. First Login (send verification, store pending password)
app.post("/send-verification", async (req, res) => {
  const { email, password } = req.body;
  try {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = uuidv4();
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, pending_password, session_id, verified, reset_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',$3,$4,false,false)`,
      [email, code, hashedPassword, sessionId]
    );

    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: "Set your password - OneProjectApp",
      html: `<p>Your verification code is: <b>${code}</b></p>
             <p>This code will expire in 3 minutes.</p>`
    });

    res.json({ success: true, message: "Verification code sent.", sessionId });
  } catch (err) {
    console.error("Send verification error:", err);
    res.status(500).json({ success: false, error: "Failed to send verification." });
  }
});

// 5. Verify code and finalize first login OR reset password
app.post('/verify-password-code', async (req, res) => {
  const { email, token } = req.body;
  try {
    const tokenCheck = await pool.query(
      `SELECT * FROM email_tokens WHERE email=$1 AND token=$2 AND expires_at > NOW() AND verified=false`,
      [email, token]
    );
    if (tokenCheck.rows.length === 0) {
      return res.json({ success: false, error: "Invalid or expired code." });
    }

    const pendingPassword = tokenCheck.rows[0].pending_password;
    const isReset = tokenCheck.rows[0].reset_flow === true;
    const hashedPassword = await bcrypt.hash(pendingPassword, 10);

    const clientResult = await pool.query(`SELECT id FROM clients WHERE company_email=$1`, [email]);
    if (clientResult.rows.length > 0) {
      await pool.query(
        `UPDATE clients SET password_hash=$1, verified=true WHERE company_email=$2`,
        [hashedPassword, email]
      );
    } else {
      await pool.query(
        `UPDATE users SET password_hash=$1, verified=true WHERE email=$2`,
        [hashedPassword, email]
      );
    }

    await pool.query(`UPDATE email_tokens SET verified=true WHERE id=$1`, [tokenCheck.rows[0].id]);

    if (isReset) {
      res.json({ success: true, message: "Password reset successfully." });
    } else {
      res.json({ success: true, message: "Account verified and password set." });
    }
  } catch (err) {
    console.error("Verify password code error:", err);
    res.status(500).json({ success: false, error: "Failed to verify code." });
  }
});

// 6. Reset Password (initiate reset by sending verification code)
app.post('/reset-password', async (req, res) => {
  const { email, password } = req.body;
  try {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = uuidv4();
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, pending_password, session_id, verified, reset_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',$3,$4,false,true)`,
      [email, code, hashedPassword, sessionId]
    );

    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: 'Reset your password - OneProjectApp',
      html: `<p>Your password reset code is: <b>${code}</b></p>
             <p>This code will expire in 3 minutes.</p>`
    });

    res.json({ success: true, message: "Reset code sent.", sessionId });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ success: false, error: "Failed to send reset code." });
  }
});

// 7. SendGrid Event Webhook (detect bounced/invalid emails)
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

// 🔹 Keep-alive ping (Render auto-sleep prevention)
setInterval(() => {
  fetch("https://oneprojectapp-backend.onrender.com/")
    .then(res => console.log("Keep-alive ping:", res.status))
    .catch(err => console.error("Keep-alive error:", err));
}, 14 * 60 * 1000);

export default app;
