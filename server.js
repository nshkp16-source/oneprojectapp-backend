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
  const { email, code, client, project, contractor, consultant } = req.body;
  try {
    // Always check latest valid token for this email
    const result = await pool.query(
      `SELECT * FROM email_tokens 
       WHERE email=$1 AND token=$2 AND expires_at > NOW() AND verified=false
       ORDER BY expires_at DESC
       LIMIT 1`,
      [email, code]
    );

    if (result.rows.length === 0) {
      return res.json({ success: false, verified: false, error: "Invalid or expired code." });
    }

    const hashedPassword = client.password_hash ? await bcrypt.hash(client.password_hash, 10) : null;

    // Insert client
    const clientResult = await pool.query(
      `INSERT INTO clients (company_name, company_email, representative, title, telephone, password_hash, verified, created_at) 
       VALUES ($1,$2,$3,$4,$5,$6,true,NOW())
       ON CONFLICT (company_email) DO UPDATE SET 
         company_name=EXCLUDED.company_name,
         representative=EXCLUDED.representative,
         title=EXCLUDED.title,
         telephone=EXCLUDED.telephone,
         password_hash=EXCLUDED.password_hash,
         verified=true
       RETURNING id;`,
      [client.company_name, client.company_email, client.representative, client.title, client.telephone, hashedPassword]
    );
    const client_id = clientResult.rows[0].id;

    // Insert project
    const projectResult = await pool.query(
      `INSERT INTO projects (name, location, contract_reference, client_id, created_at, verified)
       VALUES ($1,$2,$3,$4,NOW(),true)
       ON CONFLICT (name, client_id) DO NOTHING RETURNING id;`,
      [project.name, project.location, project.contract_reference, client_id]
    );
    let project_id = projectResult.rows[0]?.id || (await pool.query(
      `SELECT id FROM projects WHERE name=$1 AND client_id=$2`, [project.name, client_id]
    )).rows[0].id;

    // Helper for contractor/consultant
    async function addUser(user, role) {
      if (!user?.email) return;
      const userResult = await pool.query(
        `INSERT INTO users (role, company_name, email, representative, title, telephone, created_at, verified, project_id)
         VALUES ($1,$2,$3,$4,$5,$6,NOW(),true,$7)
         ON CONFLICT (email, project_id) DO UPDATE SET 
           company_name=EXCLUDED.company_name,
           representative=EXCLUDED.representative,
           title=EXCLUDED.title,
           telephone=EXCLUDED.telephone,
           verified=true
         RETURNING id;`,
        [role, user.company, user.email, user.representative, user.title, user.telephone, project_id]
      );
      const user_id = userResult.rows[0].id;
      await pool.query(
        `INSERT INTO user_projects (user_id, project_id, created_at) VALUES ($1,$2,NOW())
         ON CONFLICT (user_id, project_id) DO NOTHING;`,
        [user_id, project_id]
      );
    }

    await addUser(contractor, "Contractor");
    await addUser(consultant, "Consultant");

    // ✅ Mark token as verified
    await pool.query(`UPDATE email_tokens SET verified=true WHERE id=$1`, [result.rows[0].id]);

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
    // Delete old unverified tokens for this email
    await pool.query(`DELETE FROM email_tokens WHERE email=$1 AND verified=false`, [email]);

    // Check latest token attempts (after cleanup, may be empty)
    const check = await pool.query(
      `SELECT attempts, session_id FROM email_tokens WHERE email=$1 ORDER BY expires_at DESC LIMIT 1`,
      [email]
    );

    let newAttempts = 1;
    let sessionId = uuidv4();

    if (check.rows.length > 0) {
      if (check.rows[0].attempts >= 2) {
        // Too many resends → cleanup client/project
        await pool.query(`DELETE FROM users WHERE project_id IN (SELECT id FROM projects WHERE client_id IN (SELECT id FROM clients WHERE company_email=$1 AND verified=false))`, [email]);
        await pool.query(`DELETE FROM projects WHERE client_id IN (SELECT id FROM clients WHERE company_email=$1 AND verified=false)`, [email]);
        await pool.query(`DELETE FROM clients WHERE company_email=$1 AND verified=false`, [email]);
        return res.json({ success: false, error: "Resend attempts exceeded. Please restart account creation." });
      }
      newAttempts = check.rows[0].attempts + 1;
      sessionId = check.rows[0].session_id || uuidv4();
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();

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

// 4. First Login (send verification code only)
app.post("/send-verification", async (req, res) => {
  const { email } = req.body;
  try {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = uuidv4();

    // Insert and confirm row
    const insertResult = await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, session_id, verified, reset_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',$3,false,false)
       RETURNING *`,
      [email, code, sessionId]
    );

    console.log("Inserted token:", insertResult.rows[0]);

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

// 5. Resend verification code (first login)
app.post("/resend-verification", async (req, res) => {
  const { email } = req.body;
  try {
    // Clean up old unverified tokens
    await pool.query(
      `DELETE FROM email_tokens 
       WHERE email=$1 AND verified=false AND reset_flow=false`,
      [email]
    );

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = uuidv4();

    const insertResult = await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, session_id, verified, reset_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',$3,false,false)
       RETURNING *`,
      [email, code, sessionId]
    );

    console.log("Inserted new token:", insertResult.rows[0]);

    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: "Resend verification - OneProjectApp",
      html: `<p>Your new verification code is: <b>${code}</b></p>
             <p>This code will expire in 3 minutes.</p>`
    });

    res.json({ success: true, message: "New verification code sent.", sessionId });
  } catch (err) {
    console.error("Resend verification error:", err);
    res.status(500).json({ success: false, error: "Failed to resend verification." });
  }
});

// 6. Verify code only (no password commit here)
app.post('/verify-password-code', async (req, res) => {
  const { email, token } = req.body;
  try {
    console.log("Verifying code:", token, "for email:", email);

    const tokenCheck = await pool.query(
      `SELECT * FROM email_tokens 
       WHERE email=$1 AND token=$2 
       AND expires_at > NOW() 
       AND verified=false AND reset_flow=false
       ORDER BY expires_at DESC LIMIT 1`,
      [email, token]
    );

    console.log("DB result:", tokenCheck.rows);

    if (tokenCheck.rows.length === 0) {
      return res.json({ success: false, error: "Invalid or expired code." });
    }

    await pool.query(`UPDATE email_tokens SET verified=true WHERE id=$1`, [tokenCheck.rows[0].id]);

    res.json({ success: true, message: "Code verified. You may now set your password." });
  } catch (err) {
    console.error("Verify password code error:", err);
    res.status(500).json({ success: false, error: "Failed to verify code." });
  }
});

// 7. Set password after verification
app.post("/set-password", async (req, res) => {
  const { email, password } = req.body;
  try {
    console.log("Setting password for:", email);

    const hash = await bcrypt.hash(password, 10);

    const clientResult = await pool.query(`SELECT id FROM clients WHERE company_email=$1`, [email]);
    if (clientResult.rows.length > 0) {
      await pool.query(
        `UPDATE clients SET password_hash=$1, verified=true WHERE company_email=$2`,
        [hash, email]
      );
      console.log("Password set for client:", email);
    } else {
      await pool.query(
        `UPDATE users SET password_hash=$1, verified=true WHERE email=$2`,
        [hash, email]
      );
      console.log("Password set for user:", email);
    }

    res.json({ success: true, message: "Password set successfully." });
  } catch (err) {
    console.error("Set password error:", err);
    res.status(500).json({ success: false, error: "Failed to set password." });
  }
});

// 8. Reset Password (send verification code)
app.post('/reset-send', async (req, res) => {
  const { email } = req.body;
  try {
    // 1. Check if user has an existing password
    const clientResult = await pool.query(
      `SELECT password_hash FROM clients WHERE company_email=$1`,
      [email]
    );
    const userResult = await pool.query(
      `SELECT password_hash FROM users WHERE email=$1`,
      [email]
    );

    let passwordHash = null;
    if (clientResult.rows.length > 0) {
      passwordHash = clientResult.rows[0].password_hash;
    } else if (userResult.rows.length > 0) {
      passwordHash = userResult.rows[0].password_hash;
    }

    // 2. If no password exists, block reset flow
    if (!passwordHash) {
      return res.json({
        success: false,
        error: "This account has no password yet. Please follow the first‑login flow to set your password."
      });
    }

    // 3. Delete any existing token for this email
    await pool.query(`DELETE FROM email_tokens WHERE email=$1`, [email]);

    // 4. Create new token
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = uuidv4();

    const insertResult = await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, session_id, verified, reset_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',$3,false,true)
       RETURNING *`,
      [email, code, sessionId]
    );

    // 5. Send email immediately
    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: 'Reset your password - OneProjectApp',
      html: `<p>Your reset code is: <b>${code}</b></p>
             <p>This code will expire in 3 minutes.</p>`
    });

    // 6. Return success + expiry timestamp
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
  const { email } = req.body;
  try {
    // 1. Check if user has an existing password
    const clientResult = await pool.query(
      `SELECT password_hash FROM clients WHERE company_email=$1`,
      [email]
    );
    const userResult = await pool.query(
      `SELECT password_hash FROM users WHERE email=$1`,
      [email]
    );

    let passwordHash = null;
    if (clientResult.rows.length > 0) {
      passwordHash = clientResult.rows[0].password_hash;
    } else if (userResult.rows.length > 0) {
      passwordHash = userResult.rows[0].password_hash;
    }

    // 2. If no password exists, block reset flow
    if (!passwordHash) {
      return res.json({
        success: false,
        error: "This account has no password yet. Please follow the first‑login flow to set your password."
      });
    }

    // 3. Delete any existing token for this email
    await pool.query(`DELETE FROM email_tokens WHERE email=$1`, [email]);

    // 4. Create new token
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionId = uuidv4();

    const insertResult = await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, session_id, verified, reset_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',$3,false,true)
       RETURNING *`,
      [email, code, sessionId]
    );

    // 5. Send email immediately
    await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: "Resend reset code - OneProjectApp",
      html: `<p>Your new reset code is: <b>${code}</b></p>
             <p>This code will expire in 3 minutes.</p>`
    });

    // 6. Return success + expiry timestamp
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

// 10. Verify reset password code
app.post('/reset-verify', async (req, res) => {
  const { email, token } = req.body;
  try {
    const tokenCheck = await pool.query(
      `SELECT * FROM email_tokens 
       WHERE email=$1 AND token=$2 AND expires_at > NOW() AND verified=false AND reset_flow=true
       ORDER BY expires_at DESC LIMIT 1`,
      [email, token]
    );

    if (tokenCheck.rows.length === 0) {
      return res.json({ success: false, error: "Invalid or expired code." });
    }

    await pool.query(`UPDATE email_tokens SET verified=true WHERE id=$1`, [tokenCheck.rows[0].id]);

    res.json({ success: true, message: "Code verified. You may now set your new password." });
  } catch (err) {
    console.error("Verify reset code error:", err);
    res.status(500).json({ success: false, error: "Failed to verify reset code." });
  }
});

// 11. Save new password after verification
app.post('/reset-set-password', async (req, res) => {
  const { email, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);

    const clientResult = await pool.query(`SELECT id FROM clients WHERE company_email=$1`, [email]);
    if (clientResult.rows.length > 0) {
      await pool.query(
        `UPDATE clients SET password_hash=$1, verified=true WHERE company_email=$2`,
        [hash, email]
      );
      console.log("Password reset for client:", email);
    } else {
      await pool.query(
        `UPDATE users SET password_hash=$1, verified=true WHERE email=$2`,
        [hash, email]
      );
      console.log("Password reset for user:", email);
    }

    res.json({ success: true, message: "Password reset successfully." });
  } catch (err) {
    console.error("Reset set password error:", err);
    res.status(500).json({ success: false, error: "Failed to reset password." });
  }
});

// 12. SendGrid Event Webhook
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

// 13. Check Email Exists (fix role casing)
app.post("/check-email", async (req, res) => {
  const { email, role } = req.body;
  try {
    let result;
    if (role === "Client") {
      result = await pool.query(`SELECT id FROM clients WHERE company_email=$1`, [email]);
    } else {
      result = await pool.query(`SELECT id FROM users WHERE email=$1 AND role=$2`, [email, role]);
    }

    res.json({ exists: result.rows.length > 0 });
  } catch (err) {
    console.error("Check email error:", err);
    res.status(500).json({ success: false, error: "Server error checking email." });
  }
});

// 14. Cleanup expired tokens (manual trigger)
app.post("/cleanup-tokens", async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM email_tokens 
       WHERE expires_at < NOW() 
       AND verified=false`
    );

    res.json({
      success: true,
      message: `Expired tokens cleaned up.`,
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
}, 3 * 60 * 1000); // 3 minutes in milliseconds

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
