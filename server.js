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
      `INSERT INTO email_tokens (email, token, expires_at, attempts, session_id, verified, reset_flow)
       VALUES ($1, $2, NOW() + interval '3 minutes', 0, $3, false, false)`,
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
      return res.json({
        success: false,
        verified: false,
        error: "Invalid or expired code."
      });
    }

    // Hash password if provided
    const hashedPassword = client.password_hash
      ? await bcrypt.hash(client.password_hash, 10)
      : null;

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
      [
        client.company_name,
        client.company_email,
        client.representative,
        client.title,
        client.telephone,
        hashedPassword
      ]
    );
    const client_id = clientResult.rows[0].id;

    // Insert project
    const projectResult = await pool.query(
      `INSERT INTO projects (name, location, contract_reference, client_id, created_at, verified)
       VALUES ($1,$2,$3,$4,NOW(),true)
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
        [
          role,
          user.company,
          user.email,
          user.representative,
          user.title,
          user.telephone,
          project_id
        ]
      );

      const user_id = userResult.rows[0].id;

      await pool.query(
        `INSERT INTO user_projects (user_id, project_id, created_at) 
         VALUES ($1,$2,NOW())
         ON CONFLICT (user_id, project_id) DO NOTHING;`,
        [user_id, project_id]
      );
    }

    await addUser(contractor, "Contractor");
    await addUser(consultant, "Consultant");

    // ✅ Mark token as verified
    await pool.query(`UPDATE email_tokens SET verified=true WHERE id=$1`, [
      result.rows[0].id
    ]);

    return res.json({
      success: true,
      verified: true,
      message: "Account verified and data committed."
    });
  } catch (err) {
    console.error("Verification error:", err.message);
    res.status(500).json({
      success: false,
      verified: false,
      error: "Server error verifying code."
    });
  }
});

// 3. Resend Verification (with cleanup)
app.post("/resend-verification", async (req, res) => {
  const { email } = req.body;
  try {
    // Delete old unverified tokens for this email
    await pool.query(
      `DELETE FROM email_tokens WHERE email=$1 AND verified=false`,
      [email]
    );

    // Check latest token attempts (after cleanup, may be empty)
    const check = await pool.query(
      `SELECT attempts, session_id FROM email_tokens 
       WHERE email=$1 ORDER BY expires_at DESC LIMIT 1`,
      [email]
    );

    let newAttempts = 1;
    let sessionId = uuidv4();

    if (check.rows.length > 0) {
      if (check.rows[0].attempts >= 2) {
        // Too many resends → cleanup client/project
        await pool.query(
          `DELETE FROM users WHERE project_id IN (
             SELECT id FROM projects WHERE client_id IN (
               SELECT id FROM clients WHERE company_email=$1 AND verified=false
             )
           )`,
          [email]
        );
        await pool.query(
          `DELETE FROM projects WHERE client_id IN (
             SELECT id FROM clients WHERE company_email=$1 AND verified=false
           )`,
          [email]
        );
        await pool.query(
          `DELETE FROM clients WHERE company_email=$1 AND verified=false`,
          [email]
        );
        return res.json({
          success: false,
          error: "Resend attempts exceeded. Please restart account creation."
        });
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

    const insertResult = await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, session_id, verified, reset_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',$3,false,false)
       RETURNING *`,
      [email, code, sessionId]
    );

    console.log("Inserted token:", insertResult.rows[0]);

    const info = await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: "OneProjectApp Verification Code",
      html: `<p>Your verification code is: <b>${code}</b></p>
             <p>This code will expire in 3 minutes.</p>`
    });
    console.log("Mail response:", info);

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

    const insertResult = await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at, session_id, verified, reset_flow)
       VALUES ($1,$2,NOW() + interval '3 minutes',$3,false,false)
       RETURNING *`,
      [email, code, sessionId]
    );

    console.log("Inserted new token:", insertResult.rows[0]);

    const info = await transporter.sendMail({
      from: "skyprincenkp16@gmail.com",
      to: email,
      subject: "OneProjectApp Verification Code (Resend)",
      html: `<p>Your new verification code is: <b>${code}</b></p>
             <p>This code will expire in 3 minutes.</p>`
    });
    console.log("Mail response:", info);

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

    await pool.query(`UPDATE email_tokens SET verified=true WHERE id=$1`, [
      tokenCheck.rows[0].id
    ]);

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

    const clientResult = await pool.query(
      `SELECT id FROM clients WHERE company_email=$1`,
      [email]
    );

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

// 12. LOGIN route (Client + Non-Client users)
app.post("/login", async (req, res) => {
  const { email, password, role } = req.body;
  try {
    let result;

    // 🔹 Check Client table
    if (role === "Client") {
      result = await pool.query(
        `SELECT id, company_name, company_email, representative, title, telephone, password_hash, verified 
         FROM clients WHERE company_email=$1`,
        [email]
      );
    } else {
      // 🔹 Check Users table for non-client roles
      result = await pool.query(
        `SELECT id, role, company_name, email, representative, title, telephone, password_hash, verified, project_id 
         FROM users WHERE email=$1 AND role=$2`,
        [email, role]
      );
    }

    // 🔹 Account not found
    if (result.rows.length === 0) {
      return res.json({ success: false, error: "Account not found." });
    }

    const user = result.rows[0];

    // 🔹 Guardrail: no password yet → must follow first-login
    if (!user.password_hash) {
      return res.json({
        success: false,
        error: "No password set yet. Follow the top first login guideline."
      });
    }

    // 🔹 Compare password
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.json({ success: false, error: "Invalid password." });
    }

    // 🔹 Check verified status
    if (!user.verified) {
      return res.json({ success: false, error: "Account not verified. Please check your email." });
    }

    // 🔹 Success response
    res.json({
      success: true,
      message: "Login successful.",
      role: role,
      userDetails: {
        id: user.id,
        email: role === "Client" ? user.company_email : user.email,
        company_name: user.company_name,
        representative: user.representative,
        title: user.title,
        telephone: user.telephone,
        project_id: user.project_id || null
      }
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, error: "Server error logging in." });
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

// 14. Check Email Exists (fix role casing)
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

// 16.=========== CLIENT PROFILE ROUTES =============

// ✅ Multer is already imported at the top: import multer from "multer";
const upload = multer({
  limits: { fileSize: 1024 * 1024 }, // 1MB limit
  storage: multer.diskStorage({
    destination: "uploads/",
    filename: (req, file, cb) => {
      cb(null, Date.now() + "-" + file.originalname);
    }
  })
});

// ✅ Serve uploads folder publicly
app.use("/uploads", express.static("uploads"));

// Fetch client profile + projects (only projects where user is the client)
app.post("/client/profile", async (req, res) => {
  try {
    const { email } = req.body;

    // Fetch client info
    const clientResult = await pool.query(
      "SELECT id, company_email AS email, 'Client' AS role, profile_picture FROM clients WHERE company_email=$1",
      [email]
    );

    if (clientResult.rows.length === 0) {
      return res.status(404).json({ error: "Client not found" });
    }

    const client = clientResult.rows[0];

    // ✅ Only fetch projects where this user is the client
    const projectsResult = await pool.query(
      "SELECT id, name, location, contract_reference, created_at FROM projects WHERE client_id=$1",
      [client.id]
    );

    client.projects = projectsResult.rows;

    // If only one project, mark it as default
    if (client.projects.length === 1) {
      client.defaultProject = client.projects[0];
    }

    res.json(client);
  } catch (err) {
    console.error("Fetch client profile error:", err);
    res.status(500).json({ error: "Failed to fetch client profile" });
  }
});

// Upload client profile picture
app.post("/client/upload-picture", upload.single("profile_picture"), async (req, res) => {
  try {
    const { email } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded or file too large." });
    }

    // ✅ Use full Render backend URL
    const fileUrl = `https://oneprojectapp-backend.onrender.com/uploads/${req.file.filename}`;

    await pool.query(
      "UPDATE clients SET profile_picture=$1 WHERE company_email=$2",
      [fileUrl, email]
    );

    res.json({ success: true, url: fileUrl });
  } catch (err) {
    console.error("Upload client picture error:", err);
    res.status(500).json({ error: "Failed to upload client picture" });
  }
});

// Delete client profile picture
app.post("/client/delete-picture", async (req, res) => {
  try {
    const { email } = req.body;

    await pool.query(
      "UPDATE clients SET profile_picture=NULL WHERE company_email=$1",
      [email]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Delete client picture error:", err);
    res.status(500).json({ error: "Failed to delete client picture" });
  }
});

// Fetch project details for a specific client project
app.post("/client/project-details", async (req, res) => {
  try {
    const { email, projectId } = req.body;

    // Verify client exists
    const clientResult = await pool.query(
      "SELECT id, company_email AS email, 'Client' AS role, profile_picture FROM clients WHERE company_email=$1",
      [email]
    );
    if (clientResult.rows.length === 0) {
      return res.status(404).json({ error: "Client not found" });
    }
    const client = clientResult.rows[0];

    // ✅ Verify project belongs to this client
    const projectResult = await pool.query(
      "SELECT id, name, location, contract_reference, created_at FROM projects WHERE id=$1 AND client_id=$2",
      [projectId, client.id]
    );
    if (projectResult.rows.length === 0) {
      return res.status(404).json({ error: "Project not found or not owned by client" });
    }
    const project = projectResult.rows[0];

    // ✅ Only return client + project info
    res.json({
      client: {
        email: client.email,
        role: client.role,
        profile_picture: client.profile_picture
      },
      project: project
    });
  } catch (err) {
    console.error("Fetch project details error:", err);
    res.status(500).json({ error: "Failed to fetch project details" });
  }
});

// 17. ============ CONTRACTOR PROFILE ROUTES =============

// Fetch contractor profile + projects (projects linked via users.project_id)
app.post("/contractor/profile", async (req, res) => {
  try {
    const { email } = req.body;

    // Fetch contractor info from users table
    const contractorResult = await pool.query(
      "SELECT id, email, role, profile_picture, project_id FROM users WHERE email=$1 AND role='Contractor'",
      [email]
    );

    if (contractorResult.rows.length === 0) {
      return res.status(404).json({ error: "Contractor not found" });
    }

    const contractor = contractorResult.rows[0];

    // Fetch projects using project_id from users table
    const projectsResult = await pool.query(
      "SELECT id, name, location, contract_reference, created_at FROM projects WHERE id=$1",
      [contractor.project_id]
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
app.post("/contractor/upload-picture", upload.single("profile_picture"), async (req, res) => {
  try {
    const { email } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded or file too large." });
    }

    const fileUrl = `https://oneprojectapp-backend.onrender.com/uploads/${req.file.filename}`;

    await pool.query(
      "UPDATE users SET profile_picture=$1 WHERE email=$2 AND role='Contractor'",
      [fileUrl, email]
    );

    res.json({ success: true, url: fileUrl });
  } catch (err) {
    console.error("Upload contractor picture error:", err);
    res.status(500).json({ error: "Failed to upload contractor picture" });
  }
});

// Delete contractor profile picture
app.post("/contractor/delete-picture", async (req, res) => {
  try {
    const { email } = req.body;

    await pool.query(
      "UPDATE users SET profile_picture=NULL WHERE email=$1 AND role='Contractor'",
      [email]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Delete contractor picture error:", err);
    res.status(500).json({ error: "Failed to delete contractor picture" });
  }
});

// Fetch project details for a specific contractor project
app.post("/contractor/project-details", async (req, res) => {
  try {
    const { email, projectId } = req.body;

    const contractorResult = await pool.query(
      "SELECT id, email, role, profile_picture, project_id FROM users WHERE email=$1 AND role='Contractor'",
      [email]
    );
    if (contractorResult.rows.length === 0) {
      return res.status(404).json({ error: "Contractor not found" });
    }
    const contractor = contractorResult.rows[0];

    // Ensure the requested projectId matches the contractor's project_id
    if (contractor.project_id != projectId) {
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

// 18. ============ CONSULTANT PROFILE ROUTES =============

// Fetch consultant profile + projects (projects linked via users.project_id)
app.post("/consultant/profile", async (req, res) => {
  try {
    const { email } = req.body;

    // Fetch consultant info from users table
    const consultantResult = await pool.query(
      "SELECT id, email, role, profile_picture, project_id FROM users WHERE email=$1 AND role='Consultant'",
      [email]
    );

    if (consultantResult.rows.length === 0) {
      return res.status(404).json({ error: "Consultant not found" });
    }

    const consultant = consultantResult.rows[0];

    // Fetch projects using project_id from users table
    const projectsResult = await pool.query(
      "SELECT id, name, location, contract_reference, created_at FROM projects WHERE id=$1",
      [consultant.project_id]
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
app.post("/consultant/upload-picture", upload.single("profile_picture"), async (req, res) => {
  try {
    const { email } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded or file too large." });
    }

    const fileUrl = `https://oneprojectapp-backend.onrender.com/uploads/${req.file.filename}`;

    await pool.query(
      "UPDATE users SET profile_picture=$1 WHERE email=$2 AND role='Consultant'",
      [fileUrl, email]
    );

    res.json({ success: true, url: fileUrl });
  } catch (err) {
    console.error("Upload consultant picture error:", err);
    res.status(500).json({ error: "Failed to upload consultant picture" });
  }
});

// Delete consultant profile picture
app.post("/consultant/delete-picture", async (req, res) => {
  try {
    const { email } = req.body;

    await pool.query(
      "UPDATE users SET profile_picture=NULL WHERE email=$1 AND role='Consultant'",
      [email]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Delete consultant picture error:", err);
    res.status(500).json({ error: "Failed to delete consultant picture" });
  }
});

// Fetch project details for a specific consultant project
app.post("/consultant/project-details", async (req, res) => {
  try {
    const { email, projectId } = req.body;

    const consultantResult = await pool.query(
      "SELECT id, email, role, profile_picture, project_id FROM users WHERE email=$1 AND role='Consultant'",
      [email]
    );
    if (consultantResult.rows.length === 0) {
      return res.status(404).json({ error: "Consultant not found" });
    }
    const consultant = consultantResult.rows[0];

    // Ensure the requested projectId matches the consultant's project_id
    if (consultant.project_id != projectId) {
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

app.post("/client/profile-picture", async (req, res) => {
  const { email } = req.body;
  try {
    const result = await pool.query(
      `SELECT company_name, company_email, representative, title, telephone, profile_picture
       FROM clients
       WHERE company_email = $1`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.json({ success: false, error: "Client not found." });
    }

    const client = result.rows[0];

    res.json({
      success: true,
      company_name: client.company_name,
      company_email: client.company_email,
      representative: client.representative,
      title: client.title,
      telephone: client.telephone,
      profile_picture: client.profile_picture
    });
  } catch (err) {
    console.error("Profile fetch error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ============ PROJECT REFERENCE CHECK ============
app.post("/project-check-reference", async (req, res) => {
  const { reference, clientId } = req.body; // include clientId in request
  try {
    const duplicateCheck = await pool.query(
      `SELECT id FROM projects 
       WHERE client_id = $2 AND LOWER(contract_reference) = LOWER($1)`,
      [reference, clientId]
    );

    if (duplicateCheck.rows.length > 0) {
      return res.json({ success: false, error: "Project reference already exists for this client." });
    }

    res.json({ success: true, message: "Reference is unique for this client." });
  } catch (err) {
    console.error("Project reference check error:", err);
    res.status(500).json({ success: false, error: "Server error checking reference." });
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
