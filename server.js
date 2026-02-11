// server.js
import express from 'express';
import bodyParser from 'body-parser';
import crypto from 'crypto';
import { Pool } from 'pg';
import nodemailer from 'nodemailer';

const app = express();
app.use(bodyParser.json());

// 🔹 Neon DB connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // set this in Render
  ssl: { rejectUnauthorized: false }
});

// 🔹 Gmail SMTP setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,       // nshkp16@gmail.com
    pass: process.env.GMAIL_APP_PASS    // aaibkxbxkjyhgojm
  }
});

// -------------------- ROUTES --------------------

// Root route for Render homepage
app.get('/', (req, res) => {
  res.send('Backend is running successfully!');
});

// 1. Create Client + Send Verification
app.post('/create-client', async (req, res) => {
  const { company_name, company_email, representative_name, title, phone_number, password_hash } = req.body;

  try {
    await pool.query(
      `INSERT INTO clients (company_name, company_email, representative_name, title, phone_number, password_hash, verified)
       VALUES ($1, $2, $3, $4, $5, $6, false)
       ON CONFLICT (company_email) DO NOTHING`,
      [company_name, company_email, representative_name, title, phone_number, password_hash]
    );

    const token = crypto.randomBytes(32).toString('hex');
    await pool.query(
      `INSERT INTO email_tokens (email, token, expires_at)
       VALUES ($1, $2, NOW() + interval '1 hour')`,
      [company_email, token]
    );

    const verifyUrl = `https://oneprojectapp.netlify.app/verify?token=${token}`;
    await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: company_email,
      subject: 'Verify your account',
      html: `<p>Click <a href="${verifyUrl}">here</a> to verify your account.</p>`
    });

    res.json({ success: true, message: 'Verification email sent via Gmail' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create client' });
  }
});

// 2. Verify Client
app.get('/verify', async (req, res) => {
  const { token } = req.query;

  try {
    const result = await pool.query(
      `SELECT email FROM email_tokens WHERE token=$1 AND expires_at > NOW()`,
      [token]
    );

    if (result.rows.length === 0) {
      return res.redirect('/verify-failed.html');
    }

    const email = result.rows[0].email;
    await pool.query(`UPDATE clients SET verified=true WHERE company_email=$1`, [email]);

    res.redirect('/verify-success.html');
  } catch (err) {
    console.error(err);
    res.redirect('/verify-failed.html');
  }
});

// 3. Create Project
app.post('/create-project', async (req, res) => {
  const { name, location, contract_reference, client_email } = req.body;

  try {
    const client = await pool.query(`SELECT id FROM clients WHERE company_email=$1`, [client_email]);
    if (client.rows.length === 0) {
      return res.status(400).json({ error: 'Client not found' });
    }

    const client_id = client.rows[0].id;
    await pool.query(
      `INSERT INTO projects (name, location, contract_reference, client_id, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [name, location, contract_reference, client_id]
    );

    res.json({ success: true, message: 'Project created' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create project' });
  }
});

// 4. Assign Team Members
app.post('/assign-team', async (req, res) => {
  const { project_id, members } = req.body;

  try {
    for (const m of members) {
      await pool.query(
        `INSERT INTO team_members (name, position, task, email, project_id)
         VALUES ($1, $2, $3, $4, $5)`,
        [m.name, m.position, m.task, m.email, project_id]
      );
    }
    res.json({ success: true, message: 'Team members assigned' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to assign team members' });
  }
});

// -------------------- SERVER --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});
