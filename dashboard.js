// =========================
// IMPORTS & SETUP
// =========================
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import pkg from 'pg';
const { Pool } = pkg;

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const pool = new Pool({
  connectionString: process.env.COCKROACH_URL
});

// =========================
// SECTION 1: General Routes
// =========================
app.get('/ping', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ connected: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Database connection failed' });
  }
});

// =========================
// SECTION 2: Client Routes
// =========================
app.get('/client/projects', (req, res) => {
  res.json({ message: 'Client projects route working' });
});

// =========================
// SECTION 3: Contractor Routes
// =========================
app.get('/contractor/reports', (req, res) => {
  res.json({ message: 'Contractor reports route working' });
});

// =========================
// SECTION 4: Consultant Routes
// =========================
app.get('/consultant/reports', (req, res) => {
  res.json({ message: 'Consultant reports route working' });
});

// =========================
// SECTION 5: Project Manager Routes
// =========================
app.get('/pm/schedule', (req, res) => {
  res.json({ message: 'Project Manager schedule route working' });
});

// =========================
// SECTION 6: Team Member Routes
// =========================
app.get('/team/tasks', (req, res) => {
  res.json({ message: 'Team Member tasks route working' });
});

// =========================
// SERVER START
// =========================
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Dashboard backend running on port ${PORT}`);
});
