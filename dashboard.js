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

app.get('/ping', async (req, res) => {
  const result = await pool.query('SELECT NOW()');
  res.json({ connected: result.rows[0] });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Dashboard backend running on port ${PORT}`);
});

