import fs from 'fs';
import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function applyNotificationSchema() {
  const client = await pool.connect();
  try {
    console.log('Reading notification migration...');
    const sql = fs.readFileSync('migrations/2026-06-19-notifications-schema.sql', 'utf8');
    console.log('Applying notification schema migration...');
    await client.query(sql);
    console.log('✓ Notification schema migration applied successfully');
  } catch (err) {
    console.error('✗ Failed to apply notification schema:', err.message || err);
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

applyNotificationSchema();
