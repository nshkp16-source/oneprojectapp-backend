import fs from 'fs';
import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function applySchema() {
  const client = await pool.connect();
  try {
    console.log('Reading schema file...');
    const schema = fs.readFileSync('schema/completely schema.sql', 'utf8');

    console.log('Applying schema to database...');
    await client.query(schema);

    console.log('✓ Schema applied successfully!');
  } catch (err) {
    console.error('✗ Failed to apply schema:', err.message);
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

applySchema();
