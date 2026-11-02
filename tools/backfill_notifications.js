import { Pool } from 'pg';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function main() {
  const client = await pool.connect();
  try {
    console.log('[backfill] Starting notifications backfill...');
    await client.query('BEGIN');

    const backfillRes = await client.query(`
      WITH missing_notifications AS (
        SELECT n.id AS notification_id, n.project_id
        FROM notifications n
        LEFT JOIN notification_recipients nr ON nr.notification_id = n.id
        WHERE nr.id IS NULL
      )
      INSERT INTO notification_recipients (notification_id, recipient_role, recipient_role_id, created_at)
      SELECT m.notification_id, av.role, av.role_id, NOW()
      FROM missing_notifications m
      JOIN assignments_view av ON av.project_id = m.project_id
      ON CONFLICT ON CONSTRAINT uniq_notif_recipient_per_role DO NOTHING
    `);

    console.log('[backfill] Inserted recipients for orphaned notifications. rowCount =', backfillRes.rowCount);

    const legacyRes = await client.query(`
      SELECT nr.id AS nr_id, nr.notification_id, nr.user_id, n.project_id
      FROM notification_recipients nr
      JOIN notifications n ON n.id = nr.notification_id
      WHERE (nr.recipient_role IS NULL OR nr.recipient_role_id IS NULL) AND nr.user_id IS NOT NULL
    `);

    console.log('[backfill] Found', legacyRes.rows.length, 'legacy recipient rows to migrate');

    let migrated = 0;
    for (const r of legacyRes.rows) {
      const assign = await client.query(
        `SELECT role, role_id FROM assignments_view WHERE project_id=$1 AND role_id=$2 LIMIT 1`,
        [r.project_id, r.user_id]
      );
      if (assign.rows.length) {
        const a = assign.rows[0];
        const upd = await client.query(
          `UPDATE notification_recipients SET recipient_role=$1, recipient_role_id=$2 WHERE id=$3`,
          [a.role, a.role_id, r.nr_id]
        );
        migrated += upd.rowCount;
      } else {
        console.log('[backfill] No assignment mapping for recipient id', r.nr_id, 'user_id', r.user_id, 'project', r.project_id);
      }
    }

    console.log('[backfill] Migrated', migrated, 'legacy recipient rows');

    await client.query('COMMIT');
    console.log('[backfill] Backfill transaction committed.');
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (e) { /* ignore rollback error */ }
    console.error('[backfill] Failed:', err);
    process.exitCode = 2;
  } finally {
    client.release();
    await pool.end();
  }
}

main();
