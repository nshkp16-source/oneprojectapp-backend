import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function checkNotifications() {
  try {
    console.log('Checking notification data...\n');

    const notifCount = await pool.query('SELECT COUNT(*) FROM notifications');
    console.log(`📊 Total notifications in DB: ${notifCount.rows[0].count}`);

    const recipientCount = await pool.query('SELECT COUNT(*) FROM notification_recipients');
    console.log(`📊 Total notification recipients: ${recipientCount.rows[0].count}`);

    const orphanedNotifs = await pool.query(`
      SELECT n.id, n.project_id, n.entity_type, n.message, n.created_at
      FROM notifications n
      LEFT JOIN notification_recipients nr ON nr.notification_id = n.id
      WHERE nr.id IS NULL
      LIMIT 5
    `);

    if (orphanedNotifs.rows.length > 0) {
      console.log(`\n⚠️  Found ${orphanedNotifs.rows.length} notifications with NO recipients!`);
      console.log('Sample orphaned notifications:');
      orphanedNotifs.rows.forEach(n => {
        console.log(`  - ID: ${n.id}, Project: ${n.project_id}, Type: ${n.entity_type}, Message: ${n.message}`);
      });
    } else {
      console.log('\n✓ No orphaned notifications found');
    }

    const projectsWithAssignments = await pool.query(`
      SELECT DISTINCT p.id, p.name, COUNT(DISTINCT a.project_id) as assignment_count
      FROM projects p
      LEFT JOIN (
        SELECT project_id FROM contractor_assignments
        UNION ALL SELECT project_id FROM consultant_assignments
        UNION ALL SELECT project_id FROM team_member_assignments
        UNION ALL SELECT project_id FROM client_pm_assignments
        UNION ALL SELECT project_id FROM contractor_pm_assignments
        UNION ALL SELECT project_id FROM consultant_pm_assignments
      ) a ON p.id = a.project_id
      GROUP BY p.id
      HAVING COUNT(DISTINCT a.project_id) = 0
      LIMIT 5
    `);

    if (projectsWithAssignments.rows.length > 0) {
      console.log(`\n⚠️  Found ${projectsWithAssignments.rows.length} projects with NO assignments:`);
      projectsWithAssignments.rows.forEach(p => {
        console.log(`  - Project ID: ${p.id}, Name: ${p.name}`);
      });
    }

    console.log('\n✓ Diagnosis complete');
  } catch (err) {
    console.error('Error:', err.message);
  } finally {
    await pool.end();
  }
}

checkNotifications();
