export async function sendOverdueVerificationReminders({ pool, notifyRecordUsers, flowKey, normalizeRole }) {
  let client;
  let locked = false;
  try {
    client = await pool.connect();
    const lockResult = await client.query('SELECT pg_try_advisory_lock(71022, 1) AS locked');
    locked = lockResult.rows[0].locked;
    if (!locked) return;

    const { rows } = await client.query(
      `SELECT v.id, v.project_id, v.activity_id, v.requested_by_id, v.requested_by_role,
              v.respond_by, pe.title,
              CURRENT_DATE - v.respond_by AS overdue_days
       FROM activity_verifications v
       JOIN planning_execution pe ON pe.id = v.activity_id
       WHERE v.status = 'pending' AND v.respond_by < CURRENT_DATE
         AND (v.reminder_sent_at IS NULL OR v.reminder_sent_at <= NOW() - INTERVAL '1 day')
       ORDER BY v.respond_by, v.id LIMIT 100`
    );

    for (const verification of rows) {
      const recipientsByKey = new Map();
      const { rows: consultantLeaders } = await client.query(
        `SELECT role, role_id FROM assignments_view
         WHERE project_id = $1 AND role IN ('Consultant', 'ConsultantPM')`,
        [verification.project_id]
      );
      const { rows: pendingSigners } = await client.query(
        `SELECT signer_role, signer_user_id FROM verification_signers
         WHERE verification_id = $1 AND status = 'pending'`,
        [verification.id]
      );
      for (const recipient of [...consultantLeaders, ...pendingSigners.map((signer) => ({
        role: signer.signer_role,
        role_id: signer.signer_user_id,
      }))]) {
        const key = `${normalizeRole(recipient.role)}:${recipient.role_id}`;
        recipientsByKey.set(key, flowKey(recipient.role, recipient.role_id));
      }

      if (!recipientsByKey.size) continue;
      const notificationId = await notifyRecordUsers({
        projectId: verification.project_id,
        recordId: verification.id,
        table: 'activity_verification',
        message: `Verification for "${verification.title}" is overdue by ${verification.overdue_days} day${Number(verification.overdue_days) === 1 ? '' : 's'}. Please review it.`,
        actorId: verification.requested_by_id,
        actorRole: verification.requested_by_role,
        recipients: [...recipientsByKey.values()],
      });
      if (notificationId) {
        await client.query(
          `UPDATE activity_verifications SET reminder_sent_at = NOW()
           WHERE id = $1 AND status = 'pending'
             AND (reminder_sent_at IS NULL OR reminder_sent_at <= NOW() - INTERVAL '1 day')`,
          [verification.id]
        );
      }
    }
  } catch (error) {
    console.error('Overdue verification reminder job failed:', error);
  } finally {
    if (client && locked) {
      await client.query('SELECT pg_advisory_unlock(71022, 1)').catch((error) =>
        console.error('Unable to release verification reminder lock:', error));
    }
    if (client) client.release();
  }
}
