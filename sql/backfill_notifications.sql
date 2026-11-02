-- Backfill notification recipients for orphaned notifications
BEGIN;

WITH missing_notifications AS (
  SELECT n.id AS notification_id, n.project_id
  FROM notifications n
  LEFT JOIN notification_recipients nr ON nr.notification_id = n.id
  WHERE nr.id IS NULL
)
INSERT INTO notification_recipients (
  notification_id,
  recipient_role,
  recipient_role_id,
  created_at
)
SELECT
  m.notification_id,
  av.role,
  av.role_id,
  NOW()
FROM missing_notifications m
JOIN assignments_view av
  ON av.project_id = m.project_id
ON CONFLICT ON CONSTRAINT uniq_notif_recipient_per_role DO NOTHING;

COMMIT;

-- Migrate legacy notification_recipients that only have user_id populated
-- (run separately if you prefer to inspect results first)

-- SELECT nr.id AS nr_id, nr.notification_id, nr.user_id, n.project_id
-- FROM notification_recipients nr
-- JOIN notifications n ON n.id = nr.notification_id
-- WHERE (nr.recipient_role IS NULL OR nr.recipient_role_id IS NULL) AND nr.user_id IS NOT NULL;

-- Then for each row above, update recipient_role/recipient_role_id using assignments_view
-- UPDATE notification_recipients SET recipient_role = <role>, recipient_role_id = <role_id>, recipient_email = <role_email> WHERE id = <nr_id>;
