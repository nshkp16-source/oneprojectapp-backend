export async function checkProjectAccess(pool, userId, role, projectId, normalizeRole) {
  const projectCheck = {
    Client:       { table: 'projects',                  idCol: 'client_id' },
    Contractor:   { table: 'contractor_assignments',    idCol: 'contractor_id' },
    Consultant:   { table: 'consultant_assignments',    idCol: 'consultant_id' },
    ClientPM:     { table: 'client_pm_assignments',     idCol: 'client_pm_id' },
    ContractorPM: { table: 'contractor_pm_assignments', idCol: 'contractor_pm_id' },
    ConsultantPM: { table: 'consultant_pm_assignments', idCol: 'consultant_pm_id' },
    TeamMember:   { table: 'team_member_assignments',   idCol: 'team_member_id' },
  }[normalizeRole(role)];

  if (!projectCheck) return false;
  const query = projectCheck.table === 'projects'
    ? `SELECT 1 FROM ${projectCheck.table} WHERE id=$1 AND ${projectCheck.idCol}=$2`
    : `SELECT 1 FROM ${projectCheck.table} WHERE project_id=$1 AND ${projectCheck.idCol}=$2`;
  const { rows } = await pool.query(query, [projectId, userId]);
  return rows.length > 0;
}
