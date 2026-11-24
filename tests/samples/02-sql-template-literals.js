// Enfoque: Inyección SQL mediante template literals interpolados (${...}).
export async function findAccount(pool, email) {
  return pool.query(`SELECT id, email FROM accounts WHERE email = '${email}'`);
}

export function updateStatus(connection, id, status) {
  return connection.exec(`UPDATE tasks SET status = '${status}' WHERE id = ${id}`);
}

export function listByRole(sqlite, role) {
  return sqlite.all(`SELECT * FROM members WHERE role = '${role}'`);
}
