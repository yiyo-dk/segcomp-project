// Enfoque: Servicios async/await con construcción condicional de SQL y métodos batch/prepare.
interface SqlDriver {
  prepare(sql: string): { all(): unknown[] };
  batch(queries: string[]): Promise<void>;
}

export async function exportFilteredUsers(driver: SqlDriver, role?: string, active?: boolean) {
  let stmt = "SELECT id, name FROM users WHERE 1=1";
  if (role) {
    stmt += ` AND role = '${role}'`;
  }
  if (active !== undefined) {
    stmt += " AND active = " + String(active);
  }
  return driver.prepare(stmt).all();
}

export async function runBulkCleanup(driver: SqlDriver, table: string) {
  return driver.batch(["DELETE FROM " + table + " WHERE archived = 1"]);
}
