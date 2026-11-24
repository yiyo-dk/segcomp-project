// Enfoque: Wrappers personalizados tipados que reciben SQL construido dinámicamente.
function runCustomSql<T>(sql: string): Promise<T[]> {
  return Promise.resolve([] as T[]);
}

export async function fetchTenantReport(tenantId: string, sortCol: string) {
  const dynamicSql = `SELECT id, total FROM reports WHERE tenant_id = '${tenantId}' ORDER BY ${sortCol}`;
  return runCustomSql<{ id: number; total: number }>(dynamicSql);
}
