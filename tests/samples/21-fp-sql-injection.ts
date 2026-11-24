// Casos diseñados para provocar FALSOS POSITIVOS en sql-injection (CWE-89)

// 1. Texto en inglés (no SQL) que coincide con SELECT ... FROM en función arbitraria
export function formatUiBanner(i18n: { translate: (msg: string) => string }, folder: string) {
  return i18n.translate(`Select a file from ${folder} to continue`);
}

// 2. Objeto llamado "client" (coincide con DB_OBJECT_PATTERN) llamando a .get() con query params "from" y "limit"
export async function fetchAnalytics(
  client: { get: (url: string) => Promise<unknown> },
  startDate: string,
  limit: number,
) {
  return client.get(`https://api.example.com/events?from=${startDate}&limit=${limit}`);
}

// 3. Método "query()" de un buscador (no SQL) con palabra parcial "where"
export function searchDocs(searchIndex: { query: (q: string) => string[] }, topic: string) {
  return searchIndex.query(`articles where tag:${topic}`);
}

// 4. Variable reasignada únicamente con literales estáticos en $queryRawUnsafe
export async function runStaticBranch(
  prisma: { $queryRawUnsafe: (sql: string) => Promise<unknown[]> },
  useArchive: boolean,
) {
  let sql = 'SELECT id, name FROM active_users';
  if (useArchive) {
    sql = 'SELECT id, name FROM archived_users';
  }
  return prisma.$queryRawUnsafe(sql);
}
