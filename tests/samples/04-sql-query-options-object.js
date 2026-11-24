// Enfoque: Inyección SQL dentro de objetos de opciones de consulta ({ text }, { sql }).
export async function pgFindUser(pgClient, username) {
  return pgClient.query({
    name: "find-user",
    text: "SELECT * FROM users WHERE username = '" + username + "'",
  });
}

export async function mysqlFindItem(mysqlConn, sku) {
  return mysqlConn.execute({
    sql: `SELECT * FROM inventory WHERE sku = '${sku}'`,
    timeout: 5000,
  });
}
