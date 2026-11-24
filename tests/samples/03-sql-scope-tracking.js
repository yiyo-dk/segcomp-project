// Enfoque: Rastreo de variables locales en Scope (construcción dinámica de SQL).
export function filterInvoices(db, customerId, minTotal) {
  let query = "SELECT * FROM invoices WHERE 1=1";
  if (customerId) {
    query += " AND customer_id = " + customerId;
  }
  if (minTotal) {
    query = query + ` AND total >= ${minTotal}`;
  }
  return db.run(query);
}

export function getAuditLogs(db, actor) {
  const base = "SELECT * FROM audit_logs WHERE actor = '" + actor + "'";
  return db.all(base);
}
