// Enfoque: Casos borde (template literals sin interpolación como secreto, SQL multilínea, Map.get seguro).
export const serviceSecrets = {
  webhookSecret: `whsec_static_template_literal_without_interpolation_98765`,
  nested: {
    authToken: "tok_live_00112233445566778899aabbccddeeff",
  },
};

export function multiLineQuery(db: { query: (sql: string) => void }, dept: string) {
  const sql =
    "SELECT e.id, e.name " +
    "FROM employees e " +
    `WHERE e.department = '${dept}'`;
  db.query(sql);
}

export function safeMapAndRegex(lookup: Map<string, string>, key: string) {
  const pattern = /^dept_[a-z]+$/;
  return {
    found: lookup.get("prefix_" + key),
    valid: pattern.exec("dept_" + key),
  };
}
