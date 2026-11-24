// Enfoque: Inyección SQL por concatenación con '+' y '.concat()' en métodos de consulta.
export function getUserById(db, userId) {
  return db.query("SELECT * FROM users WHERE id = " + userId);
}

export function deleteOrder(db, orderId) {
  const sql = "DELETE FROM orders WHERE id = ".concat(orderId);
  return db.execute(sql);
}

export function searchProducts(db, term) {
  return db.query("SELECT * FROM products WHERE name LIKE '%" + term + "%'");
}
