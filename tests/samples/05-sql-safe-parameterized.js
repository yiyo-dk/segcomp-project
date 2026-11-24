// Enfoque: Falsos positivos de SQLi (consultas parametrizadas, literales estáticos, logs, rutas).
export function safeQueries(db, app, cache, regex, userId, email) {
  // Parametrizadas seguras
  db.query("SELECT * FROM users WHERE id = $1", [userId]);
  db.execute("SELECT * FROM users WHERE email = ?", [email]);
  db.query({ text: "SELECT id FROM sessions WHERE id = $1", values: [userId] });

  // Constante estática
  const STATIC_SQL = "SELECT COUNT(*) FROM users";
  db.query(STATIC_SQL);

  // Métodos con nombres similares que NO son SQL
  app.get("/users/" + userId, (req, res) => res.json({ ok: true }));
  cache.get("user:" + userId);
  regex.exec("id=" + userId);
  console.log("Fetching user " + userId);
}
