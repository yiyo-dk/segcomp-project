// Enfoque: Controlador Express realista con mezcla de SQLi, secretos y código seguro.
const INTERNAL_WEBHOOK_SECRET = "whsec_99887766554433221100ffeeddccbbaa";

export function registerRoutes(app, db) {
  // Vulnerable: SQLi por template literal
  app.get("/api/orders", async (req, res) => {
    const rows = await db.query(`SELECT * FROM orders WHERE owner = '${req.query.owner}'`);
    res.json(rows);
  });

  // Seguro: consulta parametrizada
  app.get("/api/orders/:id", async (req, res) => {
    const rows = await db.query("SELECT * FROM orders WHERE id = $1", [req.params.id]);
    res.json(rows);
  });

  return INTERNAL_WEBHOOK_SECRET;
}
