// Enfoque: Knex raw() y tagged template knex.raw`...` con interpolación insegura vs bindings.
interface KnexLike {
  raw(sql: string | TemplateStringsArray, ...bindings: unknown[]): Promise<unknown>;
}

export async function searchKnexCall(knex: KnexLike, city: string) {
  return knex.raw("SELECT * FROM branches WHERE city = '" + city + "'");
}

export async function searchKnexTagged(knex: KnexLike, city: string) {
  return knex.raw`SELECT * FROM branches WHERE city = '${city}'`;
}

export async function searchKnexSafe(knex: KnexLike, city: string) {
  return knex.raw("SELECT * FROM branches WHERE city = ?", [city]);
}
