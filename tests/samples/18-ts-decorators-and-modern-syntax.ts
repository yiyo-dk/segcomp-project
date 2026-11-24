// Enfoque: Sintaxis moderna de TypeScript (enums, genéricos, optional chaining, nullish coalescing).
export enum Environment {
  Production = "production",
  Staging = "staging",
}

export interface AuditContext<T extends Record<string, unknown>> {
  env: Environment;
  metadata?: T;
}

export function buildAndRunAudit<T extends { actorId?: string }>(
  db: { query: (sql: string) => Promise<unknown> },
  ctx: AuditContext<T>
) {
  const actor = ctx.metadata?.actorId ?? "anonymous";
  return db.query(`INSERT INTO audit (env, actor) VALUES ('${ctx.env}', '${actor}')`);
}
