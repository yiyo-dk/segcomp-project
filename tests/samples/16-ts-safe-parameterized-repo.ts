// Enfoque: Repositorio TypeScript limpio (sin vulnerabilidades esperadas).
export interface DbPool {
  query<T>(sql: string, params?: readonly unknown[]): Promise<T[]>;
}

export class SafeUserRepository {
  private readonly db: DbPool;
  private readonly apiKeyHeader = "X-Service-Api-Key";

  constructor(db: DbPool) {
    this.db = db;
  }

  public async findByEmail(email: string) {
    const query = "SELECT id, email FROM users WHERE email = $1";
    return this.db.query<{ id: string; email: string }>(query, [email]);
  }

  public getRawRegexPattern(): string {
    return String.raw`^user_\d+_${this.apiKeyHeader}$`;
  }
}
