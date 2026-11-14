import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { Scanner } from '../src/core/scanner.js';
import { sqlInjectionRule } from '../src/rules/sql-injection.rule.js';

const tempDirs: string[] = [];

function scanSource(code: string, ext = '.ts') {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sast-sqli-test-'));
  tempDirs.push(tmpDir);
  const filePath = path.join(tmpDir, `sample${ext}`);
  fs.writeFileSync(filePath, code, 'utf-8');

  const scanner = new Scanner([sqlInjectionRule]);
  return scanner.scanFile(filePath);
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir && fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe('sqlInjectionRule', () => {
  it('detects direct string concatenation and template interpolation in query calls', () => {
    const findings = scanSource(`
      function getUser(db: any, userId: string) {
        db.query("SELECT * FROM users WHERE id = " + userId);
        pool.execute(\`DELETE FROM sessions WHERE user_id = \${userId}\`);
        knex.raw("UPDATE users SET role = 'admin' WHERE id = " + userId);
        prisma.$queryRawUnsafe(userInput);
      }
    `);

    expect(findings).toHaveLength(4);
    expect(findings.every((f) => f.ruleId === 'sql-injection')).toBe(true);
    expect(findings.every((f) => f.cwe === 'CWE-89')).toBe(true);
    expect(findings.every((f) => f.severity === 'CRITICAL')).toBe(true);
    expect(findings.map((f) => f.line)).toEqual([3, 4, 5, 6]);
  });

  it('detects dynamic SQL inside query option objects ({ text, sql })', () => {
    const findings = scanSource(`
      async function findUser(client: any, connection: any, id: string, name: string) {
        await client.query({ text: \`SELECT * FROM users WHERE id = \${id}\` });
        await connection.query({
          sql: "SELECT * FROM users WHERE name = '" + name + "'",
        });
      }
    `);

    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.line)).toEqual([3, 4]);
  });

  it('tracks dynamically constructed SQL variables through local scope bindings', () => {
    const findings = scanSource(`
      function search(db: any, pool: any, userId: string) {
        const sql = "SELECT * FROM users WHERE id = " + userId;
        db.query(sql);

        let query = "SELECT * FROM users WHERE active = 1";
        query += \` AND id = \${userId}\`;
        pool.query(query);
      }
    `);

    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.line)).toEqual([4, 8]);
  });

  it('detects .concat() and custom SQL wrapper functions', () => {
    const findings = scanSource(`
      function run(db: any, userId: string) {
        db.query("SELECT * FROM users WHERE id = ".concat(userId));
        runCustomSql("SELECT * FROM accounts WHERE owner = " + userId);
      }
    `);

    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.line)).toEqual([3, 4]);
  });

  it('detects unsafe tagged template literals and dynamic raw fragments inside parameterized tags', () => {
    const findings = scanSource(`
      function queryTags(knex: any, prisma: any, Prisma: any, id: string) {
        knex.raw\`SELECT * FROM users WHERE id = \${id}\`;
        prisma.$queryRaw\`SELECT * FROM users WHERE \${Prisma.raw("id = " + id)}\`;
      }
    `);

    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.line)).toEqual([3, 4]);
  });

  it('avoids false positives on parameterized, static, and non-SQL calls', () => {
    const findings = scanSource(`
      function safeQueries(db: any, pool: any, prisma: any, app: any, map: any, userId: string) {
        db.query("SELECT * FROM users WHERE id = $1", [userId]);
        pool.execute("SELECT * FROM users WHERE id = ?", [userId]);
        db.query("SELECT * FROM " + "users");

        const STATIC_SQL = "SELECT * FROM users";
        db.query(STATIC_SQL);

        prisma.$queryRaw\`SELECT * FROM users WHERE id = \${userId}\`;
        String.raw\`SELECT * FROM users WHERE id = \${userId}\`;

        app.get("/users/" + userId);
        map.get("user_" + userId);
        /user_\\d+/.exec(userId + "_test");
        console.log("SELECT: " + userId);
        console.log("SELECT * FROM users WHERE id = " + userId);
      }
    `);

    expect(findings).toHaveLength(0);
  });
});
