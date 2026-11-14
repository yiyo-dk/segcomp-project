import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { Scanner } from '../src/core/scanner.js';
import { hardcodedSecretsRule } from '../src/rules/hardcoded-secrets.rule.js';

const tempDirs: string[] = [];

function scanSource(code: string, ext = '.ts') {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sast-secrets-test-'));
  tempDirs.push(tmpDir);
  const filePath = path.join(tmpDir, `sample${ext}`);
  fs.writeFileSync(filePath, code, 'utf-8');

  const scanner = new Scanner([hardcodedSecretsRule]);
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

describe('hardcodedSecretsRule', () => {
  it('detects secrets in VariableDeclarator with sensitive names', () => {
    const findings = scanSource(`
      const apiKey = "super-secret-api-value-123";
      const dbPassword = \`my-prod-db-password-99\`;
    `);

    expect(findings).toHaveLength(2);
    expect(findings[0]).toMatchObject({
      ruleId: 'hardcoded-secrets',
      cwe: 'CWE-798',
      severity: 'HIGH',
      line: 2,
    });
    expect(findings[0]?.message).toContain('apiKey');
    expect(findings[1]?.message).toContain('dbPassword');
  });

  it('detects secrets in ObjectProperty, AssignmentExpression, and ClassProperty', () => {
    const findings = scanSource(`
      const config = {
        clientSecret: "prod-client-secret-9876",
        "auth_token": "bearer-hardcoded-value-123",
      };

      let jwtSecret = "";
      jwtSecret = "hs256-signing-secret-xyz";

      class Service {
        private api_key = "service-secret-key-abc";
      }
    `);

    expect(findings).toHaveLength(4);
    expect(findings.map((f) => f.line)).toEqual([3, 4, 8, 11]);
  });

  it('detects high-confidence secret signatures even without sensitive variable names or in call arguments', () => {
    const awsKey = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
    const githubToken = ['ghp', '1234567890abcdefghijklmnopqr'].join('_');
    const stripeKey = ['sk', 'live', '51H8xYzAbCdEfGhIjKlMnOpQr'].join('_');
    const pemHeader = ['-----BEGIN', 'RSA PRIVATE KEY-----'].join(' ');
    const pemFooter = ['-----END', 'RSA PRIVATE KEY-----'].join(' ');

    const findings = scanSource(`
      const a = "${awsKey}";
      authenticate("${githubToken}");
      const client = createClient(\`${stripeKey}\`);
      const cert = "${pemHeader}\\nMIIEowIBAAKCAQEA\\n${pemFooter}";
      const dbUrl = "postgres://admin:SuperSecret123@db.internal:5432/prod";
    `);

    expect(findings).toHaveLength(5);
    expect(findings[0]?.severity).toBe('HIGH');
    expect(findings[0]?.message).toContain('AWS Access Key ID');
    expect(findings[1]?.severity).toBe('CRITICAL');
    expect(findings[1]?.message).toContain('GitHub Token');
    expect(findings[2]?.severity).toBe('CRITICAL');
    expect(findings[2]?.message).toContain('Stripe Secret Key');
    expect(findings[3]?.severity).toBe('CRITICAL');
    expect(findings[3]?.message).toContain('Private Key Block');
    expect(findings[4]?.severity).toBe('CRITICAL');
    expect(findings[4]?.message).toContain('Database Connection String');
  });

  it('does not report each secret node more than once', () => {
    const githubToken = ['ghp', '1234567890abcdefghijklmnopqr'].join('_');
    const findings = scanSource(`
      const githubToken = "${githubToken}";
    `);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('CRITICAL');
  });

  it('avoids false positives on env vars, function calls, placeholders, UI labels, and paths', () => {
    const findings = scanSource(`
      const apiKey = process.env.API_KEY;
      const secret = getSecretFromVault();
      const password = "";
      const token = "changeme";
      const clientSecret = "your-api-key";
      const passwordPlaceholder = "Enter your password here";
      const apiKeyHeader = "x-api-key";
      const secretUrl = "https://vault.internal/v1/secret";
      const privateKeyPath = "./certs/server.key";
      const secretEnvName = "MY_SERVICE_API_KEY";
      const greeting = "hello world";
    `);

    expect(findings).toHaveLength(0);
  });
});
