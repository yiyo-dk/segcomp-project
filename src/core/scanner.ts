import fs from 'node:fs';
import path from 'node:path';
import fg from 'fast-glob';
import traverse, { visitors, type Visitor } from '@babel/traverse';
import { parseCode } from './parser.js';
import type {
  Finding,
  FindingReportInput,
  Rule,
  RuleContext,
} from '../types/finding.js';

const SUPPORTED_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx']);
const DEFAULT_IGNORE_PATTERNS = [
  '**/node_modules/**',
  '**/dist/**',
  '**/.git/**',
  '**/coverage/**',
];

const traverseAst = (
  typeof traverse === 'function'
    ? traverse
    : (traverse as unknown as { default: typeof traverse }).default
) as typeof traverse;

function toGlobPattern(target: string): string {
  const resolved = path.resolve(target);

  if (fs.existsSync(resolved)) {
    const stats = fs.statSync(resolved);
    const posixPath = resolved.replace(/\\/g, '/');

    if (stats.isDirectory()) {
      return `${posixPath.replace(/\/+$/, '')}/**/*.{js,jsx,ts,tsx}`;
    }

    if (stats.isFile()) {
      return SUPPORTED_EXTENSIONS.has(path.extname(resolved).toLowerCase())
        ? posixPath
        : '';
    }
  }

  return target.replace(/\\/g, '/');
}

/**
 * Resolves input file paths, directories, or glob patterns into supported source files.
 */
export async function resolveTargetFiles(
  targets: string | string[],
): Promise<string[]> {
  const targetList = Array.isArray(targets) ? targets : [targets];
  const patterns = targetList
    .map(toGlobPattern)
    .filter((pattern) => pattern.length > 0);

  if (patterns.length === 0) {
    return [];
  }

  const files = await fg(patterns, {
    ignore: DEFAULT_IGNORE_PATTERNS,
    absolute: true,
    onlyFiles: true,
  });

  return files.filter((filePath) =>
    SUPPORTED_EXTENSIONS.has(path.extname(filePath).toLowerCase()),
  );
}

function createLineSnippetGetter(sourceCode: string): (line: number) => string {
  const lines = sourceCode.split(/\r?\n/);
  return (line: number): string => {
    if (line < 1 || line > lines.length) {
      return '';
    }
    return (lines[line - 1] ?? '').trim();
  };
}

function createRuleContext(
  rule: Rule,
  filePath: string,
  sourceCode: string,
  getSnippet: (line: number) => string,
  findings: Finding[],
): RuleContext {
  return {
    filePath,
    sourceCode,
    getSnippet,
    report(input: FindingReportInput): void {
      findings.push({
        ruleId: rule.id,
        cwe: rule.cwe,
        severity: input.severity ?? rule.severity,
        message: input.message ?? rule.description,
        remediation: input.remediation ?? rule.remediation,
        filePath,
        line: input.line,
        column: input.column,
        snippet: input.snippet ?? getSnippet(input.line),
      });
    },
  };
}

export class Scanner {
  private readonly rules: Rule[];

  constructor(rules: Rule[]) {
    this.rules = rules;
  }

  /**
   * Scans a single file in a single AST traversal pass across all registered rules.
   */
  public scanFile(filePath: string): Finding[] {
    if (this.rules.length === 0) {
      return [];
    }

    const sourceCode = fs.readFileSync(filePath, 'utf-8');
    const ast = parseCode(sourceCode, filePath);
    const getSnippet = createLineSnippetGetter(sourceCode);
    const findings: Finding[] = [];

    const ruleVisitors = this.rules.map((rule) => {
      const context = createRuleContext(
        rule,
        filePath,
        sourceCode,
        getSnippet,
        findings,
      );
      return rule.createVisitor(context) as Visitor;
    });

    const mergedVisitor = visitors.merge(ruleVisitors);
    traverseAst(ast, mergedVisitor);

    return findings;
  }

  /**
   * Resolves all target files and scans each one against registered rules.
   */
  public async scan(targets: string | string[]): Promise<Finding[]> {
    const files = await resolveTargetFiles(targets);
    const allFindings: Finding[] = [];

    for (const filePath of files) {
      try {
        allFindings.push(...this.scanFile(filePath));
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.warn(`Warning: skipping "${filePath}" (${message})`);
      }
    }

    return allFindings;
  }
}

export async function scanTargets(
  targets: string | string[],
  rules: Rule[],
): Promise<Finding[]> {
  const scanner = new Scanner(rules);
  return scanner.scan(targets);
}
