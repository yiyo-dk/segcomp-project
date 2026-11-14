import type { TraverseOptions as BabelTraverseOptions, Visitor } from '@babel/traverse';

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

export type TraverseOptions = BabelTraverseOptions & Visitor;

export interface Finding {
  ruleId: string;
  cwe: string;
  severity: Severity;
  message: string;
  remediation: string;
  filePath: string;
  line: number;
  column: number;
  snippet: string;
}

export interface FindingReportInput {
  message?: string;
  remediation?: string;
  severity?: Severity;
  line: number;
  column: number;
  snippet?: string;
}

export interface RuleContext {
  filePath: string;
  sourceCode: string;
  getSnippet(line: number): string;
  report(finding: FindingReportInput): void;
}

export interface Rule {
  id: string;
  cwe: string;
  name: string;
  severity: Severity;
  description: string;
  remediation: string;
  createVisitor(context: RuleContext): TraverseOptions;
}
