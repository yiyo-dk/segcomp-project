import path from 'node:path';
import type {
  Log,
  ReportingConfiguration,
  ReportingDescriptor,
  Result,
} from 'sarif';
import type { Finding, Rule, Severity } from '../types/finding.js';

const SARIF_SCHEMA_URI = 'https://json.schemastore.org/sarif-2.1.0.json';
const SARIF_VERSION = '2.1.0' as const;

function mapSeverityToSarifLevel(
  severity: Severity,
): ReportingConfiguration.level {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
      return 'note';
  }
}

function toSarifUri(filePath: string): string {
  const relative = path.relative(process.cwd(), filePath);
  const target =
    relative && !relative.startsWith('..') && !path.isAbsolute(relative)
      ? relative
      : filePath;
  return target.replace(/\\/g, '/');
}

function buildRuleDescriptors(rules: Rule[]): ReportingDescriptor[] {
  return rules.map((rule) => ({
    id: rule.id,
    name: rule.name,
    shortDescription: {
      text: rule.description,
    },
    help: {
      text: rule.remediation,
    },
    defaultConfiguration: {
      level: mapSeverityToSarifLevel(rule.severity),
    },
    properties: {
      cwe: rule.cwe,
      severity: rule.severity,
    },
  }));
}

function buildResults(findings: Finding[]): Result[] {
  return findings.map((finding) => ({
    ruleId: finding.ruleId,
    level: mapSeverityToSarifLevel(finding.severity),
    message: {
      text: finding.message,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: toSarifUri(finding.filePath),
          },
          region: {
            startLine: Math.max(1, finding.line),
            startColumn: Math.max(1, finding.column),
            snippet: finding.snippet ? { text: finding.snippet } : undefined,
          },
        },
      },
    ],
    properties: {
      cwe: finding.cwe,
      severity: finding.severity,
      remediation: finding.remediation,
    },
  }));
}

/**
 * Generates a SARIF v2.1.0 compliant log object from findings and rules.
 */
export function buildSarifLog(
  findings: Finding[],
  rules: Rule[],
  toolVersion = '1.0.0',
): Log {
  return {
    $schema: SARIF_SCHEMA_URI,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: 'sast-scan',
            version: toolVersion,
            rules: buildRuleDescriptors(rules),
          },
        },
        results: buildResults(findings),
      },
    ],
  };
}

/**
 * Serializes findings into a formatted SARIF v2.1.0 JSON string.
 */
export function formatSarifReport(
  findings: Finding[],
  rules: Rule[],
  toolVersion = '1.0.0',
): string {
  const sarifLog = buildSarifLog(findings, rules, toolVersion);
  return JSON.stringify(sarifLog, null, 2);
}
