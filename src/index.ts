#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { Command } from 'commander';
import { Scanner } from './core/scanner.js';
import { formatConsoleReport } from './reporters/console.reporter.js';
import { formatSarifReport } from './reporters/sarif.reporter.js';
import { hardcodedSecretsRule } from './rules/hardcoded-secrets.rule.js';
import { sqlInjectionRule } from './rules/sql-injection.rule.js';
import {
  SEVERITY_WEIGHT,
  type Rule,
  type Severity,
} from './types/finding.js';

type OutputFormat = 'text' | 'sarif';

interface CliOptions {
  format: string;
  out?: string;
  failOn: string;
}

const DEFAULT_RULES: Rule[] = [sqlInjectionRule, hardcodedSecretsRule];
const VALID_FORMATS = new Set<OutputFormat>(['text', 'sarif']);
const VALID_SEVERITIES = new Set<Severity>(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

function parseFormat(rawFormat: string): OutputFormat {
  const normalized = rawFormat.toLowerCase();
  if (!VALID_FORMATS.has(normalized as OutputFormat)) {
    throw new Error(
      `Invalid format "${rawFormat}". Expected one of: text, sarif.`,
    );
  }
  return normalized as OutputFormat;
}

function parseSeverity(rawSeverity: string): Severity {
  const normalized = rawSeverity.toUpperCase();
  if (!VALID_SEVERITIES.has(normalized as Severity)) {
    throw new Error(
      `Invalid severity "${rawSeverity}". Expected one of: LOW, MEDIUM, HIGH, CRITICAL.`,
    );
  }
  return normalized as Severity;
}

function hasThresholdViolation(
  severities: Severity[],
  threshold: Severity,
): boolean {
  const thresholdWeight = SEVERITY_WEIGHT[threshold];
  return severities.some((severity) => SEVERITY_WEIGHT[severity] >= thresholdWeight);
}

async function runCli(): Promise<void> {
  const program = new Command();

  program
    .name('sast-scan')
    .description('Static Application Security Testing (SAST) CLI for JS/TS')
    .version('1.0.0')
    .argument('<target>', 'Target file, directory, or glob pattern to scan')
    .option('-f, --format <format>', 'Output format (text|sarif)', 'text')
    .option('-o, --out <file>', 'Write report output to a file')
    .option(
      '-e, --fail-on <severity>',
      'Exit with code 1 when findings reach severity (LOW|MEDIUM|HIGH|CRITICAL)',
      'HIGH',
    )
    .action(async (target: string, options: CliOptions) => {
      try {
        const format = parseFormat(options.format);
        const failOnSeverity = parseSeverity(options.failOn);

        const scanner = new Scanner(DEFAULT_RULES);
        const findings = await scanner.scan(target);

        const output =
          format === 'sarif'
            ? formatSarifReport(findings, DEFAULT_RULES)
            : formatConsoleReport(findings, { colors: !options.out });

        if (options.out) {
          const outPath = path.resolve(options.out);
          fs.mkdirSync(path.dirname(outPath), { recursive: true });
          fs.writeFileSync(outPath, `${output}\n`, 'utf-8');
        } else {
          console.log(output);
        }

        const findingSeverities = findings.map((finding) => finding.severity);
        if (hasThresholdViolation(findingSeverities, failOnSeverity)) {
          process.exit(1);
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`Error: ${message}`);
        process.exit(1);
      }
    });

  await program.parseAsync(process.argv);
}

void runCli();
