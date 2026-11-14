import pc from 'picocolors';
import type { Finding, Severity } from '../types/finding.js';

export interface ConsoleReportOptions {
  colors?: boolean;
}

function formatSeverityBadge(
  severity: Severity,
  colors: ReturnType<typeof pc.createColors>,
): string {
  switch (severity) {
    case 'CRITICAL':
      return colors.bgRed(colors.white(colors.bold(` ${severity} `)));
    case 'HIGH':
      return colors.red(colors.bold(severity));
    case 'MEDIUM':
      return colors.yellow(colors.bold(severity));
    case 'LOW':
      return colors.cyan(severity);
  }
}

/**
 * Formats SAST findings into a human-readable console report.
 */
export function formatConsoleReport(
  findings: Finding[],
  options: ConsoleReportOptions = {},
): string {
  const colors = pc.createColors(options.colors ?? pc.isColorSupported);

  if (findings.length === 0) {
    return colors.green('✔ No security vulnerabilities detected.');
  }

  const lines: string[] = [];
  lines.push(
    colors.bold(
      `\nFound ${findings.length} security finding${findings.length === 1 ? '' : 's'}:\n`,
    ),
  );

  for (const finding of findings) {
    const badge = formatSeverityBadge(finding.severity, colors);
    const location = colors.dim(
      `${finding.filePath}:${finding.line}:${finding.column}`,
    );

    lines.push(
      `${badge} ${colors.bold(finding.ruleId)} ${colors.dim(`(${finding.cwe})`)}`,
    );
    lines.push(`  Location:    ${location}`);
    lines.push(`  Message:     ${finding.message}`);
    if (finding.snippet) {
      lines.push(`  Snippet:     ${colors.gray(finding.snippet)}`);
    }
    lines.push(`  Remediation: ${colors.green(finding.remediation)}`);
    lines.push('');
  }

  const counts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }

  lines.push(
    colors.bold('Summary: ') +
      `${colors.red(`CRITICAL: ${counts.CRITICAL}`)}, ` +
      `${colors.red(`HIGH: ${counts.HIGH}`)}, ` +
      `${colors.yellow(`MEDIUM: ${counts.MEDIUM}`)}, ` +
      `${colors.cyan(`LOW: ${counts.LOW}`)}`,
  );

  return lines.join('\n');
}

export function reportToConsole(
  findings: Finding[],
  options: ConsoleReportOptions = {},
): void {
  console.log(formatConsoleReport(findings, options));
}
