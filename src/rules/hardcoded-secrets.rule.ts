import path from 'node:path';
import type { Node } from '@babel/types';
import type {
  Rule,
  RuleContext,
  Severity,
  TraverseOptions,
} from '../types/finding.js';

interface SecretSignature {
  name: string;
  pattern: RegExp;
  severity: Severity;
}

const SECRET_SIGNATURES: SecretSignature[] = [
  {
    name: 'Private Key Block',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
    severity: 'CRITICAL',
  },
  {
    name: 'GitHub Token',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/,
    severity: 'CRITICAL',
  },
  {
    name: 'Stripe Secret Key',
    pattern: /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}\b/,
    severity: 'CRITICAL',
  },
  {
    name: 'Database Connection String with Credentials',
    pattern:
      /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^:\s/]+:[^@\s/]+@[^\s/]+/i,
    severity: 'CRITICAL',
  },
  {
    name: 'AWS Access Key ID',
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
    severity: 'HIGH',
  },
  {
    name: 'Slack Token',
    pattern: /\bxox[baprs]-[0-9a-zA-Z-]{10,}\b/,
    severity: 'HIGH',
  },
  {
    name: 'Google API Key',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
    severity: 'HIGH',
  },
  {
    name: 'API Secret Key (sk-)',
    pattern: /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b/,
    severity: 'HIGH',
  },
  {
    name: 'Hardcoded JWT',
    pattern:
      /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
    severity: 'HIGH',
  },
];

const SENSITIVE_NAME_PATTERN =
  /(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|refresh[_-]?token|jwt[_-]?secret|bearer[_-]?token|encryption[_-]?key|signing[_-]?key|master[_-]?key)/i;

const NON_SECRET_SUFFIX_PATTERN =
  /(?:field|input|label|placeholder|selector|regex|pattern|error|message|msg|url|uri|endpoint|path|route|header|cookie|name|type|schema|validator|hint|help|length|min|max|public[_-]?key)$/i;

const PLACEHOLDER_PATTERN =
  /^(?:changeme|change[_-]?me|your[_-]?(?:api[_-]?key|secret|token|password)|example|dummy|placeholder|todo|fixme|replace[_-]?me|insert[_-]?here|undefined|null|none|empty|xxx+|\*+|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\})$/i;

const FILE_PATH_PATTERN = /^(?:\.{0,2}\/|~\/|[a-zA-Z]:\\)/;
const PLAIN_URL_PATTERN = /^https?:\/\/[^@]+$/i;
const UPPER_SNAKE_PATTERN = /^[A-Z][A-Z0-9_]+$/;
const REPEATED_CHAR_PATTERN = /^(.)\1+$/;

const MIN_SECRET_LENGTH = 6;
const HIGH_ENTROPY_THRESHOLD = 3.8;

/**
 * Extracts a static string value from a StringLiteral or a TemplateLiteral without interpolations.
 */
export function extractStaticString(node: Node | null | undefined): string | null {
  if (!node) {
    return null;
  }

  if (node.type === 'StringLiteral') {
    return node.value;
  }

  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis
      .map((quasi) => quasi.value.cooked ?? quasi.value.raw)
      .join('');
  }

  return null;
}

/**
 * Extracts a variable, property, or member name from an AST target node.
 */
export function extractTargetName(node: Node | null | undefined): string | null {
  if (!node) {
    return null;
  }

  if (node.type === 'Identifier') {
    return node.name;
  }

  if (node.type === 'StringLiteral') {
    return node.value;
  }

  if (node.type === 'PrivateName') {
    return node.id.name;
  }

  if (node.type === 'MemberExpression') {
    if (node.computed && node.property.type !== 'StringLiteral') {
      return null;
    }
    return extractTargetName(node.property);
  }

  return null;
}

/**
 * Checks whether a string value matches a known high-confidence secret signature.
 */
export function matchSecretSignature(
  value: string,
): { name: string; severity: Severity } | null {
  for (const signature of SECRET_SIGNATURES) {
    if (signature.pattern.test(value)) {
      return { name: signature.name, severity: signature.severity };
    }
  }
  return null;
}

/**
 * Determines whether an identifier or property name is likely to hold a secret.
 */
export function isSensitiveName(name: string): boolean {
  if (!SENSITIVE_NAME_PATTERN.test(name)) {
    return false;
  }

  return !NON_SECRET_SUFFIX_PATTERN.test(name);
}

/**
 * Computes Shannon entropy in bits per character for a string.
 */
export function calculateShannonEntropy(value: string): number {
  if (value.length === 0) {
    return 0;
  }

  const frequencies = new Map<string, number>();
  for (const char of value) {
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of frequencies.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

/**
 * Filters out obvious placeholders, empty values, paths, URLs, and config key constants.
 */
export function isLikelyPlaceholderOrSafeValue(value: string): boolean {
  const trimmed = value.trim();

  if (trimmed.length < MIN_SECRET_LENGTH) {
    return true;
  }

  if (REPEATED_CHAR_PATTERN.test(trimmed)) {
    return true;
  }

  if (PLACEHOLDER_PATTERN.test(trimmed)) {
    return true;
  }

  if (FILE_PATH_PATTERN.test(trimmed) || PLAIN_URL_PATTERN.test(trimmed)) {
    return true;
  }

  if (
    UPPER_SNAKE_PATTERN.test(trimmed) &&
    calculateShannonEntropy(trimmed) < HIGH_ENTROPY_THRESHOLD
  ) {
    return true;
  }

  return false;
}

function getLocation(node: Node): { line: number; column: number } {
  return {
    line: node.loc?.start.line ?? 1,
    column: (node.loc?.start.column ?? 0) + 1,
  };
}

/**
 * Checks whether the file is located inside a `test` directory.
 */
export function isInTestDirectory(filePath: string): boolean {
  const dirSegments = path.dirname(filePath).split(/[\\/]+/);
  return dirSegments.some((segment) => segment.toLowerCase() === 'test');
}

export const hardcodedSecretsRule: Rule = {
  id: 'hardcoded-secrets',
  cwe: 'CWE-798',
  name: 'Hardcoded Secrets',
  severity: 'HIGH',
  description:
    'Potential hardcoded credential, API key, token, or secret detected in source code.',
  remediation:
    'Remove hardcoded secrets from source code and load them from environment variables or a secrets manager.',

  createVisitor(context: RuleContext): TraverseOptions {
    const reportedValueNodes = new WeakSet<Node>();
    const inTestDirectory = isInTestDirectory(context.filePath);

    function reportSecretNode(
      valueNode: Node,
      reportNode: Node,
      message: string,
      severity?: Severity,
    ): void {
      if (reportedValueNodes.has(valueNode)) {
        return;
      }

      reportedValueNodes.add(valueNode);
      const { line, column } = getLocation(reportNode);

      context.report({
        line,
        column,
        message,
        severity: inTestDirectory ? 'LOW' : severity,
      });
    }

    function checkNamedAssignment(
      targetNode: Node | null | undefined,
      valueNode: Node | null | undefined,
      reportNode: Node,
      isComputedKey = false,
    ): void {
      if (!valueNode) {
        return;
      }

      const staticValue = extractStaticString(valueNode);
      if (staticValue === null) {
        return;
      }

      const signatureMatch = matchSecretSignature(staticValue);
      if (signatureMatch) {
        reportSecretNode(
          valueNode,
          reportNode,
          `Hardcoded ${signatureMatch.name} detected.`,
          signatureMatch.severity,
        );
        return;
      }

      if (isComputedKey && targetNode?.type !== 'StringLiteral') {
        return;
      }

      const targetName = extractTargetName(targetNode);
      if (!targetName || !isSensitiveName(targetName)) {
        return;
      }

      if (isLikelyPlaceholderOrSafeValue(staticValue)) {
        return;
      }

      reportSecretNode(
        valueNode,
        reportNode,
        `Potential hardcoded secret assigned to "${targetName}".`,
      );
    }

    function checkStandaloneLiteral(node: Node): void {
      if (reportedValueNodes.has(node)) {
        return;
      }

      const staticValue = extractStaticString(node);
      if (staticValue === null) {
        return;
      }

      const signatureMatch = matchSecretSignature(staticValue);
      if (!signatureMatch) {
        return;
      }

      reportSecretNode(
        node,
        node,
        `Hardcoded ${signatureMatch.name} detected.`,
        signatureMatch.severity,
      );
    }

    return {
      VariableDeclarator(path) {
        checkNamedAssignment(path.node.id, path.node.init, path.node);
      },

      ObjectProperty(path) {
        if (path.parentPath.isObjectPattern()) {
          return;
        }
        checkNamedAssignment(
          path.node.key,
          path.node.value,
          path.node,
          path.node.computed,
        );
      },

      AssignmentExpression(path) {
        checkNamedAssignment(path.node.left, path.node.right, path.node);
      },

      ClassProperty(path) {
        checkNamedAssignment(
          path.node.key,
          path.node.value,
          path.node,
          path.node.computed,
        );
      },

      StringLiteral(path) {
        checkStandaloneLiteral(path.node);
      },

      TemplateLiteral(path) {
        checkStandaloneLiteral(path.node);
      },
    };
  },
};
