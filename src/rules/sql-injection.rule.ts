import type { Node } from '@babel/types';
import type { Scope } from '@babel/traverse';
import type { Rule, RuleContext, TraverseOptions } from '../types/finding.js';

const UNSAFE_RAW_METHODS = new Set([
  '$queryRawUnsafe',
  '$executeRawUnsafe',
]);

const QUERY_METHODS = new Set([
  'query',
  'execute',
  'raw',
  'prepare',
  'exec',
  'all',
  'get',
  'run',
  'batch',
  '$queryRawUnsafe',
  '$executeRawUnsafe',
]);

const TAGGED_UNSAFE_RAW_METHODS = new Set([
  'raw',
  '$queryRawUnsafe',
  '$executeRawUnsafe',
]);

const PARAMETERIZED_SQL_TAG_PATTERN =
  /^(?:sql|query|\$?queryRaw|\$?executeRaw)$/i;

const RAW_FRAGMENT_HELPER_METHODS = new Set([
  'raw',
  'literal',
  'unsafe',
]);

const DB_OBJECT_PATTERN =
  /(?:^|[_$])(?:db|database|pool|conn|connection|client|knex|sequelize|prisma|typeorm|dataSource|manager|repository|repo|tx|trx|stmt|statement|cursor|sqlite|mysql|pg|postgres)$/i;

const NON_SQL_LOG_OBJECTS = new Set([
  'console',
  'logger',
  'log',
  'Math',
  'JSON',
  'Object',
  'Array',
  'String',
  'Number',
  'RegExp',
  'Promise',
]);

const NON_SQL_UTILITY_METHODS = new Set([
  'log',
  'info',
  'warn',
  'error',
  'debug',
  'trace',
  'format',
  'stringify',
  'parse',
  'match',
  'test',
  'replace',
  'split',
  'join',
  'slice',
  'substring',
  'trim',
]);

const SQL_KEYWORD_PATTERN =
  /\b(?:SELECT\b[\s\S]*?\bFROM|INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|DROP\s+(?:TABLE|DATABASE|INDEX)|ALTER\s+TABLE|CREATE\s+(?:TABLE|DATABASE|INDEX)|TRUNCATE\s+TABLE|UNION\s+(?:ALL\s+)?SELECT)\b/i;

const PARTIAL_SQL_PATTERN =
  /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WHERE|FROM|JOIN|VALUES|ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|DROP\s+TABLE|ALTER\s+TABLE)\b/i;

const HIGH_CONFIDENCE_QUERY_METHODS = new Set(['query', 'execute', 'raw']);

function unwrapExpression(node: Node): Node {
  let current = node;
  while (
    current.type === 'ParenthesizedExpression' ||
    current.type === 'TSAsExpression' ||
    current.type === 'TSTypeAssertion' ||
    current.type === 'TSNonNullExpression'
  ) {
    current = current.expression;
  }
  return current;
}

function isConcatCall(node: Node): node is Extract<Node, { type: 'CallExpression' }> {
  return (
    node.type === 'CallExpression' &&
    node.callee.type === 'MemberExpression' &&
    !node.callee.computed &&
    node.callee.property.type === 'Identifier' &&
    node.callee.property.name === 'concat'
  );
}

function isDynamicConstructionNode(node: Node): boolean {
  const unwrapped = unwrapExpression(node);
  return (
    (unwrapped.type === 'BinaryExpression' && unwrapped.operator === '+') ||
    (unwrapped.type === 'TemplateLiteral' && unwrapped.expressions.length > 0) ||
    isConcatCall(unwrapped)
  );
}

/**
 * Determines whether an AST expression evaluates solely from static literals or constant bindings.
 */
export function isStaticExpression(
  node: Node | null | undefined,
  scope: Scope,
  visited = new Set<string>(),
): boolean {
  if (!node) {
    return true;
  }

  const expr = unwrapExpression(node);

  if (
    expr.type === 'StringLiteral' ||
    expr.type === 'NumericLiteral' ||
    expr.type === 'BooleanLiteral' ||
    expr.type === 'NullLiteral'
  ) {
    return true;
  }

  if (expr.type === 'TemplateLiteral') {
    return expr.expressions.every((subExpr) =>
      isStaticExpression(subExpr, scope, visited),
    );
  }

  if (expr.type === 'BinaryExpression' && expr.operator === '+') {
    return (
      isStaticExpression(expr.left, scope, visited) &&
      isStaticExpression(expr.right, scope, visited)
    );
  }

  if (isConcatCall(expr) && expr.callee.type === 'MemberExpression') {
    return (
      isStaticExpression(expr.callee.object, scope, visited) &&
      expr.arguments.every((arg) => isStaticExpression(arg, scope, visited))
    );
  }

  if (expr.type === 'Identifier') {
    if (visited.has(expr.name)) {
      return false;
    }

    const binding = scope.getBinding(expr.name);
    if (!binding || binding.kind === 'param' || !binding.constant) {
      return false;
    }

    if (!binding.path.isVariableDeclarator()) {
      return false;
    }

    visited.add(expr.name);
    const result = isStaticExpression(
      binding.path.node.init,
      binding.scope,
      visited,
    );
    visited.delete(expr.name);
    return result;
  }

  return false;
}

/**
 * Collects static string fragments from an expression and its local variable bindings.
 */
export function extractStaticText(
  node: Node | null | undefined,
  scope: Scope,
  visited = new Set<string>(),
): string {
  if (!node) {
    return '';
  }

  const expr = unwrapExpression(node);

  if (expr.type === 'StringLiteral') {
    return expr.value;
  }

  if (expr.type === 'TemplateLiteral') {
    const parts: string[] = [];
    for (let i = 0; i < expr.quasis.length; i += 1) {
      const quasi = expr.quasis[i];
      if (quasi) {
        parts.push(quasi.value.cooked ?? quasi.value.raw);
      }
      const subExpr = expr.expressions[i];
      if (subExpr) {
        const subText = extractStaticText(subExpr, scope, visited);
        if (subText) {
          parts.push(subText);
        }
      }
    }
    return parts.join(' ');
  }

  if (expr.type === 'BinaryExpression' && expr.operator === '+') {
    const leftText = extractStaticText(expr.left, scope, visited);
    const rightText = extractStaticText(expr.right, scope, visited);
    return `${leftText} ${rightText}`.trim();
  }

  if (isConcatCall(expr) && expr.callee.type === 'MemberExpression') {
    const parts = [
      extractStaticText(expr.callee.object, scope, visited),
      ...expr.arguments.map((arg) => extractStaticText(arg, scope, visited)),
    ];
    return parts.filter(Boolean).join(' ');
  }

  if (expr.type === 'Identifier') {
    if (visited.has(expr.name)) {
      return '';
    }

    const binding = scope.getBinding(expr.name);
    if (!binding) {
      return '';
    }

    visited.add(expr.name);
    const parts: string[] = [];

    if (binding.path.isVariableDeclarator() && binding.path.node.init) {
      parts.push(
        extractStaticText(binding.path.node.init, binding.scope, visited),
      );
    }

    for (const violation of binding.constantViolations) {
      if (violation.isAssignmentExpression()) {
        parts.push(
          extractStaticText(violation.node.right, violation.scope, visited),
        );
      }
    }

    visited.delete(expr.name);
    return parts.filter(Boolean).join(' ');
  }

  return '';
}

function getPropertyKeyName(node: Node): string | null {
  if (node.type === 'Identifier') {
    return node.name;
  }
  if (node.type === 'StringLiteral') {
    return node.value;
  }
  return null;
}

/**
 * Extracts the SQL expression node directly or from `{ sql | text }` query option objects.
 */
export function extractQueryNodeFromArg(
  arg: Node | null | undefined,
): Node | null {
  if (!arg) {
    return null;
  }

  const unwrapped = unwrapExpression(arg);
  if (unwrapped.type !== 'ObjectExpression') {
    return unwrapped;
  }

  for (const prop of unwrapped.properties) {
    if (prop.type !== 'ObjectProperty' || prop.computed) {
      continue;
    }
    const keyName = getPropertyKeyName(prop.key);
    if (keyName === 'sql' || keyName === 'text') {
      return prop.value;
    }
  }

  return null;
}

interface CalleeInfo {
  methodName: string | null;
  objectName: string | null;
}

function extractCalleeInfo(callee: Node): CalleeInfo {
  if (callee.type === 'Identifier') {
    return { methodName: callee.name, objectName: null };
  }

  if (
    callee.type === 'MemberExpression' ||
    callee.type === 'OptionalMemberExpression'
  ) {
    const methodName = !callee.computed
      ? getPropertyKeyName(callee.property)
      : callee.property.type === 'StringLiteral'
        ? callee.property.value
        : null;

    let objectName: string | null = null;
    if (callee.object.type === 'Identifier') {
      objectName = callee.object.name;
    } else if (
      callee.object.type === 'MemberExpression' &&
      !callee.object.computed
    ) {
      objectName = getPropertyKeyName(callee.object.property);
    }

    return { methodName, objectName };
  }

  return { methodName: null, objectName: null };
}

function isDynamicVariableFromScope(node: Node, scope: Scope): boolean {
  const unwrapped = unwrapExpression(node);
  if (unwrapped.type !== 'Identifier') {
    return false;
  }
  const binding = scope.getBinding(unwrapped.name);
  if (!binding) {
    return false;
  }

  if (binding.path.isVariableDeclarator() && binding.path.node.init) {
    if (isDynamicConstructionNode(binding.path.node.init)) {
      return true;
    }
  }

  return binding.constantViolations.some(
    (violation) =>
      violation.isAssignmentExpression() &&
      isDynamicConstructionNode(violation.node.right),
  );
}

function getLocation(node: Node): { line: number; column: number } {
  return {
    line: node.loc?.start.line ?? 1,
    column: (node.loc?.start.column ?? 0) + 1,
  };
}

export const sqlInjectionRule: Rule = {
  id: 'sql-injection',
  cwe: 'CWE-89',
  name: 'SQL Injection',
  severity: 'CRITICAL',
  description:
    'Unsanitized user input concatenated or interpolated into a SQL query.',
  remediation:
    'Use parameterized queries or prepared statements instead of string concatenation or template interpolation.',

  createVisitor(context: RuleContext): TraverseOptions {
    const reportedNodes = new WeakSet<Node>();

    function reportNode(node: Node, message: string): void {
      if (reportedNodes.has(node)) {
        return;
      }

      reportedNodes.add(node);
      const { line, column } = getLocation(node);
      context.report({
        line,
        column,
        message,
      });
    }

    return {
      CallExpression(path) {
        if (reportedNodes.has(path.node)) {
          return;
        }

        const { methodName, objectName } = extractCalleeInfo(path.node.callee);
        const firstArg = path.node.arguments[0];
        if (!firstArg || firstArg.type === 'SpreadElement') {
          return;
        }

        const queryNode = extractQueryNodeFromArg(firstArg);
        if (!queryNode) {
          return;
        }

        if (isStaticExpression(queryNode, path.scope)) {
          return;
        }

        const sinkLabel = methodName
          ? objectName
            ? `${objectName}.${methodName}()`
            : `${methodName}()`
          : 'call';

        if (methodName && UNSAFE_RAW_METHODS.has(methodName)) {
          reportNode(
            path.node,
            `Potential SQL injection via unsafe raw query method "${sinkLabel}" with dynamic input.`,
          );
          return;
        }

        const staticText = extractStaticText(queryNode, path.scope);

        if (methodName && QUERY_METHODS.has(methodName)) {
          const isDbObject = Boolean(
            objectName && DB_OBJECT_PATTERN.test(objectName),
          );
          const hasFullSql = SQL_KEYWORD_PATTERN.test(staticText);
          const hasPartialSql = PARTIAL_SQL_PATTERN.test(staticText);
          const isHighConfidenceMethod =
            HIGH_CONFIDENCE_QUERY_METHODS.has(methodName);

          if (
            hasFullSql ||
            (hasPartialSql && (isHighConfidenceMethod || isDbObject))
          ) {
            reportNode(
              path.node,
              `Potential SQL injection in "${sinkLabel}" using dynamically constructed SQL.`,
            );
          }
          return;
        }

        if (
          (objectName && NON_SQL_LOG_OBJECTS.has(objectName)) ||
          (methodName && NON_SQL_UTILITY_METHODS.has(methodName))
        ) {
          return;
        }

        const isDynamicSql =
          isDynamicConstructionNode(queryNode) ||
          isDynamicVariableFromScope(queryNode, path.scope);

        if (isDynamicSql && SQL_KEYWORD_PATTERN.test(staticText)) {
          reportNode(
            path.node,
            `Potential SQL injection in "${sinkLabel}" using dynamically constructed SQL.`,
          );
        }
      },

      TaggedTemplateExpression(path) {
        const { tag, quasi } = path.node;
        if (quasi.expressions.length === 0) {
          return;
        }

        const { methodName, objectName } = extractCalleeInfo(tag);
        const tagLabel = methodName
          ? objectName
            ? `${objectName}.${methodName}`
            : methodName
          : 'tagged template';

        if (methodName && TAGGED_UNSAFE_RAW_METHODS.has(methodName)) {
          if (objectName === 'String') {
            return;
          }

          const hasDynamicExpr = quasi.expressions.some(
            (expr) => !isStaticExpression(expr, path.scope),
          );
          if (!hasDynamicExpr) {
            return;
          }

          const templateText = quasi.quasis
            .map((q) => q.value.cooked ?? q.value.raw)
            .join(' ');
          const isDbObject = Boolean(
            objectName && DB_OBJECT_PATTERN.test(objectName),
          );

          if (
            UNSAFE_RAW_METHODS.has(methodName) ||
            isDbObject ||
            SQL_KEYWORD_PATTERN.test(templateText) ||
            PARTIAL_SQL_PATTERN.test(templateText)
          ) {
            reportNode(
              path.node,
              `Potential SQL injection in raw tagged template "${tagLabel}" with interpolated expression.`,
            );
          }
          return;
        }

        if (!methodName || !PARAMETERIZED_SQL_TAG_PATTERN.test(methodName)) {
          return;
        }

        for (const expr of quasi.expressions) {
          const unwrapped = unwrapExpression(expr);

          if (unwrapped.type === 'CallExpression') {
            const innerCallee = extractCalleeInfo(unwrapped.callee);
            const innerArg = unwrapped.arguments[0];
            if (
              innerCallee.methodName &&
              RAW_FRAGMENT_HELPER_METHODS.has(innerCallee.methodName) &&
              innerArg &&
              innerArg.type !== 'SpreadElement' &&
              !isStaticExpression(innerArg, path.scope)
            ) {
              reportNode(
                unwrapped,
                `Potential SQL injection inside parameterized template "${tagLabel}" via dynamic raw fragment "${innerCallee.methodName}()".`,
              );
            }
            continue;
          }

          if (
            isDynamicConstructionNode(unwrapped) &&
            !isStaticExpression(unwrapped, path.scope)
          ) {
            reportNode(
              unwrapped,
              `Potential SQL injection inside tagged template "${tagLabel}" using dynamic string construction.`,
            );
          }
        }
      },
    };
  },
};
