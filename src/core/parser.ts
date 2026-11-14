import fs from 'node:fs';
import { parse, type ParseResult, type ParserOptions } from '@babel/parser';
import type { File } from '@babel/types';

const DEFAULT_PARSER_OPTIONS: ParserOptions = {
  sourceType: 'unambiguous',
  errorRecovery: true,
  plugins: ['typescript', 'jsx', 'decorators-legacy'],
};

/**
 * Parses JavaScript/TypeScript source code into a Babel AST.
 */
export function parseCode(
  sourceCode: string,
  sourceFilename?: string,
): ParseResult<File> {
  return parse(sourceCode, {
    ...DEFAULT_PARSER_OPTIONS,
    sourceFilename,
  });
}

/**
 * Reads a source file from disk and returns its parsed Babel AST.
 */
export function parseFile(filePath: string): ParseResult<File> {
  const sourceCode = fs.readFileSync(filePath, 'utf-8');
  return parseCode(sourceCode, filePath);
}
