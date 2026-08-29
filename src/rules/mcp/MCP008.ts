import { makeLocation, createLineIndex } from '../../core/location.js';
import type { PartialFinding, Rule, SourceFile } from '../../core/types.js';

/**
 * MCP008 — dangerous execution sink in server source (docs/SPEC.md §7
 * catalog, §7.3 risk-surface family: `confidence: 'medium'`).
 *
 * This is PATTERN MATCHING over raw text, not data-flow analysis. It flags
 * that a sink *exists* in the source — it does not, and cannot, prove a path
 * from a tool's arguments to that sink. A `child_process.exec` call built
 * from a template literal is exactly as dangerous whether or not any of its
 * interpolated values ever came from `request.params.arguments`; conversely
 * a template-literal `exec()` built entirely from constants the process
 * itself controls is not exploitable at all. The rule can't tell those
 * apart — hence `medium` confidence and `high` (not `critical`) severity.
 * See docs/rules/MCP008.md and docs/SPEC.md §7.4 for the accepted misses
 * this implies.
 */

const EVIDENCE_MAX = 160;

function truncate(s: string): string {
  return s.length > EVIDENCE_MAX ? `${s.slice(0, EVIDENCE_MAX - 1)}…` : s;
}

interface SinkMatch {
  index: number;
  length: number;
  message: string;
  remediation: string;
  evidence: string;
}

/**
 * `eval(` — word-boundary anchored so `evaluate(` and `myEval(` never match
 * (both fail on the boundary/adjacency check on their own: `evaluate(` has
 * no `(` immediately after `eval`, and `myEval(` has no `\b` between `y` and
 * `E`). The negative lookbehind additionally excludes `.eval(` — a property
 * access on an object (`obj.eval(...)`), which the spec explicitly calls out
 * as a case that must not fire.
 */
const EVAL_RE = /(?<!\.)\beval\s*\(/g;

/** `new Function(...)` — the other classic string-to-code sink. */
const NEW_FUNCTION_RE = /\bnew\s+Function\s*\(/g;

/**
 * `child_process.exec(` — qualified on purpose. A bare `exec(` is too common
 * a function/variable name on its own (any promise-based wrapper, test
 * helper, etc.) to anchor a security finding on; requiring the
 * `child_process.` prefix keeps this specific to the Node built-in.
 */
const EXEC_QUALIFIED_RE = /\bchild_process\.exec\s*\(/g;

/**
 * `execSync(` — distinctive enough on its own (no common unrelated meaning)
 * that no qualifier is required; this also incidentally covers
 * `child_process.execSync(`, since `\b` matches at the `.execSync` boundary.
 */
const EXEC_SYNC_RE = /\bexecSync\s*\(/g;

/**
 * Extracts the raw text of the first argument of a call whose `(` is at
 * `openParenIndex`, honoring nested parens/brackets/braces and string/
 * template literals (so a comma or paren inside a string doesn't end the
 * argument early). Returns `null` if the call is never closed.
 */
function extractFirstArg(text: string, openParenIndex: number): string | null {
  let depth = 0;
  let inString: string | null = null;
  const argStart = openParenIndex + 1;

  for (let i = openParenIndex; i < text.length; i++) {
    const ch = text[i];
    if (inString !== null) {
      if (ch === '\\') { i += 1; continue; }
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { inString = ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { depth += 1; continue; }
    if (ch === ')' || ch === ']' || ch === '}') {
      depth -= 1;
      if (depth === 0) return text.slice(argStart, i);
      continue;
    }
    if (ch === ',' && depth === 1) return text.slice(argStart, i);
  }
  return null;
}

/** True when `s` is a top-level `+` outside of any string/template literal or nested bracket. */
function hasTopLevelPlus(s: string): boolean {
  let inString: string | null = null;
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inString !== null) {
      if (ch === '\\') { i += 1; continue; }
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { inString = ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { depth += 1; continue; }
    if (ch === ')' || ch === ']' || ch === '}') { depth -= 1; continue; }
    if (ch === '+' && depth === 0) return true;
  }
  return false;
}

/** True when `t` (already trimmed) is exactly one `'...'` or `"..."` literal, with no trailing content. */
function isPlainStringLiteral(t: string): boolean {
  if (t.length < 2) return false;
  const q = t[0];
  if ((q !== '"' && q !== "'") || t[t.length - 1] !== q) return false;
  const inner = t.slice(1, -1);
  for (let i = 0; i < inner.length; i++) {
    if (inner[i] === '\\') { i += 1; continue; }
    if (inner[i] === q) return false; // an unescaped quote before the end -> not a single plain literal
  }
  return true;
}

type ArgShape = 'template' | 'concat' | 'plain-literal' | 'other';

function classifyArg(raw: string): ArgShape {
  const t = raw.trim();
  if (t.startsWith('`')) return 'template';
  if (isPlainStringLiteral(t)) return 'plain-literal';
  if (hasTopLevelPlus(t)) return 'concat';
  return 'other';
}

function findEvalSinks(text: string): SinkMatch[] {
  const out: SinkMatch[] = [];
  for (const m of text.matchAll(EVAL_RE)) {
    out.push({
      index: m.index,
      length: m[0].length,
      message: 'Calls `eval()`, executing a string as code at run time.',
      remediation:
        'Avoid `eval()` entirely. If dynamic behavior is genuinely needed, use an explicit allowlist ' +
        '(a lookup table of known-safe functions) instead of evaluating arbitrary text as code.',
      evidence: truncate(m[0]),
    });
  }
  return out;
}

function findNewFunctionSinks(text: string): SinkMatch[] {
  const out: SinkMatch[] = [];
  for (const m of text.matchAll(NEW_FUNCTION_RE)) {
    out.push({
      index: m.index,
      length: m[0].length,
      message: 'Calls `new Function(...)`, compiling a string into a function body at run time.',
      remediation:
        '`new Function()` is `eval` in a different shape — the same allowlist advice applies. Replace ' +
        'with an explicit, statically-defined function.',
      evidence: truncate(m[0]),
    });
  }
  return out;
}

function findExecSinks(text: string, re: RegExp, fnLabel: string): SinkMatch[] {
  const out: SinkMatch[] = [];
  for (const m of text.matchAll(re)) {
    const openParenIndex = m.index + m[0].length - 1; // m[0] ends in '('
    const arg = extractFirstArg(text, openParenIndex);
    if (arg === null) continue;
    const shape = classifyArg(arg);
    if (shape !== 'template' && shape !== 'concat') continue; // plain literal / other: not this rule's concern

    out.push({
      index: m.index,
      length: m[0].length,
      message:
        `Calls \`${fnLabel}(...)\` with a ` +
        `${shape === 'template' ? 'template-literal' : 'string-concatenation'} argument, so the shell ` +
        `command executed is built from interpolated content rather than a fixed string.`,
      remediation:
        'Pass the command and its arguments separately to `execFile`/`spawn` (no shell, no string ' +
        'building) instead of interpolating values into a shell command string. If a shell is genuinely ' +
        'required, validate every interpolated value against a strict allowlist first.',
      evidence: truncate(`${m[0]}${arg.trim().slice(0, 80)}`),
    });
  }
  return out;
}

export const MCP008 = {
  id: 'MCP008',
  title: 'Dangerous execution sink in server source',
  severity: 'high',
  confidence: 'medium',
  owasp: 'MCP05:2025 – Command Injection & Execution',
  appliesTo: 'sourceFile',
  check(sourceFile: SourceFile) {
    if (sourceFile.language !== 'ts' && sourceFile.language !== 'js') return [];

    const matches: SinkMatch[] = [
      ...findEvalSinks(sourceFile.text),
      ...findNewFunctionSinks(sourceFile.text),
      ...findExecSinks(sourceFile.text, EXEC_QUALIFIED_RE, 'child_process.exec'),
      ...findExecSinks(sourceFile.text, EXEC_SYNC_RE, 'execSync'),
    ];
    if (matches.length === 0) return [];

    const lineStarts = createLineIndex(sourceFile.text);
    const findings: PartialFinding[] = matches
      .sort((a, b) => a.index - b.index)
      .map((m) => ({
        location: makeLocation(sourceFile.file, sourceFile.text, m.index, m.length, undefined, lineStarts),
        message: m.message,
        remediation: m.remediation,
        evidence: m.evidence,
      }));
    return findings;
  },
} satisfies Rule;
