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

/**
 * A `/` is a division rather than the start of a regex literal when the
 * previous significant character could end an expression: an identifier, a
 * number, a closing bracket, or a string.
 *
 * `}` is counted as expression-ending, which is the conservative choice — it is
 * genuinely ambiguous (block end vs object literal end), and guessing
 * "division" only ever means a regex goes unrecognised.
 */
const ENDS_EXPRESSION = /[\w$)\]}'"`]/;

/**
 * From the `/` that opens a regex literal, the index of the `/` that closes it,
 * or -1. A `/` inside a character class does not close it — `/[/]/` is one
 * regex, not two.
 */
function skipRegexLiteral(text: string, start: number): number {
  let inClass = false;
  for (let i = start + 1; i < text.length; i++) {
    const ch = text[i]!;
    if (ch === '\\') { i += 1; continue; }
    if (ch === '\n') return -1; // a regex literal cannot span a line
    if (ch === '[') inClass = true;
    else if (ch === ']') inClass = false;
    else if (ch === '/' && !inClass) return i;
  }
  return -1;
}

/**
 * Blanks out comment bodies and string *contents*, keeping every other
 * character — and every newline — exactly where it was, so an offset found in
 * the masked text addresses the same position in the original.
 *
 * ## Why strings, and not just comments
 *
 * An earlier version masked only comments, on the reasoning that JavaScript
 * string literals are hard to delimit safely because a regex literal such as
 * `/["']/` contains a quote that starts no string. That reasoning was right
 * about the difficulty and wrong about the trade: it weighed the risk of
 * masking without weighing the cost of not masking.
 *
 * A scan of `czlonkowski/n8n-mcp` settled it — **four findings out of five
 * were string contents**, and none was a sink:
 *
 *   `jsCode: 'const result = eval(item.json.code);'`  test fixture data
 *   `code?.includes('eval(')`                          a security check
 *   `'Avoid eval() - it's a security risk'`            a warning message, twice
 *
 * The last two are from that project's own dangerous-pattern validator, which
 * strips strings and comments before running its checks. It had solved this
 * exact problem, and this rule flagged the warning text of the solution.
 *
 * ## How the regex-literal problem is handled
 *
 * Two defences rather than a parser. Regex literals are recognised and skipped
 * using the previous-significant-character heuristic above, which covers the
 * shapes that occur in practice (`= /re/`, `: /re/`, `(/re/`). And every
 * quoted-string mask is bounded to its own line, which JavaScript's `'` and
 * `"` literals cannot cross anyway — so when the heuristic is fooled, the
 * damage is one line, not the rest of the file.
 *
 * The residual risk is a missed sink on a line where a regex literal contains
 * an unbalanced quote. Measured against four false positives in five on real
 * code, that is the better side to fail on.
 */
function maskLiterals(text: string): string {
  const out = text.split('');
  const blank = (from: number, to: number): void => {
    for (let i = from; i < to && i < out.length; i++) {
      if (out[i] !== '\n') out[i] = ' ';
    }
  };

  let previous = '';

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;

    if (ch === '/' && text[i + 1] === '/') {
      const nl = text.indexOf('\n', i);
      const end = nl < 0 ? text.length : nl;
      blank(i, end);
      i = end;
      continue;
    }

    if (ch === '/' && text[i + 1] === '*') {
      const close = text.indexOf('*/', i + 2);
      const end = close < 0 ? text.length : close + 2;
      blank(i, end);
      i = end - 1;
      continue;
    }

    if (ch === '/' && (previous === '' || !ENDS_EXPRESSION.test(previous))) {
      const end = skipRegexLiteral(text, i);
      if (end > 0) {
        // Left intact: a regex is code, and its contents are not prose. Skipping
        // it is what keeps a quote inside it from opening a bogus string.
        i = end;
        previous = '/';
        continue;
      }
    }

    if (ch === '"' || ch === "'" || ch === '`') {
      let closed = i;
      for (let j = i + 1; j < text.length; j++) {
        if (text[j] === '\\') { j += 1; continue; }
        if (text[j] === ch) { closed = j; break; }
        // A quoted string cannot span a newline; a template literal can.
        if (ch !== '`' && text[j] === '\n') { closed = j - 1; break; }
      }
      blank(i + 1, closed);
      i = closed;
      previous = ch;
      continue;
    }

    if (!/\s/.test(ch)) previous = ch;
  }

  return out.join('');
}

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

function findEvalSinks(masked: string): SinkMatch[] {
  const out: SinkMatch[] = [];
  for (const m of masked.matchAll(EVAL_RE)) {
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

function findNewFunctionSinks(masked: string): SinkMatch[] {
  const out: SinkMatch[] = [];
  for (const m of masked.matchAll(NEW_FUNCTION_RE)) {
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

function findExecSinks(masked: string, original: string, re: RegExp, fnLabel: string): SinkMatch[] {
  const out: SinkMatch[] = [];
  for (const m of masked.matchAll(re)) {
    const openParenIndex = m.index + m[0].length - 1; // m[0] ends in '('
    // Shape is read from the masked text, evidence from the source as written.
    const arg = extractFirstArg(masked, openParenIndex);
    const argRaw = extractFirstArg(original, openParenIndex);
    if (arg === null || argRaw === null) continue;
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
      evidence: truncate(`${m[0]}${argRaw.trim().slice(0, 80)}`),
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

    // Comments and string contents are blanked first: a sink named in prose,
    // in test data, or in a warning message is not a sink.
    const masked = maskLiterals(sourceFile.text);
    const matches: SinkMatch[] = [
      ...findEvalSinks(masked),
      ...findNewFunctionSinks(masked),
      ...findExecSinks(masked, sourceFile.text, EXEC_QUALIFIED_RE, 'child_process.exec'),
      ...findExecSinks(masked, sourceFile.text, EXEC_SYNC_RE, 'execSync'),
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
