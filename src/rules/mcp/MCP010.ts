import { makeLocation, createLineIndex } from '../../core/location.js';
import type { PartialFinding, Rule, SourceFile } from '../../core/types.js';

/**
 * MCP010 — dangerous execution sink in Python server source (docs/SPEC.md §7
 * catalog, §7.3 risk-surface family: `confidence: 'medium'`).
 *
 * MCP008's sibling, and it exists because MCP008 was blind to half the
 * ecosystem. The official `git`, `fetch` and `time` reference servers are
 * Python; so is every server in `awslabs/mcp`; so is FastMCP. A scan of
 * `awslabs/mcp` — 111 files, a monorepo of Python MCP servers — reported
 * **two** source files, because those were the only two that were not Python.
 *
 * Same contract as MCP008, deliberately: pattern matching over raw text, not
 * data-flow analysis. It reports that a sink *exists*; it cannot prove the
 * argument came from a tool call. Hence `medium` confidence and `high`, not
 * `critical`, severity.
 *
 * ## What it fires on, and why the conditions differ per sink
 *
 * Three families, with three different trigger conditions, because the thing
 * that makes them dangerous is different in each:
 *
 *  1. **String-to-code** (`eval`, `exec`) — unconditional. There is no version
 *     of these that belongs in a tool server, the same judgement MCP008 makes
 *     about its own two string-to-code sinks. (Written without the trailing
 *     parentheses on purpose: MCP008 matches raw text, and spelling its
 *     triggers out verbatim here would make this file flag itself.)
 *  2. **Shell** (`os.system`, `os.popen`, `subprocess.*` with `shell=True`) —
 *     only when the command argument is *built*, not fixed: an f-string,
 *     concatenation, `%` formatting or `.format()`. `os.system("ls")` is a
 *     shell call with nothing injectable in it. This mirrors MCP008's
 *     template-literal-or-concatenation condition on `child_process.exec`.
 *  3. **Deserialisation** (`pickle`, `marshal`, unsafe `yaml.load`) — by
 *     function, regardless of argument shape. This family has no equivalent in
 *     MCP008 because it barely exists in JavaScript, and its trigger is
 *     different in kind: `pickle.loads` executes constructor code *by design*
 *     while decoding, so the danger is the call itself, not how its argument
 *     was written. `yaml.load` is the one exception — it is safe with an
 *     explicit `Loader=`, so that is checked.
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
 * The `(?<!\.)` guard is doing real work here, not being defensive: the AWS
 * MySQL and Postgres MCP servers are full of `cursor.execute(f"SELECT ...")`.
 * That is SQL injection — a different rule, not this one — and without the
 * lookbehind this rule would bury its real findings under it.
 *
 * `\bexec\s*\(` alone would already miss `execute(` (the `(` does not follow
 * `exec`), but a method named exactly `exec` on a DB or process wrapper is
 * common enough to be worth excluding explicitly.
 */
const EVAL_RE = /(?<!\.)\beval\s*\(/g;
const EXEC_RE = /(?<!\.)\bexec\s*\(/g;

const OS_SYSTEM_RE = /\bos\.system\s*\(/g;
const OS_POPEN_RE = /\bos\.popen\s*\(/g;

/** `subprocess.run(`, `.Popen(`, `.call(`, `.check_call(`, `.check_output(`. */
const SUBPROCESS_RE = /\bsubprocess\.(run|Popen|call|check_call|check_output)\s*\(/g;

const PICKLE_RE = /\bpickle\.loads?\s*\(/g;
const MARSHAL_RE = /\bmarshal\.loads\s*\(/g;
const YAML_LOAD_RE = /\byaml\.load\s*\(/g;

/** `shell=True`, with any spacing around the `=`. */
const SHELL_TRUE_RE = /\bshell\s*=\s*True\b/;

/** `Loader=` / `SafeLoader` — an explicit loader makes `yaml.load` safe. */
const YAML_LOADER_RE = /\bLoader\s*=/;

/**
 * Blanks out comment bodies and string *contents*, keeping every other
 * character — and every newline — exactly where it was. The result is the same
 * length as the input, so an offset found in the masked text addresses the same
 * position in the original.
 *
 * This is what stops the rule reading prose as code. Scanning `awslabs/mcp` —
 * 1161 real Python files — produced exactly one finding, and it was the comment
 * `# Instead of using exec(), we'll use a function factory approach`, in a file
 * whose whole point was that it does *not* call `exec`. One finding, and it was
 * noise: precision of zero on real input.
 *
 * MCP008 has the same weakness for TypeScript and still documents it as
 * accepted — it is why a self-scan of this repository flags MCP008's own
 * source. That is a separate decision from this one; here the corpus made the
 * cost concrete, so it is paid.
 */
function maskLiterals(text: string): string {
  const out = text.split('');
  const blank = (from: number, to: number): void => {
    for (let i = from; i < to && i < out.length; i++) {
      if (out[i] !== '\n') out[i] = ' ';
    }
  };

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;

    if (ch === '#') {
      const nl = text.indexOf('\n', i);
      const end = nl < 0 ? text.length : nl;
      blank(i, end);
      i = end;
      continue;
    }

    if (ch === '"' || ch === "'") {
      const end = skipString(text, i);
      if (end < 0) {
        // Unterminated: blank to end of line and carry on rather than treating
        // the rest of the file as one string.
        const nl = text.indexOf('\n', i);
        blank(i + 1, nl < 0 ? text.length : nl);
        i = nl < 0 ? text.length : nl;
        continue;
      }
      const triple = text.startsWith(ch.repeat(3), i);
      const delimiterLength = triple ? 3 : 1;
      blank(i + delimiterLength, end - delimiterLength + 1);
      i = end;
    }
  }

  return out.join('');
}

/**
 * Reads the raw text between a call's parentheses, honouring Python string
 * literals and comments so a `)` or `,` inside either does not end the call
 * early. Returns `null` if the call is never closed.
 *
 * Written for Python rather than reusing MCP008's JavaScript walker: the
 * lexical rules genuinely differ — triple-quoted strings, string prefixes
 * (`f`, `r`, `b`, and their combinations), `#` comments, and no backticks.
 * Parameterising one scanner over two grammars would have been harder to read
 * than two short scanners.
 */
function extractCallText(text: string, openParenIndex: number): string | null {
  let depth = 0;

  for (let i = openParenIndex; i < text.length; i++) {
    const ch = text[i]!;

    if (ch === '#') {
      const nl = text.indexOf('\n', i);
      if (nl < 0) return null;
      i = nl;
      continue;
    }

    if (ch === '"' || ch === "'") {
      const end = skipString(text, i);
      if (end < 0) return null;
      i = end;
      continue;
    }

    if (ch === '(' || ch === '[' || ch === '{') { depth += 1; continue; }
    if (ch === ')' || ch === ']' || ch === '}') {
      depth -= 1;
      if (depth === 0) return text.slice(openParenIndex + 1, i);
    }
  }
  return null;
}

/**
 * Given the index of a quote character, returns the index of the closing
 * quote, or -1 if unterminated. Handles triple quotes and backslash escapes.
 */
function skipString(text: string, quoteIndex: number): number {
  const q = text[quoteIndex]!;
  const triple = text.startsWith(q.repeat(3), quoteIndex);
  const delimiter = triple ? q.repeat(3) : q;
  let i = quoteIndex + delimiter.length;

  while (i < text.length) {
    if (text[i] === '\\') { i += 2; continue; }
    if (text.startsWith(delimiter, i)) return i + delimiter.length - 1;
    // A single-quoted string cannot span a newline; treat one as unterminated
    // rather than swallowing the rest of the file.
    if (!triple && text[i] === '\n') return -1;
    i += 1;
  }
  return -1;
}

/** Splits call text on top-level commas, ignoring those inside strings or brackets. */
function splitArgs(callText: string): string[] {
  const args: string[] = [];
  let depth = 0;
  let start = 0;

  for (let i = 0; i < callText.length; i++) {
    const ch = callText[i]!;
    if (ch === '#') {
      const nl = callText.indexOf('\n', i);
      if (nl < 0) break;
      i = nl;
      continue;
    }
    if (ch === '"' || ch === "'") {
      const end = skipString(callText, i);
      if (end < 0) break;
      i = end;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') { depth += 1; continue; }
    if (ch === ')' || ch === ']' || ch === '}') { depth -= 1; continue; }
    if (ch === ',' && depth === 0) {
      args.push(callText.slice(start, i));
      start = i + 1;
    }
  }
  args.push(callText.slice(start));
  return args.map((a) => a.trim()).filter((a) => a.length > 0);
}

type ArgShape = 'fstring' | 'built' | 'plain-literal' | 'other';

/** The prefix letters Python allows before a string literal. */
const STRING_PREFIX_RE = /^([rbufRBUF]{0,3})(['"])/;

/**
 * Classifies the *first* argument of a call, which for every shell sink here
 * is the command.
 *
 * `'other'` — a bare variable, a function call — does not fire, matching
 * MCP008's treatment of `exec(cmd)`. It is the deliberate under-detection this
 * project prefers: a variable says nothing about where its value came from,
 * and firing on it would flag every well-written server that assembles its
 * argv in a helper.
 */
function classifyArg(raw: string): ArgShape {
  const t = raw.trim();
  if (t.length === 0) return 'other';

  const prefixMatch = STRING_PREFIX_RE.exec(t);
  if (prefixMatch) {
    const prefix = prefixMatch[1]!.toLowerCase();
    const quoteIndex = prefixMatch[1]!.length;
    const end = skipString(t, quoteIndex);
    const isWholeArg = end === t.length - 1;

    if (prefix.includes('f') && isWholeArg) return 'fstring';
    if (isWholeArg) return 'plain-literal';
    // A literal followed by something else: `"ls " + path`, `"ls %s" % path`,
    // `"ls {}".format(path)`. All of them build a command out of parts.
    if (end >= 0) return 'built';
  }

  if (hasTopLevelOperator(t)) return 'built';
  return 'other';
}

/** A top-level `+` or `%`, or a `.format(` call, outside any string or bracket. */
function hasTopLevelOperator(s: string): boolean {
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (ch === '"' || ch === "'") {
      const end = skipString(s, i);
      if (end < 0) return false;
      i = end;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') { depth += 1; continue; }
    if (ch === ')' || ch === ']' || ch === '}') { depth -= 1; continue; }
    if (depth !== 0) continue;
    if (ch === '+' || ch === '%') return true;
    if (s.startsWith('.format(', i)) return true;
  }
  return false;
}

const SHELL_REMEDIATION =
  'Pass the command and its arguments as a list and leave `shell=False` (the default) — ' +
  '`subprocess.run(["git", "log", rev])` — so no shell parses the string. If a shell is genuinely ' +
  'required, validate every interpolated value against a strict allowlist first, and prefer ' +
  '`shlex.quote()` over hand-built quoting.';

/** Sinks that execute a string as Python code. Unconditional. */
function findCodeSinks(masked: string): SinkMatch[] {
  const out: SinkMatch[] = [];
  for (const [re, fn] of [[EVAL_RE, 'eval'], [EXEC_RE, 'exec']] as const) {
    for (const m of masked.matchAll(re)) {
      out.push({
        index: m.index,
        length: m[0].length,
        message: `Calls \`${fn}()\`, executing a string as Python code at run time.`,
        remediation:
          `Avoid \`${fn}()\` entirely. If dynamic behaviour is genuinely needed, use an explicit ` +
          'allowlist — a dict mapping known-safe names to functions — instead of executing arbitrary text.',
        evidence: truncate(m[0]),
      });
    }
  }
  return out;
}

/** `os.system` / `os.popen`: always a shell, so only the argument shape matters. */
function findOsShellSinks(masked: string, original: string, re: RegExp, fn: string): SinkMatch[] {
  const out: SinkMatch[] = [];
  for (const m of masked.matchAll(re)) {
    const openParen = m.index + m[0].length - 1;
    // Structure is read from the masked text, evidence from the real one.
    const callText = extractCallText(masked, openParen);
    const callTextRaw = extractCallText(original, openParen);
    if (callText === null || callTextRaw === null) continue;

    const shape = classifyArg(splitArgs(callText)[0] ?? '');
    if (shape !== 'fstring' && shape !== 'built') continue;

    out.push({
      index: m.index,
      length: m[0].length,
      message:
        `Calls \`${fn}()\` with a command built from ${shape === 'fstring' ? 'an f-string' : 'string formatting'}, ` +
        'so the shell command executed is assembled from interpolated content rather than a fixed string.',
      remediation: SHELL_REMEDIATION,
      evidence: truncate(`${m[0]}${callTextRaw.trim().slice(0, 80)}`),
    });
  }
  return out;
}

/** `subprocess.*`: dangerous specifically when `shell=True` meets a built command. */
function findSubprocessSinks(masked: string, original: string): SinkMatch[] {
  const out: SinkMatch[] = [];
  for (const m of masked.matchAll(SUBPROCESS_RE)) {
    const openParen = m.index + m[0].length - 1;
    const callText = extractCallText(masked, openParen);
    const callTextRaw = extractCallText(original, openParen);
    if (callText === null || callTextRaw === null) continue;
    // Masked, so a `shell=True` inside a string or comment does not count.
    if (!SHELL_TRUE_RE.test(callText)) continue;

    const shape = classifyArg(splitArgs(callText)[0] ?? '');
    // A fixed literal is the one safe shape: `subprocess.run("ls -la", shell=True)`
    // has nothing interpolated into it. Everything else fires.
    //
    // A bare variable (`shape === 'other'`) fires HERE but not in the sinks
    // above, and the difference is `shell=True` itself. `classifyArg`'s doc
    // explains why a variable is normally left alone: a well-written server
    // assembles its argv in a helper, and the variable says nothing about where
    // the value came from. But a server that assembles an argv *list* has no
    // reason to ask for a shell — passing a list is precisely how you avoid one.
    // `shell=True` next to a non-literal is the author saying the string is a
    // shell command they built somewhere else.
    //
    // Measured before shipping: across every legitimate Python MCP server on
    // hand — the whole `awslabs/mcp` monorepo included — `shell=True` appears
    // 6 times and *not once in executable code*. All six are comments recording
    // that the author deliberately avoided it ("Use list arguments instead of
    // shell=True for security"). Masking keeps those comments out. DVMCP
    // challenge 9 is what exposed the gap: it builds `command = f"ping -c
    // {count} {host}"` on one line and runs it on the next, so the f-string is
    // out of the call and the old shape test saw only a variable.
    if (shape === 'plain-literal') continue;

    const built =
      shape === 'fstring' ? 'an f-string'
      : shape === 'built' ? 'string formatting'
      : 'a value built elsewhere';

    out.push({
      index: m.index,
      length: m[0].length,
      message:
        `Calls \`subprocess.${m[1]}(...)\` with \`shell=True\` and a command built from ` +
        `${built}. The string is parsed by a shell, ` +
        'so an interpolated value containing `;`, `|` or `$()` runs as a separate command.',
      remediation: SHELL_REMEDIATION,
      evidence: truncate(`${m[0]}${callTextRaw.trim().slice(0, 80)}`),
    });
  }
  return out;
}

/** Deserialisation that runs code while decoding. Triggered by the call itself. */
function findDeserialisationSinks(masked: string): SinkMatch[] {
  const out: SinkMatch[] = [];

  for (const [re, fn] of [[PICKLE_RE, 'pickle'], [MARSHAL_RE, 'marshal']] as const) {
    for (const m of masked.matchAll(re)) {
      out.push({
        index: m.index,
        length: m[0].length,
        message:
          `Calls \`${m[0].replace(/\s*\($/, '')}()\`. ${fn === 'pickle' ? 'Unpickling' : 'Unmarshalling'} ` +
          'executes code contained in the payload as part of decoding it, so any attacker-supplied ' +
          'bytes reaching this call are equivalent to arbitrary code execution.',
        remediation:
          'Do not deserialise untrusted data with this module. Use a data-only format — `json`, or ' +
          '`yaml.safe_load` — and validate the decoded structure against an expected schema.',
        evidence: truncate(m[0]),
      });
    }
  }

  for (const m of masked.matchAll(YAML_LOAD_RE)) {
    const openParen = m.index + m[0].length - 1;
    const callText = extractCallText(masked, openParen);
    // An explicit `Loader=` is the documented way to make this safe, so a call
    // that passes one is not this rule's concern.
    if (callText !== null && YAML_LOADER_RE.test(callText)) continue;

    out.push({
      index: m.index,
      length: m[0].length,
      message:
        'Calls `yaml.load()` with no explicit `Loader=`. The default loader constructs arbitrary ' +
        'Python objects from the document, which makes a malicious YAML file equivalent to code execution.',
      remediation:
        'Use `yaml.safe_load()`, or pass `Loader=yaml.SafeLoader` explicitly.',
      evidence: truncate(m[0]),
    });
  }

  return out;
}

export const MCP010 = {
  id: 'MCP010',
  title: 'Dangerous execution sink in Python server source',
  severity: 'high',
  confidence: 'medium',
  owasp: 'MCP05:2025 – Command Injection & Execution',
  appliesTo: 'sourceFile',
  check(sourceFile: SourceFile) {
    if (sourceFile.language !== 'py') return [];

    const text = sourceFile.text;
    // Everything structural is decided on the masked text; only the evidence
    // string comes from the source as written.
    const masked = maskLiterals(text);
    const matches: SinkMatch[] = [
      ...findCodeSinks(masked),
      ...findOsShellSinks(masked, text, OS_SYSTEM_RE, 'os.system'),
      ...findOsShellSinks(masked, text, OS_POPEN_RE, 'os.popen'),
      ...findSubprocessSinks(masked, text),
      ...findDeserialisationSinks(masked),
    ];
    if (matches.length === 0) return [];

    const lineStarts = createLineIndex(text);
    return matches
      .sort((a, b) => a.index - b.index)
      .map((m): PartialFinding => ({
        location: makeLocation(sourceFile.file, text, m.index, m.length, undefined, lineStarts),
        message: m.message,
        remediation: m.remediation,
        evidence: m.evidence,
      }));
  },
} satisfies Rule;
