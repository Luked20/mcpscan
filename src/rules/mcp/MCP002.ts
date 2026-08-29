import type { PartialFinding, Rule, ToolDefinition } from '../../core/types.js';

/**
 * Per-character-class policy — see docs/SPEC.md §7.2 and docs/rules/MCP002.md.
 *
 * "Invisible character" is not a binary category: every emoji ZWJ sequence uses
 * U+200D, ZWNJ is required spelling in Persian/Devanagari, and balanced bidi
 * isolates are the recommended way (UAX #9) to embed a Latin identifier in RTL
 * text. This rule flags by class + context, not by "is on the invisible list".
 *
 * Every codepoint below is referenced numerically (0x...) — never pasted as a
 * literal character in the source. A literal invisible character pasted here is
 * indistinguishable from a typo and has already broken this rule once before
 * (see git blame).
 */

const NAMES: Record<string, string> = {
  '200c': 'zero-width non-joiner',
  '200d': 'zero-width joiner',
  '200b': 'zero-width space',
  '2060': 'word joiner',
  feff: 'byte order mark',
  '202a': 'bidi LRE',
  '202b': 'bidi RLE',
  '202c': 'bidi PDF',
  '202d': 'bidi LRO',
  '202e': 'bidi RLO',
  '2066': 'bidi LRI',
  '2067': 'bidi RLI',
  '2068': 'bidi FSI',
  '2069': 'bidi PDI',
};

const isVariationSelector = (cp: number): boolean =>
  (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);

function describeCp(cp: number): string {
  const hex = cp.toString(16).padStart(4, '0');
  let label = NAMES[hex];
  if (!label) {
    if (cp >= 0xe0000 && cp <= 0xe007f) label = 'tag character';
    else if (isVariationSelector(cp)) label = 'variation selector';
    else label = 'invisible character';
  }
  return `U+${hex.toUpperCase()} (${label})`;
}

/** ASCII/Latin or digit — the class in which ZWJ/ZWNJ never has a legitimate joining role. */
const LATIN_OR_DIGIT = /^[\p{Script=Latin}\p{Nd}]$/u;
const isLatinOrDigit = (ch: string | undefined): boolean => ch !== undefined && LATIN_OR_DIGIT.test(ch);

/**
 * Marks, by codepoint index, which characters in `codepoints` should be
 * flagged — applying the "always / context-only / never" policy from §7.2.
 */
function classify(codepoints: string[]): boolean[] {
  const n = codepoints.length;
  const cps = codepoints.map((c) => c.codePointAt(0)!);
  const flagged = new Array<boolean>(n).fill(false);

  // Always: zero-width space, word joiner, BOM; bidi overrides (even balanced
  // ones, since they're the Trojan Source vector); tag characters (U+E0000-E007F).
  for (let i = 0; i < n; i++) {
    const c = cps[i]!;
    if (c === 0x200b || c === 0x2060 || c === 0xfeff) flagged[i] = true;
    else if (c === 0x202d || c === 0x202e) flagged[i] = true;
    else if (c >= 0xe0000 && c <= 0xe007f) flagged[i] = true;
  }

  // Always: a run of 3+ consecutive variation selectors. A single U+FE0F is
  // emoji presentation and does not flag.
  let runStart = -1;
  for (let i = 0; i <= n; i++) {
    const isVs = i < n && isVariationSelector(cps[i]!);
    if (isVs) {
      if (runStart === -1) runStart = i;
    } else if (runStart !== -1) {
      if (i - runStart >= 3) for (let j = runStart; j < i; j++) flagged[j] = true;
      runStart = -1;
    }
  }

  // Context: ZWJ/ZWNJ only when BOTH neighbors are ASCII/Latin or digits —
  // between emoji, or between Arabic/Indic letters, it's normal usage. At the
  // ends of the string (missing a neighbor on one side) there's no possible
  // joining role: flags too.
  for (let i = 0; i < n; i++) {
    const c = cps[i]!;
    if (c !== 0x200c && c !== 0x200d) continue;
    const hasLeft = i - 1 >= 0;
    const hasRight = i + 1 < n;
    if (!hasLeft || !hasRight) flagged[i] = true;
    else if (isLatinOrDigit(codepoints[i - 1]) && isLatinOrDigit(codepoints[i + 1])) flagged[i] = true;
  }

  // Context: bidi embeddings (LRE/RLE...PDF) only when unbalanced. Single stack
  // for embeddings AND overrides because PDF closes both in real Unicode — so a
  // balanced override (already always-flagged above) doesn't make a neighboring
  // embedding look unbalanced. Only an 'embedding' entry left open at the end (or
  // a PDF with nothing to close) produces an extra flag here.
  const stack: Array<{ i: number; type: 'embedding' | 'override' }> = [];
  for (let i = 0; i < n; i++) {
    const c = cps[i]!;
    if (c === 0x202a || c === 0x202b) stack.push({ i, type: 'embedding' });
    else if (c === 0x202d || c === 0x202e) stack.push({ i, type: 'override' });
    else if (c === 0x202c) {
      if (stack.length === 0) flagged[i] = true; // PDF with nothing open
      else stack.pop(); // closes the top, embedding or override — matched
    }
  }
  for (const entry of stack) if (entry.type === 'embedding') flagged[entry.i] = true;

  // Context: bidi isolates (LRI/RLI/FSI...PDI) only when unbalanced.
  const isolateStack: number[] = [];
  for (let i = 0; i < n; i++) {
    const c = cps[i]!;
    if (c === 0x2066 || c === 0x2067 || c === 0x2068) isolateStack.push(i);
    else if (c === 0x2069) {
      if (isolateStack.length === 0) flagged[i] = true; // PDI with nothing open
      else isolateStack.pop();
    }
  }
  for (const idx of isolateStack) flagged[idx] = true;

  // Never: U+200E (LRM) and U+200F (RLM) are untouched by any branch above.

  return flagged;
}

const EVIDENCE_RADIUS = 60;

/**
 * Window around the first hit — not a blind truncation from position 0, which
 * would show no signal at all for a 400-character payload with the hit at the end.
 * Sliced by codepoint (Array.from), never by code unit (`.slice`), so a surrogate
 * pair is never split in half.
 */
function buildEvidence(codepoints: string[], flagged: boolean[]): string {
  const n = codepoints.length;
  const firstHit = flagged.findIndex(Boolean);
  const start = Math.max(0, firstHit - EVIDENCE_RADIUS);
  const end = Math.min(n, firstHit + EVIDENCE_RADIUS + 1);
  const windowed = codepoints
    .slice(start, end)
    .map((c, idx) => (flagged[start + idx] ? '␡' : c))
    .join('');
  return (start > 0 ? '…' : '') + windowed + (end < n ? '…' : '');
}

function textFields(tool: ToolDefinition): Array<['name' | 'description', string]> {
  const out: Array<['name' | 'description', string]> = [['name', tool.name]];
  if (tool.description) out.push(['description', tool.description]);
  return out;
}

export const MCP002 = {
  id: 'MCP002',
  title: 'Invisible Unicode character in tool definition',
  severity: 'critical',
  confidence: 'high',
  owasp: 'MCP03:2025 – Tool Poisoning',
  appliesTo: 'tool',
  check(tool: ToolDefinition) {
    const findings: PartialFinding[] = [];
    for (const [field, value] of textFields(tool)) {
      const codepoints = Array.from(value);
      const flagged = classify(codepoints);
      const hitCount = flagged.reduce((acc, f) => acc + (f ? 1 : 0), 0);
      if (hitCount === 0) continue;

      const seen = new Set<string>();
      const descriptions: string[] = [];
      for (let i = 0; i < codepoints.length; i++) {
        if (!flagged[i]) continue;
        const desc = describeCp(codepoints[i]!.codePointAt(0)!);
        if (!seen.has(desc)) {
          seen.add(desc);
          descriptions.push(desc);
        }
      }

      findings.push({
        location: tool.loc(`${tool.origin.jsonPath}.${field}`),
        message:
          `Tool "${tool.name}" has ${hitCount} invisible character(s) in ` +
          `\`${field}\`: ${descriptions.join(', ')}.`,
        remediation:
          'Remove the invisible characters. This text is read by the model and never shown to the ' +
          'user — invisible content here is a hidden instruction, not formatting.',
        evidence: buildEvidence(codepoints, flagged),
      });
    }
    return findings;
  },
} satisfies Rule;
