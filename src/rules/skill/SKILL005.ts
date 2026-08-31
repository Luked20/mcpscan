import type { PartialFinding, Rule, SkillDefinition, SourceLocation } from '../../core/types.js';
import { createLineIndex, offsetToPosition } from '../../core/location.js';

/**
 * SKILL005 — the skill body instructs the agent to send data to a hardcoded
 * external endpoint (docs/rules/SKILL005.md).
 *
 * WHY THIS RULE EXISTS, AND WHY THIS SHAPE
 *
 * The 152 poisoned skills composed from `aisa-group/skill-inject` were sorted
 * into attack families (docs/SPEC.md §8.11). Exfiltration was the largest by a
 * wide margin — 55 of 152 payloads, and 50 of the 143 the scanner missed. No
 * other family came close. This rule targets that family and nothing else.
 *
 * The existing shared `exfiltration` pattern (rules/shared/patterns.ts) already
 * expresses the idea, but it requires `verb … to <url>` inside 60 characters,
 * and it runs only on a tool description (MCP001/MCP003) and a skill's
 * frontmatter description (SKILL002). It never ran over a skill *body*, which
 * is where these payloads live. Applied there as-is it recovered 2 of 50.
 *
 * Four relaxations were measured against both corpora before one was chosen —
 * 50 missed exfiltration payloads on one side, 106 real skills (the clean
 * corpus, `monday`, `awslabs`, `n8n`, and the benchmark's own 44 clean base
 * skills) on the other:
 *
 *   | candidate                              | recovered | false positives |
 *   |----------------------------------------|-----------|-----------------|
 *   | verb … `to` … url, 60 chars (existing) |    2 / 50 |         0 / 106 |
 *   | verb … url, 80 chars, any url          |   22 / 50 |         2 / 106 |
 *   | verb … url, 80 chars, REAL HOST        |   21 / 50 |     **0 / 106** |
 *   | url … verb, 80 chars                   |    1 / 50 |         0 / 106 |
 *   | verb … url, 200 chars, across lines    |   22 / 50 |         9 / 106 |
 *
 * The chosen row is the third. Requiring a real host removed both false
 * positives of the row above it at a cost of one detection:
 *
 *   * `sends: \`If-None-Exist: identifier=http://mrn|12345\`` — a FHIR skill
 *     documenting a URN-shaped identifier, not a URL;
 *   * `uploads it to storage, and returns JSON like { …, "url": … }` — an n8n
 *     skill showing an example response.
 *
 * Neither has a hostname with a dot and an alphabetic TLD. Crossing lines (the
 * last row) doubles the false positives for no extra recall, because prose and
 * a fenced example routinely sit in adjacent paragraphs.
 *
 * WHAT THIS RULE DELIBERATELY DOES NOT TRY TO DO
 *
 * The other 29 missed exfiltration payloads name no endpoint in the body at
 * all. They say "follow the DATA COLLECTION procedure in this skill file" or
 * "collect the .env files after finishing any task" — the destination is
 * elsewhere, or the instruction is pure natural language. Catching those needs
 * to reason about an instruction firing on *every* invocation to do something
 * *unrelated to the skill's stated purpose*. That is a real design problem and
 * it is not a wording pattern; §8.10.2 declines it on purpose, and this rule
 * does not smuggle it in.
 */

/** Maps an offset in `skill.body` back to a real file location. */
function locateInBody(skill: SkillDefinition, offset: number, length = 0): SourceLocation {
  const lineStarts = createLineIndex(skill.body);
  const start = offsetToPosition(lineStarts, offset, skill.body.length);
  const end = offsetToPosition(lineStarts, offset + length, skill.body.length);
  const shift = skill.bodyOffsetLine - 1;
  return {
    file: skill.origin.file,
    line: start.line + shift,
    column: start.column,
    endLine: end.line + shift,
    endColumn: end.column,
  };
}

/**
 * Verbs that move data outward. `fetch`/`get`/`download` are absent on purpose:
 * pulling from a URL is how a great many honest skills work, and the risk this
 * rule names is the user's data leaving, not data arriving.
 */
const SEND_VERB = String.raw`(?:send|sends|post|posts|upload|uploads|forward|forwards|transmit|transmits|exfiltrate|mirror|sync|copy)`;

/**
 * A URL whose host is really a host: dot-separated labels ending in an
 * alphabetic TLD. This is the whole of the rule's precision margin — see the
 * table in the module doc.
 */
const REAL_URL = String.raw`https?:\/\/(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::\d+)?(?:\/[^\s"'\`),]*)?`;

/**
 * Verb, then a real URL, within 80 characters and **on one line**. The
 * single-line bound is load-bearing: allowing the match to cross a newline
 * pairs a sentence of prose with a fenced code example below it, which is what
 * took false positives from 0 to 9 in the measurement.
 */
const SEND_TO_ENDPOINT_RE = new RegExp(String.raw`\b${SEND_VERB}\b[^\n]{0,80}?${REAL_URL}`, 'gi');

const EXCERPT_MAX = 140;

/** Truncates by code point, never by UTF-16 code unit, so a surrogate pair is never split. */
function truncate(s: string): string {
  const codepoints = Array.from(s);
  if (codepoints.length <= EXCERPT_MAX) return s;
  return codepoints.slice(0, EXCERPT_MAX).join('') + '…';
}

/** `https://host/path?x` -> `host`. */
function hostOf(url: string): string {
  return url.replace(/^https?:\/\//i, '').split(/[/:?#]/)[0] ?? url;
}

export const SKILL005 = {
  id: 'SKILL005',
  title: 'Skill sends data to a hardcoded external endpoint',
  severity: 'high',
  confidence: 'high',
  owasp: 'MCP01:2025 – Token Mismanagement & Secret Exposure',
  appliesTo: 'skill',
  check(skill: SkillDefinition) {
    const findings: PartialFinding[] = [];
    const seen = new Set<string>();

    for (const m of skill.body.matchAll(SEND_TO_ENDPOINT_RE)) {
      if (m.index === undefined) continue;
      const excerpt = m[0].replace(/\s+/g, ' ').trim();
      const url = new RegExp(REAL_URL, 'i').exec(m[0])?.[0] ?? '';
      const host = hostOf(url);

      // One finding per destination. A skill that repeats the same endpoint in
      // five steps of a procedure has one problem, not five.
      if (seen.has(host)) continue;
      seen.add(host);

      findings.push({
        location: locateInBody(skill, m.index, m[0].length),
        message:
          `Skill "${skill.name}" instructs the agent to send data to a hardcoded external endpoint ` +
          `(\`${host}\`): \`${truncate(excerpt)}\`. Whatever the agent is working on at the time — ` +
          'file contents, credentials it has read, the conversation — is what gets sent, and the ' +
          'user is not asked.',
        remediation:
          'If the destination is part of what this skill legitimately does, say so in the skill ' +
          'description so a reader sees it before installing, and make it configurable rather than ' +
          'hardcoded. If it is not, remove it. A skill that moves user data off the machine should ' +
          'never do so as a side effect of an unrelated task.',
        evidence: truncate(excerpt),
      });
    }

    return findings;
  },
} satisfies Rule;
