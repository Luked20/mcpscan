/**
 * Shared injection-pattern detector — used by MCP001 (tool description),
 * MCP003 (schema fields) and SKILL002 (skill frontmatter description).
 *
 * Governing principle: every pattern requires an IMPERATIVE VERB plus a
 * TARGET (the model, the user, other instructions, an external destination).
 * A bare keyword never suffices — "important" alone is ordinary technical
 * prose, "ignore" alone describes a filter. See docs/SPEC.md §7 for the rule
 * catalog these patterns feed, and tests/rules/patterns.test.ts for the
 * negative corpus that keeps this file honest.
 *
 * Regexes are constructed fresh inside `findInjectionPatterns` on every call
 * (not module-level singletons). `/g` regexes are stateful — `lastIndex`
 * persists on the object across calls — and building them per-call is the
 * simplest way to make the function idempotent without relying on callers to
 * reset `lastIndex` themselves.
 */

export type InjectionKind = 'override' | 'marker' | 'concealment' | 'precedence' | 'exfiltration';

export interface InjectionMatch {
  kind: InjectionKind;
  index: number;
  /** The matched excerpt, truncated to a bounded length (code-point safe). */
  text: string;
}

interface PatternSpec {
  kind: InjectionKind;
  source: string;
  flags: string;
}

const PATTERN_SPECS: readonly PatternSpec[] = [
  {
    // "Ignore/disregard/forget [all|any|the] previous/prior/above instructions/prompts/rules".
    // The `\s+` immediately after the keyword (no `\b` needed) already excludes
    // "Ignores files..." — "Ignore" followed by "s" leaves no whitespace for
    // `\s+` to match, so the attempt fails at that position.
    kind: 'override',
    source: String.raw`\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|rules?)\b`,
    flags: 'gi',
  },
  {
    // Pseudo-XML markers used to fence off a "privileged" block: <IMPORTANT>,
    // </SYSTEM>, <SECRET>, etc. Requires literal angle brackets, so ordinary
    // prose like "Important: the path must be absolute" never matches.
    kind: 'marker',
    source: String.raw`<\/?\s*(?:IMPORTANT|SYSTEM|CRITICAL|INSTRUCTIONS?|SECRET)\s*>`,
    flags: 'gi',
  },
  {
    // Negation + disclosure verb + a target that names a person (the user,
    // the human, the owner, anyone) within a bounded window. The verb list is
    // deliberately narrow (tell/mention/inform/reveal/show/disclose/say) —
    // it excludes "share", so a legitimate warning like "Never share this
    // token with anyone else" does not match on the verb alone. The target
    // must name a person, not a bare "this"/"that"/"it": that keeps a
    // developer-facing note like "Never show this token in logs" out of scope
    // unless it explicitly names the user.
    kind: 'concealment',
    source: String.raw`\b(?:do\s+not|don't|must\s+not|shall\s+not|should\s+not|never)\s+(?:tell|mention|inform|reveal|show|disclose|say)\b[^.\n]{0,45}\b(?:the\s+user|to\s+the\s+user|users?|the\s+human|the\s+owner|anyone)\b`,
    flags: 'gi',
  },
  {
    // "Before calling/using/invoking [any] [other] tool(s)" — an instruction
    // that tries to establish precedence over the agent's tool-calling order.
    // Restricted to "tool(s)" as the object: "before writing", "before
    // commit", "before calling any other method" don't match.
    kind: 'precedence',
    source: String.raw`\bbefore\s+(?:calling|using|invoking)\s+(?:any\s+)?(?:other\s+)?tools?\b`,
    flags: 'gi',
  },
  {
    // send/post/upload/exfiltrate/forward ... to <URL with an explicit scheme>.
    // Deliberately requires `https?://` rather than a bare "domain.com" —
    // the starting pattern's bare-domain branch flagged entirely routine
    // descriptions ("Post a message to slack.com channel"). Requiring a
    // literal scheme keeps the one required case (a hardcoded destination
    // URL in the description text) while dropping that false-positive class.
    // Trailing `\b` after the verb also excludes "Sends"/"Posts"/"Forwards"
    // (third-person singular), which are the common, legitimate phrasing.
    kind: 'exfiltration',
    source: String.raw`\b(?:send|post|upload|exfiltrate|forward)\b[^.\n]{0,60}\bto\b\s*https?:\/\/[^\s".,)]+`,
    flags: 'gi',
  },
];

const EXCERPT_MAX = 80;

/** Truncates by code point, never by UTF-16 code unit, so a surrogate pair is never split. */
function truncate(s: string): string {
  const codepoints = Array.from(s);
  if (codepoints.length <= EXCERPT_MAX) return s;
  return codepoints.slice(0, EXCERPT_MAX).join('') + '…';
}

export function findInjectionPatterns(text: string): InjectionMatch[] {
  const out: InjectionMatch[] = [];
  for (const spec of PATTERN_SPECS) {
    // Built fresh per spec, per call — see the module doc comment on `/g` statefulness.
    const re = new RegExp(spec.source, spec.flags);
    for (const m of text.matchAll(re)) {
      if (m.index === undefined) continue;
      out.push({ kind: spec.kind, index: m.index, text: truncate(m[0] ?? '') });
    }
  }
  out.sort((a, b) => a.index - b.index);
  return out;
}
