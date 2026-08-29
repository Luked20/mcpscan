import type { PartialFinding, Rule, SkillDefinition, SourceLocation } from '../../core/types.js';
import { createLineIndex, offsetToPosition } from '../../core/location.js';
import { findInjectionPatterns } from '../shared/patterns.js';
import { buildEvidence as buildInvisibleEvidence, scanInvisible } from '../shared/invisible.js';

/**
 * Maps a UTF-16 offset (and optional length) inside `skill.body` back to a
 * real file location, using `skill.bodyOffsetLine` to shift the body-local
 * line number to the real one.
 */
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

const EXCERPT_MAX = 120;

/** Truncates by code point, never by UTF-16 code unit, so a surrogate pair is never split. */
function truncate(s: string): string {
  const codepoints = Array.from(s);
  if (codepoints.length <= EXCERPT_MAX) return s;
  return codepoints.slice(0, EXCERPT_MAX).join('') + '…';
}

interface HtmlComment {
  index: number;
  length: number;
  content: string;
}

/** `<!-- ... -->` comments in the body. Markdown never renders these — the model
 * reading the raw file does — so an imperative hidden inside one is invisible
 * to whoever reviews the rendered skill, not to the agent that runs it. */
function findHtmlComments(body: string): HtmlComment[] {
  const out: HtmlComment[] = [];
  for (const m of body.matchAll(/<!--([\s\S]*?)-->/g)) {
    if (m.index === undefined) continue;
    out.push({ index: m.index, length: m[0].length, content: m[1] ?? '' });
  }
  return out;
}

/**
 * Finds the UTF-16 offset of the first flagged codepoint. `scanInvisible`
 * indexes by codepoint (via `Array.from`), which is not the same as a UTF-16
 * offset once an astral codepoint (e.g. a tag character, a surrogate pair)
 * appears earlier in the string — so the offset is rebuilt by summing the
 * UTF-16 length of every codepoint before the first hit.
 */
function firstHitOffset(codepoints: string[], flagged: boolean[]): { offset: number; length: number } {
  let offset = 0;
  for (let i = 0; i < codepoints.length; i++) {
    if (flagged[i]) return { offset, length: codepoints[i]!.length };
    offset += codepoints[i]!.length;
  }
  return { offset: 0, length: 0 };
}

export const SKILL001 = {
  id: 'SKILL001',
  title: 'Hidden instruction in skill body',
  severity: 'critical',
  confidence: 'high',
  owasp: 'MCP10:2025 – Context Injection & Over-Sharing',
  appliesTo: 'skill',
  check(skill: SkillDefinition) {
    const findings: PartialFinding[] = [];

    for (const comment of findHtmlComments(skill.body)) {
      const matches = findInjectionPatterns(comment.content);
      if (matches.length === 0) continue;

      const kinds = [...new Set(matches.map((m) => m.kind))];
      findings.push({
        location: locateInBody(skill, comment.index, comment.length),
        message:
          `Skill "${skill.name}" hides a model-directed instruction inside an HTML comment: ` +
          `${kinds.join(', ')}. HTML comments do not render in the rendered markdown, but the model ` +
          'reads the raw file — so this instruction is invisible to a human reviewer, not to the agent.',
        remediation:
          'Remove the comment. If the content is legitimate, rewrite it as ordinary visible text in the ' +
          "skill body — a skill should never carry instructions that only the model can see.",
        evidence: truncate(comment.content.trim()),
      });
    }

    const { codepoints, flagged, hitCount, descriptions } = scanInvisible(skill.body);
    if (hitCount > 0) {
      const { offset, length } = firstHitOffset(codepoints, flagged);
      findings.push({
        location: locateInBody(skill, offset, length),
        message: `Skill "${skill.name}" has ${hitCount} invisible character(s) in its body: ${descriptions.join(', ')}.`,
        remediation:
          'Remove the invisible characters. This text is read by the model and never shown to a user ' +
          'reviewing the skill file — invisible content here is a hidden instruction, not formatting.',
        evidence: buildInvisibleEvidence(codepoints, flagged),
      });
    }

    return findings;
  },
} satisfies Rule;
