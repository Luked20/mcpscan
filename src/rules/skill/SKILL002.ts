import type { PartialFinding, Rule, SkillDefinition } from '../../core/types.js';
import { findInjectionPatterns, type InjectionMatch } from '../shared/patterns.js';

const EVIDENCE_RADIUS = 60;

/**
 * Window around the first match, sliced by code point — same approach as
 * MCP001's `buildEvidence` (and MCP003's after it). Duplicated rather than
 * shared, per the precedent in MCP003.ts: each rule's evidence window is
 * small, and the copies are free to diverge.
 */
function buildEvidence(text: string, matches: readonly InjectionMatch[]): string {
  const codepoints = Array.from(text);
  const firstMatch = matches[0];
  if (!firstMatch) return '';
  const firstCp = Array.from(text.slice(0, firstMatch.index)).length;
  const start = Math.max(0, firstCp - EVIDENCE_RADIUS);
  const end = Math.min(codepoints.length, firstCp + EVIDENCE_RADIUS + 1);
  const windowed = codepoints.slice(start, end).join('');
  return (start > 0 ? '…' : '') + windowed + (end < codepoints.length ? '…' : '');
}

export const SKILL002 = {
  id: 'SKILL002',
  title: 'Model-directed instruction in skill description',
  severity: 'critical',
  confidence: 'high',
  owasp: 'MCP10:2025 – Context Injection & Over-Sharing',
  appliesTo: 'skill',
  check(skill: SkillDefinition) {
    if (!skill.description) return [];

    const matches = findInjectionPatterns(skill.description);
    if (matches.length === 0) return [];

    const kinds = [...new Set(matches.map((m) => m.kind))];

    const finding: PartialFinding = {
      location: skill.frontmatterLoc('description'),
      message:
        `Skill "${skill.name}" has a model-directed instruction embedded in its description: ` +
        `${kinds.join(', ')}. The description is the privileged field: it is loaded into the agent's ` +
        "context to decide whether the skill applies, and the user never reads it.",
      remediation:
        'The description should state, in one declarative sentence, when the skill applies — not what ' +
        'to do. Operational instructions belong in the skill body, which a user can actually read before ' +
        'the skill runs.',
      evidence: buildEvidence(skill.description, matches),
    };
    return [finding];
  },
} satisfies Rule;
