import type { PartialFinding, Rule, ToolDefinition } from '../../core/types.js';
import { buildEvidence, scanInvisible } from '../shared/invisible.js';

/**
 * The per-character-class classification policy lives in `../shared/invisible.ts`
 * — shared with SKILL001, which applies the same policy to a skill's body text.
 * See that module's doc comment, and docs/SPEC.md §7.2, for the policy itself.
 */

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
      const { codepoints, flagged, hitCount, descriptions } = scanInvisible(value);
      if (hitCount === 0) continue;

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
