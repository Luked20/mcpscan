import type { PartialFinding, Rule, ToolDefinition } from '../../core/types.js';
import { findInjectionPatterns, type InjectionMatch } from '../shared/patterns.js';

const EVIDENCE_RADIUS = 60;

/**
 * Window around the first match, sliced by code point (never by UTF-16 code
 * unit, which could split a surrogate pair) — same approach as MCP002's
 * `buildEvidence`. `match.index` is a UTF-16 offset (from `String.matchAll`),
 * so it's first converted to a code-point index via the prefix slice.
 */
function buildEvidence(description: string, matches: readonly InjectionMatch[]): string {
  const codepoints = Array.from(description);
  const firstMatch = matches[0];
  if (!firstMatch) return '';
  const firstCp = Array.from(description.slice(0, firstMatch.index)).length;
  const start = Math.max(0, firstCp - EVIDENCE_RADIUS);
  const end = Math.min(codepoints.length, firstCp + EVIDENCE_RADIUS + 1);
  const windowed = codepoints.slice(start, end).join('');
  return (start > 0 ? '…' : '') + windowed + (end < codepoints.length ? '…' : '');
}

export const MCP001 = {
  id: 'MCP001',
  title: 'Model-directed instruction in tool description',
  severity: 'critical',
  confidence: 'high',
  owasp: 'MCP03:2025 – Tool Poisoning',
  appliesTo: 'tool',
  check(tool: ToolDefinition) {
    if (!tool.description) return [];

    const matches = findInjectionPatterns(tool.description);
    if (matches.length === 0) return [];

    const kinds = [...new Set(matches.map((m) => m.kind))];

    const finding: PartialFinding = {
      location: tool.loc(`${tool.origin.jsonPath}.description`),
      message:
        `Tool "${tool.name}" has a model-directed instruction embedded in its description: ` +
        `${kinds.join(', ')}.`,
      remediation:
        'Remove the imperative text. A tool description documents what the tool does; it does not ' +
        'give orders to the agent. If the tool genuinely must be called before another, express that ' +
        "in the schema (a required parameter) or in the server's documentation, not in the description.",
      evidence: buildEvidence(tool.description, matches),
    };
    return [finding];
  },
} satisfies Rule;
