import type { PartialFinding, Rule, ToolDefinition } from '../../core/types.js';
import { findInjectionPatterns, type InjectionMatch } from '../shared/patterns.js';
import { walkSchemaStrings } from '../shared/schema-walk.js';
import { formatJsonPath } from '../../core/location.js';

const EVIDENCE_RADIUS = 60;

/**
 * Window around the first match, sliced by code point — same approach as
 * MCP001's `buildEvidence` (and MCP002's before it). Duplicated rather than
 * shared: each rule's evidence window is small and the three copies have
 * already diverged slightly (MCP002 marks the hit character itself; MCP001
 * and MCP003 don't need to).
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

export const MCP003 = {
  id: 'MCP003',
  title: 'Model-directed instruction inside inputSchema',
  severity: 'critical',
  confidence: 'high',
  owasp: 'MCP03:2025 – Tool Poisoning',
  appliesTo: 'tool',
  check(tool: ToolDefinition) {
    if (tool.inputSchema === undefined) return [];

    // Paths are relative to the tool, so they can be handed straight to
    // `tool.loc()` and rendered as the field name without stripping a prefix.
    const hits = walkSchemaStrings(tool.inputSchema, ['inputSchema']);

    const findings: PartialFinding[] = [];
    for (const hit of hits) {
      const matches = findInjectionPatterns(hit.value);
      if (matches.length === 0) continue;

      const kinds = [...new Set(matches.map((m) => m.kind))];
      const field = formatJsonPath(hit.path);

      findings.push({
        location: tool.loc(hit.path),
        message:
          `Tool "${tool.name}" has a model-directed instruction embedded in schema field ` +
          `\`${field}\`: ${kinds.join(', ')}.`,
        remediation:
          'Schema fields describe the shape of a value, not instructions for the agent. Remove the ' +
          'imperative text and constrain the value with `pattern`, `enum`, or `format` instead.',
        evidence: buildEvidence(hit.value, matches),
      });
    }
    return findings;
  },
} satisfies Rule;
