import type { PartialFinding, Rule, ToolDefinition } from '../../core/types.js';

/** Zero-width, word joiner, BOM, bidi overrides, e tag characters (U+E0000-E007F). */
const INVISIBLE = /[\u200B\u200C\u200D\u2060\uFEFF\u202A-\u202E\u2066-\u2069]|[\u{E0000}-\u{E007F}]/gu;

const NAMES: Record<string, string> = {
  '200b': 'zero-width space', '200c': 'zero-width non-joiner', '200d': 'zero-width joiner',
  '2060': 'word joiner', 'feff': 'byte order mark',
  '202a': 'bidi LRE', '202b': 'bidi RLE', '202c': 'bidi PDF', '202d': 'bidi LRO', '202e': 'bidi RLO',
  '2066': 'bidi LRI', '2067': 'bidi RLI', '2068': 'bidi FSI', '2069': 'bidi PDI',
};

function describe(cp: number): string {
  const hex = cp.toString(16).padStart(4, '0');
  const label = NAMES[hex] ?? (cp >= 0xe0000 && cp <= 0xe007f ? 'tag character' : 'caractere invisível');
  return `U+${hex.toUpperCase()} (${label})`;
}

/** Campos textuais que o modelo lê e o usuário não vê. */
function textFields(tool: ToolDefinition): Array<[string, string]> {
  const out: Array<[string, string]> = [['tools_name', tool.name]];
  if (tool.description) out.push(['description', tool.description]);
  return out;
}

export const MCP002 = {
  id: 'MCP002',
  title: 'Caractere Unicode invisível em definição de tool',
  severity: 'critical',
  confidence: 'high',
  owasp: 'MCP03:2025 – Tool Poisoning',
  appliesTo: 'tool',
  check(tool: ToolDefinition) {
    const findings: PartialFinding[] = [];
    for (const [field, value] of textFields(tool)) {
      INVISIBLE.lastIndex = 0;
      const hits = [...value.matchAll(INVISIBLE)];
      if (hits.length === 0) continue;
      const codepoints = [...new Set(hits.map((h) => describe(h[0]!.codePointAt(0)!)))];
      const jsonPath = field === 'tools_name'
        ? `${tool.origin.jsonPath}.name`
        : `${tool.origin.jsonPath}.description`;
      findings.push({
        location: tool.loc(jsonPath),
        message:
          `A tool "${tool.name}" tem ${hits.length} caractere(s) invisível(is) em ` +
          `\`${field === 'tools_name' ? 'name' : 'description'}\`: ${codepoints.join(', ')}.`,
        remediation:
          'Remova os caracteres invisíveis. Esse texto é lido pelo modelo e não aparece para o ' +
          'usuário — conteúdo invisível ali é instrução oculta, não formatação.',
        evidence: value.replace(INVISIBLE, '␡').slice(0, 120),
      });
    }
    return findings;
  },
} satisfies Rule;
