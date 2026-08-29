import type { PartialFinding, Rule, ToolDefinition } from '../../core/types.js';

/**
 * Política por classe de caractere — ver docs/SPEC.md §7.2 e docs/rules/MCP002.md.
 *
 * "Caractere invisível" não é uma categoria binária: todo emoji ZWJ usa U+200D,
 * ZWNJ é ortografia obrigatória em persa/devanágari, e isolates bidi balanceados
 * são o jeito recomendado (UAX #9) de embutir um identificador latino em texto RTL.
 * Esta regra sinaliza por classe + contexto, não por "está na lista de invisíveis".
 *
 * Todo codepoint abaixo é referenciado numericamente (0x...) — nunca colado como
 * caractere literal no fonte. Um invisível colado aqui é indistinguível de um erro
 * de digitação e já quebrou esta regra antes (ver git blame).
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
    else if (isVariationSelector(cp)) label = 'seletor de variação';
    else label = 'caractere invisível';
  }
  return `U+${hex.toUpperCase()} (${label})`;
}

/** ASCII/Latin ou dígito — a classe em que ZWJ/ZWNJ nunca tem papel legítimo de junção. */
const LATIN_OR_DIGIT = /^[\p{Script=Latin}\p{Nd}]$/u;
const isLatinOrDigit = (ch: string | undefined): boolean => ch !== undefined && LATIN_OR_DIGIT.test(ch);

/**
 * Marca, por índice de codepoint, quais caracteres de `codepoints` devem ser
 * sinalizados — aplicando a política "sempre / só em contexto / nunca" do §7.2.
 */
function classify(codepoints: string[]): boolean[] {
  const n = codepoints.length;
  const cps = codepoints.map((c) => c.codePointAt(0)!);
  const flagged = new Array<boolean>(n).fill(false);

  // Sempre: zero-width space, word joiner, BOM; overrides bidi (mesmo balanceados,
  // são o vetor do Trojan Source); tag characters (U+E0000-E007F).
  for (let i = 0; i < n; i++) {
    const c = cps[i]!;
    if (c === 0x200b || c === 0x2060 || c === 0xfeff) flagged[i] = true;
    else if (c === 0x202d || c === 0x202e) flagged[i] = true;
    else if (c >= 0xe0000 && c <= 0xe007f) flagged[i] = true;
  }

  // Sempre: corrida de 3+ seletores de variação consecutivos. Um único U+FE0F é
  // apresentação de emoji e não dispara.
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

  // Contexto: ZWJ/ZWNJ só quando os DOIS vizinhos são ASCII/latinos ou dígitos —
  // entre emoji, ou entre letras árabes/índicas, é uso normal. Nas pontas da string
  // (sem vizinho de um lado) não há papel de junção possível: dispara também.
  for (let i = 0; i < n; i++) {
    const c = cps[i]!;
    if (c !== 0x200c && c !== 0x200d) continue;
    const hasLeft = i - 1 >= 0;
    const hasRight = i + 1 < n;
    if (!hasLeft || !hasRight) flagged[i] = true;
    else if (isLatinOrDigit(codepoints[i - 1]) && isLatinOrDigit(codepoints[i + 1])) flagged[i] = true;
  }

  // Contexto: embeddings bidi (LRE/RLE...PDF) só quando desbalanceados. Pilha única
  // para embeddings E overrides porque PDF fecha os dois em Unicode real — assim um
  // override balanceado (já sempre sinalizado acima) não faz um embedding vizinho
  // parecer desbalanceado. Só entrada do tipo 'embedding' deixada aberta no fim (ou
  // PDF sem nada pra fechar) gera flag extra aqui.
  const stack: Array<{ i: number; type: 'embedding' | 'override' }> = [];
  for (let i = 0; i < n; i++) {
    const c = cps[i]!;
    if (c === 0x202a || c === 0x202b) stack.push({ i, type: 'embedding' });
    else if (c === 0x202d || c === 0x202e) stack.push({ i, type: 'override' });
    else if (c === 0x202c) {
      if (stack.length === 0) flagged[i] = true; // PDF sem abertura
      else stack.pop(); // fecha o topo, seja embedding ou override — casado
    }
  }
  for (const entry of stack) if (entry.type === 'embedding') flagged[entry.i] = true;

  // Contexto: isolates bidi (LRI/RLI/FSI...PDI) só quando desbalanceados.
  const isolateStack: number[] = [];
  for (let i = 0; i < n; i++) {
    const c = cps[i]!;
    if (c === 0x2066 || c === 0x2067 || c === 0x2068) isolateStack.push(i);
    else if (c === 0x2069) {
      if (isolateStack.length === 0) flagged[i] = true; // PDI sem abertura
      else isolateStack.pop();
    }
  }
  for (const idx of isolateStack) flagged[idx] = true;

  // Nunca: U+200E (LRM) e U+200F (RLM) não são tocados por nenhum ramo acima.

  return flagged;
}

const EVIDENCE_RADIUS = 60;

/**
 * Janela ao redor do primeiro hit — não um truncamento cego a partir da posição 0,
 * que num payload de 400 caracteres com o hit no fim não mostra nenhum sinal.
 * Fatiada por codepoint (Array.from), nunca por code unit (`.slice`), para nunca
 * partir um par surrogate ao meio.
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
  title: 'Caractere Unicode invisível em definição de tool',
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
          `A tool "${tool.name}" tem ${hitCount} caractere(s) invisível(is) em ` +
          `\`${field}\`: ${descriptions.join(', ')}.`,
        remediation:
          'Remova os caracteres invisíveis. Esse texto é lido pelo modelo e não aparece para o ' +
          'usuário — conteúdo invisível ali é instrução oculta, não formatação.',
        evidence: buildEvidence(codepoints, flagged),
      });
    }
    return findings;
  },
} satisfies Rule;
