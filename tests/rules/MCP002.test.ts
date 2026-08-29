import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectManifest } from '../../src/collect/mcp-manifest.js';
import { MCP002 } from '../../src/rules/mcp/MCP002.js';
import type { PartialFinding } from '../../src/core/types.js';

/**
 * Caracteres invisíveis são construídos por codepoint, nunca colados como literal:
 * um literal invisível no fonte é indistinguível de um erro de digitação e já
 * quebrou esta regra uma vez.
 */
const cp = (...c: number[]) => String.fromCodePoint(...c);
const ZWSP = cp(0x200b);
const ZWNJ = cp(0x200c);
const ZWJ = cp(0x200d);
const LRM = cp(0x200e);
const WJ = cp(0x2060);
const BOM = cp(0xfeff);
const LRE = cp(0x202a);
const PDF = cp(0x202c);
const RLO = cp(0x202e);
const LRI = cp(0x2066);
const FSI = cp(0x2068);
const PDI = cp(0x2069);

/** `String.prototype.isWellFormed` existe no Node 22; a lib do TS aqui é ES2022. */
const wellFormed = (s: string) => (s as string & { isWellFormed(): boolean }).isWellFormed();

const loadFixture = (kind: 'vulnerable' | 'clean') => {
  const f = `tests/fixtures/MCP002/${kind}/tools.json`;
  return collectManifest(f, readFileSync(f, 'utf8'));
};

const check = (tool: { name: string; description?: string }): PartialFinding[] => {
  const tools = collectManifest('x.json', JSON.stringify({ tools: [tool] }));
  return tools.flatMap((t) => MCP002.check(t));
};

const onDescription = (description: string) => check({ name: 'read_file', description });

describe('MCP002 — casos legítimos (não pode disparar)', () => {
  const legitimos: Array<[string, string]> = [
    ['emoji ZWJ (mulher + laptop)', 'Faz deploy ' + cp(0x1f469) + ZWJ + cp(0x1f4bb) + ' rapido'],
    [
      'emoji ZWJ (família e bandeira)',
      cp(0x1f468) + ZWJ + cp(0x1f469) + ZWJ + cp(0x1f467) + ' ' +
        cp(0x1f3f3) + cp(0xfe0f) + ZWJ + cp(0x1f308),
    ],
    ['persa com ZWNJ obrigatório', cp(0x645, 0x6cc) + ZWNJ + cp(0x634, 0x648, 0x62f)],
    [
      'árabe com isolate FSI…PDI balanceado',
      cp(0x627, 0x642, 0x631, 0x623) + ' ' + FSI + 'read_file' + PDI + ' ' + cp(0x645, 0x644, 0x641),
    ],
    ['hebraico com LRM', cp(0x5e9, 0x5dc, 0x5d5, 0x5dd) + LRM + ' read_file'],
    ['seletor de apresentação de emoji isolado', 'Marca ' + cp(0x2764, 0xfe0f) + ' concluído.'],
    ['devanágari com ZWNJ entre letras índicas', cp(0x915, 0x94d) + ZWNJ + cp(0x937)],
    ['dois seletores de variação consecutivos', 'a' + cp(0xfe00, 0xfe01) + 'b'],
    ['ASCII puro', 'Reads a file from disk and returns its contents.'],
    ['acentos e cedilha', 'Ação — coração ✅ ünïcode'],
    ['CJK', '读取磁盘上的文件并返回内容。'],
    ['emoji sem ZWJ', 'Deploy 🚀 rápido ✅'],
    ['embedding LRE…PDF balanceado', 'valor ' + LRE + 'read_file' + PDF + ' final'],
    ['isolate LRI…PDI balanceado', 'valor ' + LRI + 'read_file' + PDI + ' final'],
  ];

  it.each(legitimos)('não dispara: %s', (_nome, description) => {
    expect(onDescription(description)).toEqual([]);
  });

  it('não dispara em nenhuma tool da fixture clean', () => {
    expect(loadFixture('clean').flatMap((t) => MCP002.check(t))).toEqual([]);
  });
});

describe('MCP002 — casos maliciosos (tem que disparar)', () => {
  const maliciosos: Array<[string, string, string]> = [
    ['tag characters', 'Lê um arquivo.' + cp(0xe0049, 0xe0067, 0xe006e), 'U+E0049'],
    ['zero-width space entre palavras latinas', 'read' + ZWSP + 'file', 'U+200B'],
    ['word joiner no meio', 'read' + WJ + 'file', 'U+2060'],
    ['BOM no meio', 'read' + BOM + 'file', 'U+FEFF'],
    ['override RLO mesmo balanceado', 'a' + RLO + 'txt.exe' + PDF + 'b', 'U+202E'],
    ['override LRO', 'a' + cp(0x202d) + 'txt' + PDF + 'b', 'U+202D'],
    ['embedding LRE sem PDF', 'valor ' + LRE + 'read_file', 'U+202A'],
    ['embedding RLE sem PDF', 'valor ' + cp(0x202b) + 'read_file', 'U+202B'],
    ['PDF sem abertura', 'valor ' + PDF + 'read_file', 'U+202C'],
    ['isolate FSI sem PDI', 'valor ' + FSI + 'read_file', 'U+2068'],
    ['PDI sem abertura', 'valor ' + PDI + 'read_file', 'U+2069'],
    ['ZWJ entre duas letras ASCII', 'read' + ZWJ + 'file', 'U+200D'],
    ['ZWJ entre dígitos', '1' + ZWJ + '2', 'U+200D'],
    ['ZWJ no fim da string', 'deploy' + ZWJ, 'U+200D'],
    ['ZWJ no início da string', ZWJ + 'deploy', 'U+200D'],
    ['ZWNJ entre duas letras ASCII', 'read' + ZWNJ + 'file', 'U+200C'],
    ['corrida de 3 seletores de variação', 'a' + cp(0xfe00, 0xfe01, 0xfe02) + 'b', 'U+FE00'],
    ['corrida de 3 seletores suplementares', 'a' + cp(0xe0100, 0xe0101, 0xe0102) + 'b', 'U+E0100'],
  ];

  it.each(maliciosos)('dispara: %s', (_nome, description, esperado) => {
    const findings = onDescription(description);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.jsonPath).toBe('tools[0].description');
    expect(findings[0]!.message).toContain(esperado);
  });

  it('detecta tag characters na fixture vulnerable', () => {
    const findings = loadFixture('vulnerable').flatMap((t) => MCP002.check(t));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.jsonPath).toBe('tools[0].description');
    expect(findings[0]!.message).toContain('U+E0049');
  });

  it('detecta no campo name, com jsonPath de name', () => {
    const findings = check({ name: 'read' + ZWSP + 'file', description: 'Lê um arquivo.' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.jsonPath).toBe('tools[0].name');
    expect(findings[0]!.message).toContain('`name`');
  });

  it('reporta name e description separadamente', () => {
    const findings = check({ name: 'read' + ZWSP + 'file', description: 'x' + BOM + 'y' });
    expect(findings.map((f) => f.location.jsonPath)).toEqual([
      'tools[0].name',
      'tools[0].description',
    ]);
  });

  it('lista cada codepoint distinto na mensagem', () => {
    const findings = onDescription('a' + ZWSP + 'b' + WJ + 'c' + BOM + 'd');
    expect(findings).toHaveLength(1);
    const msg = findings[0]!.message;
    for (const u of ['U+200B', 'U+2060', 'U+FEFF']) expect(msg).toContain(u);
    expect(msg).toContain('3 caractere');
  });
});

describe('MCP002 — evidência', () => {
  it('substitui o caractere detectado por ␡ em vez de propagar o payload', () => {
    const findings = onDescription('read' + ZWSP + 'file');
    expect(findings[0]!.evidence).toBe('read␡file');
    expect(findings[0]!.evidence).not.toContain(ZWSP);
  });

  it('mostra a vizinhança do hit, não só o preenchimento inicial', () => {
    const findings = onDescription('A'.repeat(380) + ' senha=' + ZWSP + 'segredo');
    const ev = findings[0]!.evidence!;
    expect(ev).toContain('␡');
    expect(ev).toContain('senha=');
    expect(ev.length).toBeLessThanOrEqual(140);
  });

  it('não parte pares surrogates: evidência sempre well-formed', () => {
    const findings = onDescription('X' + cp(0x1f600).repeat(70) + ZWSP);
    const ev = findings[0]!.evidence!;
    expect(wellFormed(ev)).toBe(true);
    expect(ev).toContain('␡');
  });

  it('mantém caracteres legítimos vizinhos intactos na evidência', () => {
    const findings = onDescription(cp(0x1f469) + ZWJ + cp(0x1f4bb) + ' read' + ZWSP + 'file');
    expect(findings[0]!.evidence).toContain(ZWJ);
  });
});

describe('MCP002 — robustez da implementação', () => {
  it('é idempotente: duas chamadas seguidas dão o mesmo resultado', () => {
    const tools = collectManifest('x.json', JSON.stringify({
      tools: [{ name: 'read_file', description: 'read' + ZWSP + 'file' }],
    }));
    const t = tools[0]!;
    expect(MCP002.check(t)).toEqual(MCP002.check(t));
    expect(MCP002.check(t)).toHaveLength(1);
  });

  it('metadata da regra continua estável', () => {
    expect(MCP002.id).toBe('MCP002');
    expect(MCP002.severity).toBe('critical');
    expect(MCP002.confidence).toBe('high');
    expect(MCP002.owasp).toBe('MCP03:2025 – Tool Poisoning');
    expect(MCP002.appliesTo).toBe('tool');
  });
});
