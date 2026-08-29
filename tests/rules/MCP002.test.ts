import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectManifest } from '../../src/collect/mcp-manifest.js';
import { MCP002 } from '../../src/rules/mcp/MCP002.js';
import type { PartialFinding } from '../../src/core/types.js';

/**
 * Invisible characters are built by codepoint, never pasted as a literal: a
 * literal invisible character in the source is indistinguishable from a typo
 * and has already broken this rule once.
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

/** `String.prototype.isWellFormed` exists in Node 22; the TS lib here targets ES2022. */
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

describe('MCP002 — legitimate cases (must not trigger)', () => {
  const legitimate: Array<[string, string]> = [
    ['emoji ZWJ (woman + laptop)', 'Faz deploy ' + cp(0x1f469) + ZWJ + cp(0x1f4bb) + ' rapido'],
    [
      'emoji ZWJ (family and flag)',
      cp(0x1f468) + ZWJ + cp(0x1f469) + ZWJ + cp(0x1f467) + ' ' +
        cp(0x1f3f3) + cp(0xfe0f) + ZWJ + cp(0x1f308),
    ],
    ['Persian with required ZWNJ', cp(0x645, 0x6cc) + ZWNJ + cp(0x634, 0x648, 0x62f)],
    [
      'Arabic with balanced FSI…PDI isolate',
      cp(0x627, 0x642, 0x631, 0x623) + ' ' + FSI + 'read_file' + PDI + ' ' + cp(0x645, 0x644, 0x641),
    ],
    ['Hebrew with LRM', cp(0x5e9, 0x5dc, 0x5d5, 0x5dd) + LRM + ' read_file'],
    ['standalone emoji presentation selector', 'Marca ' + cp(0x2764, 0xfe0f) + ' concluído.'],
    ['Devanagari with ZWNJ between Indic letters', cp(0x915, 0x94d) + ZWNJ + cp(0x937)],
    ['two consecutive variation selectors', 'a' + cp(0xfe00, 0xfe01) + 'b'],
    ['plain ASCII', 'Reads a file from disk and returns its contents.'],
    ['accents and cedilla', 'Ação — coração ✅ ünïcode'],
    ['CJK', '读取磁盘上的文件并返回内容。'],
    ['emoji without ZWJ', 'Deploy 🚀 rápido ✅'],
    ['balanced LRE…PDF embedding', 'valor ' + LRE + 'read_file' + PDF + ' final'],
    ['balanced LRI…PDI isolate', 'valor ' + LRI + 'read_file' + PDI + ' final'],
  ];

  it.each(legitimate)('does not trigger: %s', (_name, description) => {
    expect(onDescription(description)).toEqual([]);
  });

  it('does not trigger on any tool in the clean fixture', () => {
    expect(loadFixture('clean').flatMap((t) => MCP002.check(t))).toEqual([]);
  });
});

describe('MCP002 — malicious cases (must trigger)', () => {
  const malicious: Array<[string, string, string]> = [
    ['tag characters', 'Lê um arquivo.' + cp(0xe0049, 0xe0067, 0xe006e), 'U+E0049'],
    ['zero-width space between Latin words', 'read' + ZWSP + 'file', 'U+200B'],
    ['word joiner in the middle', 'read' + WJ + 'file', 'U+2060'],
    ['BOM in the middle', 'read' + BOM + 'file', 'U+FEFF'],
    ['RLO override even when balanced', 'a' + RLO + 'txt.exe' + PDF + 'b', 'U+202E'],
    ['LRO override', 'a' + cp(0x202d) + 'txt' + PDF + 'b', 'U+202D'],
    ['LRE embedding without PDF', 'valor ' + LRE + 'read_file', 'U+202A'],
    ['RLE embedding without PDF', 'valor ' + cp(0x202b) + 'read_file', 'U+202B'],
    ['PDF with nothing open', 'valor ' + PDF + 'read_file', 'U+202C'],
    ['FSI isolate without PDI', 'valor ' + FSI + 'read_file', 'U+2068'],
    ['PDI with nothing open', 'valor ' + PDI + 'read_file', 'U+2069'],
    ['ZWJ between two ASCII letters', 'read' + ZWJ + 'file', 'U+200D'],
    ['ZWJ between digits', '1' + ZWJ + '2', 'U+200D'],
    ['ZWJ at the end of the string', 'deploy' + ZWJ, 'U+200D'],
    ['ZWJ at the start of the string', ZWJ + 'deploy', 'U+200D'],
    ['ZWNJ between two ASCII letters', 'read' + ZWNJ + 'file', 'U+200C'],
    ['run of 3 variation selectors', 'a' + cp(0xfe00, 0xfe01, 0xfe02) + 'b', 'U+FE00'],
    ['run of 3 supplementary selectors', 'a' + cp(0xe0100, 0xe0101, 0xe0102) + 'b', 'U+E0100'],
  ];

  it.each(malicious)('triggers: %s', (_name, description, expected) => {
    const findings = onDescription(description);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.jsonPath).toBe('tools[0].description');
    expect(findings[0]!.message).toContain(expected);
  });

  it('detects tag characters in the vulnerable fixture', () => {
    const findings = loadFixture('vulnerable').flatMap((t) => MCP002.check(t));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.jsonPath).toBe('tools[0].description');
    expect(findings[0]!.message).toContain('U+E0049');
  });

  it('detects in the name field, with jsonPath of name', () => {
    const findings = check({ name: 'read' + ZWSP + 'file', description: 'Lê um arquivo.' });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.jsonPath).toBe('tools[0].name');
    expect(findings[0]!.message).toContain('`name`');
  });

  it('reports name and description separately', () => {
    const findings = check({ name: 'read' + ZWSP + 'file', description: 'x' + BOM + 'y' });
    expect(findings.map((f) => f.location.jsonPath)).toEqual([
      'tools[0].name',
      'tools[0].description',
    ]);
  });

  it('lists each distinct codepoint in the message', () => {
    const findings = onDescription('a' + ZWSP + 'b' + WJ + 'c' + BOM + 'd');
    expect(findings).toHaveLength(1);
    const msg = findings[0]!.message;
    for (const u of ['U+200B', 'U+2060', 'U+FEFF']) expect(msg).toContain(u);
    expect(msg).toContain('3 invisible');
  });
});

describe('MCP002 — evidence', () => {
  it('replaces the detected character with ␡ instead of propagating the payload', () => {
    const findings = onDescription('read' + ZWSP + 'file');
    expect(findings[0]!.evidence).toBe('read␡file');
    expect(findings[0]!.evidence).not.toContain(ZWSP);
  });

  it('shows the neighborhood of the hit, not just the leading padding', () => {
    const findings = onDescription('A'.repeat(380) + ' senha=' + ZWSP + 'segredo');
    const ev = findings[0]!.evidence!;
    expect(ev).toContain('␡');
    expect(ev).toContain('senha=');
    expect(ev.length).toBeLessThanOrEqual(140);
  });

  it('never splits surrogate pairs: evidence is always well-formed', () => {
    const findings = onDescription('X' + cp(0x1f600).repeat(70) + ZWSP);
    const ev = findings[0]!.evidence!;
    expect(wellFormed(ev)).toBe(true);
    expect(ev).toContain('␡');
  });

  it('keeps legitimate neighboring characters intact in the evidence', () => {
    const findings = onDescription(cp(0x1f469) + ZWJ + cp(0x1f4bb) + ' read' + ZWSP + 'file');
    expect(findings[0]!.evidence).toContain(ZWJ);
  });
});

describe('MCP002 — implementation robustness', () => {
  it('is idempotent: two consecutive calls give the same result', () => {
    const tools = collectManifest('x.json', JSON.stringify({
      tools: [{ name: 'read_file', description: 'read' + ZWSP + 'file' }],
    }));
    const t = tools[0]!;
    expect(MCP002.check(t)).toEqual(MCP002.check(t));
    expect(MCP002.check(t)).toHaveLength(1);
  });

  it('rule metadata stays stable', () => {
    expect(MCP002.id).toBe('MCP002');
    expect(MCP002.severity).toBe('critical');
    expect(MCP002.confidence).toBe('high');
    expect(MCP002.owasp).toBe('MCP03:2025 – Tool Poisoning');
    expect(MCP002.appliesTo).toBe('tool');
  });
});
