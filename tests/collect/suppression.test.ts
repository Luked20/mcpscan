import { describe, it, expect } from 'vitest';
import { collectSuppressions } from '../../src/collect/suppression.js';

const parse = (text: string) => collectSuppressions('x.json', text);
const one = (text: string) => {
  const found = parse(text);
  expect(found).toHaveLength(1);
  return found[0]!;
};

describe('collectSuppressions — well-formed', () => {
  it('parses the rule id and the reason', () => {
    const s = one('// mcpscan-disable-next-line MCP004 -- validated in validatePath()');
    expect(s.ruleIds).toEqual(['MCP004']);
    expect(s.reason).toBe('validated in validatePath()');
    expect(s.defect).toBeUndefined();
  });

  it('applies to the line after the comment, not the comment line', () => {
    const s = one(['const a = 1;', '// mcpscan-disable-next-line MCP004 -- reason', 'const b = 2;'].join('\n'));
    expect(s.line).toBe(2);
    expect(s.targetLine).toBe(3);
  });

  it('accepts several rule ids, comma- or space-separated', () => {
    expect(one('// mcpscan-disable-next-line MCP004, MCP005 -- both reviewed').ruleIds).toEqual(['MCP004', 'MCP005']);
    expect(one('// mcpscan-disable-next-line MCP004 MCP005 -- both reviewed').ruleIds).toEqual(['MCP004', 'MCP005']);
  });

  it('keeps a reason that itself contains a double dash', () => {
    // Splitting on the *first* separator, not the last: the reason is free text.
    expect(one('// mcpscan-disable-next-line MCP004 -- see PR -- follow-up filed').reason)
      .toBe('see PR -- follow-up filed');
  });

  it.each([
    ['line comment (TS/JS, JSONC)', '// mcpscan-disable-next-line MCP004 -- reason'],
    ['hash comment (YAML, Python)', '# mcpscan-disable-next-line MCP004 -- reason'],
    ['html comment (SKILL.md)', '<!-- mcpscan-disable-next-line MCP004 -- reason -->'],
    ['block comment (TS/JS)', '/* mcpscan-disable-next-line MCP004 -- reason */'],
    ['indented', '      // mcpscan-disable-next-line MCP004 -- reason'],
  ])('reads the marker inside a %s', (_label, line) => {
    const s = one(line);
    expect(s.ruleIds).toEqual(['MCP004']);
    expect(s.reason).toBe('reason');
  });

  it('does not mistake the closing --> of an html comment for the reason separator', () => {
    // `-->` contains `--`. Stripping the terminator has to happen first, or the
    // reason parses as ">" and a suppression with no reason silently works.
    const s = one('<!-- mcpscan-disable-next-line MCP004 -->');
    expect(s.defect).toBe('missing-reason');
  });

  it('records the column of the marker so the diagnostic can point at it', () => {
    expect(one('  // mcpscan-disable-next-line MCP004 -- reason').column).toBe(6);
  });

  it('handles CRLF line endings', () => {
    const s = one(['// mcpscan-disable-next-line MCP004 -- reason', 'next'].join('\r\n'));
    expect(s.reason).toBe('reason');
  });
});

describe('collectSuppressions — defective', () => {
  it('flags a suppression with no separator at all', () => {
    const s = one('// mcpscan-disable-next-line MCP004');
    expect(s.defect).toBe('missing-reason');
    expect(s.ruleIds).toEqual(['MCP004']);
  });

  it('flags a suppression whose reason is empty after the separator', () => {
    expect(one('// mcpscan-disable-next-line MCP004 --').defect).toBe('missing-reason');
    expect(one('// mcpscan-disable-next-line MCP004 --    ').defect).toBe('missing-reason');
  });

  it('flags a suppression that names no rule', () => {
    const s = one('// mcpscan-disable-next-line -- everything here is fine, trust me');
    expect(s.defect).toBe('missing-rule-id');
    expect(s.ruleIds).toEqual([]);
  });

  it('carries the comment text as written, for the diagnostic evidence', () => {
    expect(one('  // mcpscan-disable-next-line MCP004').raw).toBe('// mcpscan-disable-next-line MCP004');
  });
});

describe('collectSuppressions — silence', () => {
  it('finds nothing in a file with no marker', () => {
    expect(parse('const path = "/etc/passwd";\n// just a normal comment\n')).toEqual([]);
  });

  it('does not match a different mcpscan directive', () => {
    expect(parse('// mcpscan-disable-file MCP004 -- not a supported directive')).toEqual([]);
  });

  it.each([
    ['a string literal in code', "const MARKER = 'mcpscan-disable-next-line';"],
    ['a JSON string value', '  "note": "mcpscan-disable-next-line MCP004 -- x",'],
    ['prose naming it in a doc comment', ' * A `mcpscan-disable-next-line MCP004 -- reason` comment.'],
    ['a sentence', 'Write mcpscan-disable-next-line MCP004 -- reason above the line.'],
  ])('does not treat %s as a suppression', (_label, line) => {
    // The marker has to START a comment. Without this the scanner flagged its
    // own source: suppression.ts and core/suppress.ts necessarily contain the
    // marker in strings and doc comments.
    expect(parse(line)).toEqual([]);
  });

  it('still matches a jsdoc continuation line, which is a real comment', () => {
    expect(parse(' * mcpscan-disable-next-line MCP004 -- reason')).toHaveLength(1);
  });

  it('finds every suppression in a multi-line file', () => {
    const found = parse([
      '// mcpscan-disable-next-line MCP004 -- one',
      'a',
      '// mcpscan-disable-next-line MCP005 -- two',
      'b',
    ].join('\n'));
    expect(found.map((s) => s.targetLine)).toEqual([2, 4]);
  });
});
