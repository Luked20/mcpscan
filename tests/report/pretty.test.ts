import { describe, it, expect } from 'vitest';
import { formatPretty } from '../../src/report/pretty.js';
import type { Finding } from '../../src/core/types.js';
import type { ScanStats } from '../../src/scan.js';

const STATS: ScanStats = { filesExamined: 40, filesWithTools: 3, tools: 12, servers: 2, skills: 1, sourceFiles: 0, unreadable: 0, suppressed: 0 };

const f: Finding = {
  ruleId: 'MCP002', title: 'Invisible Unicode character in tool definition',
  severity: 'critical', confidence: 'high', owasp: 'MCP03:2025 – Tool Poisoning',
  location: { file: 'src/tools.json', line: 14, column: 32, endLine: 14, endColumn: 40, jsonPath: 'tools[1].description' },
  message: 'Tool "x" has 1 invisible character.',
  remediation: 'Remove the invisible characters.',
  helpUri: 'https://x/MCP002.md', provenance: 'static',
};

describe('formatPretty', () => {
  const out = formatPretty([f], { color: false, stats: STATS });
  it('shows severity, rule, and a clickable location', () => {
    expect(out).toContain('CRITICAL');
    expect(out).toContain('MCP002');
    expect(out).toContain('src/tools.json:14:32');
  });
  it('always shows Fix and a link', () => {
    expect(out).toContain('Fix:');
    expect(out).toContain('https://x/MCP002.md');
  });
  it('without color, emits no ANSI codes', () => {
    expect(out).not.toContain('[');
  });
  it('explicitly says when there is nothing', () => {
    expect(formatPretty([], { color: false, stats: STATS }))
      .toContain('No problems found');
  });
  it('separates files scanned from files with tools in the header', () => {
    expect(out).toContain('40 file(s) scanned');
    expect(out).toContain('3 with tools');
    expect(out).toContain('12 tool(s)');
    expect(out).toContain('1 skill(s)');
  });
});

describe('formatPretty: a scan that looked at nothing', () => {
  const zero: ScanStats = { filesExamined: 0, filesWithTools: 0, tools: 0, servers: 0, skills: 0, sourceFiles: 0, unreadable: 0, suppressed: 0 };
  const out = formatPretty([], {
    color: false, stats: zero, error: 'no MCP server or agent skill found in src',
  });

  it('does not look like a clean scan', () => {
    expect(out).not.toContain('No problems found');
  });
  it('says it could not scan anything and shows why', () => {
    expect(out).toContain('Nothing scanned');
    expect(out).toContain('no MCP server or agent skill found in src');
  });
  it('shows partial findings alongside the error when they exist', () => {
    const partial = formatPretty([f], { color: false, stats: zero, error: 'rule(s) failed' });
    expect(partial).toContain('MCP002');
    expect(partial).toContain('rule(s) failed');
  });
});
