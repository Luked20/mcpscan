import { describe, it, expect } from 'vitest';
import { formatPretty } from '../../src/report/pretty.js';
import type { Finding } from '../../src/core/types.js';
import type { ScanStats } from '../../src/scan.js';

const STATS: ScanStats = { filesExamined: 40, filesWithTools: 3, tools: 12, servers: 2, skills: 1, resources: 0, prompts: 0, sourceFiles: 0, unreadable: 0, suppressed: 0, baselined: 0, liveTools: 0 };

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
  const zero: ScanStats = { filesExamined: 0, filesWithTools: 0, tools: 0, servers: 0, skills: 0, resources: 0, prompts: 0, sourceFiles: 0, unreadable: 0, suppressed: 0, baselined: 0, liveTools: 0 };
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

describe('formatPretty: --quiet', () => {
  const quiet = (findings: Finding[], stats: ScanStats = STATS, error?: string) =>
    formatPretty(findings, {
      color: false, stats, quiet: true, ...(error !== undefined ? { error } : {}),
    });

  it('prints nothing at all when a successful scan is clean', () => {
    expect(quiet([])).toBe('');
  });

  it('prints the findings, without the header or the severity summary', () => {
    const out = quiet([f]);
    expect(out).toContain('MCP002');
    expect(out).toContain('src/tools.json:14:32');
    expect(out).not.toContain('file(s) scanned');
    expect(out).not.toContain('1 critical');
  });

  it('still reports a scan that could not look', () => {
    // The one thing --quiet must never do is make "could not look" look like
    // "clean" (SPEC §16.6). Silence is only ever allowed to mean clean.
    const zero: ScanStats = {
      filesExamined: 0, filesWithTools: 0, tools: 0, servers: 0, skills: 0,
      resources: 0, prompts: 0,
      sourceFiles: 0, unreadable: 0, suppressed: 0, baselined: 0, liveTools: 0,
    };
    const out = quiet([], zero, 'path not found: nope');
    expect(out).not.toBe('');
    expect(out).toContain('Nothing scanned');
    expect(out).toContain('path not found: nope');
  });
});

describe('formatPretty: counters for findings that were dropped', () => {
  const withCounts = (over: Partial<ScanStats>) =>
    formatPretty([], { color: false, stats: { ...STATS, ...over } });

  it('reports suppressed and baselined counts in the header', () => {
    // These findings do not appear in the report, so the header is the only
    // place a reader learns they existed -- a heavily filtered scan must not
    // look like a clean one.
    expect(withCounts({ suppressed: 3 })).toContain('3 suppressed');
    expect(withCounts({ baselined: 7 })).toContain('7 baselined');
    expect(withCounts({ suppressed: 3, baselined: 7 })).toContain('3 suppressed · 7 baselined');
  });

  it('omits each counter when it is zero', () => {
    const out = withCounts({});
    expect(out).not.toContain('suppressed');
    expect(out).not.toContain('baselined');
  });
});
