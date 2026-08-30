import { describe, it, expect } from 'vitest';
import { applySuppressions, SUPPRESSION_DIAGNOSTIC } from '../../src/core/suppress.js';
import { scan } from '../../src/scan.js';
import { RULES } from '../../src/rules/index.js';
import type { Finding, Suppression } from '../../src/core/types.js';

const KNOWN = new Set(RULES.map((r) => r.id));
const HELP = 'https://example.test/rules/';

function finding(ruleId: string, file: string, line: number): Finding {
  return {
    ruleId,
    title: 'x',
    severity: 'high',
    confidence: 'medium',
    location: { file, line, column: 1, endLine: line, endColumn: 2 },
    message: 'm',
    remediation: 'r',
    helpUri: `${HELP}${ruleId}.md`,
    provenance: 'static',
  };
}

function suppression(partial: Partial<Suppression> & { targetLine: number }): Suppression {
  return {
    file: 'a.json',
    line: partial.targetLine - 1,
    column: 1,
    ruleIds: ['MCP004'],
    reason: 'reviewed',
    raw: '// mcpscan-disable-next-line MCP004 -- reviewed',
    ...partial,
  };
}

/** A suppression with no reason at all — the `missing-reason` defect. */
function withoutReason(partial: Partial<Suppression> & { targetLine: number }): Suppression {
  const { reason: _dropped, ...rest } = suppression({ ...partial, defect: 'missing-reason' });
  return rest;
}

const apply = (findings: Finding[], suppressions: Suppression[]) =>
  applySuppressions(findings, suppressions, KNOWN, HELP);

describe('applySuppressions — what it silences', () => {
  it('drops a finding whose rule, file and line all match', () => {
    const r = apply([finding('MCP004', 'a.json', 10)], [suppression({ targetLine: 10 })]);
    expect(r.findings).toEqual([]);
    expect(r.suppressed).toBe(1);
  });

  it('does NOT drop a finding from a different rule on the same line', () => {
    const r = apply([finding('MCP005', 'a.json', 10)], [suppression({ targetLine: 10 })]);
    expect(r.findings).toHaveLength(1);
    expect(r.suppressed).toBe(0);
  });

  it('does NOT drop a finding on a different line', () => {
    const r = apply([finding('MCP004', 'a.json', 11)], [suppression({ targetLine: 10 })]);
    expect(r.findings).toHaveLength(1);
  });

  it('does NOT drop a finding in a different file', () => {
    const r = apply([finding('MCP004', 'b.json', 10)], [suppression({ targetLine: 10, file: 'a.json' })]);
    expect(r.findings).toHaveLength(1);
  });

  it('silences every rule the comment names', () => {
    const r = apply(
      [finding('MCP004', 'a.json', 10), finding('MCP005', 'a.json', 10)],
      [suppression({ targetLine: 10, ruleIds: ['MCP004', 'MCP005'] })],
    );
    expect(r.findings).toEqual([]);
    expect(r.suppressed).toBe(2);
  });
});

describe('applySuppressions — what it reports', () => {
  const diagnostics = (fs: Finding[]) => fs.filter((f) => f.ruleId === SUPPRESSION_DIAGNOSTIC.id);

  it('reports a suppression with no reason, and does not honour it', () => {
    const r = apply(
      [finding('MCP004', 'a.json', 10)],
      [withoutReason({ targetLine: 10 })],
    );
    expect(r.suppressed).toBe(0);
    expect(r.findings.filter((f) => f.ruleId === 'MCP004')).toHaveLength(1);

    const d = diagnostics(r.findings);
    expect(d).toHaveLength(1);
    expect(d[0]!.severity).toBe('info');
    expect(d[0]!.message).toMatch(/no justification/i);
  });

  it('reports a suppression that names no rule, and does not honour it', () => {
    const r = apply(
      [finding('MCP004', 'a.json', 10)],
      [suppression({ targetLine: 10, defect: 'missing-rule-id', ruleIds: [] })],
    );
    expect(r.suppressed).toBe(0);
    expect(diagnostics(r.findings)[0]!.message).toMatch(/names no rule/i);
  });

  it('reports a suppression naming a rule that does not exist', () => {
    // The silent-typo failure: it looks like protection and provides none.
    const r = apply([finding('MCP004', 'a.json', 10)], [suppression({ targetLine: 10, ruleIds: ['MCP404'] })]);
    expect(r.suppressed).toBe(0);

    const d = diagnostics(r.findings);
    expect(d).toHaveLength(1);
    expect(d[0]!.message).toContain('MCP404');
    expect(d[0]!.message).toContain('MCP004'); // lists the valid ids
  });

  it('honours the known ids in a comment that also names an unknown one, and still reports it', () => {
    const r = apply(
      [finding('MCP004', 'a.json', 10)],
      [suppression({ targetLine: 10, ruleIds: ['MCP004', 'MCP404'] })],
    );
    expect(r.suppressed).toBe(1);
    expect(r.findings.filter((f) => f.ruleId === 'MCP004')).toEqual([]);
    expect(diagnostics(r.findings)).toHaveLength(1);
  });

  it('points the diagnostic at the comment line, not the suppressed line', () => {
    const r = apply([], [withoutReason({ targetLine: 10 })]);
    expect(diagnostics(r.findings)[0]!.location.line).toBe(9);
  });

  it('carries the comment as evidence', () => {
    const r = apply([], [withoutReason({ targetLine: 10 })]);
    expect(diagnostics(r.findings)[0]!.evidence).toContain('mcpscan-disable-next-line');
  });

  it('emits nothing at all when there are no suppressions', () => {
    const r = apply([finding('MCP004', 'a.json', 10)], []);
    expect(r.findings).toHaveLength(1);
    expect(r.suppressed).toBe(0);
  });
});

describe('suppressions end to end (tests/fixtures/suppression)', () => {
  // One manifest, four file tools that each trip MCP004, each annotated
  // differently: one correctly, three defectively.
  const FIXTURE = 'tests/fixtures/suppression';

  it('silences only the correctly annotated finding, and reports the rest', async () => {
    const result = await scan({ path: FIXTURE, failOn: 'none' });
    expect(result.error).toBeUndefined();

    const mcp004 = result.findings.filter((f) => f.ruleId === 'MCP004');
    const diagnostics = result.findings.filter((f) => f.ruleId === SUPPRESSION_DIAGNOSTIC.id);

    // read_file suppressed; write_file (no reason), load_file (unknown rule)
    // and append_file (no rule id) all still reported.
    expect(mcp004.map((f) => f.message)).toHaveLength(3);
    expect(mcp004.some((f) => f.message.includes('read_file'))).toBe(false);
    expect(diagnostics).toHaveLength(3);
    expect(result.stats.suppressed).toBe(1);
  });

  it('a suppressed finding does not affect the exit code', async () => {
    // Only read_file is suppressed, so this still exits 1 -- but the count of
    // what it exits on is one lower, which is the entire point.
    const result = await scan({ path: FIXTURE, failOn: 'high' });
    expect(result.exitCode).toBe(1);
  });

  it('a malformed suppression never fails the build on its own', async () => {
    // `info` is below every --fail-on level (SPEC §9).
    const result = await scan({ path: FIXTURE, failOn: 'high', rules: ['MCP005'] });
    expect(result.findings.every((f) => f.severity === 'info')).toBe(true);
    expect(result.exitCode).toBe(0);
  });
});
