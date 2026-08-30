import { describe, it, expect } from 'vitest';
import { formatSarif } from '../../src/report/sarif.js';
import { RULES } from '../../src/rules/index.js';
import type { Finding } from '../../src/core/types.js';

const base: Finding = {
  ruleId: 'MCP002', title: 'Invisible Unicode', severity: 'critical', confidence: 'high',
  location: { file: 'src/tools.json', line: 14, column: 32, endLine: 14, endColumn: 40, jsonPath: 'tools[1].description' },
  message: 'msg', remediation: 'fix', evidence: 'abc',
  helpUri: 'https://x/MCP002.md', provenance: 'static',
};

describe('formatSarif', () => {
  const doc = JSON.parse(formatSarif([base], RULES, '0.1.0', { executionSuccessful: true }));
  it('has version 2.1.0 and a schema', () => {
    expect(doc.version).toBe('2.1.0');
    expect(doc.$schema).toContain('sarif');
  });
  it('declares every rule in the registry, plus the suppression diagnostic, in the driver', () => {
    // +1: MCPSCAN001 is emitted outside the rule engine (core/suppress.ts) but a
    // result can carry its id, so the driver has to declare it too.
    expect(doc.runs[0].tool.driver.rules).toHaveLength(RULES.length + 1);
  });
  it('maps critical to level error', () => {
    expect(doc.runs[0].results[0].level).toBe('error');
  });
  it('emits a region with line and column', () => {
    expect(doc.runs[0].results[0].locations[0].physicalLocation.region)
      .toEqual({ startLine: 14, startColumn: 32, endLine: 14, endColumn: 40 });
  });
  it('fingerprint does NOT change when the line changes', () => {
    const moved = { ...base, location: { ...base.location, line: 99, endLine: 99 } };
    const a = JSON.parse(formatSarif([base], RULES, '0.1.0', { executionSuccessful: true })).runs[0].results[0].partialFingerprints;
    const b = JSON.parse(formatSarif([moved], RULES, '0.1.0', { executionSuccessful: true })).runs[0].results[0].partialFingerprints;
    expect(a['mcpScan/v1']).toBe(b['mcpScan/v1']);
  });
  it('fingerprint changes when the jsonPath changes', () => {
    const other = { ...base, location: { ...base.location, jsonPath: 'tools[2].description' } };
    const a = JSON.parse(formatSarif([base], RULES, '0.1.0', { executionSuccessful: true })).runs[0].results[0].partialFingerprints;
    const b = JSON.parse(formatSarif([other], RULES, '0.1.0', { executionSuccessful: true })).runs[0].results[0].partialFingerprints;
    expect(a['mcpScan/v1']).not.toBe(b['mcpScan/v1']);
  });
  it('fingerprint changes when the ruleId changes', () => {
    const other: Finding = { ...base, ruleId: 'MCP099' };
    const a = JSON.parse(formatSarif([base], RULES, '0.1.0', { executionSuccessful: true })).runs[0].results[0].partialFingerprints;
    const b = JSON.parse(formatSarif([other], RULES, '0.1.0', { executionSuccessful: true })).runs[0].results[0].partialFingerprints;
    expect(a['mcpScan/v1']).not.toBe(b['mcpScan/v1']);
  });
  it('fingerprint changes when the file changes', () => {
    const other = { ...base, location: { ...base.location, file: 'src/other.json' } };
    const a = JSON.parse(formatSarif([base], RULES, '0.1.0', { executionSuccessful: true })).runs[0].results[0].partialFingerprints;
    const b = JSON.parse(formatSarif([other], RULES, '0.1.0', { executionSuccessful: true })).runs[0].results[0].partialFingerprints;
    expect(a['mcpScan/v1']).not.toBe(b['mcpScan/v1']);
  });
  it('artifactLocation.uri uses forward slashes even with a backslash in the file', () => {
    const winPath = { ...base, location: { ...base.location, file: 'src\\tools.json' } };
    const d = JSON.parse(formatSarif([winPath], RULES, '0.1.0', { executionSuccessful: true }));
    expect(d.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('src/tools.json');
  });
  it('a finding without jsonPath and without evidence still produces a stable fingerprint and valid output', () => {
    const minimal: Finding = {
      ruleId: 'MCP002', title: 'x', severity: 'low', confidence: 'low',
      location: { file: 'a.json', line: 1, column: 1, endLine: 1, endColumn: 2 },
      message: 'm', remediation: 'r', helpUri: 'https://x', provenance: 'static',
    };
    const d1 = JSON.parse(formatSarif([minimal], RULES, '0.1.0', { executionSuccessful: true }));
    const d2 = JSON.parse(formatSarif([minimal], RULES, '0.1.0', { executionSuccessful: true }));
    expect(d1.runs[0].results[0].partialFingerprints['mcpScan/v1'])
      .toBe(d2.runs[0].results[0].partialFingerprints['mcpScan/v1']);
    expect(typeof d1.runs[0].results[0].partialFingerprints['mcpScan/v1']).toBe('string');
  });
  it('zero findings produces a valid document with empty results and all rules declared', () => {
    const d = JSON.parse(formatSarif([], RULES, '0.1.0', { executionSuccessful: true }));
    expect(d.runs[0].results).toEqual([]);
    expect(d.runs[0].tool.driver.rules).toHaveLength(RULES.length + 1);
  });
  it('every result.ruleId matches a rule declared in the driver', () => {
    const d = JSON.parse(formatSarif([base], RULES, '0.1.0', { executionSuccessful: true }));
    const declared = new Set(d.runs[0].tool.driver.rules.map((r: { id: string }) => r.id));
    for (const r of d.runs[0].results) {
      expect(declared.has(r.ruleId)).toBe(true);
    }
  });
  it('message.text is not empty and contains the message and remediation', () => {
    const text = doc.runs[0].results[0].message.text as string;
    expect(text.length).toBeGreaterThan(0);
    expect(text).toContain('msg');
    expect(text).toContain('fix');
  });
});

describe('formatSarif invocations (exit-2 "false clean" fix)', () => {
  it('invocations is always present with exactly one element', () => {
    const d = JSON.parse(formatSarif([base], RULES, '0.1.0', { executionSuccessful: true }));
    expect(d.runs[0].invocations).toHaveLength(1);
  });

  it('a successful scan with findings marks executionSuccessful true and has no notifications', () => {
    const d = JSON.parse(formatSarif([base], RULES, '0.1.0', { executionSuccessful: true }));
    expect(d.runs[0].invocations[0].executionSuccessful).toBe(true);
    expect(d.runs[0].invocations[0].toolExecutionNotifications).toBeUndefined();
  });

  it('a successful scan with zero findings (genuinely clean) still marks executionSuccessful true', () => {
    const d = JSON.parse(formatSarif([], RULES, '0.1.0', { executionSuccessful: true }));
    expect(d.runs[0].results).toEqual([]);
    expect(d.runs[0].invocations[0].executionSuccessful).toBe(true);
  });

  it('a failed scan marks executionSuccessful false and emits exactly one error notification carrying the CLI error string', () => {
    const d = JSON.parse(formatSarif([], RULES, '0.1.0', {
      executionSuccessful: false,
      error: 'path not found: nao/existe',
    }));
    expect(d.runs[0].invocations[0].executionSuccessful).toBe(false);
    const notifs = d.runs[0].invocations[0].toolExecutionNotifications;
    expect(notifs).toHaveLength(1);
    expect(notifs[0].level).toBe('error');
    expect(notifs[0].message.text).toContain('path not found: nao/existe');
    expect(notifs[0].descriptor).toEqual({ id: 'mcpscan/scan-failed' });
  });

  it('endTimeUtc parses as a valid date', () => {
    const d = JSON.parse(formatSarif([base], RULES, '0.1.0', { executionSuccessful: true }));
    const t = d.runs[0].invocations[0].endTimeUtc;
    expect(typeof t).toBe('string');
    expect(Number.isNaN(new Date(t).getTime())).toBe(false);
  });

  it('the failure document does not leak a command line or working directory', () => {
    const d = JSON.parse(formatSarif([], RULES, '0.1.0', {
      executionSuccessful: false,
      error: 'path not found: nao/existe',
    }));
    const inv = d.runs[0].invocations[0];
    expect(inv).not.toHaveProperty('commandLine');
    expect(inv).not.toHaveProperty('arguments');
    expect(inv).not.toHaveProperty('workingDirectory');
  });

  it('a failure document cannot be mistaken for a clean scan by inspecting the document alone', () => {
    const d = JSON.parse(formatSarif([], RULES, '0.1.0', {
      executionSuccessful: false,
      error: 'path not found: nao/existe',
    }));
    expect(claimsSuccessfulAnalysis(d)).toBe(false);

    const clean = JSON.parse(formatSarif([], RULES, '0.1.0', { executionSuccessful: true }));
    expect(claimsSuccessfulAnalysis(clean)).toBe(true);
  });
});

/**
 * "Does this SARIF document claim a successful analysis?" â€” the predicate a
 * consumer (or a test) should use to tell a genuinely clean scan apart from a
 * failed one that still produced an (empty) document.
 */
function claimsSuccessfulAnalysis(doc: { runs: Array<{ invocations?: Array<{ executionSuccessful: boolean }> }> }): boolean {
  const inv = doc.runs[0]?.invocations?.[0];
  return inv?.executionSuccessful === true;
}
