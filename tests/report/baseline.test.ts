import { describe, it, expect } from 'vitest';
import { formatBaseline, parseBaseline, BASELINE_VERSION } from '../../src/report/baseline.js';
import { FINGERPRINT_KEY, fingerprint } from '../../src/core/fingerprint.js';
import { scan } from '../../src/scan.js';
import type { Finding } from '../../src/core/types.js';

function finding(over: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'MCP004',
    title: 'x',
    severity: 'high',
    confidence: 'medium',
    location: { file: 'server/tools.json', line: 10, column: 1, endLine: 10, endColumn: 2, jsonPath: 'tools[0]' },
    message: 'm',
    remediation: 'r',
    evidence: 'e',
    helpUri: 'https://example.test/MCP004.md',
    provenance: 'static',
    ...over,
  };
}

const doc = (findings: Finding[]) => JSON.parse(formatBaseline(findings));

describe('formatBaseline', () => {
  it('writes a versioned document naming the fingerprint scheme', () => {
    const d = doc([finding()]);
    expect(d.version).toBe(BASELINE_VERSION);
    expect(d.fingerprintKey).toBe(FINGERPRINT_KEY);
  });

  it('records the fingerprint plus enough context to review the entry', () => {
    const d = doc([finding()]);
    expect(d.findings).toEqual([{
      fingerprint: fingerprint(finding()),
      ruleId: 'MCP004',
      file: 'server/tools.json',
      jsonPath: 'tools[0]',
    }]);
  });

  it('stores neither the message nor the line', () => {
    // Message text is explicitly not public contract (SPEC §16.5) and the line
    // is not part of the identity -- storing either would churn the committed
    // file for reasons nothing matches on.
    const entry = doc([finding()]).findings[0];
    expect(entry).not.toHaveProperty('message');
    expect(entry).not.toHaveProperty('line');
  });

  it('normalises Windows separators in the recorded path', () => {
    const d = doc([finding({ location: { ...finding().location, file: 'server\\tools.json' } })]);
    expect(d.findings[0].file).toBe('server/tools.json');
  });

  it('sorts by fingerprint so the committed diff stays readable', () => {
    const many = ['MCP001', 'MCP009', 'MCP004'].map((ruleId) => finding({ ruleId }));
    const fps = doc(many).findings.map((f: { fingerprint: string }) => f.fingerprint);
    expect(fps).toEqual([...fps].sort());
  });

  it('collapses two findings that share one identity', () => {
    expect(doc([finding(), finding({ location: { ...finding().location, line: 99 } })]).findings).toHaveLength(1);
  });
});

describe('parseBaseline — accepted', () => {
  it('round-trips what formatBaseline wrote', () => {
    const f = finding();
    const parsed = parseBaseline(formatBaseline([f]), 'b.json');
    expect(parsed).toBeInstanceOf(Set);
    expect(parsed as Set<string>).toContain(fingerprint(f));
  });

  it('accepts a document with no fingerprintKey, treating it as the current scheme', () => {
    const text = JSON.stringify({ version: BASELINE_VERSION, findings: [{ fingerprint: 'abc' }] });
    expect(parseBaseline(text, 'b.json')).toEqual(new Set(['abc']));
  });
});

describe('parseBaseline — rejected', () => {
  // Every one of these returns an error the CLI turns into exit 2. Degrading to
  // "no baseline" would turn every accepted finding back on at once, which
  // reads as the scanner having found new problems.
  it('rejects malformed JSON', () => {
    expect(parseBaseline('{ nope', 'b.json')).toMatch(/^b\.json is not valid JSON/);
  });

  it('rejects a wrong version', () => {
    expect(parseBaseline(JSON.stringify({ version: 99, findings: [] }), 'b.json')).toMatch(/has version 99/);
  });

  it('rejects a document written under a different fingerprint scheme', () => {
    const text = JSON.stringify({ version: BASELINE_VERSION, fingerprintKey: 'mcpScan/v2', findings: [] });
    expect(parseBaseline(text, 'b.json')).toMatch(/fingerprint scheme "mcpScan\/v2"/);
  });

  it('rejects a missing findings array', () => {
    expect(parseBaseline(JSON.stringify({ version: BASELINE_VERSION }), 'b.json')).toMatch(/no "findings" array/);
  });

  it('rejects an entry with no fingerprint', () => {
    const text = JSON.stringify({ version: BASELINE_VERSION, findings: [{ ruleId: 'MCP004' }] });
    expect(parseBaseline(text, 'b.json')).toMatch(/findings\[0\] has no "fingerprint" string/);
  });
});

describe('baseline end to end', () => {
  const VULN = 'tests/fixtures/MCP004/vulnerable';

  it('a baseline generated from a scan silences that same scan', async () => {
    const before = await scan({ path: VULN, failOn: 'high' });
    expect(before.exitCode).toBe(1);
    expect(before.findings.length).toBeGreaterThan(0);

    const baseline = parseBaseline(formatBaseline(before.findings), 'b.json') as Set<string>;
    const after = await scan({ path: VULN, failOn: 'high', baseline });

    expect(after.findings).toEqual([]);
    expect(after.exitCode).toBe(0);
    expect(after.stats.baselined).toBe(before.findings.length);
  });

  it('a finding absent from the baseline still fails the build', async () => {
    const all = await scan({ path: VULN, failOn: 'high' });
    // Everything except one: the point of a baseline is that new findings survive it.
    const partial = parseBaseline(formatBaseline(all.findings.slice(1)), 'b.json') as Set<string>;
    const after = await scan({ path: VULN, failOn: 'high', baseline: partial });

    expect(after.findings).toHaveLength(1);
    expect(after.exitCode).toBe(1);
  });

  it('an empty baseline changes nothing', async () => {
    const plain = await scan({ path: VULN, failOn: 'high' });
    const withEmpty = await scan({ path: VULN, failOn: 'high', baseline: new Set() });
    expect(withEmpty.findings).toEqual(plain.findings);
    expect(withEmpty.stats.baselined).toBe(0);
  });
});
