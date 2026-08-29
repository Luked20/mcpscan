import { describe, it, expect } from 'vitest';
import { scan } from '../../src/scan.js';
import { formatSarif } from '../../src/report/sarif.js';
import { RULES } from '../../src/rules/index.js';

/**
 * The "false clean" family: an exit-2 scan ("couldn't look") used to still emit
 * a SARIF document with `results: []` and no invocation metadata — indistinguishable
 * from a genuinely clean scan. GitHub code scanning reconciles uploads and CLOSES
 * previously-open alerts when it receives a document it reads as a successful,
 * clean analysis. This is the wiring from scan() -> formatSarif() that must mark
 * the document unsuccessful on exit 2, end to end.
 */
describe('scan() + formatSarif on exit 2 ("path not found")', () => {
  it('produces a SARIF document that does not read as clean', async () => {
    const result = await scan({ path: 'nao/existe', failOn: 'high' });
    expect(result.exitCode).toBe(2);
    expect(result.error).toBeTruthy();

    const doc = JSON.parse(formatSarif(result.findings, RULES, '0.1.0', {
      executionSuccessful: result.exitCode !== 2,
      ...(result.error !== undefined ? { error: result.error } : {}),
    }));

    expect(doc.runs[0].results).toEqual([]);
    expect(doc.runs[0].invocations).toHaveLength(1);
    expect(doc.runs[0].invocations[0].executionSuccessful).toBe(false);
    expect(doc.runs[0].invocations[0].toolExecutionNotifications).toHaveLength(1);
    expect(doc.runs[0].invocations[0].toolExecutionNotifications[0].message.text).toContain(result.error);
  });

  it('a genuinely clean scan (exit 0) still reads as a successful analysis', async () => {
    const result = await scan({ path: 'tests/fixtures/MCP002/clean', failOn: 'high' });
    expect(result.exitCode).toBe(0);

    const doc = JSON.parse(formatSarif(result.findings, RULES, '0.1.0', {
      executionSuccessful: result.exitCode !== 2,
    }));

    expect(doc.runs[0].results).toEqual([]);
    expect(doc.runs[0].invocations[0].executionSuccessful).toBe(true);
    expect(doc.runs[0].invocations[0].toolExecutionNotifications).toBeUndefined();
  });
});
