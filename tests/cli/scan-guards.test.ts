import { describe, it, expect } from 'vitest';
import { RULES } from '../../src/rules/index.js';
import { scan } from '../../src/scan.js';
import type { Severity } from '../../src/core/types.js';

const VULN = 'tests/fixtures/MCP002/vulnerable';

describe('rule selection', () => {
  it('unknown ID in --rules is exit 2, not a silent scan', async () => {
    const r = await scan({ path: VULN, failOn: 'high', rules: ['MCP999'] });
    expect(r.exitCode).toBe(2);
    expect(r.error).toContain('MCP999');
    expect(r.error).toContain('MCP002'); // lists the valid ones
  });

  it('unknown ID in --disable is also exit 2', async () => {
    const r = await scan({ path: VULN, failOn: 'high', disable: ['MCP02'] });
    expect(r.exitCode).toBe(2);
    expect(r.error).toContain('MCP02');
  });

  it('empty rule set after filtering is exit 2', async () => {
    // Derived from the registry, not hardcoded: a hardcoded list silently stops
    // emptying the rule set the moment a rule is added, and the test then passes
    // for the wrong reason.
    const r = await scan({
      path: VULN,
      failOn: 'high',
      disable: RULES.map((rule) => rule.id),
    });
    expect(r.exitCode).toBe(2);
    expect(r.error).toBeTruthy();
  });

  it('a known ID still works', async () => {
    const r = await scan({ path: VULN, failOn: 'high', rules: ['MCP002'] });
    expect(r.exitCode).toBe(1);
    expect(r.error).toBeUndefined();
  });
});

describe('nothing to scan', () => {
  it('zero subjects is exit 2, not a green checkmark', async () => {
    const r = await scan({ path: 'tests/fixtures/empty', failOn: 'high' });
    expect(r.exitCode).toBe(2);
    expect(r.error).toContain('tests/fixtures/empty');
  });

  it('stats separate files scanned from files with tools', async () => {
    const r = await scan({ path: VULN, failOn: 'high' });
    expect(r.stats).toEqual({ filesExamined: 1, filesWithTools: 1, tools: 1, servers: 0, skills: 0 });
  });

  it('a directory holding only a SKILL.md is a real subject, not exit 2', async () => {
    const r = await scan({ path: 'tests/fixtures/skill-md/basic', failOn: 'high' });
    expect(r.error).toBeUndefined();
    expect(r.exitCode).not.toBe(2);
    expect(r.stats.skills).toBe(1);
    expect(r.stats.tools).toBe(0);
  });
});

describe('invalid --fail-on', () => {
  it('a value outside the set is exit 2', async () => {
    const r = await scan({ path: VULN, failOn: 'NONE' as Severity });
    expect(r.exitCode).toBe(2);
    expect(r.error).toContain('NONE');
  });

  it('does not let the threshold silently accept everything', async () => {
    const r = await scan({ path: VULN, failOn: 'NONE' as Severity });
    expect(r.exitCode).not.toBe(1);
    expect(r.exitCode).not.toBe(0);
  });
});
