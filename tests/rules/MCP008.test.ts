import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectSource } from '../../src/collect/source.js';
import { MCP008 } from '../../src/rules/mcp/MCP008.js';
import type { PartialFinding } from '../../src/core/types.js';

const loadFixture = (kind: 'vulnerable' | 'clean') => {
  const f = `tests/fixtures/MCP008/${kind}/server.ts`;
  return collectSource(f, readFileSync(f, 'utf8'));
};

const check = (text: string, file = 'server.ts'): PartialFinding[] => MCP008.check(collectSource(file, text));

describe('MCP008 — vulnerable fixture', () => {
  it('detects all four sinks', () => {
    const findings = MCP008.check(loadFixture('vulnerable'));
    expect(findings.length).toBe(4);
  });

  it('reports real line numbers, not all the same line', () => {
    const findings = MCP008.check(loadFixture('vulnerable'));
    const lines = new Set(findings.map((f) => f.location.line));
    expect(lines.size).toBeGreaterThan(1);
  });
});

describe('MCP008 — clean fixture', () => {
  it('produces no findings', () => {
    expect(MCP008.check(loadFixture('clean'))).toEqual([]);
  });
});

describe('MCP008 — language gate', () => {
  it('does not fire on language "py"', () => {
    expect(check('eval(userInput)', 'server.py')).toEqual([]);
  });
  it('does not fire on language "other"', () => {
    expect(check('eval(userInput)', 'server.txt')).toEqual([]);
  });
  it('fires on "js"', () => {
    expect(check('eval(userInput)', 'server.js')).toHaveLength(1);
  });
});

describe('MCP008 — eval()', () => {
  it('fires on a plain eval() call', () => {
    expect(check('eval(userInput);')).toHaveLength(1);
  });
  it('does NOT fire on "evaluate(...)" (longer identifier)', () => {
    expect(check('evaluate(expression);')).toEqual([]);
  });
  it('does NOT fire on "myEval(...)" (longer identifier)', () => {
    expect(check('myEval(x);')).toEqual([]);
  });
  it('does NOT fire on ".eval(" as a property access on an object', () => {
    expect(check('sandbox.eval(code);')).toEqual([]);
  });
});

describe('MCP008 — new Function()', () => {
  it('fires on new Function(...)', () => {
    expect(check("new Function('x', src);")).toHaveLength(1);
  });
});

describe('MCP008 — child_process.exec() / execSync()', () => {
  it('fires when the argument is a template literal', () => {
    expect(check('child_process.exec(`ls ${dir}`);')).toHaveLength(1);
  });
  it('fires when the argument is a string concatenation', () => {
    expect(check("child_process.exec('rm -rf ' + userInput);")).toHaveLength(1);
  });
  it('does NOT fire when the argument is a constant string literal', () => {
    expect(check("child_process.exec('git status');")).toEqual([]);
  });
  it('fires on execSync with a template literal', () => {
    expect(check('execSync(`tar -cf ${name}.tar ${name}`);')).toHaveLength(1);
  });
  it('fires on execSync with concatenation', () => {
    expect(check("execSync('echo ' + msg);")).toHaveLength(1);
  });
  it('does NOT fire on execSync with a constant string literal', () => {
    expect(check("execSync('git status');")).toEqual([]);
  });
  it('does NOT fire on execFile with an argument array', () => {
    expect(check("execFile('ls', [dir]);")).toEqual([]);
  });
  it('does NOT fire on spawn with an argument array', () => {
    expect(check("spawn('git', ['status']);")).toEqual([]);
  });
  it('does NOT fire on a bare, unqualified exec() call', () => {
    // Only the qualified `child_process.exec(` form is in scope -- a bare
    // `exec(` is too common a name (any promise wrapper, test helper) to
    // anchor a security finding on.
    expect(check('exec(`ls ${dir}`);')).toEqual([]);
  });
});

describe('MCP008 — location', () => {
  it('locates the finding at the real offset of the sink, not offset 0', () => {
    const findings = check('const a = 1;\nconst b = 2;\neval(userInput);\n');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.line).toBe(3);
  });
});
