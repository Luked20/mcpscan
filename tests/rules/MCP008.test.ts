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

describe('MCP008 — comments are not code', () => {
  const check = (ts: string) => MCP008.check(collectSource('server.ts', ts));

  it.each([
    ['a line comment', '// never call eval(x) here\nconst a = 1;'],
    ['a trailing line comment', 'const a = 1; // we removed the eval(...) call'],
    ['a block comment', '/* do not use new Function(body) */\nconst a = 1;'],
    ['a jsdoc block', '/**\n * Avoid child_process.exec(`ls ${p}`).\n */\nconst a = 1;'],
  ])('does NOT flag a sink named in %s', (_label, code) => {
    expect(check(code)).toEqual([]);
  });

  it('still flags a real call on the line after a comment mentioning it', () => {
    expect(check('// we used to call eval() here\neval(x);')).toHaveLength(1);
  });

  it('keeps line numbers correct across a masked block comment', () => {
    const code = ['/*', ' * mentions eval() and new Function()', ' */', '', 'eval(userInput);'].join('\n');
    const findings = check(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.line).toBe(5);
  });

  it('does not mistake // inside a string for a comment', () => {
    // Masking `https://…` as a comment would blank the rest of the line and
    // hide the real sink after it.
    expect(check('const url = "https://x"; eval(userInput);')).toHaveLength(1);
  });

  it('still reports the real argument as evidence', () => {
    const findings = check('execSync(`ls ${dir}`);');
    expect(findings[0]!.evidence).toContain('ls ${dir}');
  });

  it('does not throw on an unterminated block comment', () => {
    expect(() => check('/* unterminated\neval(x);')).not.toThrow();
  });
});

describe('MCP008 — string contents are not code', () => {
  const check = (ts: string) => MCP008.check(collectSource('server.ts', ts));

  // Every line here is from czlonkowski/n8n-mcp, where four findings out of
  // five were string contents and none was a sink.
  it.each([
    ['test fixture data', "const cfg = { jsCode: 'const result = eval(item.json.code);' };"],
    ['a security check', "if (code?.includes('eval(') || code?.includes('exec(')) warn();"],
    ['a warning message', "const m = 'Avoid eval() - it is a security risk';"],
    ['a template literal', 'const m = `never call eval() yourself`;'],
    ['a double-quoted string', 'const m = "do not use new Function(body)";'],
  ])('does NOT flag a sink named in %s', (_label, code) => {
    expect(check(code)).toEqual([]);
  });

  it('still flags a real call beside a string that mentions one', () => {
    expect(check(`const m = 'avoid eval()'; eval(userInput);`)).toHaveLength(1);
  });

  it('is not fooled by a quote inside a regex literal', () => {
    // The reason string masking was avoided at first: `/["']/` has a quote that
    // opens no string. Skipping regex literals keeps the sink after it visible.
    expect(check('const RE = /["\']/; eval(userInput);')).toHaveLength(1);
  });

  // Each carries the hazard itself — an unbalanced quote inside the regex. If
  // the literal is not recognised in that position, the quote opens a bogus
  // string, the rest of the line is masked, and the sink after it disappears.
  it.each([
    ['assignment', `const RE = /["']/; eval(x);`],
    ['object value', `const t = { pattern: /["']/ }; eval(x);`],
    ['call argument', `test(/["']/); eval(x);`],
    ['return', `function f() { return /["']/; } eval(x);`],
  ])('recognises a regex literal in %s position', (_label, code) => {
    expect(check(code)).toHaveLength(1);
  });

  it('treats a slash after an expression as division, not a regex', () => {
    expect(check('const half = total / 2; eval(x);')).toHaveLength(1);
  });

  it('bounds a quoted string to its own line', () => {
    // An unterminated quote must not swallow the rest of the file.
    expect(check("const broken = 'oops;\neval(userInput);")).toHaveLength(1);
  });

  it('keeps line numbers correct across a masked multi-line template', () => {
    const code = ['const t = `', 'mentions eval() here', '`;', '', 'eval(userInput);'].join('\n');
    const findings = check(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.line).toBe(5);
  });

  it('still classifies a template argument correctly after masking', () => {
    const findings = check('execSync(`ls ${dir}`);');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('template-literal');
    expect(findings[0]!.evidence).toContain('ls ${dir}');
  });

  it('still clears a fixed-string command', () => {
    expect(check('execSync("ls -la");')).toEqual([]);
  });
});
