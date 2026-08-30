import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { MCP010 } from '../../src/rules/mcp/MCP010.js';
import { collectSource } from '../../src/collect/source.js';
import type { PartialFinding } from '../../src/core/types.js';

const check = (python: string): PartialFinding[] =>
  MCP010.check(collectSource('server.py', python));

const loadFixture = (kind: 'vulnerable' | 'clean') => {
  const f = `tests/fixtures/MCP010/${kind}/server.py`;
  return MCP010.check(collectSource(f, readFileSync(f, 'utf8')));
};

describe('MCP010 — fixtures', () => {
  it('flags every sink in the vulnerable fixture', () => {
    const findings = loadFixture('vulnerable');
    // os.popen(f-string), os.system(%), check_output(shell=True), run(shell=True),
    // eval, exec, pickle.loads, marshal.loads, yaml.load = 9
    expect(findings).toHaveLength(9);
  });

  it('finds nothing in the clean fixture', () => {
    expect(loadFixture('clean')).toEqual([]);
  });

  it('reports findings in source order', () => {
    const lines = loadFixture('vulnerable').map((f) => f.location.line);
    expect(lines).toEqual([...lines].sort((a, b) => a - b));
  });
});

describe('MCP010 — string executed as code', () => {
  it.each(['eval(user_input)', 'exec(source)', 'eval (x)'])('flags %s', (code) => {
    expect(check(code)).toHaveLength(1);
  });

  it('does NOT flag a method call named eval or exec on an object', () => {
    expect(check('engine.eval(x)\nrunner.exec(y)')).toEqual([]);
  });

  it('does NOT flag cursor.execute, which is SQL, not process execution', () => {
    // The AWS MySQL and Postgres MCP servers are full of these.
    expect(check('cursor.execute(f"SELECT * FROM {table}")')).toEqual([]);
  });

  it('does NOT flag an identifier that merely starts with eval', () => {
    expect(check('evaluate(x)\nevaluator(y)')).toEqual([]);
  });
});

describe('MCP010 — shell sinks', () => {
  it.each([
    ['os.system with an f-string', 'os.system(f"ls {path}")'],
    ['os.popen with an f-string', 'os.popen(f"ls {path}")'],
    ['os.system with concatenation', 'os.system("ls " + path)'],
    ['os.system with % formatting', 'os.system("ls %s" % path)'],
    ['os.system with .format()', 'os.system("ls {}".format(path))'],
  ])('flags %s', (_label, code) => {
    expect(check(code)).toHaveLength(1);
  });

  it.each([
    ['a fixed command', 'os.system("rsync --version")'],
    ['a bare variable', 'os.system(cmd)'],
    ['a function call', 'os.system(build_command())'],
  ])('does NOT flag %s', (_label, code) => {
    expect(check(code)).toEqual([]);
  });

  it('flags subprocess with shell=True and a built command', () => {
    expect(check('subprocess.run(f"git log {rev}", shell=True)')).toHaveLength(1);
  });

  it.each(['run', 'Popen', 'call', 'check_call', 'check_output'])('covers subprocess.%s', (fn) => {
    expect(check(`subprocess.${fn}(f"ls {p}", shell=True)`)).toHaveLength(1);
  });

  it('does NOT flag subprocess without shell=True, even with an f-string', () => {
    // An argument list is the correct way to spawn a process, and building one
    // of its elements from an f-string does not weaken it.
    expect(check('subprocess.run(["git", "log", rev])')).toEqual([]);
    expect(check('subprocess.run(f"git log {rev}")')).toEqual([]);
    expect(check('subprocess.run(f"git log {rev}", shell=False)')).toEqual([]);
  });

  it('does NOT flag shell=True with a fixed command', () => {
    expect(check('subprocess.call("ls -la | wc -l", shell=True)')).toEqual([]);
  });

  it('reads a call split across several lines', () => {
    const code = [
      'subprocess.run(',
      '    "tar czf out.tgz " + path,',
      '    shell=True,',
      '    check=True,',
      ')',
    ].join('\n');
    expect(check(code)).toHaveLength(1);
  });

  it('is not confused by a comma or paren inside the command string', () => {
    expect(check('os.system(f"echo (a, b) {x}")')).toHaveLength(1);
  });

  it('handles a triple-quoted command', () => {
    expect(check('os.system(f"""ls {path}""")')).toHaveLength(1);
  });
});

describe('MCP010 — deserialisation', () => {
  it.each([
    'pickle.loads(blob)',
    'pickle.load(fh)',
    'marshal.loads(blob)',
  ])('flags %s regardless of argument shape', (code) => {
    expect(check(code)).toHaveLength(1);
  });

  it('flags yaml.load with no Loader', () => {
    expect(check('yaml.load(text)')).toHaveLength(1);
  });

  it.each([
    'yaml.load(text, Loader=yaml.SafeLoader)',
    'yaml.load(text, Loader=Loader)',
    'yaml.safe_load(text)',
  ])('does NOT flag %s', (code) => {
    expect(check(code)).toEqual([]);
  });
});

describe('MCP010 — language gate', () => {
  it('ignores a TypeScript file, which is MCP008 territory', () => {
    const ts = collectSource('server.ts', 'eval(x); os.system(`ls ${p}`);');
    expect(MCP010.check(ts)).toEqual([]);
  });

  it('inspects a .py file', () => {
    expect(collectSource('server.py', 'eval(x)').language).toBe('py');
    expect(check('eval(x)')).toHaveLength(1);
  });
});

describe('MCP010 — behaviour', () => {
  it('is idempotent: two consecutive calls give the same result', () => {
    const file = collectSource('server.py', 'os.system(f"ls {p}")\neval(x)');
    expect(MCP010.check(file)).toEqual(MCP010.check(file));
    expect(MCP010.check(file)).toHaveLength(2);
  });

  it('does not hang or throw on an unterminated call', () => {
    expect(() => check('os.system(f"ls {p}"')).not.toThrow();
    expect(() => check('subprocess.run("x" + y, shell=True')).not.toThrow();
  });

  it('does not throw on an unterminated string', () => {
    expect(() => check('os.system("ls\nprint(1)')).not.toThrow();
  });

  it('rule metadata stays stable', () => {
    expect(MCP010.id).toBe('MCP010');
    expect(MCP010.severity).toBe('high');
    expect(MCP010.confidence).toBe('medium');
    expect(MCP010.owasp).toBe('MCP05:2025 – Command Injection & Execution');
    expect(MCP010.appliesTo).toBe('sourceFile');
  });
});

describe('MCP010 — prose is not code', () => {
  // The one finding a scan of awslabs/mcp produced before this existed was the
  // comment `# Instead of using exec(), we'll use a function factory approach`,
  // in a file whose whole point was that it does not call exec. One finding
  // across 1161 real Python files, and it was noise.
  it.each([
    ['a line comment', '# Instead of using exec(), we use a factory\nreturn 1'],
    ['a comment after code', 'x = 1  # never call eval(x) here'],
    ['a docstring', '"""This module avoids eval() and os.system(f"ls {p}")."""'],
    ['a single-quoted docstring', "'''Do not use pickle.loads(blob).'''"],
    ['a string literal', 'MESSAGE = "we do not call subprocess.run(cmd, shell=True)"'],
  ])('does NOT flag a sink named in %s', (_label, code) => {
    expect(check(code)).toEqual([]);
  });

  it('still flags a real call on the line after a comment mentioning it', () => {
    expect(check('# we used to call eval() here\neval(x)')).toHaveLength(1);
  });

  it('keeps line numbers correct across a masked multi-line docstring', () => {
    const code = ['"""', 'Mentions eval() and os.system("x").', '"""', '', 'eval(user_input)'].join('\n');
    const findings = check(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.line).toBe(5);
  });

  it('does not treat shell=True inside a string as a keyword argument', () => {
    expect(check('subprocess.run(f"echo shell=True {x}")')).toEqual([]);
  });

  it('reports the real command as evidence, not the masked one', () => {
    const findings = check('os.system(f"ls {path}")');
    expect(findings[0]!.evidence).toContain('ls {path}');
  });
});
