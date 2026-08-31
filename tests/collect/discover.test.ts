import { describe, it, expect } from 'vitest';
import { discover } from '../../src/collect/index.js';

describe('discover', () => {
  it('finds tools in the fixtures directory', async () => {
    const t = await discover('tests/fixtures/MCP002/vulnerable');
    expect(t.tools.map((x) => x.name)).toContain('read_file');
  });
  it('uses relative paths with a forward slash', async () => {
    const t = await discover('tests/fixtures/MCP002/vulnerable');
    expect(t.tools[0]!.origin.file.includes('\\')).toBe(false);
  });
  it('does not blow up on a directory with nothing relevant', async () => {
    const t = await discover('tests/fixtures/empty');
    expect(t.tools).toEqual([]);
  });
  it('scans a file passed directly', async () => {
    const t = await discover('tests/fixtures/MCP002/vulnerable/tools.json');
    expect(t.tools.map((x) => x.name)).toContain('read_file');
  });
  it('uses the basename as the relative path for a single file', async () => {
    const t = await discover('tests/fixtures/MCP002/vulnerable/tools.json');
    expect(t.tools[0]!.origin.file).toBe('tools.json');
  });
  it('counts files examined, not just those that produced tools', async () => {
    const t = await discover('tests/fixtures/MCP002/vulnerable');
    expect(t.filesExamined).toBe(1);
  });

  it('finds skills via SKILL.md, populating ScanTarget.skills', async () => {
    const t = await discover('tests/fixtures/skill-md/basic');
    expect(t.skills).toHaveLength(1);
    expect(t.skills[0]!.name).toBe('git-commit-helper');
    expect(t.tools).toEqual([]);
  });

  it('scans a SKILL.md file passed directly', async () => {
    const t = await discover('tests/fixtures/skill-md/basic/SKILL.md');
    expect(t.skills).toHaveLength(1);
    expect(t.skills[0]!.origin.file).toBe('SKILL.md');
  });

  it('finds .ts source files, populating ScanTarget.sourceFiles', async () => {
    const t = await discover('tests/fixtures/MCP008/vulnerable');
    expect(t.sourceFiles).toHaveLength(1);
    expect(t.sourceFiles[0]!.file).toBe('server.ts');
    expect(t.sourceFiles[0]!.language).toBe('ts');
  });

  it('counts a source file toward filesExamined, not toward tools', async () => {
    const t = await discover('tests/fixtures/MCP008/vulnerable');
    expect(t.filesExamined).toBe(1);
    expect(t.tools).toEqual([]);
  });

  it('does not run the manifest collector against a .ts file', async () => {
    // A .ts file will never be valid JSON, so collectManifest would already
    // return [] for it; this asserts the routing itself, not just the outcome.
    const t = await discover('tests/fixtures/MCP008/vulnerable');
    expect(t.unreadable).toEqual([]);
  });

  it('skips test files when collecting source, at the collector level', async () => {
    // A sink inside a test file never runs in front of an agent -- it is not
    // deployed code. tests/fixtures/source-exclusion/ has the identical sink in
    // src/handler.ts (must be found) and four excluded variants (must not):
    // *.test.ts basename, and tests/, __tests__/, spec/ directory segments.
    const t = await discover('tests/fixtures/source-exclusion');
    expect(t.sourceFiles.map((f) => f.file).sort()).toEqual(['src/handler.ts']);
  });
});

describe('discover — scripts a skill ships', () => {
  it('reads them, with contents and a root-relative path', async () => {
    const t = await discover('tests/fixtures/SKILL004/bundled-vulnerable');
    expect(t.skills).toHaveLength(1);
    const scripts = t.skills[0]!.bundledScripts;
    expect(scripts.map((s) => s.file)).toEqual(['scripts/setup.sh']);
    expect(scripts[0]!.language).toBe('sh');
    expect(scripts[0]!.text).toContain('curl -sLO');
  });

  it('leaves the array empty for a skill that ships none', async () => {
    // Not undefined, and not a reason to fail: a skill with no scripts is the
    // normal case, and every rule reading this field must see [] rather than
    // have to guard for absence.
    const t = await discover('tests/fixtures/SKILL004/clean');
    expect(t.skills).toHaveLength(1);
    expect(t.skills[0]!.bundledScripts).toEqual([]);
  });

  it('does not report a skill\'s scripts as unreadable', async () => {
    // `unreadable` means "a file whose name declared what it is would not
    // parse". A helper script never claimed to be anything, so it does not
    // belong in that channel even when it cannot be read.
    const t = await discover('tests/fixtures/SKILL004/bundled-vulnerable');
    expect(t.unreadable).toEqual([]);
  });
});
