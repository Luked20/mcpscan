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
});
