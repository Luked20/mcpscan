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
});
