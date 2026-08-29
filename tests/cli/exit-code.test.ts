import { describe, it, expect } from 'vitest';
import { scan } from '../../src/scan.js';

describe('scan + exit code', () => {
  it('returns 1 when there is a finding at the fail-on level', async () => {
    const r = await scan({ path: 'tests/fixtures/MCP002/vulnerable', failOn: 'high' });
    expect(r.findings.length).toBeGreaterThan(0);
    expect(r.exitCode).toBe(1);
  });
  it('returns 0 on a clean directory', async () => {
    const r = await scan({ path: 'tests/fixtures/MCP002/clean', failOn: 'high' });
    expect(r.findings).toEqual([]);
    expect(r.exitCode).toBe(0);
  });
  it('returns 0 when the finding is below the threshold', async () => {
    const r = await scan({ path: 'tests/fixtures/MCP002/vulnerable', failOn: 'none' });
    expect(r.findings.length).toBeGreaterThan(0);
    expect(r.exitCode).toBe(0);
  });
  it('returns 1 when the target is the file itself', async () => {
    const r = await scan({ path: 'tests/fixtures/MCP002/vulnerable/tools.json', failOn: 'high' });
    expect(r.findings.length).toBeGreaterThan(0);
    expect(r.exitCode).toBe(1);
  });
  it('returns 2 on a nonexistent path', async () => {
    const r = await scan({ path: 'nao/existe', failOn: 'high' });
    expect(r.exitCode).toBe(2);
  });
});
