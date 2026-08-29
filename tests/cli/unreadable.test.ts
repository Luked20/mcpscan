import { describe, it, expect } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scan } from '../../src/scan.js';
import { discover } from '../../src/collect/index.js';

/**
 * A file whose *name* declares what it is must never be dropped in silence.
 *
 * The regression this guards: a valid SKILL.md sitting next to a malformed one
 * reported "No problems found" and exit 0. The malformed file was never scanned
 * and nothing said so — the fifth appearance of the invariant in SPEC §16.6.
 */
async function withTree(
  files: Record<string, string>,
  fn: (dir: string) => Promise<void>,
): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), 'mcpscan-unreadable-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const full = join(dir, rel);
      mkdirSync(join(full, '..'), { recursive: true });
      writeFileSync(full, content, 'utf8');
    }
    // `await`, not `return fn(dir)`: returning the promise completes the try
    // block immediately, so `finally` would delete the tree out from under the
    // scan that is still running inside it.
    await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const GOOD_SKILL = '---\nname: good\ndescription: A perfectly ordinary skill.\n---\n\n# Good\n';
// The unquoted scalar contains ": ", which YAML reads as a nested mapping.
const BAD_SKILL = '---\nname: bad\ndescription: Deploys. Important: run tests first.\n---\n\n# Bad\n';
const GOOD_CONFIG = '{ "mcpServers": { "s": { "command": "node", "args": ["./s.js"] } } }';
const BAD_CONFIG = '{ "mcpServers": { ';

describe('unreadable declared files', () => {
  it('a malformed SKILL.md beside a valid one is exit 2, not a clean report', async () => {
    await withTree({ 'ok/SKILL.md': GOOD_SKILL, 'bad/SKILL.md': BAD_SKILL }, async (dir) => {
      const r = await scan({ path: dir, failOn: 'high' });
      expect(r.exitCode).toBe(2);
      expect(r.error).toContain('could not parse');
      expect(r.error).toContain('bad/SKILL.md');
      expect(r.stats.unreadable).toBe(1);
      // The valid skill was still collected — this is a partial report, not a dead scan.
      expect(r.stats.skills).toBe(1);
    });
  });

  it('a malformed .mcp.json beside a valid one is exit 2', async () => {
    await withTree({ 'ok/.mcp.json': GOOD_CONFIG, 'bad/.mcp.json': BAD_CONFIG }, async (dir) => {
      const r = await scan({ path: dir, failOn: 'high' });
      expect(r.exitCode).toBe(2);
      expect(r.stats.unreadable).toBe(1);
      expect(r.stats.servers).toBe(1);
    });
  });

  it('an ordinary .json that is simply not a manifest stays silent', async () => {
    // Nothing claimed this file was an MCP artifact, so silence is correct.
    await withTree({ 'ok/SKILL.md': GOOD_SKILL, 'tsconfig.json': '{ "compilerOptions": {} }' }, async (dir) => {
      const r = await scan({ path: dir, failOn: 'high' });
      expect(r.stats.unreadable).toBe(0);
      expect(r.exitCode).toBe(0);
    });
  });

  it('a clean tree reports zero unreadable', async () => {
    await withTree({ 'ok/SKILL.md': GOOD_SKILL }, async (dir) => {
      const r = await scan({ path: dir, failOn: 'high' });
      expect(r.exitCode).toBe(0);
      expect(r.stats.unreadable).toBe(0);
    });
  });

  it('discover records the reason, not just the count', async () => {
    await withTree({ 'bad/SKILL.md': BAD_SKILL }, async (dir) => {
      const t = await discover(dir);
      expect(t.unreadable).toHaveLength(1);
      expect(t.unreadable[0]!.file).toBe('bad/SKILL.md');
      expect(t.unreadable[0]!.reason).toMatch(/frontmatter/i);
    });
  });
});
