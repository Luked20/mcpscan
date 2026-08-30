import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectManifest } from '../../src/collect/mcp-manifest.js';
import { MCP004 } from '../../src/rules/mcp/MCP004.js';
import type { PartialFinding, ScanTarget, ToolDefinition } from '../../src/core/types.js';

const loadFixture = (kind: 'vulnerable' | 'clean') => {
  const f = `tests/fixtures/MCP004/${kind}/tools.json`;
  return collectManifest(f, readFileSync(f, 'utf8'));
};

interface ToolShorthand {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

const makeTarget = (tools: ToolDefinition[]): ScanTarget =>
  ({ root: '.', servers: [], tools, skills: [], sourceFiles: [], unreadable: [], filesExamined: 1 });

/**
 * MCP004 is `appliesTo: 'target'` — its scope exemption is a property of the
 * whole manifest, so the rule is handed every tool at once rather than one.
 */
const checkAll = (tools: ToolDefinition[]): PartialFinding[] => MCP004.check(makeTarget(tools));

const check = (tool: ToolShorthand): PartialFinding[] =>
  checkAll(collectManifest('x.json', JSON.stringify({ tools: [tool] })));

describe('MCP004 — vulnerable fixture', () => {
  it('detects at least one finding per offending tool', () => {
    const findings = checkAll(loadFixture('vulnerable'));
    // get_file_contents(path), write_file(filename), list_directory(directory),
    // read_file(path), sync_files(source, dest) = 6 findings across 5 tools.
    expect(findings.length).toBe(6);
  });

  it('locates the finding at the property jsonPath', () => {
    const findings = checkAll(loadFixture('vulnerable'));
    const first = findings.find((f) => f.location.jsonPath === 'tools[0].inputSchema.properties.path');
    expect(first).toBeDefined();
  });

  it('names the tool and the parameter in the message', () => {
    const findings = checkAll(loadFixture('vulnerable'));
    const first = findings[0]!;
    expect(first.message).toContain('get_file_contents');
    expect(first.message).toContain('path');
  });

  it('includes actionable remediation mentioning pattern/enum', () => {
    const findings = checkAll(loadFixture('vulnerable'));
    expect(findings[0]!.remediation).toMatch(/pattern/i);
    expect(findings[0]!.remediation).toMatch(/enum/i);
  });

  it('produces multiple findings for a tool with multiple offending parameters (sync_files)', () => {
    const findings = check({
      name: 'sync_files',
      description: 'Copies files between two locations on disk.',
      inputSchema: {
        type: 'object',
        properties: {
          source: { type: 'string' },
          dest: { type: 'string' },
        },
      },
    });
    expect(findings).toHaveLength(2);
  });

  it('detects a tool that only reveals itself as a file tool through its name', () => {
    const findings = check({
      name: 'read_file',
      description: 'Returns the requested content, given an identifier.',
      inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
    });
    expect(findings).toHaveLength(1);
  });

  it('detects the filename variant', () => {
    const findings = check({
      name: 'write_file',
      description: 'Writes content to a file on disk.',
      inputSchema: { type: 'object', properties: { filename: { type: 'string' } } },
    });
    expect(findings).toHaveLength(1);
  });

  it('detects the directory variant', () => {
    const findings = check({
      name: 'list_directory',
      description: 'Lists the contents of a directory.',
      inputSchema: { type: 'object', properties: { directory: { type: 'string' } } },
    });
    expect(findings).toHaveLength(1);
  });
});

describe('MCP004 — clean fixture', () => {
  it('yields zero findings across every tool', () => {
    const findings = checkAll(loadFixture('clean'));
    expect(findings).toEqual([]);
  });
});

describe('MCP004 — negative conditions', () => {
  it('does not fire when the parameter has a pattern', () => {
    const findings = check({
      name: 'read_file',
      description: 'Reads a file from disk.',
      inputSchema: { properties: { path: { type: 'string', pattern: '^/data/.*$' } } },
    });
    expect(findings).toEqual([]);
  });

  it('does not fire when the parameter has an enum', () => {
    const findings = check({
      name: 'read_file',
      description: 'Reads a file from disk.',
      inputSchema: { properties: { path: { type: 'string', enum: ['a.txt', 'b.txt'] } } },
    });
    expect(findings).toEqual([]);
  });

  it('does not fire when the parameter has a const', () => {
    const findings = check({
      name: 'read_file',
      description: 'Reads a file from disk.',
      inputSchema: { properties: { path: { type: 'string', const: 'fixed.txt' } } },
    });
    expect(findings).toEqual([]);
  });

  it('does not fire when the parameter has a format', () => {
    const findings = check({
      name: 'read_file',
      description: 'Reads a file from disk.',
      inputSchema: { properties: { path: { type: 'string', format: 'uri' } } },
    });
    expect(findings).toEqual([]);
  });

  it('does not fire when the tool is not a file tool', () => {
    const findings = check({
      name: 'build_url',
      description: 'Builds the request URL.',
      inputSchema: { properties: { path: { type: 'string' } } },
    });
    expect(findings).toEqual([]);
  });

  it('does not fire when the parameter is not a path-shaped name', () => {
    const findings = check({
      name: 'read_file',
      description: 'Reads a file from disk.',
      inputSchema: { properties: { query: { type: 'string' } } },
    });
    expect(findings).toEqual([]);
  });

  it('does not fire when the parameter is not a string', () => {
    const findings = check({
      name: 'read_file',
      description: 'Reads a file from disk.',
      inputSchema: { properties: { path: { type: 'number' } } },
    });
    expect(findings).toEqual([]);
  });

  it('does not fire when there is no inputSchema at all', () => {
    const findings = check({ name: 'read_file', description: 'Reads a file from disk.' });
    expect(findings).toEqual([]);
  });

  it('does not fire when the description merely mentions files far from a verb', () => {
    const findings = check({
      name: 'get_open_connections',
      description: 'Returns the number of open network connections. See also the file-based variant.',
      inputSchema: { properties: { path: { type: 'string' } } },
    });
    expect(findings).toEqual([]);
  });
});

describe('MCP004 — behaviour', () => {
  it('is idempotent: two consecutive calls give the same result', () => {
    const tools = collectManifest('x.json', JSON.stringify({
      tools: [{
        name: 'read_file',
        description: 'Reads a file from disk.',
        inputSchema: { properties: { path: { type: 'string' } } },
      }],
    }));
    expect(checkAll(tools)).toEqual(checkAll(tools));
    expect(checkAll(tools)).toHaveLength(1);
  });

  it('rule metadata stays stable', () => {
    expect(MCP004.id).toBe('MCP004');
    expect(MCP004.severity).toBe('high');
    expect(MCP004.confidence).toBe('medium');
    expect(MCP004.owasp).toBe('MCP02:2025 – Privilege Escalation via Scope Creep');
    expect(MCP004.appliesTo).toBe('target');
  });
});

describe('MCP004 — cross-rule precision', () => {
  for (const id of ['MCP001', 'MCP002', 'MCP003', 'MCP005']) {
    it(`does not fire on the ${id} clean fixture`, () => {
      const f = `tests/fixtures/${id}/clean/tools.json`;
      const tools = collectManifest(f, readFileSync(f, 'utf8'));
      expect(checkAll(tools)).toEqual([]);
    });
  }
});

describe('MCP004 — manifest-wide scope exemption', () => {
  const pathTool = (name: string, description: string) => ({
    name,
    description,
    inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
  });

  const fromManifest = (file: string, tools: unknown[]) =>
    collectManifest(file, JSON.stringify({ tools }));

  it('fires on a file tool whose manifest never declares a restricted scope', () => {
    const tools = fromManifest('server/tools.json', [pathTool('read_file', 'Reads a file from disk.')]);
    expect(checkAll(tools)).toHaveLength(1);
  });

  it('does NOT fire when the tool itself declares the restriction', () => {
    const tools = fromManifest('server/tools.json', [
      pathTool('read_file', 'Reads a file from disk. Only works within allowed directories.'),
    ]);
    expect(checkAll(tools)).toEqual([]);
  });

  it('exempts every tool in a manifest where any one tool declares the restriction', () => {
    // The shape the regression corpus actually produced: the official
    // filesystem server's `read_file` is a deprecated one-line alias with no
    // room for the claim, sitting directly above `read_text_file`, which makes
    // it. Flagging one while clearing the other contradicts itself inside a
    // single file, for two tools the same handler protects identically.
    const tools = fromManifest('server/tools.json', [
      pathTool('read_file', 'Read the complete contents of a file as text. DEPRECATED: Use read_text_file instead.'),
      pathTool(
        'read_text_file',
        'Read the complete contents of a file from the file system as text. Only works within allowed directories.',
      ),
    ]);
    expect(checkAll(tools)).toEqual([]);
  });

  it('does NOT let one manifest\'s declaration exempt a different manifest', () => {
    const scoped = fromManifest('scoped/tools.json', [
      pathTool('read_text_file', 'Reads a file. Only works within allowed directories.'),
    ]);
    const open = fromManifest('open/tools.json', [pathTool('read_file', 'Reads a file from disk.')]);
    const findings = checkAll([...scoped, ...open]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('read_file');
  });

  it('accepts the "must be within allowed directories" phrasing', () => {
    const tools = fromManifest('server/tools.json', [{
      name: 'move_file',
      description: 'Move or rename files and directories. Both source and destination must be within allowed directories.',
      inputSchema: {
        type: 'object',
        properties: { source: { type: 'string' }, destination: { type: 'string' } },
      },
    }]);
    expect(checkAll(tools)).toEqual([]);
  });

  it('does NOT treat prose that merely mentions a directory as a scope declaration', () => {
    const tools = fromManifest('server/tools.json', [
      pathTool('read_file', 'Reads a file from disk. The directory is resolved relative to the project root.'),
    ]);
    expect(checkAll(tools)).toHaveLength(1);
  });
});
