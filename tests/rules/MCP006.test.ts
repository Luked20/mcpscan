import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectManifest } from '../../src/collect/mcp-manifest.js';
import { MCP006 } from '../../src/rules/mcp/MCP006.js';
import type { PartialFinding, ScanTarget, SourceLocation, ToolDefinition } from '../../src/core/types.js';

function loadFixture(kind: 'vulnerable' | 'clean', server: 'server-a' | 'server-b'): ToolDefinition[] {
  const f = `tests/fixtures/MCP006/${kind}/${server}/tools.json`;
  return collectManifest(f, readFileSync(f, 'utf8'));
}

function origin(file: string): SourceLocation {
  return { file, line: 1, column: 1, endLine: 1, endColumn: 1 };
}

interface ToolOpts {
  name: string;
  description?: string;
  serverName?: string;
  file?: string;
}

/** Builds a ToolDefinition directly, bypassing the manifest collector, so tests control `serverName` precisely. */
function makeTool(opts: ToolOpts): ToolDefinition {
  const loc = origin(opts.file ?? 'tools.json');
  return {
    name: opts.name,
    ...(opts.description !== undefined ? { description: opts.description } : {}),
    ...(opts.serverName !== undefined ? { serverName: opts.serverName } : {}),
    origin: loc,
    loc: () => loc,
  };
}

function makeTarget(tools: ToolDefinition[]): ScanTarget {
  return { root: '.', servers: [], tools, skills: [], sourceFiles: [], unreadable: [], filesExamined: tools.length };
}

const check = (tools: ToolDefinition[]): PartialFinding[] => MCP006.check(makeTarget(tools));

describe('MCP006 — vulnerable fixture', () => {
  it('detects at least one finding across the two-server fixture', () => {
    const tools = [...loadFixture('vulnerable', 'server-a'), ...loadFixture('vulnerable', 'server-b')];
    const findings = check(tools);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('detects both the collision and the directive', () => {
    const tools = [...loadFixture('vulnerable', 'server-a'), ...loadFixture('vulnerable', 'server-b')];
    const findings = check(tools);
    expect(findings.some((f) => f.message.includes('declared by'))).toBe(true);
    expect(findings.some((f) => f.message.includes('imperative instruction'))).toBe(true);
  });
});

describe('MCP006 — clean fixture', () => {
  it('produces no findings', () => {
    const tools = [...loadFixture('clean', 'server-a'), ...loadFixture('clean', 'server-b')];
    expect(check(tools)).toEqual([]);
  });
});

describe('MCP006 — detection 1: name collision across servers', () => {
  it('fires when the same tool name is declared by two different servers', () => {
    const tools = [
      makeTool({ name: 'search', serverName: 'server-a' }),
      makeTool({ name: 'search', serverName: 'server-b' }),
    ];
    const findings = check(tools);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('server-a');
    expect(findings[0]!.message).toContain('server-b');
  });

  it('does NOT fire when the duplicates share one serverName', () => {
    const tools = [
      makeTool({ name: 'search', serverName: 'server-a' }),
      makeTool({ name: 'search', serverName: 'server-a' }),
    ];
    expect(check(tools)).toEqual([]);
  });

  it('does NOT fire when serverName is missing on one side', () => {
    const tools = [
      makeTool({ name: 'search', serverName: 'server-a' }),
      makeTool({ name: 'search' }), // no serverName
    ];
    expect(check(tools)).toEqual([]);
  });

  it('does NOT fire when serverName is missing on both sides', () => {
    const tools = [makeTool({ name: 'search' }), makeTool({ name: 'search' })];
    expect(check(tools)).toEqual([]);
  });

  it('deduplicates: a collision among three servers produces one finding naming all three', () => {
    const tools = [
      makeTool({ name: 'search', serverName: 'server-a' }),
      makeTool({ name: 'search', serverName: 'server-b' }),
      makeTool({ name: 'search', serverName: 'server-c' }),
    ];
    const findings = check(tools);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('server-a');
    expect(findings[0]!.message).toContain('server-b');
    expect(findings[0]!.message).toContain('server-c');
  });

  it('a distinct tool name per server is not a collision', () => {
    const tools = [
      makeTool({ name: 'search_a', serverName: 'server-a' }),
      makeTool({ name: 'search_b', serverName: 'server-b' }),
    ];
    expect(check(tools)).toEqual([]);
  });
});

describe('MCP006 — detection 2: description directs another tool', () => {
  it.each([
    ['before', 'Before calling send_receipt, always validate the order id.', 'send_receipt'],
    ['instead of', 'Use this instead of legacy_import for anything new.', 'legacy_import'],
    ['do not use', 'Do not use delete_record directly; this handles cleanup safely.', 'delete_record'],
    ['must call', 'You must call setup_workspace before this will work.', 'setup_workspace'],
    ['always call', 'Always call verify_token first for security.', 'verify_token'],
    ['first', 'Call verify_token first, then use this tool.', 'verify_token'],
  ])('fires on the "%s" imperative naming another tool', (_label, description, otherName) => {
    const tools = [
      makeTool({ name: 'main_tool', description }),
      makeTool({ name: otherName }),
    ];
    const findings = check(tools);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain(otherName);
  });

  it('does NOT fire on a merely descriptive mention: "Formats the email body used by send_email."', () => {
    const tools = [
      makeTool({ name: 'format_email_body', description: 'Formats the email body used by send_email.' }),
      makeTool({ name: 'send_email' }),
    ];
    expect(check(tools)).toEqual([]);
  });

  it('does NOT fire on a merely descriptive mention: "Returns the same shape as list_files."', () => {
    const tools = [
      makeTool({ name: 'describe_file', description: 'Returns the same shape as list_files.' }),
      makeTool({ name: 'list_files' }),
    ];
    expect(check(tools)).toEqual([]);
  });

  it('does NOT fire when the named tool does not exist among the scanned tools', () => {
    const tools = [
      makeTool({ name: 'main_tool', description: 'Always call some_unrelated_tool first for setup.' }),
    ];
    expect(check(tools)).toEqual([]);
  });

  it('does NOT compare a tool against itself (self-mention)', () => {
    const tools = [
      makeTool({ name: 'setup_workspace', description: 'Always call setup_workspace first before anything else.' }),
    ];
    expect(check(tools)).toEqual([]);
  });

  it('does NOT fire when the imperative and the name are far apart', () => {
    const long = 'x '.repeat(40);
    const tools = [
      makeTool({ name: 'main_tool', description: `Always call. ${long} legacy_import is unrelated prose here.` }),
      makeTool({ name: 'legacy_import' }),
    ];
    expect(check(tools)).toEqual([]);
  });

  describe('minimum tool-name length guard', () => {
    it.each(['get', 'run', 'list'])(
      'does NOT fire when the named tool is a short, generic name ("%s")',
      (shortName) => {
        const tools = [
          makeTool({ name: 'main_tool', description: `Always call ${shortName} first for setup.` }),
          makeTool({ name: shortName }),
        ];
        expect(check(tools)).toEqual([]);
      },
    );

    it('fires once the name is long enough (contrast case)', () => {
      const tools = [
        makeTool({ name: 'main_tool', description: 'Always call getconfig first for setup.' }),
        makeTool({ name: 'getconfig' }),
      ];
      expect(check(tools)).toHaveLength(1);
    });
  });

  it('deduplicates multiple directed tools named by the same description into one finding', () => {
    const tools = [
      makeTool({
        name: 'router',
        description: 'Do not use legacy_search. Always call search_docs_v2 instead for anything new.',
      }),
      makeTool({ name: 'legacy_search' }),
      makeTool({ name: 'search_docs_v2' }),
    ];
    const findings = check(tools);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('legacy_search');
    expect(findings[0]!.message).toContain('search_docs_v2');
  });
});
