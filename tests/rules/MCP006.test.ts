import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectManifest } from '../../src/collect/mcp-manifest.js';
import { collectMcpConfig } from '../../src/collect/mcp-config.js';
import { MCP006 } from '../../src/rules/mcp/MCP006.js';
import type {
  PartialFinding, ScanTarget, ServerDefinition, SourceLocation, ToolDefinition,
} from '../../src/core/types.js';

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
  /** Defaults to 'declared' when `serverName` is set — most tests here are exercising the
   *  collision mechanism itself, not the declared/derived distinction (that gets its own
   *  describe block below, built on `collectManifest` directly). */
  serverNameSource?: 'declared' | 'derived';
  file?: string;
}

/** Builds a ToolDefinition directly, bypassing the manifest collector, so tests control `serverName` precisely. */
function makeTool(opts: ToolOpts): ToolDefinition {
  const loc = origin(opts.file ?? 'tools.json');
  return {
    name: opts.name,
    ...(opts.description !== undefined ? { description: opts.description } : {}),
    ...(opts.serverName !== undefined
      ? { serverName: opts.serverName, serverNameSource: opts.serverNameSource ?? 'declared' }
      : {}),
    origin: loc,
    loc: () => loc,
  };
}

function makeTarget(tools: ToolDefinition[], servers: ServerDefinition[] = []): ScanTarget {
  return { root: '.', servers, tools, resources: [], prompts: [], skills: [], sourceFiles: [], suppressions: [], unreadable: [], filesExamined: tools.length };
}

const check = (tools: ToolDefinition[], servers: ServerDefinition[] = []): PartialFinding[] =>
  MCP006.check(makeTarget(tools, servers));

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
      makeTool({ name: 'search', serverName: 'server-a', file: 'server-a/tools.json' }),
      makeTool({ name: 'search', serverName: 'server-b', file: 'server-b/tools.json' }),
    ];
    const findings = check(tools);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('server-a');
    expect(findings[0]!.message).toContain('server-b');
  });

  it('does NOT fire when the duplicates come from one manifest file', () => {
    const tools = [
      makeTool({ name: 'search', serverName: 'server-a' }),
      makeTool({ name: 'search', serverName: 'server-a' }),
    ];
    expect(check(tools)).toEqual([]);
  });

  it('does NOT fire when serverName is missing on one side', () => {
    const tools = [
      makeTool({ name: 'search', serverName: 'server-a', file: 'server-a/tools.json' }),
      makeTool({ name: 'search', file: 'server-b/tools.json' }), // no serverName
    ];
    expect(check(tools)).toEqual([]);
  });

  it('does NOT fire when serverName is missing on both sides', () => {
    const tools = [makeTool({ name: 'search' }), makeTool({ name: 'search' })];
    expect(check(tools)).toEqual([]);
  });

  it('deduplicates: a collision among three servers produces one finding naming all three', () => {
    const tools = [
      makeTool({ name: 'search', serverName: 'server-a', file: 'server-a/tools.json' }),
      makeTool({ name: 'search', serverName: 'server-b', file: 'server-b/tools.json' }),
      makeTool({ name: 'search', serverName: 'server-c', file: 'server-c/tools.json' }),
    ];
    const findings = check(tools);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('server-a');
    expect(findings[0]!.message).toContain('server-b');
    expect(findings[0]!.message).toContain('server-c');
  });

  it('a distinct tool name per server is not a collision', () => {
    const tools = [
      makeTool({ name: 'search_a', serverName: 'server-a', file: 'server-a/tools.json' }),
      makeTool({ name: 'search_b', serverName: 'server-b', file: 'server-b/tools.json' }),
    ];
    expect(check(tools)).toEqual([]);
  });
});

describe('MCP006 — detection 1: declared vs. derived server names', () => {
  it('does NOT fire when both serverNames are derived (directory fallback), even on a real name collision', () => {
    // Mirrors the real self-scan bug: two unrelated fixture directories, neither manifest
    // declares a root "name", both happen to expose "read_file". A directory is not a
    // deployment, so this must not be reported as tool shadowing.
    const toolsA = collectManifest(
      'dir-one/tools.json',
      JSON.stringify({ tools: [{ name: 'read_file', description: 'Reads a file.' }] }),
    );
    const toolsB = collectManifest(
      'dir-two/tools.json',
      JSON.stringify({ tools: [{ name: 'read_file', description: 'Reads a file too.' }] }),
    );
    expect(toolsA[0]!.serverNameSource).toBe('derived');
    expect(toolsB[0]!.serverNameSource).toBe('derived');
    expect(check([...toolsA, ...toolsB])).toEqual([]);
  });

  it('fires when both manifests explicitly declare the same colliding "name"', () => {
    const toolsA = collectManifest(
      'dir-one/tools.json',
      JSON.stringify({ name: 'files', tools: [{ name: 'read_file' }] }),
    );
    const toolsB = collectManifest(
      'dir-two/tools.json',
      JSON.stringify({ name: 'files', tools: [{ name: 'read_file' }] }),
    );
    expect(toolsA[0]!.serverNameSource).toBe('declared');
    const findings = check([...toolsA, ...toolsB]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('read_file');
  });

  it('does NOT fire when one side declares a name and the other is only derived', () => {
    const toolsA = collectManifest(
      'dir-one/tools.json',
      JSON.stringify({ name: 'files', tools: [{ name: 'read_file' }] }),
    );
    const toolsB = collectManifest(
      'dir-two/tools.json',
      JSON.stringify({ tools: [{ name: 'read_file' }] }), // no root "name" -> derived
    );
    expect(check([...toolsA, ...toolsB])).toEqual([]);
  });

  it('fires when two explicitly-named servers collide, even with a third derived-name server present', () => {
    const declaredA = makeTool({
      name: 'read_file', serverName: 'files', serverNameSource: 'declared', file: 'dir-one/tools.json',
    });
    const declaredB = makeTool({
      name: 'read_file', serverName: 'files', serverNameSource: 'declared', file: 'dir-two/tools.json',
    });
    const derivedC = makeTool({
      name: 'read_file', serverName: 'some/random/dir', serverNameSource: 'derived', file: 'some/random/dir/tools.json',
    });
    const findings = check([declaredA, declaredB, derivedC]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('files');
    expect(findings[0]!.message).not.toContain('some/random/dir');
  });
});

describe('MCP006 — detection 1b: colliding server entries in one client config file', () => {
  it('fires when two entries in one .mcp.json run the identical command', () => {
    const config = JSON.stringify({
      mcpServers: {
        'files-a': { command: 'npx', args: ['-y', 'files-mcp@latest'] },
        'files-b': { command: 'npx', args: ['-y', 'files-mcp@latest'] },
      },
    });
    const servers = collectMcpConfig('.mcp.json', config);
    const findings = check([], servers);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('files-a');
    expect(findings[0]!.message).toContain('files-b');
  });

  it('does NOT fire when the two entries run different commands', () => {
    const config = JSON.stringify({
      mcpServers: {
        'files-a': { command: 'npx', args: ['-y', 'files-mcp@latest'] },
        'git-a': { command: 'npx', args: ['-y', 'git-mcp@latest'] },
      },
    });
    const servers = collectMcpConfig('.mcp.json', config);
    expect(check([], servers)).toEqual([]);
  });

  it('does NOT fire across two different config files, even with an identical command', () => {
    const configA = JSON.stringify({ mcpServers: { 'files-a': { command: 'npx', args: ['-y', 'files-mcp@latest'] } } });
    const configB = JSON.stringify({ mcpServers: { 'files-b': { command: 'npx', args: ['-y', 'files-mcp@latest'] } } });
    const servers = [...collectMcpConfig('a/.mcp.json', configA), ...collectMcpConfig('b/.mcp.json', configB)];
    expect(check([], servers)).toEqual([]);
  });

  it('fires for two http servers in one config file with the identical url', () => {
    const config = JSON.stringify({
      mcpServers: {
        remote1: { url: 'https://example.com/mcp' },
        remote2: { url: 'https://example.com/mcp' },
      },
    });
    const servers = collectMcpConfig('.mcp.json', config);
    const findings = check([], servers);
    expect(findings).toHaveLength(1);
  });
});

describe('MCP006 — detection 2: description directs another tool', () => {
  /**
   * Detection 2 only compares tools from *different* manifests: a description
   * naming a sibling in the same file is that server documenting its own
   * workflow. So every pair here is deliberately split across two files.
   */
  const directing = (name: string, description: string) =>
    makeTool({ name, description, file: 'directing/tools.json' });
  const elsewhere = (name: string) => makeTool({ name, file: 'other/tools.json' });

  it.each([
    ['before', 'Before calling send_receipt, always validate the order id.', 'send_receipt'],
    ['instead of', 'Use this instead of legacy_import for anything new.', 'legacy_import'],
    ['do not use', 'Do not use delete_record directly; this handles cleanup safely.', 'delete_record'],
    ['must call', 'You must call setup_workspace before this will work.', 'setup_workspace'],
    ['always call', 'Always call verify_token first for security.', 'verify_token'],
    ['first', 'Call verify_token first, then use this tool.', 'verify_token'],
  ])('fires on the "%s" imperative naming another tool', (_label, description, otherName) => {
    const tools = [
      directing('main_tool', description),
      elsewhere(otherName),
    ];
    const findings = check(tools);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain(otherName);
  });

  it('does NOT fire on a merely descriptive mention: "Formats the email body used by send_email."', () => {
    const tools = [
      directing('format_email_body', 'Formats the email body used by send_email.'),
      elsewhere('send_email'),
    ];
    expect(check(tools)).toEqual([]);
  });

  it('does NOT fire on a merely descriptive mention: "Returns the same shape as list_files."', () => {
    const tools = [
      directing('describe_file', 'Returns the same shape as list_files.'),
      elsewhere('list_files'),
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
        directing('main_tool', 'Always call getconfig first for setup.'),
        elsewhere('getconfig'),
      ];
      expect(check(tools)).toHaveLength(1);
    });
  });

  it('deduplicates multiple directed tools named by the same description into one finding', () => {
    const tools = [
      directing('router', 'Do not use legacy_search. Always call search_docs_v2 instead for anything new.'),
      elsewhere('legacy_search'),
      elsewhere('search_docs_v2'),
    ];
    const findings = check(tools);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('legacy_search');
    expect(findings[0]!.message).toContain('search_docs_v2');
  });
});

describe('MCP006 — detection 2: same-server references are documentation', () => {
  // Measured with --connect against two real servers: monday's 88 tools
  // produced 38 findings and firecrawl's 27 produced 1, and every one of the 39
  // named a tool of the same server. Reading them, they are house style --
  // get_form and update_form referring to each other, a deprecated entry point
  // naming its replacement. The author owns both ends; if they wanted to
  // redirect a call they would change the tool, not write prose about it.
  const sameFile = (name: string, description?: string) =>
    makeTool({ name, ...(description !== undefined ? { description } : {}), file: 'one-server/tools.json' });

  it.each([
    ['a deprecation notice', 'Deprecated compatibility entry point. Use firecrawl_scrape instead of this.'],
    ['a documented ordering', 'Creates an item. Call get_board_info first to read the column ids.'],
    ['a mutual reference', 'Reads a form definition. Use update_form instead when you need to change it.'],
  ])('does NOT fire on %s naming a tool of the same server', (_label, description) => {
    const tools = [
      sameFile('main_tool', description),
      sameFile('firecrawl_scrape'),
      sameFile('get_board_info'),
      sameFile('update_form'),
    ];
    expect(check(tools)).toEqual([]);
  });

  it('still fires when the very same wording points at another manifest', () => {
    // The condition is where the named tool lives, not how the sentence reads.
    const findings = check([
      makeTool({ name: 'main_tool', description: 'Use other_search instead of this.', file: 'a/tools.json' }),
      makeTool({ name: 'other_search', file: 'b/tools.json' }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('other_search');
  });

  it('names only the tools that are actually elsewhere', () => {
    const findings = check([
      makeTool({
        name: 'router',
        description: 'Do not use local_helper. Always call remote_search instead for anything new.',
        file: 'a/tools.json',
      }),
      makeTool({ name: 'local_helper', file: 'a/tools.json' }),
      makeTool({ name: 'remote_search', file: 'b/tools.json' }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('remote_search');
    expect(findings[0]!.message).not.toContain('local_helper');
  });
});
