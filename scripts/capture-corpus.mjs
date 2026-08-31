#!/usr/bin/env node
/**
 * Regenerates the regression corpus in `tests/corpus/` (docs/SPEC.md §8.2).
 *
 * Four parts, captured three different ways:
 *  - `servers/` — real `tools/list` output from the official MCP reference
 *    servers, obtained by starting each one and asking it (see below).
 *  - `skills/`  — real `SKILL.md` files from `anthropics/skills`, downloaded
 *    verbatim at a pinned commit. Nothing is executed for these.
 *  - `source/`  — real MCP server *implementations* (TypeScript), downloaded
 *    verbatim at a pinned commit. This is what MCP008 gets measured against.
 *  - `configs/` — real MCP client configuration, for MCP007 and MCP009. Two
 *    provenances, kept distinct because they are not equally strong evidence:
 *    a `.mcp.json` actually committed to a public repository, and install
 *    snippets extracted verbatim from each server's own README — the exact
 *    JSON the vendor tells users to paste into their client config.
 *
 * The corpus has to be *real* manifests, not manifests I wrote: a fixture I
 * author is unconsciously shaped by the rules I'm testing, which is the exact
 * blind spot the corpus exists to cover. The reference servers build their
 * tool schemas at runtime (zod / pydantic), so there is no literal JSON in
 * their source to copy — the only faithful way to get their real `tools/list`
 * output is to ask them for it.
 *
 * So this script starts each server over stdio, speaks the MCP handshake,
 * captures `tools/list` verbatim, and writes it to disk. It is run **by hand,
 * rarely** — the corpus is committed, and `tests/corpus.test.ts` never
 * downloads or executes anything. Committed alongside the corpus so the
 * provenance of every byte in it is auditable and reproducible, rather than
 * being a pile of JSON someone has to take on trust.
 *
 *   node scripts/capture-corpus.mjs            # capture all
 *   node scripts/capture-corpus.mjs memory     # capture one
 *
 * Note this runs third-party code (the official @modelcontextprotocol/*
 * packages, pinned by exact version below). That is why it is a separate,
 * manual script and not part of `npm test`.
 */
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT_DIR = join(ROOT, 'tests', 'corpus', 'servers');

/**
 * Every entry is pinned to an exact version. An unpinned corpus would silently
 * change what the regression test measures the next time someone regenerates it.
 */
const SERVERS = [
  { id: 'memory', pkg: '@modelcontextprotocol/server-memory@2026.7.4', args: [] },
  { id: 'sequential-thinking', pkg: '@modelcontextprotocol/server-sequential-thinking@2026.7.4', args: [] },
  { id: 'everything', pkg: '@modelcontextprotocol/server-everything@2026.8.18', args: [] },
  // Needs an allowed-directory argument to start. The directory is irrelevant to
  // `tools/list` -- it only affects what the tools would be permitted to touch at
  // call time -- so the repo root is passed purely to satisfy argv.
  { id: 'filesystem', pkg: '@modelcontextprotocol/server-filesystem@2026.7.10', args: ['.'] },
];

const PROTOCOL_VERSION = '2025-06-18';

/** Reads newline-delimited JSON-RPC off a stream, dispatching by `id`. */
function createReader(stream, onMessage) {
  let buffer = '';
  stream.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    let nl;
    while ((nl = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (line.length === 0) continue;
      try {
        onMessage(JSON.parse(line));
      } catch {
        // A server that writes non-JSON to stdout (a banner, a warning) is not
        // an error here -- skip the line and keep reading for the response.
      }
    }
  });
}

async function capture({ id, pkg, args }) {
  const child = spawn('npx', ['-y', pkg, ...args], {
    stdio: ['pipe', 'pipe', 'pipe'],
    shell: process.platform === 'win32',
  });

  const pending = new Map();
  const send = (id, method, params) => {
    const msg = { jsonrpc: '2.0', ...(id === null ? {} : { id }), method, params };
    child.stdin.write(`${JSON.stringify(msg)}\n`);
    if (id === null) return Promise.resolve();
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
    });
  };

  createReader(child.stdout, (msg) => {
    const entry = pending.get(msg.id);
    if (!entry) return;
    pending.delete(msg.id);
    if (msg.error) entry.reject(new Error(`${msg.error.code}: ${msg.error.message}`));
    else entry.resolve(msg.result);
  });

  let stderr = '';
  child.stderr.on('data', (c) => { stderr += c.toString('utf8'); });

  const timeout = setTimeout(() => {
    child.kill();
    for (const { reject } of pending.values()) {
      reject(new Error(`timed out waiting for ${pkg}. stderr:\n${stderr}`));
    }
    pending.clear();
  }, 120_000);

  try {
    const init = await send(1, 'initialize', {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'mcpscan-corpus', version: '0' },
    });
    await send(null, 'notifications/initialized', {});
    const list = await send(2, 'tools/list', {});

    // The server's own reported name, not one this script invents -- it becomes
    // the manifest's root `"name"`, which is what makes MCP006 treat it as a
    // *declared* server identity rather than a directory-derived guess.
    const name = init?.serverInfo?.name ?? id;
    const manifest = { name, tools: list.tools };

    const dir = join(OUT_DIR, id);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'tools.json'), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');

    // Provenance next to the data: which package, which version, when.
    const meta = { id, package: pkg, args, serverInfo: init?.serverInfo, capturedAt: new Date().toISOString().slice(0, 10), protocolVersion: PROTOCOL_VERSION };
    writeFileSync(join(dir, 'PROVENANCE.txt'),
      `${meta.id}\n  package: ${meta.package}\n  args: ${JSON.stringify(meta.args)}\n` +
      `  serverInfo: ${JSON.stringify(meta.serverInfo)}\n  protocol: ${meta.protocolVersion}\n` +
      `  captured: ${meta.capturedAt} by scripts/capture-corpus.mjs\n`, 'utf8');

    console.log(`${id}: ${list.tools.length} tool(s) from ${name} -> tests/corpus/servers/${id}/tools.json`);
  } finally {
    clearTimeout(timeout);
    child.kill();
  }
}

/**
 * Agent skills, pinned to exact commits for the same reason the server packages
 * are pinned to exact versions: the corpus must not change under the test
 * without someone deciding that it should.
 *
 * Two vendors on purpose. The anthropics set is large but written by one
 * organisation in one house style, which is a narrow sample for prose-heavy
 * rules. The monday set is a second voice — and it earned its place: all five
 * SKILL003 findings on it were false, one detector reading markdown
 * blockquotes and `<placeholder>` syntax as shell redirects.
 */
const SKILL_SOURCES = [
  {
    prefix: "",
    repo: "anthropics/skills",
    commit: "3b3fad96af16a10759d930941b4520ba0c40edae",
    path: (id) => `skills/${id}/SKILL.md`,
    ids: [
      "academy-guide", "algorithmic-art", "brand-guidelines", "canvas-design", "claude-api",
      "discernment-nudge", "doc-coauthoring", "docx", "frontend-design", "internal-comms",
      "mcp-builder", "pdf", "pptx", "skill-creator", "slack-gif-creator", "theme-factory",
      "web-artifacts-builder", "webapp-testing", "xlsx",
    ],
  },
  {
    prefix: "monday-",
    repo: "mondaycom/mcp",
    commit: "8ca3cbaa4c8f3094e8da7676f3335735c065548a",
    path: (id) => `plugins/monday-crm/skills/${id}/SKILL.md`,
    ids: [
      "activity-insights", "automate-crm", "daily-briefing", "data-cleanup", "forecast",
      "log-activity", "meeting-to-deal", "run-sequence", "workspace-builder",
    ],
  },
];

async function captureSkills() {
  const outDir = join(ROOT, "tests", "corpus", "skills");
  const provenance = [];

  for (const source of SKILL_SOURCES) {
    for (const id of source.ids) {
      const text = await download(raw(source.repo, source.commit, source.path(id)));
      const dir = join(outDir, source.prefix + id);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "SKILL.md"), text, "utf8");
      console.log(`${source.prefix}${id}: ${text.length} bytes -> tests/corpus/skills/${source.prefix}${id}/SKILL.md`);
    }
    provenance.push(
      source.repo,
      `  commit: ${source.commit}`,
      `  skills: ${source.ids.map((i) => source.prefix + i).join(", ")}`,
      "",
    );
  }

  provenance.push(`captured: ${new Date().toISOString().slice(0, 10)} by scripts/capture-corpus.mjs`, "");
  writeFileSync(join(outDir, 'PROVENANCE.txt'), provenance.join('\n'), 'utf8');
}

/**
 * The reference-server monorepo, pinned. Everything below that comes from it —
 * server implementations and README install snippets alike — reads the same
 * commit, so the source and the config that describes it never drift apart.
 */
const SERVERS_REPO = 'modelcontextprotocol/servers';
const SERVERS_COMMIT = 'cda92bdaacd558192fedf1a60d2bb27510792388';

const raw = (repo, commit, path) => `https://raw.githubusercontent.com/${repo}/${commit}/${path}`;

async function download(url) {
  const res = await fetch(url, { headers: { 'user-agent': 'mcpscan-corpus' } });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return res.text();
}

/**
 * Real MCP server implementations — what MCP008 (dangerous execution sinks in
 * server source) gets measured against. Until this existed, MCP008 was the
 * only rule with no real-world input at all: its own fixtures are code I wrote
 * to trip it, which cannot show it firing on code nobody wrote to trip it.
 *
 * `filesystem` is deliberately the largest entry. It is a server whose entire
 * job is touching the filesystem on paths an agent supplies — precisely the
 * shape a sink rule is most likely to over-match on.
 */
const SOURCE_FILES = [
  {
    id: 'filesystem',
    files: [
      'src/filesystem/index.ts', 'src/filesystem/lib.ts', 'src/filesystem/path-utils.ts',
      'src/filesystem/path-validation.ts', 'src/filesystem/roots-utils.ts',
    ],
  },
  { id: 'memory', files: ['src/memory/index.ts'] },
  {
    id: 'sequential-thinking',
    files: ['src/sequentialthinking/index.ts', 'src/sequentialthinking/lib.ts', 'src/sequentialthinking/version.ts'],
  },
  { id: 'everything', files: ['src/everything/index.ts'] },
  // A third-party TypeScript server, and the one that settled how MCP008
  // handles string contents: four of its five findings were sinks named in
  // strings -- test fixture data, a security check, and two warning messages
  // from its own dangerous-pattern validator.
  {
    id: 'n8n',
    repo: 'czlonkowski/n8n-mcp',
    commit: 'f895e5ecc732aed31e2ca9748027034f5b19cccd',
    files: ['src/services/config-validator.ts', 'scripts/test-code-node-enhancements.ts'],
  },
  // Python, for MCP010. The reference servers are split between the two
  // languages, and until these were here MCP010 had no real-world input at
  // all -- the same gap MCP008 had before source/ existed.
  { id: 'git', files: ['src/git/src/mcp_server_git/server.py'] },
  { id: 'fetch', files: ['src/fetch/src/mcp_server_fetch/server.py'] },
  { id: 'time', files: ['src/time/src/mcp_server_time/server.py'] },
];

async function captureSource() {
  const outDir = join(ROOT, 'tests', 'corpus', 'source');
  for (const entry of SOURCE_FILES) {
    const dir = join(outDir, entry.id);
    mkdirSync(dir, { recursive: true });
    const repo = entry.repo ?? SERVERS_REPO;
    const commit = entry.commit ?? SERVERS_COMMIT;
    for (const path of entry.files) {
      const text = await download(raw(repo, commit, path));
      const name = path.slice(path.lastIndexOf('/') + 1);
      writeFileSync(join(dir, name), text, 'utf8');
      console.log(`${entry.id}: ${text.length} bytes -> tests/corpus/source/${entry.id}/${name}`);
    }
    writeFileSync(join(dir, 'PROVENANCE.txt'),
      [
        repo,
        `  commit: ${commit}`,
        ...entry.files.map((f) => `  file:   ${f}`),
        `  captured: ${new Date().toISOString().slice(0, 10)} by scripts/capture-corpus.mjs`,
        '',
      ].join('\n'), 'utf8');
  }
}

/**
 * Real MCP client configuration — what MCP007 (unpinned provenance) and MCP009
 * (credentials in config) get measured against.
 *
 * Two provenances, and the difference matters enough to keep them labelled:
 *
 *  - `file`: a config actually committed to a public repository. The strongest
 *    evidence there is, and also the rarest — a client config is normally
 *    per-developer and gitignored, which is why only one entry has it.
 *  - `readme`: the install snippet published in a server's own README. Not
 *    found in the wild, but not invented either: it is the exact JSON the
 *    vendor instructs users to paste into their client config, so it is what
 *    real config files end up containing.
 *
 * A README entry selects its block by a substring rather than an index, so the
 * choice is legible here and does not silently pick a different block if the
 * document is reordered.
 */
const CONFIGS = [
  {
    id: 'mcp-docs', kind: 'file', filename: '.mcp.json',
    repo: SERVERS_REPO, commit: SERVERS_COMMIT, path: '.mcp.json',
  },
  {
    id: 'filesystem-npx', kind: 'readme', filename: 'claude_desktop_config.json',
    repo: SERVERS_REPO, commit: SERVERS_COMMIT, path: 'src/filesystem/README.md',
    select: '"command": "npx"',
  },
  {
    id: 'filesystem-docker', kind: 'readme', filename: 'claude_desktop_config.json',
    repo: SERVERS_REPO, commit: SERVERS_COMMIT, path: 'src/filesystem/README.md',
    select: '"command": "docker"',
  },
  {
    id: 'memory', kind: 'readme', filename: 'claude_desktop_config.json',
    repo: SERVERS_REPO, commit: SERVERS_COMMIT, path: 'src/memory/README.md',
    select: 'MEMORY_FILE_PATH',
  },
  {
    id: 'everything', kind: 'readme', filename: 'claude_desktop_config.json',
    repo: SERVERS_REPO, commit: SERVERS_COMMIT, path: 'src/everything/README.md',
    select: '"command": "npx"',
  },
  // Third-party, and included specifically because they carry credentials:
  // firecrawl puts a placeholder API key in `env`, tavily puts one in the
  // command's URL. MCP009 must flag neither -- they are placeholders, not keys.
  {
    id: 'firecrawl', kind: 'readme', filename: 'claude_desktop_config.json',
    repo: 'firecrawl/firecrawl-mcp-server', commit: '8c93c5617ed2674e30e8bf828699a59641a3d534',
    path: 'README.md', select: 'FIRECRAWL_API_KEY',
  },
  {
    id: 'tavily', kind: 'readme', filename: 'claude_desktop_config.json',
    repo: 'tavily-ai/tavily-mcp', commit: '248dc9e3e385305ad3281120284ff662af4b5940',
    path: 'README.md', select: 'tavilyApiKey',
  },
];

/** Every fenced ```json block in a markdown document that declares MCP servers. */
function mcpServerBlocks(markdown) {
  const fence = /```json\n([\s\S]*?)```/g;
  return [...markdown.matchAll(fence)].map((m) => m[1]).filter((b) => b.includes('"mcpServers"'));
}

async function captureConfigs() {
  const outDir = join(ROOT, 'tests', 'corpus', 'configs');
  for (const entry of CONFIGS) {
    const url = raw(entry.repo, entry.commit, entry.path);
    const text = await download(url);

    let content;
    if (entry.kind === 'file') {
      content = text;
    } else {
      const blocks = mcpServerBlocks(text);
      const block = blocks.find((b) => b.includes(entry.select));
      if (block === undefined) {
        throw new Error(
          `${entry.id}: no mcpServers block containing ${JSON.stringify(entry.select)} in ${url} ` +
          `(${blocks.length} block(s) found). The README changed -- re-pin the commit or update the selector.`,
        );
      }
      content = block.trimEnd() + '\n';
    }

    const dir = join(outDir, entry.id);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, entry.filename), content, 'utf8');
    writeFileSync(join(dir, 'PROVENANCE.txt'),
      [
        entry.repo,
        `  commit: ${entry.commit}`,
        `  path:   ${entry.path}`,
        entry.kind === 'file'
          ? '  source: the file itself, verbatim -- committed to that repository'
          : `  source: README install snippet, verbatim -- the fenced json block containing ${JSON.stringify(entry.select)}`,
        `  captured: ${new Date().toISOString().slice(0, 10)} by scripts/capture-corpus.mjs`,
        '',
      ].join('\n'), 'utf8');
    console.log(`${entry.id}: ${content.length} bytes -> tests/corpus/configs/${entry.id}/${entry.filename}`);
  }
}

const only = process.argv.slice(2);
if (only.length === 0 || only.includes('skills')) await captureSkills();
if (only.length === 0 || only.includes('source')) await captureSource();
if (only.length === 0 || only.includes('configs')) await captureConfigs();

const GROUPS = ['skills', 'source', 'configs'];
const selected = only.length > 0 ? SERVERS.filter((s) => only.includes(s.id)) : SERVERS;
if (only.length > 0 && selected.length === 0 && !only.some((o) => GROUPS.includes(o))) {
  console.error(
    `nothing matched ${JSON.stringify(only)}. ` +
    `Known servers: ${SERVERS.map((s) => s.id).join(', ')}. Known groups: ${GROUPS.join(', ')}.`,
  );
  process.exit(2);
}
for (const server of selected) {
  await capture(server);
}
