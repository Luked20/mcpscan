#!/usr/bin/env node
/**
 * Regenerates the regression corpus in `tests/corpus/` (docs/SPEC.md §8.2).
 *
 * Two halves, captured two different ways:
 *  - `servers/` — real `tools/list` output from the official MCP reference
 *    servers, obtained by starting each one and asking it (see below).
 *  - `skills/`  — real `SKILL.md` files from `anthropics/skills`, downloaded
 *    verbatim at a pinned commit. Nothing is executed for these.
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
 * Agent skills, pinned to an exact commit for the same reason the server
 * packages are pinned to an exact version: the corpus must not change under
 * the test without someone deciding that it should.
 */
const SKILLS_REPO = 'anthropics/skills';
const SKILLS_COMMIT = '3b3fad96af16a10759d930941b4520ba0c40edae';
const SKILLS = [
  'academy-guide', 'algorithmic-art', 'brand-guidelines', 'canvas-design', 'claude-api',
  'discernment-nudge', 'doc-coauthoring', 'docx', 'frontend-design', 'internal-comms',
  'mcp-builder', 'pdf', 'pptx', 'skill-creator', 'slack-gif-creator', 'theme-factory',
  'web-artifacts-builder', 'webapp-testing', 'xlsx',
];

async function captureSkills() {
  const outDir = join(ROOT, 'tests', 'corpus', 'skills');
  for (const id of SKILLS) {
    const url = `https://raw.githubusercontent.com/${SKILLS_REPO}/${SKILLS_COMMIT}/skills/${id}/SKILL.md`;
    const res = await fetch(url, { headers: { 'user-agent': 'mcpscan-corpus' } });
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
    const text = await res.text();
    const dir = join(outDir, id);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'SKILL.md'), text, 'utf8');
    console.log(`${id}: ${text.length} bytes -> tests/corpus/skills/${id}/SKILL.md`);
  }
  writeFileSync(join(outDir, 'PROVENANCE.txt'),
    `${SKILLS_REPO}
  commit: ${SKILLS_COMMIT}
  skills: ${SKILLS.join(', ')}
` +
    `  captured: ${new Date().toISOString().slice(0, 10)} by scripts/capture-corpus.mjs
`, 'utf8');
}

const only = process.argv.slice(2);
if (only.length === 0 || only.includes('skills')) await captureSkills();

const selected = only.length > 0 ? SERVERS.filter((s) => only.includes(s.id)) : SERVERS;
if (only.length > 0 && selected.length === 0 && !only.includes('skills')) {
  console.error(`no server matched ${JSON.stringify(only)}. Known: ${SERVERS.map((s) => s.id).join(', ')}, skills`);
  process.exit(2);
}
for (const server of selected) {
  await capture(server);
}
