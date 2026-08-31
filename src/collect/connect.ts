import { spawn } from 'node:child_process';
import { collectManifest } from './mcp-manifest.js';
import type { ToolDefinition } from '../core/types.js';

/**
 * `--connect` — start an MCP server and ask it for its tools (docs/SPEC.md §9).
 *
 * ## Why this exists
 *
 * Every other collector reads files. That works for client configs, for
 * `SKILL.md`, and for server source — and it does not work for the thing this
 * scanner is most about. A real MCP server declares its tools **in code**,
 * built at startup from zod or pydantic, so there is no manifest on disk to
 * read. Scanning four real repositories made the size of that hole concrete:
 * `awslabs/mcp`, `mondaycom/mcp` and `firecrawl-mcp-server` each yielded
 * **zero** tools from the filesystem, which meant MCP001–MCP006 — tool
 * poisoning, schema poisoning, tool shadowing, the rules this project leads
 * with — had nothing to run on.
 *
 * Asking the server closes it. `firecrawl-mcp-server` goes from 0 tools to 27,
 * and from no findings to one.
 *
 * ## This runs the target's code
 *
 * Which is why it is a flag and never a default. Starting a server is not
 * reading a file: it executes whatever the command names, with the caller's
 * environment. The flag is the consent, and the report labels every finding
 * that came from it with `provenance: 'live'`.
 *
 * ## Failure is exit 2, never silence
 *
 * A server that will not start, times out, or answers with an error produces
 * an error string here and exit 2 at the CLI — "could not look", never
 * "nothing found" (SPEC §16.6). The alternative, a clean report for a server
 * that never ran, is the exact false-clean this project keeps guarding against.
 */

const PROTOCOL_VERSION = '2025-06-18';
/**
 * Generous on purpose. The clock covers more than the handshake: `npx -y` and
 * `uvx` download the package first, and a cold `npx -y
 * @mondaydotcomorg/monday-api-mcp` blew straight through a 30s budget while npm
 * was still installing -- the scan reported a timeout for a server that had not
 * started yet. Override with `--connect-timeout`.
 */
const DEFAULT_TIMEOUT_MS = 120_000;

interface JsonRpcMessage {
  id?: number;
  result?: { serverInfo?: { name?: string }; tools?: unknown[] };
  error?: { code?: number; message?: string };
}

export interface ConnectOptions {
  /** The command line that starts the server, e.g. `npx -y firecrawl-mcp`. */
  command: string;
  timeoutMs?: number;
}

export interface ConnectResult {
  tools: ToolDefinition[];
  /** The name the server reported at `initialize`, not one this scanner invents. */
  serverName: string;
  /** The synthetic document the tools were collected from, for the report. */
  file: string;
}

/**
 * Reads newline-delimited JSON-RPC out of a stream chunk, returning complete
 * messages and whatever partial line is left over.
 *
 * Split out and exported because it is the part with edge cases — a message
 * arriving in two chunks, several in one — and the part that can be tested
 * without starting anything.
 */
export function readMessages(buffer: string): { messages: JsonRpcMessage[]; rest: string } {
  const messages: JsonRpcMessage[] = [];
  let rest = buffer;

  for (;;) {
    const nl = rest.indexOf('\n');
    if (nl < 0) break;
    const line = rest.slice(0, nl).trim();
    rest = rest.slice(nl + 1);
    if (line.length === 0) continue;
    try {
      messages.push(JSON.parse(line) as JsonRpcMessage);
    } catch {
      // A server that writes a banner or a warning to stdout is not an error:
      // skip the line and keep reading for the response.
    }
  }
  return { messages, rest };
}

/**
 * Turns a `tools/list` result into `ToolDefinition`s by rendering it as the
 * manifest it would be and handing that to the existing collector.
 *
 * Reusing `collectManifest` rather than mapping the array by hand is what
 * gives live tools real line and column numbers — positions inside the
 * document the server just returned — and it means a live tool and a
 * file-based tool are the same shape to every rule, with no second code path
 * to keep in step.
 */
export function toolsFromListResult(tools: unknown[], serverName: string): ConnectResult {
  // Distinctive on purpose: it must never collide with a real path, because
  // MCP006 treats one file as one deployment.
  const file = `connect:${serverName}/tools.json`;
  const text = JSON.stringify({ name: serverName, tools }, null, 2);
  return { tools: collectManifest(file, text), serverName, file };
}

/**
 * Starts the server, speaks the handshake, and returns its tools — or an error
 * string describing what went wrong.
 */
export async function connectAndListTools(opts: ConnectOptions): Promise<ConnectResult | string> {
  const argv = opts.command.trim().split(/\s+/);
  const program = argv[0];
  if (program === undefined || program.length === 0) return '--connect needs a command to run';

  const child = spawn(program, argv.slice(1), {
    stdio: ['pipe', 'pipe', 'pipe'],
    // `npx` and friends are batch files on Windows and are not directly
    // executable; the server inherits this process's environment either way,
    // which is how a real client passes it an API key.
    shell: process.platform === 'win32',
  });

  const pending = new Map<number, (m: JsonRpcMessage) => void>();
  let buffer = '';
  let stderr = '';
  let spawnError: string | undefined;

  child.on('error', (err) => { spawnError = err.message; });
  child.stderr.on('data', (c: Buffer) => { stderr += c.toString('utf8'); });
  child.stdout.on('data', (c: Buffer) => {
    const { messages, rest } = readMessages(buffer + c.toString('utf8'));
    buffer = rest;
    for (const m of messages) {
      if (m.id === undefined) continue;
      const resolve = pending.get(m.id);
      if (resolve) { pending.delete(m.id); resolve(m); }
    }
  });

  const send = (id: number | null, method: string, params: unknown): Promise<JsonRpcMessage> => {
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', ...(id === null ? {} : { id }), method, params })}\n`);
    if (id === null) return Promise.resolve({});
    return new Promise((resolve) => pending.set(id, resolve));
  };

  const failed = new Promise<string>((resolve) => {
    const timer = setTimeout(
      () => resolve(timeoutMessage(opts.command, opts.timeoutMs ?? DEFAULT_TIMEOUT_MS, stderr)),
      opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    );
    timer.unref?.();
    // `close`, not `exit`: `exit` fires when the process ends, before its stdio
    // streams have finished flushing, so the stderr that explains *why* it died
    // is often still empty. That is the whole value of the message — a server
    // that quits over a missing API key says so on stderr and nowhere else.
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve(exitMessage(opts.command, code, spawnError, stderr));
    });
  });

  try {
    const init = await Promise.race([send(1, 'initialize', {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'mcpscan', version: '0' },
    }), failed]);
    if (typeof init === 'string') return init;
    if (init.error) return `${opts.command} rejected initialize: ${init.error.message ?? 'unknown error'}`;

    await send(null, 'notifications/initialized', {});

    const list = await Promise.race([send(2, 'tools/list', {}), failed]);
    if (typeof list === 'string') return list;
    if (list.error) return `${opts.command} rejected tools/list: ${list.error.message ?? 'unknown error'}`;

    const tools = list.result?.tools;
    if (!Array.isArray(tools)) return `${opts.command} answered tools/list without a "tools" array`;

    return toolsFromListResult(tools, init.result?.serverInfo?.name ?? opts.command);
  } finally {
    child.kill();
  }
}

function withStderr(message: string, stderr: string): string {
  const tail = stderr.trim().split('\n').slice(-3).join(' | ').slice(0, 300);
  return tail.length > 0 ? `${message}. Server stderr: ${tail}` : message;
}

function timeoutMessage(command: string, ms: number, stderr: string): string {
  return withStderr(`${command} did not answer within ${ms / 1000}s`, stderr);
}

function exitMessage(command: string, code: number | null, spawnError: string | undefined, stderr: string): string {
  if (spawnError !== undefined) return withStderr(`could not start ${command}: ${spawnError}`, stderr);
  return withStderr(`${command} exited (code ${code ?? 'unknown'}) before answering`, stderr);
}
