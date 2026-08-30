import { parseTree, findNodeAtLocation, getNodeValue, type Node } from 'jsonc-parser';
import { makeLocation, createLineIndex, formatJsonPath } from '../core/location.js';
import { createLocator } from './mcp-manifest.js';
import type { ServerDefinition, SourceLocation } from '../core/types.js';

/**
 * Accepted root keys for a client config file. `mcpServers` is the
 * Claude Desktop / Claude Code convention; `servers` is used by some
 * other clients (e.g. VS Code's `.vscode/mcp.json`). Checked in this
 * order — the first one present in the document wins.
 */
const ROOT_KEYS = ['mcpServers', 'servers'] as const;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function detectTransport(value: Record<string, unknown>): ServerDefinition['transport'] {
  const url = value['url'];
  if (typeof url === 'string' && url.length > 0) {
    return url.includes('/sse') ? 'sse' : 'http';
  }
  if (typeof value['command'] === 'string' && value['command'].length > 0) {
    return 'stdio';
  }
  return 'unknown';
}

/**
 * `collectMcpConfig(file, text)` — same shape/contract as `collectManifest`:
 * no I/O, returns `[]` on any parse failure rather than throwing.
 *
 * Parses the standard MCP client config shape (`{"mcpServers": {...}}` or
 * `{"servers": {...}}`), one `ServerDefinition` per entry, with `loc()`
 * resolving to real file positions via `jsonc-parser` + `makeLocation`,
 * exactly as `collectManifest` does for tools.
 */
export function collectMcpConfig(file: string, text: string): ServerDefinition[] {
  let root: Node | undefined;
  try {
    root = parseTree(text);
  } catch {
    return [];
  }
  if (!root) return [];

  let rootKey: (typeof ROOT_KEYS)[number] | undefined;
  let serversNode: Node | undefined;
  for (const key of ROOT_KEYS) {
    const node = findNodeAtLocation(root, [key]);
    if (node && node.type === 'object') {
      rootKey = key;
      serversNode = node;
      break;
    }
  }
  if (!rootKey || !serversNode) return [];

  const lineStarts = createLineIndex(text);
  const servers: ServerDefinition[] = [];
  for (const property of serversNode.children ?? []) {
    // An object's children are `property` nodes: children[0] = key, children[1] = value.
    const [keyNode, valueNode] = property.children ?? [];
    if (!keyNode || !valueNode) continue;

    const name = String(getNodeValue(keyNode));
    const value = getNodeValue(valueNode) as unknown;
    if (!isPlainObject(value)) continue; // a server entry that isn't an object is skipped, not thrown on

    // Segments, never a joined string: a server named `awslabs.mysql-mcp-server`
    // is one key, and re-splitting `mcpServers.awslabs.mysql-mcp-server` by dot
    // would make it two that address nothing. See `ToolDefinition.loc`.
    const base = [rootKey, name] as const;
    const origin = makeLocation(file, text, valueNode.offset, valueNode.length, formatJsonPath(base), lineStarts);
    const locate = createLocator(file, text, root!, lineStarts, base);

    const command = typeof value['command'] === 'string' ? value['command'] : undefined;
    const args = Array.isArray(value['args'])
      ? value['args'].filter((a): a is string => typeof a === 'string')
      : undefined;
    const env = isPlainObject(value['env'])
      ? (Object.fromEntries(
          Object.entries(value['env']).filter((e): e is [string, string] => typeof e[1] === 'string'),
        ) as Record<string, string>)
      : undefined;
    const url = typeof value['url'] === 'string' ? value['url'] : undefined;

    servers.push({
      name,
      transport: detectTransport(value),
      ...(command !== undefined ? { command } : {}),
      ...(args !== undefined ? { args } : {}),
      ...(env !== undefined ? { env } : {}),
      ...(url !== undefined ? { url } : {}),
      tools: [],
      origin,
      loc: (p) => locate(p, origin),
    });
  }
  return servers;
}
