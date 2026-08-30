import { parseTree, findNodeAtLocation, getNodeValue, type Node } from 'jsonc-parser';
import { basename, dirname, extname } from 'node:path/posix';
import { makeLocation, createLineIndex } from '../core/location.js';
import type { ToolDefinition, SourceLocation } from '../core/types.js';

/**
 * 'tools[0].inputSchema.properties.path' -> ['tools', 0, 'inputSchema', 'properties', 'path']
 *
 * Fails closed: anything that doesn't match in full returns `null`, so the
 * caller falls back to `origin`. Returning a *partial* path was worse than
 * locating nothing — 'tools[0].name[' became ['tools', 0], and the finding showed
 * up at the position of the entire `tools[0]` object stamped with the wrong
 * jsonPath: plausible, authoritative-looking in SARIF, and wrong.
 *
 * Known limitation (left unresolved on purpose): a legal JSON key containing a
 * dot — `properties["my.path"]`, common in path schemas — gets split incorrectly
 * and simply fails to resolve, falling back to `origin`.
 */
export function parseJsonPath(path: string): (string | number)[] | null {
  if (path === '') return null;
  const out: (string | number)[] = [];
  for (const part of path.split('.')) {
    const m = /^([^[\]]*)((?:\[\d+\])*)$/.exec(part);
    if (!m) return null;
    const [, key = '', brackets = ''] = m;
    if (key) out.push(key);
    for (const i of brackets.matchAll(/\[(\d+)\]/g)) out.push(Number(i[1]));
    // An empty segment ('a..b', or '.' itself) produces nothing: invalid path.
    if (!key && !brackets) return null;
  }
  return out.length > 0 ? out : null;
}

/**
 * `ToolDefinition.serverName` — MCP006 needs to tell "the same tool name from
 * two different servers" apart from "the same tool listed twice in one file".
 *
 * Rule: if the manifest declares a root-level string `name` (the convention
 * an MCP server's own manifest uses to name itself), that wins, and
 * `serverNameSource` is `'declared'`. Otherwise the *containing directory* of
 * the file stands in for the server, purely for display — manifests are
 * conventionally laid out one directory per server (`server-a/tools.json`,
 * `server-b/tools.json`). When the file sits at the scan root (no containing
 * directory to use — `dirname` is `'.'`, including the single-file-scan case
 * where `file` is just a basename), fall back to the file's own basename with
 * its extension stripped, so `tools.json` at the root still yields a stable,
 * non-empty name (`"tools"`) rather than the meaningless `'.'`.
 *
 * A *derived* name is a guess this scanner made, not a claim the manifest
 * author made: two unrelated directories that both happen to contain a
 * `tools.json` are not evidence that any client loads both together. MCP006
 * detection 1 relies on `serverNameSource` to ignore derived names entirely —
 * see the field's doc comment on `ToolDefinition` in `core/types.ts`.
 */
function deriveServerName(file: string, rootName: string | undefined): { name: string; source: 'declared' | 'derived' } {
  if (rootName !== undefined && rootName.length > 0) return { name: rootName, source: 'declared' };
  const dir = dirname(file);
  if (dir !== '.') return { name: dir, source: 'derived' };
  return { name: basename(file, extname(file)), source: 'derived' };
}

export function collectManifest(file: string, text: string): ToolDefinition[] {
  let root: Node | undefined;
  try {
    root = parseTree(text);
  } catch {
    return [];
  }
  if (!root) return [];

  const toolsNode = findNodeAtLocation(root, ['tools']);
  if (!toolsNode || toolsNode.type !== 'array') return [];

  const nameNode = findNodeAtLocation(root, ['name']);
  const rootName = nameNode && nameNode.type === 'string' ? (getNodeValue(nameNode) as string) : undefined;
  const { name: serverName, source: serverNameSource } = deriveServerName(file, rootName);

  const lineStarts = createLineIndex(text);
  const locate = (jsonPath: string, fallback: SourceLocation): SourceLocation => {
    const segments = parseJsonPath(jsonPath);
    if (!segments) return fallback;
    const node = findNodeAtLocation(root!, segments);
    if (!node) return fallback;
    return makeLocation(file, text, node.offset, node.length, jsonPath, lineStarts);
  };

  const tools: ToolDefinition[] = [];
  (toolsNode.children ?? []).forEach((child, i) => {
    const value = getNodeValue(child) as Record<string, unknown> | undefined;
    if (!value || typeof value !== 'object') return;
    const origin = makeLocation(file, text, child.offset, child.length, `tools[${i}]`, lineStarts);
    tools.push({
      name: typeof value['name'] === 'string' ? value['name'] : `<unnamed #${i}>`,
      ...(typeof value['description'] === 'string' ? { description: value['description'] } : {}),
      ...(value['inputSchema'] !== undefined ? { inputSchema: value['inputSchema'] } : {}),
      serverName,
      serverNameSource,
      origin,
      loc: (p: string) => locate(p, origin),
    });
  });
  return tools;
}
