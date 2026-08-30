import { parseTree, findNodeAtLocation, getNodeValue, type Node } from 'jsonc-parser';
import { basename, dirname, extname } from 'node:path/posix';
import { makeLocation, createLineIndex, formatJsonPath } from '../core/location.js';
import type { ToolDefinition, SourceLocation } from '../core/types.js';

/**
 * Builds the `loc()` a collected subject carries.
 *
 * `base` is the subject's own path segments (`['tools', 3]`, or
 * `['mcpServers', 'awslabs.mysql-mcp-server']`), known here because this is the
 * code that walked the document to find it. Callers pass only the segments
 * *below* that, so a rule never restates — or re-parses — a path it did not
 * build.
 *
 * Fails closed: a path that does not resolve returns `fallback` (the subject's
 * own location). Pointing at the parent is a coarser answer; pointing at a
 * position derived from a half-parsed path would be a wrong one, stamped
 * authoritatively into SARIF.
 */
export function createLocator(
  file: string,
  text: string,
  root: Node,
  lineStarts: number[],
  base: readonly (string | number)[],
): (path: readonly (string | number)[], fallback: SourceLocation) => SourceLocation {
  return (path, fallback) => {
    const segments = [...base, ...path];
    const node = findNodeAtLocation(root, segments as (string | number)[]);
    if (!node) return fallback;
    return makeLocation(file, text, node.offset, node.length, formatJsonPath(segments), lineStarts);
  };
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

  const tools: ToolDefinition[] = [];
  (toolsNode.children ?? []).forEach((child, i) => {
    const value = getNodeValue(child) as Record<string, unknown> | undefined;
    if (!value || typeof value !== 'object') return;
    const base = ['tools', i] as const;
    const origin = makeLocation(file, text, child.offset, child.length, formatJsonPath(base), lineStarts);
    const locate = createLocator(file, text, root!, lineStarts, base);
    tools.push({
      name: typeof value['name'] === 'string' ? value['name'] : `<unnamed #${i}>`,
      ...(typeof value['description'] === 'string' ? { description: value['description'] } : {}),
      ...(value['inputSchema'] !== undefined ? { inputSchema: value['inputSchema'] } : {}),
      serverName,
      serverNameSource,
      origin,
      loc: (p) => locate(p, origin),
    });
  });
  return tools;
}
