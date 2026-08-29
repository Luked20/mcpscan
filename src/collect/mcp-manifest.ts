import { parseTree, findNodeAtLocation, getNodeValue, type Node } from 'jsonc-parser';
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
      origin,
      loc: (p: string) => locate(p, origin),
    });
  });
  return tools;
}
