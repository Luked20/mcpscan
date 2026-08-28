import { parseTree, findNodeAtLocation, getNodeValue, type Node } from 'jsonc-parser';
import { makeLocation, createLineIndex } from '../core/location.js';
import type { ToolDefinition, SourceLocation } from '../core/types.js';

/** 'tools[0].inputSchema.properties.path' -> ['tools', 0, 'inputSchema', 'properties', 'path'] */
export function parseJsonPath(path: string): (string | number)[] {
  const out: (string | number)[] = [];
  for (const part of path.split('.')) {
    const m = /^([^[\]]*)((\[\d+\])*)$/.exec(part);
    if (!m) return out;
    if (m[1]) out.push(m[1]);
    for (const i of m[2]!.matchAll(/\[(\d+)\]/g)) out.push(Number(i[1]));
  }
  return out;
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
    const node = findNodeAtLocation(root!, parseJsonPath(jsonPath));
    if (!node) return fallback;
    return makeLocation(file, text, node.offset, node.length, jsonPath, lineStarts);
  };

  const tools: ToolDefinition[] = [];
  (toolsNode.children ?? []).forEach((child, i) => {
    const value = getNodeValue(child) as Record<string, unknown> | undefined;
    if (!value || typeof value !== 'object') return;
    const origin = makeLocation(file, text, child.offset, child.length, `tools[${i}]`, lineStarts);
    tools.push({
      name: typeof value['name'] === 'string' ? value['name'] : `<sem nome #${i}>`,
      ...(typeof value['description'] === 'string' ? { description: value['description'] } : {}),
      ...(value['inputSchema'] !== undefined ? { inputSchema: value['inputSchema'] } : {}),
      origin,
      loc: (p: string) => locate(p, origin),
    });
  });
  return tools;
}
