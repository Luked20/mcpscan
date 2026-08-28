import { parseTree, findNodeAtLocation, getNodeValue, type Node } from 'jsonc-parser';
import { makeLocation, createLineIndex } from '../core/location.js';
import type { ToolDefinition, SourceLocation } from '../core/types.js';

/**
 * 'tools[0].inputSchema.properties.path' -> ['tools', 0, 'inputSchema', 'properties', 'path']
 *
 * Falha fechado: qualquer coisa que não case por inteiro devolve `null`, para o
 * chamador cair no `origin`. Devolver um caminho *parcial* era pior que não
 * localizar nada — 'tools[0].name[' virava ['tools', 0], e o finding aparecia na
 * posição do objeto `tools[0]` inteiro carimbado com o jsonPath errado: plausível,
 * autoritativo no SARIF, e errado.
 *
 * Limitação conhecida (não resolvida de propósito): uma chave JSON legal contendo
 * ponto — `properties["my.path"]`, comum em schemas de path — é dividida errado e
 * simplesmente não resolve, caindo no `origin`.
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
    // Um segmento vazio ('a..b', ou o próprio '.') não produz nada: caminho inválido.
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
      name: typeof value['name'] === 'string' ? value['name'] : `<sem nome #${i}>`,
      ...(typeof value['description'] === 'string' ? { description: value['description'] } : {}),
      ...(value['inputSchema'] !== undefined ? { inputSchema: value['inputSchema'] } : {}),
      origin,
      loc: (p: string) => locate(p, origin),
    });
  });
  return tools;
}
