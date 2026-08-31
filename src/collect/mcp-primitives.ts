import { parseTree, findNodeAtLocation, getNodeValue, type Node } from 'jsonc-parser';
import { makeLocation, createLineIndex, formatJsonPath } from '../core/location.js';
import { createLocator } from './mcp-manifest.js';
import type { PromptDefinition, ResourceDefinition } from '../core/types.js';

/**
 * The other two MCP primitives, read from a manifest.
 *
 * MCP has three: tools, **resources** and **prompts**. Until the recall corpus
 * measured it (docs/SPEC.md §8.5) this scanner collected only the first, which
 * is not a missing rule but two thirds of the protocol going unexamined. DVMCP
 * challenge 1 puts its entire vulnerability in resources — an
 * `internal://credentials` entry kept out of the listing, and a
 * `notes://{user_id}` template interpolating caller input into a URI — and no
 * rule over tools could have seen either.
 *
 * These are separate functions rather than a generalised `collectPrimitive`
 * because the three shapes genuinely differ: a tool has an `inputSchema`, a
 * resource has a `uri` and a `mimeType`, a prompt has an `arguments` list. What
 * they share — locating a field inside the document — is already shared, via
 * `createLocator`.
 *
 * Same contract as every other collector: text in, structure out, no I/O, and
 * `[]` rather than a throw when the document is not what it claimed.
 */

/** Accepted root keys, in the shape a captured `resources/list` produces. */
const RESOURCE_KEYS = ['resources', 'resourceTemplates'] as const;

function parse(text: string): Node | undefined {
  try {
    return parseTree(text);
  } catch {
    return undefined;
  }
}

/** The manifest's own declared `name`, when it has one. */
function declaredServerName(root: Node): string | undefined {
  const node = findNodeAtLocation(root, ['name']);
  return node && node.type === 'string' ? (getNodeValue(node) as string) : undefined;
}

/**
 * Resources and resource templates from one document.
 *
 * Both root keys are read, and both produce `ResourceDefinition`s: they are two
 * calls in the protocol (`resources/list`, `resources/templates/list`) but the
 * same kind of thing to a rule. `isTemplate` keeps them distinguishable, which
 * matters because a template's uri carries `{placeholders}` a caller fills — a
 * parameterised surface, where a plain resource's uri is fixed.
 */
export function collectResources(file: string, text: string): ResourceDefinition[] {
  const root = parse(text);
  if (!root) return [];

  const serverName = declaredServerName(root);
  const lineStarts = createLineIndex(text);
  const out: ResourceDefinition[] = [];

  for (const key of RESOURCE_KEYS) {
    const node = findNodeAtLocation(root, [key]);
    if (!node || node.type !== 'array') continue;
    const isTemplate = key === 'resourceTemplates';

    (node.children ?? []).forEach((child, i) => {
      const value = getNodeValue(child) as Record<string, unknown> | undefined;
      if (!value || typeof value !== 'object') return;

      // A template names its uri `uriTemplate`; a plain resource, `uri`.
      const uri = typeof value['uriTemplate'] === 'string'
        ? value['uriTemplate']
        : typeof value['uri'] === 'string' ? value['uri'] : undefined;
      if (uri === undefined) return; // a resource with no uri addresses nothing

      const base = [key, i] as const;
      const origin = makeLocation(file, text, child.offset, child.length, formatJsonPath(base), lineStarts);
      const locate = createLocator(file, text, root, lineStarts, base);

      out.push({
        uri,
        name: typeof value['name'] === 'string' ? value['name'] : uri,
        ...(typeof value['description'] === 'string' ? { description: value['description'] } : {}),
        ...(typeof value['mimeType'] === 'string' ? { mimeType: value['mimeType'] } : {}),
        ...(isTemplate ? { isTemplate: true } : {}),
        ...(serverName !== undefined ? { serverName } : {}),
        origin,
        loc: (p) => locate(p, origin),
      });
    });
  }

  return out;
}

/** Prompts from one document, in the shape a captured `prompts/list` produces. */
export function collectPrompts(file: string, text: string): PromptDefinition[] {
  const root = parse(text);
  if (!root) return [];

  const promptsNode = findNodeAtLocation(root, ['prompts']);
  if (!promptsNode || promptsNode.type !== 'array') return [];

  const serverName = declaredServerName(root);
  const lineStarts = createLineIndex(text);
  const out: PromptDefinition[] = [];

  (promptsNode.children ?? []).forEach((child, i) => {
    const value = getNodeValue(child) as Record<string, unknown> | undefined;
    if (!value || typeof value !== 'object') return;
    if (typeof value['name'] !== 'string') return; // a prompt is addressed by name

    const base = ['prompts', i] as const;
    const origin = makeLocation(file, text, child.offset, child.length, formatJsonPath(base), lineStarts);
    const locate = createLocator(file, text, root, lineStarts, base);

    const args = Array.isArray(value['arguments'])
      ? value['arguments']
          .filter((a): a is Record<string, unknown> => a !== null && typeof a === 'object')
          .filter((a) => typeof a['name'] === 'string')
          .map((a) => ({
            name: a['name'] as string,
            ...(typeof a['description'] === 'string' ? { description: a['description'] } : {}),
            ...(typeof a['required'] === 'boolean' ? { required: a['required'] } : {}),
          }))
      : undefined;

    out.push({
      name: value['name'],
      ...(typeof value['description'] === 'string' ? { description: value['description'] } : {}),
      ...(args !== undefined && args.length > 0 ? { arguments: args } : {}),
      ...(serverName !== undefined ? { serverName } : {}),
      origin,
      loc: (p) => locate(p, origin),
    });
  });

  return out;
}
