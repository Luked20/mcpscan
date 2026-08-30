/**
 * Walks a JSON Schema (a tool's `inputSchema`) and collects every free-text
 * string, with the jsonPath that locates it. Used by MCP003 to run the
 * shared injection detector (`patterns.ts`) against schema fields, not just
 * `description`.
 *
 * A JSON Schema mixes three kinds of key:
 *  - TEXT_KEYS: free text meant for a human/model reader (`description`,
 *    `title`, `default`, `const`, `examples`, `enum`, `$comment`). Every
 *    string reachable under one of these, however deeply nested, is emitted.
 *  - CONTAINER_KEYS: a map from an ARBITRARY NAME to a nested schema node
 *    (`properties`, `$defs`, `definitions`, `patternProperties`). The map's
 *    own keys are identifiers, not text and not structure — they are never
 *    checked against TEXT_KEYS. Without this distinction, a tool parameter
 *    literally named "description" (a perfectly ordinary name, e.g. an
 *    issue-creation tool's own `description` input) would have its ENTIRE
 *    nested schema treated as free text, including its `type` field.
 *  - Everything else (`type`, `required`, `items`, `additionalProperties`,
 *    `anyOf`/`oneOf`/`allOf`, ...) is structural: walked to find nested
 *    schema nodes, but never itself emitted as text.
 */

export interface SchemaStringHit {
  /**
   * Path segments relative to the tool, ready to hand to `tool.loc()`.
   *
   * Segments rather than a dotted string because a schema property may legally
   * be named with a dot in it (`properties["my.path"]`, ordinary in path
   * schemas), and a joined path cannot be split back into the right segments.
   */
  path: (string | number)[];
  value: string;
}

const TEXT_KEYS = new Set(['description', 'title', 'default', 'const', 'examples', 'enum', '$comment']);

/** Keys whose object value maps an arbitrary name -> a nested schema node. */
const CONTAINER_KEYS = new Set(['properties', '$defs', 'definitions', 'patternProperties']);

/**
 * Guards a pathological, non-cyclic schema (e.g. thousands of levels of
 * nested `properties`) from exhausting the call stack. No legitimate
 * `inputSchema` nests anywhere close to this deep.
 */
const MAX_DEPTH = 200;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

export function walkSchemaStrings(node: unknown, basePath: readonly (string | number)[]): SchemaStringHit[] {
  const out: SchemaStringHit[] = [];
  const seen = new WeakSet<object>();

  function visit(value: unknown, path: (string | number)[], depth: number, textMode: boolean): void {
    if (depth > MAX_DEPTH) return;
    if (value === null || value === undefined) return;

    if (typeof value === 'string') {
      if (textMode) out.push({ path, value });
      return;
    }
    if (typeof value !== 'object') return; // number, boolean

    const obj = value as object;
    if (seen.has(obj)) return;
    seen.add(obj);

    if (Array.isArray(value)) {
      value.forEach((item, i) => visit(item, [...path, i], depth + 1, textMode));
      return;
    }

    const record = value as Record<string, unknown>;

    // Already inside a TEXT_KEY's value: every string reachable here is free
    // text, regardless of what its own keys are named (e.g. an object inside
    // `default` legitimately has arbitrary keys).
    if (textMode) {
      for (const [key, v] of Object.entries(record)) {
        visit(v, [...path, key], depth + 1, true);
      }
      return;
    }

    for (const [key, v] of Object.entries(record)) {
      if (CONTAINER_KEYS.has(key)) {
        if (isPlainObject(v) && !seen.has(v)) {
          seen.add(v);
          for (const [name, schemaNode] of Object.entries(v)) {
            visit(schemaNode, [...path, key, name], depth + 1, false);
          }
        }
        continue;
      }
      visit(v, [...path, key], depth + 1, TEXT_KEYS.has(key));
    }
  }

  visit(node, [...basePath], 0, false);
  return out;
}
