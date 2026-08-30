import { describe, it, expect } from 'vitest';
import { walkSchemaStrings } from '../../../src/rules/shared/schema-walk.js';
import { formatJsonPath } from '../../../src/core/location.js';

/**
 * The walker returns path *segments*; rendered to the dotted string form here so
 * the assertions below stay readable. Every call in this file walks from the
 * same base, so the helper also drops that repetition.
 */
const walk = (schema: unknown) =>
  walkSchemaStrings(schema, ['inputSchema']).map((h) => ({ path: formatJsonPath(h.path), value: h.value }));

describe('walkSchemaStrings — required cases from the task', () => {
  const schema = {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'the path', default: 'x' },
      mode: { type: 'string', enum: ['r', 'w'] },
    },
  };

  const hits = walk(schema);

  it('finds the description under a nested property', () => {
    expect(hits).toContainEqual({ path: 'inputSchema.properties.path.description', value: 'the path' });
  });

  it('finds the default under a nested property', () => {
    expect(hits).toContainEqual({ path: 'inputSchema.properties.path.default', value: 'x' });
  });

  it('finds an enum entry with its array index', () => {
    expect(hits).toContainEqual({ path: 'inputSchema.properties.mode.enum[0]', value: 'r' });
  });

  it('does not emit structural keys or property names', () => {
    const paths = hits.map((h) => h.path);
    expect(paths).not.toContain('inputSchema.type');
    expect(paths).not.toContain('inputSchema.properties.path.type');
    expect(paths).not.toContain('inputSchema.properties.mode.type');
    // The property names themselves ('path', 'mode') are never emitted as values.
    expect(hits.some((h) => h.value === 'path')).toBe(false);
    expect(hits.some((h) => h.value === 'mode')).toBe(false);
  });
});

describe('walkSchemaStrings — text-bearing keys', () => {
  it.each(['description', 'title', 'default', 'const', '$comment'] as const)(
    'emits a string value under `%s`',
    (key) => {
      const schema = { type: 'string', [key]: 'free text here' };
      const hits = walk(schema);
      expect(hits).toContainEqual({ path: `inputSchema.${key}`, value: 'free text here' });
    },
  );

  it('emits every string entry of an `examples` array', () => {
    const schema = { type: 'string', examples: ['one', 'two'] };
    const hits = walk(schema);
    expect(hits).toContainEqual({ path: 'inputSchema.examples[0]', value: 'one' });
    expect(hits).toContainEqual({ path: 'inputSchema.examples[1]', value: 'two' });
  });

  it('does not emit non-string enum/examples entries, but keeps recursing', () => {
    const schema = { enum: [1, null, true, 'yes'] };
    const hits = walk(schema);
    expect(hits).toEqual([{ path: 'inputSchema.enum[3]', value: 'yes' }]);
  });
});

describe('walkSchemaStrings — structural keys never leak into text', () => {
  it('does not emit anything from `type`, `required`, `properties`, `items`, `additionalProperties`', () => {
    const schema = {
      type: 'object',
      required: ['path'],
      properties: { path: { type: 'string' } },
      items: { type: 'string' },
      additionalProperties: false,
    };
    expect(walk(schema)).toEqual([]);
  });

  it('a property literally named "description" does not turn its whole schema into free text', () => {
    // properties.description is a PARAMETER NAME, not the text-bearing key.
    // Only its own nested `description` field (if any) should be text.
    const schema = {
      type: 'object',
      properties: {
        description: { type: 'string', description: 'the actual field description' },
      },
    };
    const hits = walk(schema);
    expect(hits).toEqual([
      { path: 'inputSchema.properties.description.description', value: 'the actual field description' },
    ]);
  });
});

describe('walkSchemaStrings — nested composition', () => {
  it('walks into nested properties', () => {
    const schema = {
      type: 'object',
      properties: {
        outer: {
          type: 'object',
          properties: {
            inner: { type: 'string', description: 'deep text' },
          },
        },
      },
    };
    const hits = walk(schema);
    expect(hits).toContainEqual({
      path: 'inputSchema.properties.outer.properties.inner.description',
      value: 'deep text',
    });
  });

  it('walks into items (single-schema form)', () => {
    const schema = { type: 'array', items: { type: 'string', description: 'item text' } };
    const hits = walk(schema);
    expect(hits).toContainEqual({ path: 'inputSchema.items.description', value: 'item text' });
  });

  it('walks into items (tuple/array form)', () => {
    const schema = {
      type: 'array',
      items: [
        { type: 'string', description: 'first item' },
        { type: 'string', description: 'second item' },
      ],
    };
    const hits = walk(schema);
    expect(hits).toContainEqual({ path: 'inputSchema.items[0].description', value: 'first item' });
    expect(hits).toContainEqual({ path: 'inputSchema.items[1].description', value: 'second item' });
  });

  it('walks into anyOf / oneOf / allOf', () => {
    const schema = {
      anyOf: [{ type: 'string', description: 'a' }],
      oneOf: [{ type: 'string', description: 'b' }],
      allOf: [{ type: 'string', description: 'c' }],
    };
    const hits = walk(schema);
    expect(hits).toContainEqual({ path: 'inputSchema.anyOf[0].description', value: 'a' });
    expect(hits).toContainEqual({ path: 'inputSchema.oneOf[0].description', value: 'b' });
    expect(hits).toContainEqual({ path: 'inputSchema.allOf[0].description', value: 'c' });
  });

  it('walks into $defs, keyed by definition name (not checked against text keys)', () => {
    const schema = {
      $defs: {
        description: { type: 'string', description: 'a def literally named description' },
      },
    };
    const hits = walk(schema);
    expect(hits).toEqual([
      { path: 'inputSchema.$defs.description.description', value: 'a def literally named description' },
    ]);
  });
});

describe('walkSchemaStrings — cyclic and pathological input', () => {
  it('does not infinitely recurse on a self-referencing object', () => {
    const cyclic: Record<string, unknown> = { type: 'object' };
    cyclic['properties'] = { self: cyclic };
    expect(() => walk(cyclic)).not.toThrow();
  });

  it('does not infinitely recurse on a self-referencing array', () => {
    const cyclic: unknown[] = ['a'];
    cyclic.push(cyclic);
    expect(() => walk({ enum: cyclic })).not.toThrow();
  });

  it('does not throw on a pathologically deep, non-cyclic schema (depth cap)', () => {
    let node: unknown = { type: 'string', description: 'leaf' };
    for (let i = 0; i < 5000; i++) {
      node = { type: 'object', properties: { child: node } };
    }
    expect(() => walk(node)).not.toThrow();
  });
});

describe('walkSchemaStrings — inputs that must not throw', () => {
  it.each([null, undefined, 42, true, 'a bare string', ['a', 'b'], []])(
    'handles %j without throwing',
    (v) => {
      expect(() => walk(v)).not.toThrow();
    },
  );

  it('returns [] for null', () => {
    expect(walk(null)).toEqual([]);
  });

  it('returns [] for a primitive', () => {
    expect(walk(42)).toEqual([]);
  });

  it('a bare top-level string is not emitted (no text-key context at the root)', () => {
    expect(walk('free text')).toEqual([]);
  });

  it('handles null and primitives nested inside an object without throwing', () => {
    const schema = { type: 'string', default: null, title: 3 as unknown as string, description: undefined };
    expect(() => walk(schema)).not.toThrow();
    expect(walk(schema)).toEqual([]);
  });
});
