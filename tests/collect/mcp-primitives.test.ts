import { describe, it, expect } from 'vitest';
import { collectResources, collectPrompts } from '../../src/collect/mcp-primitives.js';

const doc = (obj: unknown) => JSON.stringify(obj, null, 2);

describe('collectResources', () => {
  it('reads resources and templates from one document', () => {
    const out = collectResources('x.json', doc({
      name: 'srv',
      resources: [{ uri: 'config://settings', name: 'settings', mimeType: 'application/json' }],
      resourceTemplates: [{ uriTemplate: 'notes://{user_id}', name: 'notes' }],
    }));
    expect(out.map((r) => [r.uri, r.isTemplate ?? false])).toEqual([
      ['config://settings', false],
      ['notes://{user_id}', true],
    ]);
  });

  it('carries the declared server name', () => {
    const out = collectResources('x.json', doc({ name: 'srv', resources: [{ uri: 'a://b', name: 'b' }] }));
    expect(out[0]!.serverName).toBe('srv');
  });

  it('falls back to the uri when a resource has no name', () => {
    const out = collectResources('x.json', doc({ resources: [{ uri: 'a://b' }] }));
    expect(out[0]!.name).toBe('a://b');
  });

  it('skips an entry with no uri — it addresses nothing', () => {
    expect(collectResources('x.json', doc({ resources: [{ name: 'orphan' }] }))).toEqual([]);
  });

  it('locates a field precisely', () => {
    const out = collectResources('x.json', doc({
      resources: [{ uri: 'a://b', name: 'b', description: 'A thing.' }],
    }));
    const loc = out[0]!.loc(['description']);
    expect(loc.jsonPath).toBe('resources[0].description');
    expect(loc.line).toBeGreaterThan(1);
  });

  it.each([
    ['a document with no resources', { tools: [] }],
    ['malformed JSON', '{ nope'],
    ['resources that is not an array', { resources: 'no' }],
  ])('returns [] for %s', (_label, input) => {
    expect(collectResources('x.json', typeof input === 'string' ? input : doc(input))).toEqual([]);
  });
});

describe('collectPrompts', () => {
  it('reads a prompt with its arguments', () => {
    const out = collectPrompts('x.json', doc({
      prompts: [{
        name: 'summarise',
        description: 'Summarise a document.',
        arguments: [{ name: 'document', required: true }, { name: 'style' }],
      }],
    }));
    expect(out).toHaveLength(1);
    expect(out[0]!.arguments).toEqual([{ name: 'document', required: true }, { name: 'style' }]);
  });

  it('skips a prompt with no name — a prompt is addressed by name', () => {
    expect(collectPrompts('x.json', doc({ prompts: [{ description: 'nameless' }] }))).toEqual([]);
  });

  it('drops argument entries that are not named', () => {
    const out = collectPrompts('x.json', doc({
      prompts: [{ name: 'p', arguments: [{ name: 'ok' }, { description: 'no name' }, 'nonsense'] }],
    }));
    expect(out[0]!.arguments).toEqual([{ name: 'ok' }]);
  });

  it('omits arguments entirely when there are none usable', () => {
    const out = collectPrompts('x.json', doc({ prompts: [{ name: 'p', arguments: [] }] }));
    expect(out[0]!.arguments).toBeUndefined();
  });

  it('locates a field precisely', () => {
    const out = collectPrompts('x.json', doc({ prompts: [{ name: 'p', description: 'A prompt.' }] }));
    expect(out[0]!.loc(['description']).jsonPath).toBe('prompts[0].description');
  });

  it.each([
    ['a document with no prompts', { tools: [] }],
    ['malformed JSON', '{ nope'],
  ])('returns [] for %s', (_label, input) => {
    expect(collectPrompts('x.json', typeof input === 'string' ? input : doc(input))).toEqual([]);
  });
});
