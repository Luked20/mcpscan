import { describe, it, expect } from 'vitest';
import { parseConfig, resolveOptions, CONFIG_VERSION } from '../../src/config.js';
import type { Config } from '../../src/config.js';

const parse = (obj: unknown) => parseConfig(JSON.stringify(obj), 'mcpscan.config.json');
const ok = (obj: unknown): Config => {
  const r = parse(obj);
  if (typeof r === 'string') throw new Error(`expected a config, got error: ${r}`);
  return r;
};
const err = (obj: unknown): string => {
  const r = parse(obj);
  if (typeof r !== 'string') throw new Error(`expected an error, got ${JSON.stringify(r)}`);
  return r;
};

describe('parseConfig — accepted', () => {
  it('reads every supported key', () => {
    expect(ok({
      version: CONFIG_VERSION,
      failOn: 'critical',
      rules: ['MCP001', 'MCP002'],
      disable: ['MCP007'],
      format: 'sarif',
      baseline: 'mcpscan-baseline.json',
    })).toEqual({
      failOn: 'critical',
      rules: ['MCP001', 'MCP002'],
      disable: ['MCP007'],
      format: 'sarif',
      baseline: 'mcpscan-baseline.json',
    });
  });

  it('accepts a config with nothing but a version', () => {
    expect(ok({ version: CONFIG_VERSION })).toEqual({});
  });
});

describe('parseConfig — rejected', () => {
  it('rejects a missing version, naming the version to add', () => {
    // The config file is public contract (SPEC §16.1) and a wire format with no
    // version field cannot be changed later without breaking existing files.
    expect(err({ failOn: 'critical' })).toMatch(/no "version" field.*Add "version": 1/);
  });

  it('rejects a version this build does not read', () => {
    expect(err({ version: 99, failOn: 'critical' })).toMatch(/has version 99/);
  });

  it('rejects an unrecognised key rather than ignoring it', () => {
    // The failure mode SPEC §16.1 lists for the config file is "scan silently
    // runs with defaults". A typo'd key is exactly that, so it is an error.
    const message = err({ version: CONFIG_VERSION, failon: 'critical' });
    expect(message).toContain('unrecognised key(s): failon');
    expect(message).toContain('Valid keys:');
  });

  it.each([
    ['failOn', { version: CONFIG_VERSION, failOn: 'HIGH' }],
    ['failOn', { version: CONFIG_VERSION, failOn: 'catastrophic' }],
    ['format', { version: CONFIG_VERSION, format: 'yaml' }],
    ['rules', { version: CONFIG_VERSION, rules: 'MCP001' }],
    ['disable', { version: CONFIG_VERSION, disable: [1, 2] }],
    ['baseline', { version: CONFIG_VERSION, baseline: '' }],
  ])('rejects an invalid %s value', (key, obj) => {
    expect(err(obj)).toContain(`"${key}"`);
  });

  it('rejects a document that is not an object', () => {
    expect(parseConfig('[]', 'c.json')).toMatch(/expected a JSON object/);
    expect(parseConfig('"x"', 'c.json')).toMatch(/expected a JSON object/);
  });

  it('rejects malformed JSON, naming the file', () => {
    expect(parseConfig('{ nope', 'c.json')).toMatch(/^c\.json is not valid JSON/);
  });
});

describe('resolveOptions — precedence is flag > config > default', () => {
  const NO_CONFIG: Config = {};

  it('falls back to built-in defaults with neither flag nor config', () => {
    expect(resolveOptions({}, NO_CONFIG, false)).toEqual({ format: 'json', failOn: 'high' });
  });

  it('defaults format to pretty on a TTY and json otherwise', () => {
    expect(resolveOptions({}, NO_CONFIG, true).format).toBe('pretty');
    expect(resolveOptions({}, NO_CONFIG, false).format).toBe('json');
  });

  it('uses the config when no flag is given', () => {
    const config: Config = { failOn: 'critical', format: 'sarif', baseline: 'b.json' };
    expect(resolveOptions({}, config, false)).toMatchObject({
      failOn: 'critical', format: 'sarif', baseline: 'b.json',
    });
  });

  it('lets a flag override the config, for every option', () => {
    const config: Config = {
      failOn: 'none', format: 'json', rules: ['MCP001'], disable: ['MCP002'], baseline: 'from-config.json',
    };
    expect(resolveOptions(
      { failOn: 'high', format: 'sarif', rules: 'MCP004', disable: 'MCP005', baseline: 'from-flag.json' },
      config,
      false,
    )).toEqual({
      failOn: 'high',
      format: 'sarif',
      rules: ['MCP004'],
      disable: ['MCP005'],
      baseline: 'from-flag.json',
    });
  });

  it('splits a comma-separated flag but takes a config array as-is', () => {
    expect(resolveOptions({ rules: 'MCP001,MCP002' }, NO_CONFIG, false).rules).toEqual(['MCP001', 'MCP002']);
    expect(resolveOptions({}, { rules: ['MCP001', 'MCP002'] }, false).rules).toEqual(['MCP001', 'MCP002']);
  });

  it('does not invent options the user never set', () => {
    // `rules: undefined` and `rules: []` mean different things to scan() -- an
    // empty array is "no active rules", which is exit 2.
    const resolved = resolveOptions({}, NO_CONFIG, false);
    expect('rules' in resolved).toBe(false);
    expect('disable' in resolved).toBe(false);
    expect('baseline' in resolved).toBe(false);
  });
});
