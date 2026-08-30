import { readFileSync } from 'node:fs';
import { FORMATS } from './report/format.js';
import { FAIL_ON_VALUES } from './core/severity.js';

/**
 * `mcpscan.config.json` (`--config`, docs/SPEC.md §9).
 *
 * The config file is **public contract** (§16.1): it lives in someone else's
 * repository, and the failure mode listed there for changing it is "scan
 * silently runs with defaults" — the worst kind, because the scan still
 * reports success. Two consequences are built in here from the first version:
 *
 *  1. **It carries a `version` field** (§16.3). A wire format without one
 *     cannot be changed later without breaking whoever already wrote one.
 *  2. **An unrecognised key is an error, not a shrug.** A typo like
 *     `"failon"` would otherwise leave the setting at its default while the
 *     file looks like it says otherwise, and nothing would ever say so.
 *     Rejecting costs a clear error once; accepting costs a wrong scan
 *     forever.
 *
 * Precedence is CLI flag > config file > built-in default. A flag someone
 * typed is a decision they made for this run and must win over a file.
 */

export const CONFIG_VERSION = 1;
export const DEFAULT_CONFIG_FILE = 'mcpscan.config.json';

export interface Config {
  failOn?: string;
  rules?: string[];
  disable?: string[];
  format?: string;
  baseline?: string;
}

const KNOWN_KEYS = ['version', 'failOn', 'rules', 'disable', 'format', 'baseline'] as const;

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}

/**
 * Parses config text. Returns the config, or an error message for exit 2.
 *
 * Rule ids are deliberately *not* validated here — `scan()` already rejects an
 * unknown id wherever it came from, with one message and one code path. Two
 * validators for one thing is how they drift apart.
 */
export function parseConfig(text: string, file: string): Config | string {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    return `${file} is not valid JSON: ${(err as Error).message}`;
  }

  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
    return `${file} is not a config document (expected a JSON object)`;
  }
  const obj = doc as Record<string, unknown>;

  if (obj['version'] !== CONFIG_VERSION) {
    return obj['version'] === undefined
      ? `${file} has no "version" field. Add "version": ${CONFIG_VERSION}.`
      : `${file} has version ${JSON.stringify(obj['version'])}, but this mcpscan reads version ` +
        `${CONFIG_VERSION}.`;
  }

  const unknown = Object.keys(obj).filter((k) => !(KNOWN_KEYS as readonly string[]).includes(k));
  if (unknown.length > 0) {
    return `${file} has unrecognised key(s): ${unknown.join(', ')}. ` +
      `Valid keys: ${KNOWN_KEYS.join(', ')}. (A typo here would silently leave the setting at its default.)`;
  }

  const config: Config = {};

  if (obj['failOn'] !== undefined) {
    const v = obj['failOn'];
    if (typeof v !== 'string' || !(FAIL_ON_VALUES as readonly string[]).includes(v)) {
      return `${file}: "failOn" must be one of ${FAIL_ON_VALUES.join(' | ')}, got ${JSON.stringify(v)}`;
    }
    config.failOn = v;
  }

  if (obj['format'] !== undefined) {
    const v = obj['format'];
    if (typeof v !== 'string' || !(FORMATS as readonly string[]).includes(v)) {
      return `${file}: "format" must be one of ${FORMATS.join(' | ')}, got ${JSON.stringify(v)}`;
    }
    config.format = v;
  }

  for (const key of ['rules', 'disable'] as const) {
    const v = obj[key];
    if (v === undefined) continue;
    if (!isStringArray(v)) return `${file}: "${key}" must be an array of rule ids, got ${JSON.stringify(v)}`;
    config[key] = v;
  }

  if (obj['baseline'] !== undefined) {
    const v = obj['baseline'];
    if (typeof v !== 'string' || v.length === 0) {
      return `${file}: "baseline" must be a path, got ${JSON.stringify(v)}`;
    }
    config.baseline = v;
  }

  return config;
}

/** The raw option values commander hands back, before any default is applied. */
export interface CliFlags {
  format?: string;
  failOn?: string;
  /** Comma-separated on the command line; an array in the config file. */
  rules?: string;
  disable?: string;
  baseline?: string;
}

export interface ResolvedOptions {
  format: string;
  failOn: string;
  rules?: string[];
  disable?: string[];
  baseline?: string;
}

/**
 * Merges the three sources into what the scan actually runs with.
 *
 * Precedence is **CLI flag > config file > built-in default**, without
 * exception: a flag someone typed is a decision they made for this run, and a
 * file in the repository must never override it.
 *
 * Pure, and separate from `main()`, so the precedence can be tested directly.
 * It is the kind of logic that is easy to get subtly wrong (an option whose
 * default is applied too early stops the config from ever being consulted) and
 * impossible to notice from the outside — the scan just quietly runs with the
 * wrong settings.
 */
export function resolveOptions(flags: CliFlags, config: Config, isTty: boolean): ResolvedOptions {
  const rules = flags.rules !== undefined ? flags.rules.split(',') : config.rules;
  const disable = flags.disable !== undefined ? flags.disable.split(',') : config.disable;
  const baseline = flags.baseline ?? config.baseline;

  return {
    // `pretty` only when a human is watching; a redirected stdout gets JSON.
    format: flags.format ?? config.format ?? (isTty ? 'pretty' : 'json'),
    failOn: flags.failOn ?? config.failOn ?? 'high',
    ...(rules !== undefined ? { rules } : {}),
    ...(disable !== undefined ? { disable } : {}),
    ...(baseline !== undefined ? { baseline } : {}),
  };
}

/**
 * Reads the config from disk.
 *
 * `explicit` distinguishes the two cases that must not behave alike: a file
 * the user *named* and that is missing is an error (they expected settings to
 * apply and none did), while the default file simply not existing is the
 * normal case for most repositories and means "no config".
 */
export function loadConfig(file: string, explicit: boolean): Config | string {
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code === 'ENOENT' && !explicit) return {};
    return `could not read config ${file}: ${e.message}`;
  }
  return parseConfig(text, file);
}
