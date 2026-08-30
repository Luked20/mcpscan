import { FINGERPRINT_KEY, fingerprint, toPosix } from '../core/fingerprint.js';
import type { Finding } from '../core/types.js';

/**
 * The baseline file (`--baseline`, docs/SPEC.md §9).
 *
 * Adopting a scanner on an existing codebase is the moment it either gets used
 * or gets deleted. A repository that has never been scanned lights up on the
 * first run, and a developer facing forty findings they did not introduce has
 * two options: fix all of them before merging anything, or turn the scanner
 * off. The baseline is the third option — record what is already there, fail
 * the build only on what is new, and burn the backlog down separately.
 *
 * This is a blunter instrument than a suppression comment and is meant to be:
 * a suppression carries a written reason for one specific line (§8.3), a
 * baseline says "not today" to a whole set at once. Prefer the comment when
 * the finding has an answer; the baseline is for the ones that do not have one
 * yet.
 *
 * ## Identity
 *
 * Entries match on the same fingerprint SARIF uses, which excludes the line
 * number (see `core/fingerprint.ts`). A baseline that went stale every time
 * someone added an import above a finding would be worse than no baseline.
 *
 * ## What is stored, and what is not
 *
 * `fingerprint` is the only field that is read back. `ruleId`, `file` and
 * `jsonPath` are written so a human reviewing the file can see what was
 * accepted — a list of opaque hashes is not something anyone can review, and
 * an unreviewable baseline is how findings quietly become permanent.
 *
 * The `message` is deliberately **not** stored: it is not part of the public
 * contract (§16.5), so recording it would churn the file on every wording
 * change, for a field nothing matches on. Same for the line number.
 */

export const BASELINE_VERSION = 1;

export interface BaselineEntry {
  fingerprint: string;
  ruleId: string;
  file: string;
  jsonPath?: string;
}

export interface BaselineFile {
  version: number;
  /** Which fingerprint scheme produced these, so a future scheme is detectable (§16.3). */
  fingerprintKey: string;
  findings: BaselineEntry[];
}

/** Renders the current findings as a baseline document (`--format baseline`). */
export function formatBaseline(findings: Finding[]): string {
  const seen = new Set<string>();
  const entries: BaselineEntry[] = [];

  for (const f of findings) {
    const fp = fingerprint(f);
    if (seen.has(fp)) continue; // two findings with one identity collapse; see fingerprint.ts
    seen.add(fp);
    entries.push({
      fingerprint: fp,
      ruleId: f.ruleId,
      file: toPosix(f.location.file),
      ...(f.location.jsonPath !== undefined ? { jsonPath: f.location.jsonPath } : {}),
    });
  }

  // Sorted by fingerprint: a baseline is committed, so its diff has to be
  // readable. Ordering by anything positional would reshuffle the whole file
  // when one finding moves.
  entries.sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0));

  const doc: BaselineFile = { version: BASELINE_VERSION, fingerprintKey: FINGERPRINT_KEY, findings: entries };
  return JSON.stringify(doc, null, 2);
}

/**
 * Parses a baseline document into the fingerprint set `scan()` takes.
 *
 * Returns an error string rather than throwing or defaulting to "no baseline":
 * a baseline that silently fails to load turns every already-accepted finding
 * back on, which looks exactly like the scanner having found new problems. The
 * caller makes that exit 2 — "could not look" (§16.6), not "here are your
 * results".
 */
export function parseBaseline(text: string, file: string): Set<string> | string {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    return `${file} is not valid JSON: ${(err as Error).message}`;
  }

  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
    return `${file} is not a baseline document (expected a JSON object)`;
  }
  const obj = doc as Record<string, unknown>;

  if (obj['version'] !== BASELINE_VERSION) {
    return `${file} has version ${JSON.stringify(obj['version'])}, but this mcpscan writes and ` +
      `reads version ${BASELINE_VERSION}. Regenerate it with --format baseline.`;
  }

  // A baseline written under a different fingerprint scheme would silently
  // match nothing. Better to say so than to report every finding as new.
  if (obj['fingerprintKey'] !== undefined && obj['fingerprintKey'] !== FINGERPRINT_KEY) {
    return `${file} was written with fingerprint scheme ${JSON.stringify(obj['fingerprintKey'])}, ` +
      `but this mcpscan uses ${FINGERPRINT_KEY}. Regenerate it with --format baseline.`;
  }

  const findings = obj['findings'];
  if (!Array.isArray(findings)) {
    return `${file} has no "findings" array`;
  }

  const fingerprints = new Set<string>();
  for (const [i, entry] of findings.entries()) {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      return `${file}: findings[${i}] is not an object`;
    }
    const fp = (entry as Record<string, unknown>)['fingerprint'];
    if (typeof fp !== 'string' || fp.length === 0) {
      return `${file}: findings[${i}] has no "fingerprint" string`;
    }
    fingerprints.add(fp);
  }

  return fingerprints;
}
