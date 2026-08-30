import { createHash } from 'node:crypto';
import type { Finding } from './types.js';

/**
 * One identity for a finding, shared by everything that has to recognise the
 * same finding across two runs: the SARIF `partialFingerprints` GitHub keys its
 * alerts on, and the baseline file (`--baseline`).
 *
 * It lives here, on its own, because those two having *different* notions of
 * "the same finding" would be a bug factory: a baseline that stopped matching
 * after an unrelated edit, or a GitHub alert that reopened while the baseline
 * still suppressed it, and no obvious place to look.
 */

/** A relative path in a wire format always uses '/', even when collected on Windows. */
export const toPosix = (file: string): string => file.split('\\').join('/');

/**
 * Deliberately **excludes the line number**. If it did not, any edit above a
 * finding would produce a new identity: GitHub would close the old alert and
 * open a new one on every commit that shifted a line, and a baseline would go
 * stale for reasons that have nothing to do with the code it describes.
 *
 * What it includes — rule, file, JSON path, evidence — is what makes the
 * finding *this* finding rather than another one of the same kind in the same
 * file. Two identical findings that differ only in line number collapse to one
 * identity, which is the correct trade: the alternative churns on every edit.
 *
 * The key naming this scheme is `mcpScan/v1` (SPEC §16.3). Changing what goes
 * into this hash is a major version bump and must ship as a new key alongside
 * the old one, never as a redefinition of `v1`.
 */
export const FINGERPRINT_KEY = 'mcpScan/v1';

export function fingerprint(f: Finding): string {
  return createHash('sha256')
    .update([
      f.ruleId,
      toPosix(f.location.file),
      f.location.jsonPath ?? '',
      (f.evidence ?? '').trim(),
    ].join('\u0000'))
    .digest('hex')
    .slice(0, 16);
}
