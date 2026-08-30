import { SUPPRESSION_MARKER } from '../collect/suppression.js';
import type { Confidence, Finding, Severity, SourceLocation, Suppression } from './types.js';

/**
 * Applying suppressions (docs/SPEC.md §8.3) — the other half of
 * `src/collect/suppression.ts`, which only parses them.
 *
 * Two jobs, and the second is the reason this is not a one-line `filter`:
 *
 *  1. Drop findings a well-formed suppression covers.
 *  2. **Report every suppression that did not work.** A suppression with no
 *     reason, a suppression that names no rule, a suppression that names a rule
 *     that does not exist — each of those looks like protection to whoever
 *     wrote it and provides none. Silently ignoring them is the worst outcome
 *     available: the developer believes a line is annotated, the scanner
 *     believes nothing was said, and neither finds out. So they become `info`
 *     findings under `MCPSCAN001`.
 *
 * `info` is the right level and not a hedge: `--fail-on` only accepts
 * critical/high/medium/low (SPEC §9), so a malformed suppression can never turn
 * CI red on its own. It shows up in the report, where a person reads it.
 */

/**
 * Not a detection rule and deliberately not in the `MCP###`/`SKILL###`
 * namespace: it says nothing about the security of the scanned server, only
 * that an annotation in it is unusable. It is registered nowhere — the engine
 * builds findings from `RULES`, and this is emitted after that — so its
 * metadata lives here, next to the code that uses it.
 */
export const SUPPRESSION_DIAGNOSTIC: {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  /** Always absent: this is not a vulnerability, so no OWASP category applies to it. */
  owasp?: string;
} = {
  id: 'MCPSCAN001',
  title: 'Malformed suppression comment',
  severity: 'info',
  confidence: 'high',
};

export interface SuppressionResult {
  findings: Finding[];
  /** How many real findings were dropped. Reported, never silent. */
  suppressed: number;
}

function diagnosticLocation(s: Suppression): SourceLocation {
  return {
    file: s.file,
    line: s.line,
    column: s.column,
    endLine: s.line,
    endColumn: s.column + SUPPRESSION_MARKER.length,
  };
}

function diagnostic(s: Suppression, message: string, remediation: string, helpBaseUri: string): Finding {
  return {
    ruleId: SUPPRESSION_DIAGNOSTIC.id,
    title: SUPPRESSION_DIAGNOSTIC.title,
    severity: SUPPRESSION_DIAGNOSTIC.severity,
    confidence: SUPPRESSION_DIAGNOSTIC.confidence,
    location: diagnosticLocation(s),
    message,
    remediation,
    evidence: s.raw,
    helpUri: `${helpBaseUri}${SUPPRESSION_DIAGNOSTIC.id}.md`,
    provenance: 'static',
  };
}

const EXAMPLE = `${SUPPRESSION_MARKER} MCP004 -- path is validated in validatePath()`;

function defectDiagnostics(s: Suppression, helpBaseUri: string): Finding[] {
  if (s.defect === 'missing-reason') {
    return [diagnostic(
      s,
      'Suppression comment has no justification, so it was ignored and the finding on the ' +
      'next line still stands. Everything after `--` is the mandatory reason.',
      `Write the reason: \`${EXAMPLE}\`. If the finding is a true positive, fix it instead of suppressing it.`,
      helpBaseUri,
    )];
  }

  if (s.defect === 'missing-rule-id') {
    return [diagnostic(
      s,
      'Suppression comment names no rule, so it was ignored and the finding on the next line ' +
      'still stands. A suppression has to say which rule it silences — a blanket suppression ' +
      'would also silence every rule written after it.',
      `Name the rule: \`${EXAMPLE}\`. List several separated by commas to suppress more than one.`,
      helpBaseUri,
    )];
  }

  return [];
}

/**
 * `knownRuleIds` is every *registered* rule, not just the active ones: a
 * suppression naming a rule that `--disable` turned off for this run is
 * correct and forward-looking, not a typo. A rule id that exists nowhere is a
 * typo, and a typo that silently suppresses nothing is precisely the failure
 * mode SPEC §9 makes exit-2 for `--rules`/`--disable`.
 */
export function applySuppressions(
  findings: Finding[],
  suppressions: readonly Suppression[],
  knownRuleIds: ReadonlySet<string>,
  helpBaseUri: string,
): SuppressionResult {
  const diagnostics: Finding[] = [];

  // file -> target line -> rule ids silenced there, from usable suppressions only.
  const active = new Map<string, Map<number, Set<string>>>();

  for (const s of suppressions) {
    if (s.defect !== undefined) {
      diagnostics.push(...defectDiagnostics(s, helpBaseUri));
      continue;
    }

    const unknown = s.ruleIds.filter((id) => !knownRuleIds.has(id));
    if (unknown.length > 0) {
      diagnostics.push(diagnostic(
        s,
        `Suppression comment names ${unknown.length === 1 ? 'a rule' : 'rules'} that ` +
        `${unknown.length === 1 ? 'does' : 'do'} not exist (${unknown.join(', ')}), so ` +
        `${unknown.length === 1 ? 'it silences' : 'they silence'} nothing. Valid ids: ` +
        `${[...knownRuleIds].sort().join(', ')}.`,
        'Correct the rule id. A suppression for a rule that does not exist looks like ' +
        'protection and provides none.',
        helpBaseUri,
      ));
    }

    const known = s.ruleIds.filter((id) => knownRuleIds.has(id));
    if (known.length === 0) continue;

    const byLine = active.get(s.file) ?? new Map<number, Set<string>>();
    const ids = byLine.get(s.targetLine) ?? new Set<string>();
    for (const id of known) ids.add(id);
    byLine.set(s.targetLine, ids);
    active.set(s.file, byLine);
  }

  const kept: Finding[] = [];
  let suppressed = 0;
  for (const f of findings) {
    if (active.get(f.location.file)?.get(f.location.line)?.has(f.ruleId)) {
      suppressed += 1;
      continue;
    }
    kept.push(f);
  }

  return { findings: [...kept, ...diagnostics], suppressed };
}
