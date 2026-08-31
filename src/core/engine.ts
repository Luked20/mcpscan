import {
  CONFIDENCE_CEILING,
  type Finding, type PartialFinding, type Rule, type ScanContext, type ScanTarget, type Severity,
} from './types.js';
import { rank, compareSeverity } from './severity.js';
import { helpUriFor } from './help.js';

function clamp(severity: Severity, ceiling: Severity): Severity {
  return rank(severity) > rank(ceiling) ? ceiling : severity;
}

/** A rule that threw. One entry per rule, not per subject. */
export interface RuleFailure {
  ruleId: string;
  message: string;      // exception message
  subjectCount: number; // how many subjects failed for this rule
}

export interface RuleRunResult {
  findings: Finding[];
  failures: RuleFailure[];
}

interface Attempt {
  partials: PartialFinding[];
  failedSubjects: number;
  firstError?: string;
}

/** Runs `check` over each subject, accumulating partials and counting exceptions. */
function attempt<S>(subjects: readonly S[], run: (subject: S) => PartialFinding[]): Attempt {
  const partials: PartialFinding[] = [];
  let failedSubjects = 0;
  let firstError: string | undefined;

  for (const subject of subjects) {
    try {
      partials.push(...run(subject));
    } catch (err) {
      // A broken rule can't take down the scan or silence the others — but it also
      // can't become an `info` finding that --fail-on ignores. It becomes a failure.
      failedSubjects += 1;
      firstError ??= err instanceof Error ? err.message : String(err);
    }
  }

  return { partials, failedSubjects, ...(firstError !== undefined ? { firstError } : {}) };
}

function cmp(a: string | number, b: string | number): number {
  // No localeCompare: ordering can't depend on the host's ICU, or JSON/SARIF
  // output stops being byte-reproducible across machines.
  return a < b ? -1 : a > b ? 1 : 0;
}

export function runRules(target: ScanTarget, rules: Rule[], helpBaseUri: string): RuleRunResult {
  const ctx: ScanContext = { target, helpBaseUri };
  const findings: Finding[] = [];
  const failures: RuleFailure[] = [];

  for (const rule of rules) {
    const severity = clamp(rule.severity, CONFIDENCE_CEILING[rule.confidence]);

    let a: Attempt;
    switch (rule.appliesTo) {
      case 'tool': a = attempt(target.tools, (s) => rule.check(s, ctx)); break;
      case 'resource': a = attempt(target.resources, (s) => rule.check(s, ctx)); break;
      case 'prompt': a = attempt(target.prompts, (s) => rule.check(s, ctx)); break;
      case 'server': a = attempt(target.servers, (s) => rule.check(s, ctx)); break;
      case 'skill': a = attempt(target.skills, (s) => rule.check(s, ctx)); break;
      case 'sourceFile': a = attempt(target.sourceFiles, (s) => rule.check(s, ctx)); break;
      case 'target': a = attempt([target], (s) => rule.check(s, ctx)); break;
    }

    if (a.failedSubjects > 0) {
      failures.push({
        ruleId: rule.id,
        message: a.firstError ?? 'unknown error',
        subjectCount: a.failedSubjects,
      });
    }

    for (const p of a.partials) {
      findings.push({
        ...p,
        ruleId: rule.id,
        title: rule.title,
        severity,
        confidence: rule.confidence,
        ...(rule.owasp !== undefined ? { owasp: rule.owasp } : {}),
        helpUri: helpUriFor(rule.id, helpBaseUri),
        provenance: 'static',
      });
    }
  }

  return { findings: sortFindings(findings), failures };
}

/**
 * The report's canonical order. Exported because suppression diagnostics are
 * appended after `runRules` has already sorted (see `core/suppress.ts`), and
 * two different orderings in one report would be worse than none.
 */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) =>
    compareSeverity(b.severity, a.severity) ||
    cmp(a.location.file, b.location.file) ||
    cmp(a.location.line, b.location.line) ||
    cmp(a.location.column, b.location.column) ||
    cmp(a.ruleId, b.ruleId));
}
