import {
  CONFIDENCE_CEILING,
  type Finding, type PartialFinding, type Rule, type ScanContext, type ScanTarget, type Severity,
} from './types.js';
import { rank, compareSeverity } from './severity.js';

function clamp(severity: Severity, ceiling: Severity): Severity {
  return rank(severity) > rank(ceiling) ? ceiling : severity;
}

/** Uma regra que lançou. Uma entrada por regra, não por subject. */
export interface RuleFailure {
  ruleId: string;
  message: string;      // mensagem da exceção
  subjectCount: number; // quantos subjects falharam para essa regra
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

/** Roda `check` sobre cada subject, acumulando partials e contando as exceções. */
function attempt<S>(subjects: readonly S[], run: (subject: S) => PartialFinding[]): Attempt {
  const partials: PartialFinding[] = [];
  let failedSubjects = 0;
  let firstError: string | undefined;

  for (const subject of subjects) {
    try {
      partials.push(...run(subject));
    } catch (err) {
      // Uma regra quebrada não pode derrubar o scan nem silenciar as outras — mas
      // também não pode virar um finding `info` que o --fail-on ignora. Vira falha.
      failedSubjects += 1;
      firstError ??= err instanceof Error ? err.message : String(err);
    }
  }

  return { partials, failedSubjects, ...(firstError !== undefined ? { firstError } : {}) };
}

function cmp(a: string | number, b: string | number): number {
  // Sem localeCompare: a ordem não pode depender do ICU do host, senão JSON/SARIF
  // deixam de ser byte-reproduzíveis entre máquinas.
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
      case 'server': a = attempt(target.servers, (s) => rule.check(s, ctx)); break;
      case 'skill': a = attempt(target.skills, (s) => rule.check(s, ctx)); break;
      case 'sourceFile': a = attempt(target.sourceFiles, (s) => rule.check(s, ctx)); break;
      case 'target': a = attempt([target], (s) => rule.check(s, ctx)); break;
    }

    if (a.failedSubjects > 0) {
      failures.push({
        ruleId: rule.id,
        message: a.firstError ?? 'erro desconhecido',
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
        helpUri: `${helpBaseUri}${rule.id}.md`,
        provenance: 'static',
      });
    }
  }

  findings.sort((a, b) =>
    compareSeverity(b.severity, a.severity) ||
    cmp(a.location.file, b.location.file) ||
    cmp(a.location.line, b.location.line) ||
    cmp(a.location.column, b.location.column) ||
    cmp(a.ruleId, b.ruleId));

  return { findings, failures };
}
