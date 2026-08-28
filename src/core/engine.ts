import { CONFIDENCE_CEILING, type Finding, type Rule, type ScanContext, type ScanTarget, type Severity }
  from './types.js';
import { rank, compareSeverity } from './severity.js';

function clamp(severity: Severity, ceiling: Severity): Severity {
  return rank(severity) > rank(ceiling) ? ceiling : severity;
}

function subjectsFor(target: ScanTarget, kind: Rule['appliesTo']): unknown[] {
  switch (kind) {
    case 'tool': return target.tools;
    case 'server': return target.servers;
    case 'skill': return target.skills;
    case 'sourceFile': return target.sourceFiles;
    case 'target': return [target];
  }
}

export function runRules(target: ScanTarget, rules: Rule<never>[], helpBaseUri: string): Finding[] {
  const ctx: ScanContext = { target, helpBaseUri };
  const findings: Finding[] = [];

  for (const rule of rules) {
    const severity = clamp(rule.severity, CONFIDENCE_CEILING[rule.confidence]);
    for (const subject of subjectsFor(target, rule.appliesTo)) {
      let partials;
      try {
        partials = rule.check(subject as never, ctx);
      } catch (err) {
        // Uma regra quebrada não pode derrubar o scan inteiro nem silenciar as outras.
        findings.push({
          ruleId: 'ENGINE001', title: 'Regra falhou durante a execução',
          severity: 'info', confidence: 'high', location: target.servers[0]?.origin ?? {
            file: '<engine>', line: 1, column: 1, endLine: 1, endColumn: 1,
          },
          message: `A regra ${rule.id} lançou: ${(err as Error).message}`,
          remediation: `Abra uma issue com o arquivo analisado. Rode com --disable ${rule.id} para contornar.`,
          helpUri: `${helpBaseUri}ENGINE001.md`, provenance: 'static',
        });
        continue;
      }
      for (const p of partials) {
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
  }

  return findings.sort((a, b) =>
    compareSeverity(b.severity, a.severity) ||
    a.location.file.localeCompare(b.location.file) ||
    a.location.line - b.location.line ||
    a.ruleId.localeCompare(b.ruleId));
}
