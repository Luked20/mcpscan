import { FINGERPRINT_KEY, fingerprint, toPosix } from '../core/fingerprint.js';
import { SUPPRESSION_DIAGNOSTIC } from '../core/suppress.js';
import type { Finding, Rule, Severity } from '../core/types.js';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note',
};

const SECURITY_SCORE: Record<Severity, string> = {
  critical: '9.0', high: '7.5', medium: '5.0', low: '3.0', info: '1.0',
};

export interface SarifInvocationOptions {
  /** false when the scan could not run to completion (exit code 2, "couldn't look"). */
  executionSuccessful: boolean;
  /**
   * The same error string the CLI writes to stderr. Required when
   * `executionSuccessful` is false; surfaced as a `toolExecutionNotifications` entry
   * so the failure is visible from the document alone, not just the process exit code.
   */
  error?: string;
}

export function formatSarif(
  findings: Finding[],
  rules: Rule[],
  version: string,
  invocation: SarifInvocationOptions,
): string {
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'mcpscan',
          version,
          informationUri: 'https://github.com/luked20/mcpscan',
          // Every ruleId a result can carry needs a descriptor here, or the
          // document references a rule it never declares. MCPSCAN001 is emitted
          // outside the rule engine (see core/suppress.ts), so it is appended
          // rather than coming from `rules`.
          rules: [...rules, SUPPRESSION_DIAGNOSTIC].map((r) => ({
            id: r.id,
            // SARIF requires name != id when both are present (SARIF1001): id is the
            // stable, opaque identifier, name is the human-readable label.
            name: r.title,
            shortDescription: { text: r.title },
            fullDescription: { text: r.owasp ? `${r.title} (OWASP MCP: ${r.owasp})` : r.title },
            helpUri: `https://github.com/luked20/mcpscan/blob/main/docs/rules/${r.id}.md`,
            defaultConfiguration: { level: LEVEL[r.severity] },
            properties: { tags: ['security', 'mcp'], 'security-severity': SECURITY_SCORE[r.severity] },
          })),
        },
      },
      invocations: [{
        executionSuccessful: invocation.executionSuccessful,
        endTimeUtc: new Date().toISOString(),
        // No commandLine / arguments / workingDirectory: a SARIF file gets
        // committed and shared, and absolute paths from a developer's
        // machine are needless leakage.
        ...(invocation.executionSuccessful ? {} : {
          toolExecutionNotifications: [{
            level: 'error',
            message: { text: invocation.error ?? 'scan failed' },
            descriptor: { id: 'mcpscan/scan-failed' },
          }],
        }),
      }],
      results: findings.map((f) => ({
        ruleId: f.ruleId,
        level: LEVEL[f.severity],
        message: { text: `${f.message} ${f.remediation}` },
        partialFingerprints: { [FINGERPRINT_KEY]: fingerprint(f) },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: toPosix(f.location.file) },
            region: {
              startLine: f.location.line,
              startColumn: f.location.column,
              endLine: f.location.endLine,
              endColumn: f.location.endColumn,
            },
          },
        }],
      })),
    }],
  }, null, 2);
}
