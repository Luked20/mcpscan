import { createHash } from 'node:crypto';
import type { Finding, Rule, Severity } from '../core/types.js';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note',
};

const SECURITY_SCORE: Record<Severity, string> = {
  critical: '9.0', high: '7.5', medium: '5.0', low: '3.0', info: '1.0',
};

/** A relative URI in SARIF always uses '/', even when collected on Windows. */
const toPosix = (file: string): string => file.split('\\').join('/');

/**
 * Fingerprint stable across commits. Does NOT include the line number: if it
 * did, any edit above the finding would create a new alert on GitHub and the
 * user would turn the tool off within the second week.
 */
function fingerprint(f: Finding): string {
  return createHash('sha256')
    .update([f.ruleId, toPosix(f.location.file), f.location.jsonPath ?? '', (f.evidence ?? '').trim()].join('\u0000'))
    .digest('hex')
    .slice(0, 16);
}

export function formatSarif(findings: Finding[], rules: Rule[], version: string): string {
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'mcpscan',
          version,
          informationUri: 'https://github.com/luked20/mcpscan',
          rules: rules.map((r) => ({
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
      results: findings.map((f) => ({
        ruleId: f.ruleId,
        level: LEVEL[f.severity],
        message: { text: `${f.message} ${f.remediation}` },
        partialFingerprints: { 'mcpScan/v1': fingerprint(f) },
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
