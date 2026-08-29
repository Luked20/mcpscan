import type { Finding, Severity } from '../core/types.js';

const CMD: Record<Severity, 'error' | 'warning' | 'notice'> = {
  critical: 'error', high: 'error', medium: 'warning', low: 'notice', info: 'notice',
};

const esc = (s: string) => s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const toPosix = (file: string): string => file.split('\\').join('/');

export function formatGithub(findings: Finding[]): string {
  return findings.map((f) =>
    `::${CMD[f.severity]} file=${toPosix(f.location.file)},line=${f.location.line},col=${f.location.column},` +
    `title=${esc(`${f.ruleId}: ${f.title}`)}::${esc(`${f.message} ${f.remediation} ${f.helpUri}`)}`
  ).join('\n');
}
