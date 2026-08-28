import pc from 'picocolors';
import type { Finding, Severity } from '../core/types.js';

export interface PrettyOptions {
  color: boolean;
  stats: { files: number; tools: number; skills: number };
}

const PAINT: Record<Severity, (s: string) => string> = {
  critical: pc.red, high: pc.red, medium: pc.yellow, low: pc.cyan, info: pc.gray,
};

export function formatPretty(findings: Finding[], opts: PrettyOptions): string {
  const c = (fn: (s: string) => string, s: string) => (opts.color ? fn(s) : s);
  const { files, tools, skills } = opts.stats;
  const lines: string[] = [
    `mcpscan · ${files} arquivo(s) · ${tools} tool(s) · ${skills} skill(s)`,
    '',
  ];

  if (findings.length === 0) {
    lines.push(c(pc.green, 'Nenhum problema encontrado.'), '');
    return lines.join('\n');
  }

  for (const f of findings) {
    const sev = c(PAINT[f.severity], f.severity.toUpperCase().padEnd(8));
    lines.push(`${sev}  ${c(pc.bold, f.ruleId)}  ${f.title}`);
    const where = `${f.location.file}:${f.location.line}:${f.location.column}`;
    lines.push(`  ${c(pc.underline, where)}${f.location.jsonPath ? `  ${c(pc.gray, f.location.jsonPath)}` : ''}`);
    lines.push(`  ${f.message}`);
    lines.push(`  ${c(pc.green, 'Fix:')} ${f.remediation}`);
    lines.push(`  ${c(pc.gray, f.helpUri)}`);
    lines.push('');
  }

  const counts = (['critical', 'high', 'medium', 'low', 'info'] as Severity[])
    .map((s) => [s, findings.filter((f) => f.severity === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`)
    .join(' · ');
  lines.push(`  ${counts}`, '');
  return lines.join('\n');
}
