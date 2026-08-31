import pc from 'picocolors';
import type { Finding, Severity } from '../core/types.js';
import type { ScanStats } from '../scan.js';

export interface PrettyOptions {
  color: boolean;
  stats: ScanStats;
  /** Present when the scan couldn't look at anything (exit 2). */
  error?: string;
  /**
   * `--quiet`: drop the header and the severity summary, and say nothing at all
   * when a successful scan found nothing.
   *
   * What it must never hide is the difference between "clean" and "could not
   * look" (SPEC §16.6). So an `error` still prints, in full, quiet or not — the
   * silence is reserved for the one case where silence is true.
   */
  quiet?: boolean;
}

const PAINT: Record<Severity, (s: string) => string> = {
  critical: pc.red, high: pc.red, medium: pc.yellow, low: pc.cyan, info: pc.gray,
};

type Paint = (fn: (s: string) => string, s: string) => string;

function findingLines(findings: Finding[], c: Paint): string[] {
  const lines: string[] = [];
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
  return lines;
}

export function formatPretty(findings: Finding[], opts: PrettyOptions): string {
  const c = (fn: (s: string) => string, s: string) => (opts.color ? fn(s) : s);
  const {
    filesExamined, filesWithTools, tools, servers, skills, sourceFiles,
    unreadable, suppressed, baselined, liveTools,
  } = opts.stats;

  const header =
    `mcpscan · ${filesExamined} file(s) scanned · ${filesWithTools} with tools · ` +
    `${tools} tool(s) · ${servers} server(s) · ${skills} skill(s) · ${sourceFiles} source file(s)` +
    (unreadable > 0 ? ` · ${unreadable} unreadable` : '') +
    // Suppressed and baselined findings are dropped from the report, so these
    // counters are the only place a reader learns they existed. A silent drop
    // would make a heavily suppressed or heavily baselined scan
    // indistinguishable from a clean one.
    (suppressed > 0 ? ` · ${suppressed} suppressed` : '') +
    (baselined > 0 ? ` · ${baselined} baselined` : '');

  const lines: string[] = opts.quiet === true ? [] : [header, ''];

  // A scan that couldn't look at anything must not look like a clean scan --
  // this branch ignores `quiet` on purpose. Silence is only ever allowed to
  // mean "clean", never "could not look".
  if (opts.error !== undefined) {
    if (findings.length > 0) lines.push(...findingLines(findings, c));
    lines.push(c(pc.red, `Nothing scanned: ${opts.error}`), '');
    return lines.join('\n');
  }

  // A scan that found no tools at all, in a tree that plainly holds an MCP
  // server, has not exercised MCP001-MCP006 — the tool-poisoning and shadowing
  // rules this scanner leads with. Real servers build their tools in code at
  // startup, so there is no manifest to read: `awslabs/mcp`, `mondaycom/mcp`
  // and `firecrawl-mcp-server` all yield zero. Saying only "No problems found"
  // there is the same false comfort as a clean report on a path that does not
  // exist, and it went unnoticed for exactly that reason.
  const missingTools = tools === 0 && liveTools === 0 && (sourceFiles > 0 || servers > 0);
  const hint = 'No tools were read. MCP servers usually build their tools in code, so there is no ' +
    'manifest on disk — rerun with --connect "<command that starts the server>" to scan the tools ' +
    'it actually serves.';

  if (findings.length === 0) {
    if (opts.quiet === true) return '';
    lines.push(c(pc.green, 'No problems found.'));
    if (missingTools) lines.push('', c(pc.yellow, hint));
    lines.push('');
    return lines.join('\n');
  }

  lines.push(...findingLines(findings, c));
  if (opts.quiet === true) return lines.join('\n');

  const counts = (['critical', 'high', 'medium', 'low', 'info'] as Severity[])
    .map((s) => [s, findings.filter((f) => f.severity === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`)
    .join(' · ');
  lines.push(`  ${counts}`);
  if (missingTools) lines.push('', c(pc.yellow, hint));
  lines.push('');
  return lines.join('\n');
}
