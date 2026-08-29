import { statSync } from 'node:fs';
import { discover } from './collect/index.js';
import { runRules } from './core/engine.js';
import { RULES } from './rules/index.js';
import { atLeast, isFailOn, FAIL_ON_VALUES } from './core/severity.js';
import type { Finding, Rule, ScanTarget, Severity } from './core/types.js';

export const HELP_BASE_URI = 'https://github.com/luked20/mcpscan/blob/main/docs/rules/';

export interface ScanOptions {
  path: string;
  failOn: Severity | 'none';
  rules?: string[];
  disable?: string[];
}

export interface ScanStats {
  /** Files read. */
  filesExamined: number;
  /** Subset that actually produced tools. */
  filesWithTools: number;
  tools: number;
  skills: number;
}

export interface ScanResult {
  findings: Finding[];
  exitCode: 0 | 1 | 2;
  stats: ScanStats;
  error?: string;
}

const emptyStats = (): ScanStats => ({ filesExamined: 0, filesWithTools: 0, tools: 0, skills: 0 });

const fail = (error: string, findings: Finding[] = [], stats = emptyStats()): ScanResult =>
  ({ findings, exitCode: 2, stats, error });

/** Nothing discovered isn't "clean": it's "pointed at the wrong place". */
function hasSubjects(t: ScanTarget): boolean {
  return t.tools.length > 0 || t.skills.length > 0 ||
    t.servers.length > 0 || t.sourceFiles.length > 0;
}

/** Returns the active rule set, or an error message if the selection makes no sense. */
function selectRules(opts: ScanOptions): Rule[] | string {
  const known = new Set(RULES.map((r) => r.id));
  const valid = RULES.map((r) => r.id).join(', ');
  const unknown = [...(opts.rules ?? []), ...(opts.disable ?? [])].filter((id) => !known.has(id));
  if (unknown.length > 0) {
    return `unknown rule(s): ${[...new Set(unknown)].join(', ')}. Valid: ${valid}`;
  }

  let active = RULES;
  if (opts.rules?.length) active = active.filter((r) => opts.rules!.includes(r.id));
  if (opts.disable?.length) active = active.filter((r) => !opts.disable!.includes(r.id));
  if (active.length === 0) return `no active rules after --rules/--disable. Valid: ${valid}`;
  return active;
}

export async function scan(opts: ScanOptions): Promise<ScanResult> {
  const failOn = opts.failOn;
  if (!isFailOn(failOn)) {
    return fail(`invalid --fail-on: ${String(failOn)}. Use: ${FAIL_ON_VALUES.join(' | ')}`);
  }

  const active = selectRules(opts);
  if (typeof active === 'string') return fail(active);

  try {
    statSync(opts.path);
  } catch {
    return fail(`path not found: ${opts.path}`);
  }

  try {
    const target = await discover(opts.path);
    const stats: ScanStats = {
      filesExamined: target.filesExamined,
      filesWithTools: new Set(target.tools.map((t) => t.origin.file)).size,
      tools: target.tools.length,
      skills: target.skills.length,
    };

    if (!hasSubjects(target)) {
      return fail(
        `no MCP server or agent skill found in ${opts.path} ` +
        `(${stats.filesExamined} file(s) scanned)`,
        [], stats,
      );
    }

    const { findings, failures } = runRules(target, active, HELP_BASE_URI);

    // A rule that threw means "couldn't look", not "is clean". The findings already
    // collected still go into a partial report, but the exit code says 2.
    if (failures.length > 0) {
      const detail = failures
        .map((f) => `${f.ruleId} (${f.subjectCount} subjects): ${f.message}`)
        .join('; ');
      return fail(`rule(s) failed during the scan: ${detail}`, findings, stats);
    }

    const fails = failOn !== 'none' && findings.some((f) => atLeast(f.severity, failOn));
    return { findings, exitCode: fails ? 1 : 0, stats };
  } catch (err) {
    return fail((err as Error).message);
  }
}
