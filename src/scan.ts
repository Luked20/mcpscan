import { statSync } from 'node:fs';
import { discover } from './collect/index.js';
import { runRules, sortFindings } from './core/engine.js';
import { applySuppressions } from './core/suppress.js';
import { fingerprint } from './core/fingerprint.js';
import { RULES } from './rules/index.js';
import { atLeast, isFailOn, FAIL_ON_VALUES } from './core/severity.js';
import type { Finding, Rule, ScanTarget, Severity } from './core/types.js';

export const HELP_BASE_URI = 'https://github.com/luked20/mcpscan/blob/main/docs/rules/';

export interface ScanOptions {
  path: string;
  failOn: Severity | 'none';
  rules?: string[];
  disable?: string[];
  /**
   * Fingerprints of findings already accepted (`--baseline`). Parsed by the
   * caller — `scan()` does no I/O of its own beyond reading the scanned tree,
   * and a baseline that failed to load must never reach here looking like an
   * empty one (see `report/baseline.ts`).
   */
  baseline?: ReadonlySet<string>;
}

export interface ScanStats {
  /** Files read. */
  filesExamined: number;
  /** Subset that actually produced tools. */
  filesWithTools: number;
  tools: number;
  /** MCP servers declared in client config files. */
  servers: number;
  skills: number;
  /** Source files handed to the source rules -- MCP008 has no other input. */
  sourceFiles: number;
  /** Name-declared files no collector could parse. */
  unreadable: number;
  /** Findings dropped by a well-formed suppression comment. Reported, never silent. */
  suppressed: number;
  /** Findings dropped because the baseline already lists them. Reported, never silent. */
  baselined: number;
}

export interface ScanResult {
  findings: Finding[];
  exitCode: 0 | 1 | 2;
  stats: ScanStats;
  error?: string;
}

const emptyStats = (): ScanStats =>
  ({ filesExamined: 0, filesWithTools: 0, tools: 0, servers: 0, skills: 0, sourceFiles: 0, unreadable: 0, suppressed: 0, baselined: 0 });

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
      servers: target.servers.length,
      skills: target.skills.length,
      sourceFiles: target.sourceFiles.length,
      unreadable: target.unreadable.length,
      suppressed: 0,
      baselined: 0,
    };

    if (!hasSubjects(target)) {
      return fail(
        `no MCP server or agent skill found in ${opts.path} ` +
        `(${stats.filesExamined} file(s) scanned)`,
        [], stats,
      );
    }

    const run = runRules(target, active, HELP_BASE_URI);
    const { failures } = run;

    // Suppressions are applied against every *registered* rule id, not just the
    // ones active this run: a suppression naming a rule `--disable` turned off
    // is correct and forward-looking, while one naming a rule that exists
    // nowhere is a typo that silences nothing, and gets reported (SPEC §8.3).
    const suppression = applySuppressions(
      run.findings, target.suppressions, new Set(RULES.map((r) => r.id)), HELP_BASE_URI,
    );
    stats.suppressed = suppression.suppressed;

    // Baseline after suppressions, not before: a finding with a written
    // justification on its own line is already answered, and counting it
    // again as 'baselined' would overstate the untriaged backlog -- which is
    // the one number the baseline exists to make visible.
    const accepted = opts.baseline;
    const kept = accepted === undefined
      ? suppression.findings
      : suppression.findings.filter((f) => !accepted.has(fingerprint(f)));
    stats.baselined = suppression.findings.length - kept.length;

    const findings = sortFindings(kept);

    // A rule that threw means "couldn't look", not "is clean". The findings already
    // collected still go into a partial report, but the exit code says 2.
    if (failures.length > 0) {
      const detail = failures
        .map((f) => `${f.ruleId} (${f.subjectCount} subjects): ${f.message}`)
        .join('; ');
      return fail(`rule(s) failed during the scan: ${detail}`, findings, stats);
    }

    // A file whose name declared what it is but which would not parse was not
    // scanned. Reporting green for it would be a lie, so this is exit 2 like any
    // other "could not look" -- see SPEC 9 and 16.6.
    if (target.unreadable.length > 0) {
      const detail = target.unreadable.map((u) => `${u.file} (${u.reason})`).join('; ');
      return fail(`could not parse ${target.unreadable.length} declared file(s): ${detail}`, findings, stats);
    }

    const fails = failOn !== 'none' && findings.some((f) => atLeast(f.severity, failOn));
    return { findings, exitCode: fails ? 1 : 0, stats };
  } catch (err) {
    return fail((err as Error).message);
  }
}
