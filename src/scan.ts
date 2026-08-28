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
  /** Arquivos lidos. */
  filesExamined: number;
  /** Subconjunto que de fato produziu tools. */
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

const EMPTY_STATS: ScanStats = { filesExamined: 0, filesWithTools: 0, tools: 0, skills: 0 };

const fail = (error: string, findings: Finding[] = [], stats = EMPTY_STATS): ScanResult =>
  ({ findings, exitCode: 2, stats, error });

/** Nada descoberto não é "limpo": é "apontei para o lugar errado". */
function hasSubjects(t: ScanTarget): boolean {
  return t.tools.length > 0 || t.skills.length > 0 ||
    t.servers.length > 0 || t.sourceFiles.length > 0;
}

/** Devolve o conjunto ativo, ou uma mensagem de erro se a seleção não faz sentido. */
function selectRules(opts: ScanOptions): Rule[] | string {
  const known = new Set(RULES.map((r) => r.id));
  const valid = RULES.map((r) => r.id).join(', ');
  const unknown = [...(opts.rules ?? []), ...(opts.disable ?? [])].filter((id) => !known.has(id));
  if (unknown.length > 0) {
    return `regra(s) desconhecida(s): ${[...new Set(unknown)].join(', ')}. Válidas: ${valid}`;
  }

  let active = RULES;
  if (opts.rules?.length) active = active.filter((r) => opts.rules!.includes(r.id));
  if (opts.disable?.length) active = active.filter((r) => !opts.disable!.includes(r.id));
  if (active.length === 0) return `nenhuma regra ativa depois de --rules/--disable. Válidas: ${valid}`;
  return active;
}

export async function scan(opts: ScanOptions): Promise<ScanResult> {
  if (!isFailOn(opts.failOn)) {
    return fail(`--fail-on inválido: ${String(opts.failOn)}. Use: ${FAIL_ON_VALUES.join(' | ')}`);
  }

  const active = selectRules(opts);
  if (typeof active === 'string') return fail(active);

  try {
    statSync(opts.path);
  } catch {
    return fail(`caminho não encontrado: ${opts.path}`);
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
        `nenhum MCP server ou agent skill encontrado em ${opts.path} ` +
        `(${stats.filesExamined} arquivo(s) examinado(s))`,
        [], stats,
      );
    }

    const { findings, failures } = runRules(target, active, HELP_BASE_URI);

    // Uma regra que lançou é "não consegui olhar", não "está limpo". Os findings já
    // coletados voltam para um relatório parcial, mas o exit code diz 2.
    if (failures.length > 0) {
      const detail = failures
        .map((f) => `${f.ruleId} (${f.subjectCount} subjects): ${f.message}`)
        .join('; ');
      return fail(`regra(s) falharam durante o scan: ${detail}`, findings, stats);
    }

    const fails = opts.failOn !== 'none' && findings.some((f) => atLeast(f.severity, opts.failOn as Severity));
    return { findings, exitCode: fails ? 1 : 0, stats };
  } catch (err) {
    return fail((err as Error).message);
  }
}
