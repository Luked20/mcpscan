export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';

/** Teto: uma regra nunca emite severidade acima do que sua confiança permite. */
export const CONFIDENCE_CEILING: Record<Confidence, Severity> = {
  high: 'critical',
  medium: 'high',
  low: 'medium',
};

export interface SourceLocation {
  file: string;      // relativo ao root, separador '/'
  line: number;      // 1-based
  column: number;    // 1-based
  endLine: number;
  endColumn: number;
  jsonPath?: string;
}

export interface ToolDefinition {
  name: string;
  description?: string;
  inputSchema?: unknown;
  serverName?: string;
  origin: SourceLocation;
  /** Localização de um campo interno; cai em `origin` se o caminho não existir. */
  loc(jsonPath: string): SourceLocation;
}

export interface ServerDefinition {
  name: string;
  transport: 'stdio' | 'http' | 'sse' | 'unknown';
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  tools: ToolDefinition[];
  origin: SourceLocation;
  loc(jsonPath: string): SourceLocation;
}

export interface SkillDefinition {
  name: string;
  description?: string;
  allowedTools?: string[];
  frontmatter: Record<string, unknown>;
  body: string;
  bodyOffsetLine: number;
  referencedFiles: string[];
  origin: SourceLocation;
  /** Linha real de uma chave do frontmatter. */
  frontmatterLoc(key: string): SourceLocation;
}

export interface SourceFile {
  file: string;
  text: string;
  language: 'ts' | 'js' | 'py' | 'other';
}

export interface ScanTarget {
  root: string;
  servers: ServerDefinition[];
  tools: ToolDefinition[];   // todas as tools, de qualquer origem
  skills: SkillDefinition[];
  sourceFiles: SourceFile[];
  /** Arquivos lidos com sucesso — não "arquivos que produziram tools". */
  filesExamined: number;
}

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  owasp?: string;
  location: SourceLocation;
  message: string;
  remediation: string;
  evidence?: string;
  helpUri: string;
  provenance: 'static' | 'live';
}

export interface ScanContext {
  target: ScanTarget;
  helpBaseUri: string;
}

export type RuleSubjectKind = 'tool' | 'server' | 'skill' | 'sourceFile' | 'target';

/** O que uma regra devolve. O engine preenche o resto a partir da metadata da regra. */
export type PartialFinding = Omit<Finding,
  'ruleId' | 'title' | 'severity' | 'confidence' | 'owasp' | 'helpUri' | 'provenance'
>;

interface RuleMeta {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  owasp?: string;
}

/**
 * União discriminada por `appliesTo` — não um genérico livre `Rule<S>`.
 *
 * Com `Rule<S>`, uma regra declarando `appliesTo: 'tool'` e tipada `Rule<SkillDefinition>`
 * compilava sem erro (bivariância de parâmetro em método) e só estourava em runtime,
 * onde o engine transformava a exceção em falso-limpo. A união move o erro para o typecheck.
 */
export type Rule =
  | (RuleMeta & { appliesTo: 'tool';       check(subject: ToolDefinition,   ctx: ScanContext): PartialFinding[] })
  | (RuleMeta & { appliesTo: 'server';     check(subject: ServerDefinition, ctx: ScanContext): PartialFinding[] })
  | (RuleMeta & { appliesTo: 'skill';      check(subject: SkillDefinition,  ctx: ScanContext): PartialFinding[] })
  | (RuleMeta & { appliesTo: 'sourceFile'; check(subject: SourceFile,       ctx: ScanContext): PartialFinding[] })
  | (RuleMeta & { appliesTo: 'target';     check(subject: ScanTarget,       ctx: ScanContext): PartialFinding[] });
