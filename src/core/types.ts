export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';

/** Ceiling: a rule never emits a severity higher than its confidence allows. */
export const CONFIDENCE_CEILING: Record<Confidence, Severity> = {
  high: 'critical',
  medium: 'high',
  low: 'medium',
};

export interface SourceLocation {
  file: string;      // relative to root, '/' separator
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
  /**
   * Whether `serverName` is a claim the manifest author actually made (a root-level
   * `"name"` field) or a guess this scanner made up from the containing directory.
   * MCP006 detection 1 (tool-name collision across servers) must only compare
   * `'declared'` names — two directories that happen to sit next to each other are
   * not evidence that any client loads both, so a `'derived'` name can never be
   * used to claim two tools belong to different, competing servers.
   */
  serverNameSource?: 'declared' | 'derived';
  origin: SourceLocation;
  /** Location of an inner field; falls back to `origin` if the path doesn't exist. */
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
  /** Actual line of a frontmatter key. */
  frontmatterLoc(key: string): SourceLocation;
}

export interface SourceFile {
  file: string;
  text: string;
  language: 'ts' | 'js' | 'py' | 'other';
}

/**
 * A file whose *name* declared what it is -- SKILL.md, .mcp.json -- but which no
 * collector could parse. Distinct from a .json that simply is not a manifest:
 * there, silence is correct, because nothing claimed it was one.
 */
export interface UnreadableFile {
  file: string;
  reason: string;
}

/**
 * Why a suppression comment cannot be honoured. A suppression that is present
 * but unusable is never silently ignored — see `docs/SPEC.md` §8.3 and
 * `src/collect/suppression.ts`.
 */
export type SuppressionDefect = 'missing-reason' | 'missing-rule-id';

/**
 * One `mcpscan-disable-next-line <ID> -- <reason>` comment (SPEC §8.3).
 *
 * `defect` being set is what separates "this line is suppressed" from "someone
 * tried to suppress this line and it did not take": a defective suppression
 * suppresses nothing and is reported instead.
 */
export interface Suppression {
  file: string;
  /** 1-based line the comment itself is on. */
  line: number;
  /** 1-based column where the marker starts, so the diagnostic can point at it. */
  column: number;
  /** 1-based line the comment applies to — always `line + 1`. */
  targetLine: number;
  /** Rule ids named by the comment. Empty when `defect` is `'missing-rule-id'`. */
  ruleIds: string[];
  /** The mandatory justification. Absent when `defect` is `'missing-reason'`. */
  reason?: string;
  defect?: SuppressionDefect;
  /** The comment text as written, for the diagnostic's evidence. */
  raw: string;
}

export interface ScanTarget {
  root: string;
  servers: ServerDefinition[];
  tools: ToolDefinition[];   // all tools, from any origin
  skills: SkillDefinition[];
  sourceFiles: SourceFile[];
  /** Suppression comments found in any scanned file, defective ones included. */
  suppressions: Suppression[];
  /** Name-declared files that could not be parsed. Never silently dropped. */
  unreadable: UnreadableFile[];
  /** Files read successfully — not "files that produced tools". */
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

/** What a rule returns. The engine fills in the rest from the rule's metadata. */
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
 * Union discriminated by `appliesTo` — not a free generic `Rule<S>`.
 *
 * With `Rule<S>`, a rule declaring `appliesTo: 'tool'` but typed `Rule<SkillDefinition>`
 * compiled without error (method-parameter bivariance) and only blew up at runtime,
 * where the engine turned the exception into a false-clean. The union moves the error to typecheck.
 */
export type Rule =
  | (RuleMeta & { appliesTo: 'tool';       check(subject: ToolDefinition,   ctx: ScanContext): PartialFinding[] })
  | (RuleMeta & { appliesTo: 'server';     check(subject: ServerDefinition, ctx: ScanContext): PartialFinding[] })
  | (RuleMeta & { appliesTo: 'skill';      check(subject: SkillDefinition,  ctx: ScanContext): PartialFinding[] })
  | (RuleMeta & { appliesTo: 'sourceFile'; check(subject: SourceFile,       ctx: ScanContext): PartialFinding[] })
  | (RuleMeta & { appliesTo: 'target';     check(subject: ScanTarget,       ctx: ScanContext): PartialFinding[] });
