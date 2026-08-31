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
  /**
   * Whether this tool was read from a file or obtained by starting the server
   * (`--connect`). MCP006 must not compare across the two: a live capture and a
   * manifest found in the same scan are most likely the same server observed
   * twice, not two servers a client would load together.
   */
  provenance?: 'static' | 'live';
  origin: SourceLocation;
  /**
   * Location of an inner field, addressed by **path segments relative to this
   * subject** — `tool.loc(['inputSchema', 'properties', name])`. Falls back to
   * `origin` when the path does not exist in the document.
   *
   * Segments, not a string, and relative, not absolute, for the same reason:
   * a dotted path cannot be split back into segments once a key contains a dot
   * of its own. This used to take a string that callers built by concatenating
   * `origin.jsonPath`, and a real server named `awslabs.mysql-mcp-server`
   * produced `mcpServers.awslabs.mysql-mcp-server.args`, which re-parsed into
   * four segments, resolved to nothing, and silently reported the whole server
   * object instead of the field. Passing segments makes that unrepresentable,
   * and passing them relative means a rule never has to know its own base path.
   */
  loc(path: readonly (string | number)[]): SourceLocation;
}

/**
 * An MCP **resource** — the second of the protocol's three primitives, and the
 * one this scanner was blind to until `tests/corpus/malicious/` measured it.
 *
 * DVMCP challenge 1 hides its entire vulnerability here rather than in a tool:
 * an `internal://credentials` resource kept out of the listing, and a
 * `notes://{user_id}` template that interpolates caller input into a URI. No
 * rule over `ToolDefinition` could ever have seen either.
 *
 * A resource and a *resource template* are separate calls in the protocol
 * (`resources/list` and `resources/templates/list`) but the same kind of thing
 * to a rule, so they share this shape and are told apart by `isTemplate`. The
 * distinction matters: a template's `uri` contains `{placeholders}` a caller
 * fills, which is a parameterised surface, while a plain resource's is fixed.
 */
export interface ResourceDefinition {
  /** The `uri`, or the `uriTemplate` when `isTemplate` is set. */
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
  /** From `resources/templates/list`: the uri carries `{placeholders}`. */
  isTemplate?: boolean;
  serverName?: string;
  provenance?: 'static' | 'live';
  origin: SourceLocation;
  /** Same contract as `ToolDefinition.loc`: segments, relative to this resource. */
  loc(path: readonly (string | number)[]): SourceLocation;
}

/**
 * An MCP **prompt** — the third primitive. A stored, named message template the
 * user can invoke, whose text goes into the model's context.
 *
 * Collected for the same reason as resources: it is part of the protocol's
 * attack surface and was going unexamined. What specifically goes wrong with
 * prompts is deliberately not assumed here — see `docs/SPEC.md` §8.5 on why
 * collection comes before rules.
 */
export interface PromptDefinition {
  name: string;
  description?: string;
  arguments?: Array<{ name: string; description?: string; required?: boolean }>;
  serverName?: string;
  provenance?: 'static' | 'live';
  origin: SourceLocation;
  /** Same contract as `ToolDefinition.loc`: segments, relative to this prompt. */
  loc(path: readonly (string | number)[]): SourceLocation;
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
  /** Same contract as `ToolDefinition.loc`: segments, relative to this server. */
  loc(path: readonly (string | number)[]): SourceLocation;
}

export interface SkillDefinition {
  name: string;
  description?: string;
  allowedTools?: string[];
  frontmatter: Record<string, unknown>;
  body: string;
  bodyOffsetLine: number;
  referencedFiles: string[];
  /**
   * The executable files shipped inside the skill's own directory, with their
   * contents. `referencedFiles` holds names a link in the body points at;
   * this holds the code the skill actually carries, whether the body links to
   * it or merely tells the agent to run it by name.
   *
   * A skill's payload is routinely not in `SKILL.md` at all: the body says
   * "run the backup.sh script from this skills scripts directory" -- ordinary
   * documentation -- and `scripts/backup.sh` fetches and executes a remote
   * file. Until this field existed no rule opened that file. See SPEC 8.10.
   */
  bundledScripts: BundledScript[];
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
 * An executable file a skill ships beside its `SKILL.md`.
 *
 * Separate from `SourceFile` on purpose. A `SourceFile` is server code that
 * runs when the server runs; a `BundledScript` is code an *agent* is told to
 * execute while following a skill, and the shell scripts that dominate this
 * category are not scanned as `SourceFile` at all. Keeping them apart also
 * keeps their findings attributable to the skill that carries them.
 */
export interface BundledScript {
  /** Path relative to the scan root, `/`-separated — the same shape as `SourceFile.file`. */
  file: string;
  text: string;
  language: 'sh' | 'py' | 'js' | 'ts' | 'ps1' | 'other';
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
  /** MCP resources and resource templates, from a manifest or from `--connect`. */
  resources: ResourceDefinition[];
  /** MCP prompts, from a manifest or from `--connect`. */
  prompts: PromptDefinition[];
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

export type RuleSubjectKind =
  | 'tool' | 'resource' | 'prompt' | 'server' | 'skill' | 'sourceFile' | 'target';

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
  | (RuleMeta & { appliesTo: 'tool';       check(subject: ToolDefinition,     ctx: ScanContext): PartialFinding[] })
  | (RuleMeta & { appliesTo: 'resource';   check(subject: ResourceDefinition, ctx: ScanContext): PartialFinding[] })
  | (RuleMeta & { appliesTo: 'prompt';     check(subject: PromptDefinition,   ctx: ScanContext): PartialFinding[] })
  | (RuleMeta & { appliesTo: 'server';     check(subject: ServerDefinition, ctx: ScanContext): PartialFinding[] })
  | (RuleMeta & { appliesTo: 'skill';      check(subject: SkillDefinition,  ctx: ScanContext): PartialFinding[] })
  | (RuleMeta & { appliesTo: 'sourceFile'; check(subject: SourceFile,       ctx: ScanContext): PartialFinding[] })
  | (RuleMeta & { appliesTo: 'target';     check(subject: ScanTarget,       ctx: ScanContext): PartialFinding[] });
