import type { PartialFinding, Rule, SkillDefinition } from '../../core/types.js';

/**
 * `allowed-tools` entries are scope-qualified in real skills — `Bash(git *)`,
 * `Agent(name)`, `Workflow(x)` — alongside bare `Read`/`Write`. The scope is
 * not this rule's concern; only the tool name before `(` is. See
 * docs/SPEC.md §15 for the corpus this was verified against.
 */
function normalizeDeclaredTools(allowedTools: readonly string[]): Set<string> {
  const out = new Set<string>();
  for (const entry of allowedTools) {
    const name = entry.split('(')[0]?.trim();
    if (name) out.add(name);
  }
  return out;
}

interface CodeSegment {
  content: string;
}

const FENCE_RE = /```[^\n]*\n([\s\S]*?)```/g;
const INLINE_RE = /`([^`\n]+)`/g;

/**
 * Fenced code blocks and inline code spans in the body — the only places a
 * command actually gets *run*, as opposed to merely mentioned in prose.
 * Fenced blocks are extracted (and removed from the remaining text) before
 * scanning for inline spans, so a single backtick inside a fenced block's
 * content (e.g. a shell one-liner containing a backtick) can't be mistaken
 * for the start of an inline span in the surrounding prose.
 */
function findCodeSegments(body: string): CodeSegment[] {
  const segments: CodeSegment[] = [];
  const strippedParts: string[] = [];
  let lastIndex = 0;

  for (const m of body.matchAll(FENCE_RE)) {
    if (m.index === undefined) continue;
    segments.push({ content: m[1] ?? '' });
    strippedParts.push(body.slice(lastIndex, m.index));
    lastIndex = m.index + m[0].length;
  }
  strippedParts.push(body.slice(lastIndex));

  for (const m of strippedParts.join('\n').matchAll(INLINE_RE)) {
    segments.push({ content: m[1] ?? '' });
  }
  return segments;
}

/** Shell commands with no legitimate reason to be typed anywhere but a command line. */
const SHELL_CMD_RE =
  /^(?:\$\s*)?(?:sudo\s+)?(?:curl|wget|npm|pip|git|chmod|rm|mv|docker|kubectl|bash|sh|node|python)\b/;

/** A read verb followed by something that reads as a path argument. */
const READ_CMD_RE = /^(?:\$\s*)?(?:sudo\s+)?(?:cat|less|head|tail)\s+\S/;

/**
 * A shell redirect to what looks like a filename: not `>=` (comparison), not
 * `->` (an arrow, e.g. a Rust/TS return-type marker), and the target has to
 * contain a letter and only filename-shaped characters — so `x > 5` inside a
 * fenced code example doesn't read as "writes a file".
 */
const WRITE_REDIRECT_RE = /(?<![=-])>{1,2}(?!=)\s*([^\s>]+)/;

function looksLikeFilename(target: string): boolean {
  return /^[.\w/-]+$/.test(target) && /[A-Za-z]/.test(target);
}

type Detection = { matched: true; excerpt: string } | { matched: false };

function detectShellCommand(segments: readonly CodeSegment[]): Detection {
  for (const seg of segments) {
    for (const rawLine of seg.content.split('\n')) {
      const line = rawLine.trim();
      if (line.length > 0 && SHELL_CMD_RE.test(line)) return { matched: true, excerpt: line };
    }
  }
  return { matched: false };
}

function detectFileRead(segments: readonly CodeSegment[]): Detection {
  for (const seg of segments) {
    for (const rawLine of seg.content.split('\n')) {
      const line = rawLine.trim();
      if (line.length > 0 && READ_CMD_RE.test(line)) return { matched: true, excerpt: line };
    }
  }
  return { matched: false };
}

function detectFileWrite(segments: readonly CodeSegment[]): Detection {
  for (const seg of segments) {
    for (const rawLine of seg.content.split('\n')) {
      const line = rawLine.trim();
      if (line.length === 0) continue;
      const m = WRITE_REDIRECT_RE.exec(line);
      if (m && looksLikeFilename(m[1] ?? '')) return { matched: true, excerpt: line };
    }
  }
  return { matched: false };
}

export const SKILL003 = {
  id: 'SKILL003',
  title: 'Skill uses a capability it does not declare',
  severity: 'high',
  confidence: 'medium',
  owasp: 'MCP02:2025 – Privilege Escalation via Scope Creep',
  appliesTo: 'skill',
  check(skill: SkillDefinition) {
    // `allowed-tools` absent (the overwhelming majority of real skills — see
    // docs/SPEC.md §15) means no declaration was made at all, which is a
    // different thing from an incomplete declaration. Treating absence as
    // under-declaration would fire on essentially every skill in existence.
    if (!skill.allowedTools || skill.allowedTools.length === 0) return [];

    const declared = normalizeDeclaredTools(skill.allowedTools);
    const declaredList = skill.allowedTools.join(', ');
    const segments = findCodeSegments(skill.body);
    const location = skill.frontmatterLoc('allowed-tools');

    const findings: PartialFinding[] = [];

    const shell = detectShellCommand(segments);
    if (shell.matched && !declared.has('Bash')) {
      findings.push({
        location,
        message:
          `Skill "${skill.name}" runs a shell command in its body (e.g. \`${shell.excerpt}\`), ` +
          `but "allowed-tools" does not declare "Bash". Declared: ${declaredList}.`,
        remediation:
          'Add "Bash" to allowed-tools, or remove the shell command from the body. An incomplete ' +
          "declaration makes a reviewer underestimate the skill's actual reach.",
        evidence: shell.excerpt,
      });
    }

    const read = detectFileRead(segments);
    if (read.matched && !declared.has('Read')) {
      findings.push({
        location,
        message:
          `Skill "${skill.name}" reads a file in its body (e.g. \`${read.excerpt}\`), but ` +
          `"allowed-tools" does not declare "Read". Declared: ${declaredList}.`,
        remediation:
          'Add "Read" to allowed-tools, or remove the file-reading instruction from the body. An ' +
          "incomplete declaration makes a reviewer underestimate the skill's actual reach.",
        evidence: read.excerpt,
      });
    }

    const write = detectFileWrite(segments);
    if (write.matched && !declared.has('Write')) {
      findings.push({
        location,
        message:
          `Skill "${skill.name}" writes a file in its body (e.g. \`${write.excerpt}\`), but ` +
          `"allowed-tools" does not declare "Write". Declared: ${declaredList}.`,
        remediation:
          'Add "Write" to allowed-tools, or remove the file-writing instruction from the body. An ' +
          "incomplete declaration makes a reviewer underestimate the skill's actual reach.",
        evidence: write.excerpt,
      });
    }

    return findings;
  },
} satisfies Rule;
