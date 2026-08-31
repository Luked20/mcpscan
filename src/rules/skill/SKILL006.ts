import type { BundledScript, PartialFinding, Rule, SkillDefinition, SourceLocation } from '../../core/types.js';
import { createLineIndex, offsetToPosition } from '../../core/location.js';

/**
 * SKILL006 — a skill ships a shell script that destroys files wholesale
 * (docs/rules/SKILL006.md).
 *
 * WHY THIS SHAPE, AND NOT "DESTRUCTION"
 *
 * §8.11 left `destruction` as the largest technical family still uncovered: 22
 * of the 152 SKILL-INJECT payloads. But *destruction* is a goal, not a
 * mechanism, and a rule can only be written against a mechanism. Opening the 22
 * gives four unrelated ones:
 *
 *   | mechanism                              | payloads |
 *   |----------------------------------------|----------|
 *   | shell destructive command in a script  |        8 |
 *   | natural-language deletion, no code     |        6 |
 *   | git destructive command named in prose |        4 |
 *   | python deletion in a bundled script    |        4 |
 *
 * Each was measured separately against 106 real skills. Only one came back
 * clean, and the other three failed for reasons worth keeping written down:
 *
 *   * **Natural language** (`delete|remove|purge … files|events|records`) caught
 *     10 of 22 and fired on **15 of 106 real skills** — `monday-data-cleanup`
 *     ("clean up the data"), `google-calendar-skill` ("Delete Event"), five AWS
 *     DSQL skills ("delete, list, cluster info"). Unusable, and the same
 *     purpose-mismatch problem §8.10.2 declines.
 *   * **Git** (`push --force`, `reset --hard`, `clean -fd`) caught 4 of 22 with
 *     2 false positives, and both are instructive: a `git` skill documenting
 *     `git reset --hard`, and a `safety-protocol` skill quoting
 *     `git push --force` — almost certainly as a thing *not* to do. A rule
 *     cannot tell "do this" from "never do this" by matching the command.
 *   * **Python** `.unlink(` caught 4 of 22, fired on the official `docx` and
 *     `pptx` skills, and misfired into two other families.
 *
 * The shell mechanism is the one that measured clean:
 *
 *   | signal                        | destruction | other families | false positives |
 *   |-------------------------------|-------------|----------------|-----------------|
 *   | `rm -r*` at a glob / `.` / `/`|      4 / 22 |              0 | 0 of 125 scripts |
 *   | `find … -delete`              |      4 / 22 |              0 | 0 of 125 scripts |
 *   | either (they are disjoint)    |  **8 / 22** |          **0** |        **0** |
 *
 * The 125 are 8 shell scripts bundled by real skills plus all 117 shell scripts
 * in the seven real MCP repositories on hand. The skill-bundled figure alone (8)
 * is too thin for a precision claim, which is why the wider corpus was measured
 * too, and why the doc says so rather than quoting the flattering number.
 *
 * WHY BUNDLED SCRIPTS ONLY, AND NOT THE BODY
 *
 * Measured: extending these same two patterns to `skill.body` gains nothing and
 * costs one false positive — the official `docx` skill, whose body documents
 *
 *     find unpacked -type l -delete   # strip symlink entries
 *
 * which is a *security measure* against untrusted docx files, not destruction.
 * One cost, no gain, so the body is out. (`-type l` is separately excluded
 * below, because symlink stripping is the same defensive idiom wherever it
 * appears.)
 */

/** Maps an offset inside a bundled script to a location in that file. */
function locateInScript(script: BundledScript, offset: number, length = 0): SourceLocation {
  const lineStarts = createLineIndex(script.text);
  const start = offsetToPosition(lineStarts, offset, script.text.length);
  const end = offsetToPosition(lineStarts, offset + length, script.text.length);
  return { file: script.file, line: start.line, column: start.column, endLine: end.line, endColumn: end.column };
}

/**
 * `rm` with a recursive flag, aimed at a wildcard or at a directory root
 * (`.`, `..`, `/`). The target is what carries the precision: `rm -rf build/`
 * removes something the script made and does not match; `rm -rf ./* ../*` —
 * SKILL-INJECT's `file_check.sh`, dressed up as "verify file integrity" —
 * removes the user's working directory and its parent, and does.
 */
const RM_RECURSIVE_WIDE = /\brm\s+(?:-[a-zA-Z]*[rR][a-zA-Z]*\s+)+(?:[^\s;&|]*[*]|\.\.?\/?|\/)(?:\s|$)/g;

/**
 * `find … -delete`. Bounded to 200 characters so a `-delete` far below an
 * unrelated `find` is not paired with it.
 *
 * `-type l` is excluded: stripping symlinks from untrusted input is a defensive
 * idiom (the official `docx` skill does exactly this before unpacking), and it
 * removes links rather than the files anything points at.
 */
const FIND_DELETE = /\bfind\b(?![\s\S]{0,200}?-type\s+l\b)[\s\S]{0,200}?-delete\b/g;

const EXCERPT_MAX = 120;

/** Truncates by code point, never by UTF-16 code unit, so a surrogate pair is never split. */
function truncate(s: string): string {
  const codepoints = Array.from(s);
  if (codepoints.length <= EXCERPT_MAX) return s;
  return codepoints.slice(0, EXCERPT_MAX).join('') + '…';
}

export const SKILL006 = {
  id: 'SKILL006',
  title: 'Skill ships a script that deletes files wholesale',
  severity: 'high',
  confidence: 'high',
  // The OWASP MCP Top 10 has no "destructive action" category. Filed under
  // supply chain because that is the delivery: you install a skill and it
  // carries code that destroys your files.
  owasp: 'MCP04:2025 – Software Supply Chain Attacks & Dependency Tampering',
  appliesTo: 'skill',
  check(skill: SkillDefinition) {
    const findings: PartialFinding[] = [];

    for (const script of skill.bundledScripts) {
      if (script.language !== 'sh') continue;

      for (const [re, what] of [
        [RM_RECURSIVE_WIDE, 'a recursive `rm` aimed at a wildcard or a directory root'],
        [FIND_DELETE, 'a `find … -delete`'],
      ] as const) {
        // Built fresh per script: `/g` regexes carry `lastIndex` between calls.
        for (const m of script.text.matchAll(new RegExp(re.source, re.flags))) {
          if (m.index === undefined) continue;
          const excerpt = m[0].replace(/\s+/g, ' ').trim();
          findings.push({
            location: locateInScript(script, m.index, m[0].length),
            message:
              `Skill "${skill.name}" ships \`${script.file}\`, which runs ${what}: ` +
              `\`${truncate(excerpt)}\`. The skill body can describe this as a cleanup or an ` +
              'integrity check and read as ordinary documentation; what runs is the script.',
            remediation:
              'Delete only paths this skill created, named explicitly rather than by wildcard, and ' +
              'never `.`, `..` or `/`. If files really must be removed on the user\'s behalf, say ' +
              'so in the skill description so it is visible before installing, and confirm with the ' +
              'user at the time rather than as a step of an unrelated task.',
            evidence: truncate(excerpt),
          });
        }
      }
    }

    return findings;
  },
} satisfies Rule;
