import { parse as parseYaml } from 'yaml';
import { createLineIndex, makeLocation } from '../core/location.js';
import type { BundledScript, SkillDefinition, SourceLocation } from '../core/types.js';

/**
 * Matches the opening `---` fence. Deliberately simple (a literal line, not a
 * YAML-aware fence scanner) — see the module doc below for why.
 */
const OPEN_FENCE_RE = /^---\r?\n/;

/**
 * Matches the *first* `\n---` after the opening fence, optionally followed by
 * a trailing newline (or end of file). This is a plain-text scan, not a YAML
 * document-boundary parser: a frontmatter block that legitimately contained a
 * line that is exactly `---` (inside a block scalar, say) would close early.
 * Real `SKILL.md` frontmatter is a small flat key/value block, so this
 * tradeoff is the same one `frontmatterLoc` below makes on purpose — simple
 * and correct for the real shape, not exhaustively general.
 */
const CLOSE_FENCE_RE = /\r?\n---\r?\n?/;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * `allowed-tools` accepts either a YAML list or a comma-separated string
 * (docs disagree with reality; real installed skills use a YAML list).
 * Entries are returned verbatim — `Bash(git *)` stays `Bash(git *)`. Stripping
 * the `(...)` scope down to the bare tool name is a concern for whichever
 * rule consumes this field (e.g. a future SKILL003), not the collector.
 */
function parseAllowedTools(value: unknown): string[] | undefined {
  let raw: string[];
  if (Array.isArray(value)) {
    raw = value.filter((v): v is string => typeof v === 'string');
  } else if (typeof value === 'string') {
    raw = value.split(',');
  } else {
    return undefined;
  }
  const items = raw.map((v) => v.trim()).filter((v) => v.length > 0);
  return items.length > 0 ? items : undefined;
}

/** Relative markdown links in the body, e.g. `](./helper.sh)`. A link with an
 * explicit scheme (`https://...`, `mailto:...`) or an in-page anchor (`#...`)
 * isn't a reference to a sibling file, so it's excluded. */
function findReferencedFiles(body: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const m of body.matchAll(/\]\(([^)\s]+)\)/g)) {
    const target = m[1];
    if (!target) continue;
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(target)) continue;
    if (target.startsWith('#')) continue;
    if (seen.has(target)) continue;
    seen.add(target);
    out.push(target);
  }
  return out;
}

/** `some/dir/SKILL.md` -> `dir`. No parent segment -> the file's own basename. */
function fallbackName(file: string): string {
  const parts = file.split('/').filter((p) => p.length > 0);
  if (parts.length >= 2) return parts[parts.length - 2]!;
  return parts[0] ?? file;
}

/**
 * `collectSkill(file, text, bundledScripts)` — same contract as the other
 * collectors: no I/O, returns `null` rather than throwing on anything malformed
 * (no frontmatter, invalid YAML, frontmatter that isn't a mapping).
 *
 * `bundledScripts` is passed in rather than read here precisely because of that
 * no-I/O contract: finding a skill's sibling files means touching the disk, so
 * `discover()` does it and hands the results over. Defaulting to `[]` keeps
 * every existing caller — and every unit test that builds a skill from a string
 * — working unchanged.
 *
 * Frontmatter is parsed as plain text first (fence detection above), then the
 * captured block is handed to the `yaml` package. `frontmatterLoc(key)` scans
 * that same raw block line-by-line for `^\s*key\s*:` rather than walking a
 * YAML CST — simpler, and sufficient because it anchors the match to the
 * start of a line, so a key name appearing inside another key's *value*
 * (`description: "say name: nicely"`) never matches unless it genuinely
 * starts a line of its own.
 */
export function collectSkill(
  file: string,
  text: string,
  bundledScripts: BundledScript[] = [],
): SkillDefinition | null {
  const openMatch = OPEN_FENCE_RE.exec(text);
  if (!openMatch) return null;

  const afterOpen = text.slice(openMatch[0].length);
  const closeMatch = CLOSE_FENCE_RE.exec(afterOpen);
  if (!closeMatch) return null;

  const frontmatterStart = openMatch[0].length;
  const frontmatterRaw = afterOpen.slice(0, closeMatch.index);
  const bodyStart = frontmatterStart + closeMatch.index + closeMatch[0].length;
  const body = text.slice(bodyStart);
  const header = text.slice(0, bodyStart);
  const bodyOffsetLine = (header.match(/\n/g)?.length ?? 0) + 1;

  let parsed: unknown;
  try {
    parsed = parseYaml(frontmatterRaw);
  } catch {
    return null;
  }
  if (!isPlainObject(parsed)) return null;
  const frontmatter = parsed;

  const lineStarts = createLineIndex(text);
  const origin = makeLocation(file, text, 0, 0, undefined, lineStarts);

  const name =
    typeof frontmatter['name'] === 'string' && frontmatter['name'].length > 0
      ? frontmatter['name']
      : fallbackName(file);
  const description = typeof frontmatter['description'] === 'string' ? frontmatter['description'] : undefined;
  const allowedTools = parseAllowedTools(frontmatter['allowed-tools']);
  const referencedFiles = findReferencedFiles(body);

  function frontmatterLoc(key: string): SourceLocation {
    const lineRe = new RegExp(`^\\s*${escapeRegExp(key)}\\s*:`);
    for (const m of frontmatterRaw.matchAll(/^(.*)$/gm)) {
      const line = m[1] ?? '';
      if (!lineRe.test(line)) continue;
      const offset = frontmatterStart + (m.index ?? 0);
      return makeLocation(file, text, offset, line.length, undefined, lineStarts);
    }
    return origin;
  }

  return {
    name,
    ...(description !== undefined ? { description } : {}),
    ...(allowedTools !== undefined ? { allowedTools } : {}),
    frontmatter,
    body,
    bodyOffsetLine,
    referencedFiles,
    bundledScripts,
    origin,
    frontmatterLoc,
  };
}
