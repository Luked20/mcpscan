import type { PartialFinding, Rule, SkillDefinition, SourceLocation } from '../../core/types.js';
import { createLineIndex, offsetToPosition } from '../../core/location.js';

/**
 * Maps a UTF-16 offset (and optional length) inside `skill.body` back to a
 * real file location, using `skill.bodyOffsetLine` to shift the body-local
 * line number to the real one. Same approach as SKILL001's `locateInBody` —
 * duplicated rather than shared, per the precedent set there.
 */
function locateInBody(skill: SkillDefinition, offset: number, length = 0): SourceLocation {
  const lineStarts = createLineIndex(skill.body);
  const start = offsetToPosition(lineStarts, offset, skill.body.length);
  const end = offsetToPosition(lineStarts, offset + length, skill.body.length);
  const shift = skill.bodyOffsetLine - 1;
  return {
    file: skill.origin.file,
    line: start.line + shift,
    column: start.column,
    endLine: end.line + shift,
    endColumn: end.column,
  };
}

const EXCERPT_MAX = 120;

/** Truncates by code point, never by UTF-16 code unit, so a surrogate pair is never split. */
function truncate(s: string): string {
  const codepoints = Array.from(s);
  if (codepoints.length <= EXCERPT_MAX) return s;
  return codepoints.slice(0, EXCERPT_MAX).join('') + '…';
}

/**
 * `curl … | sh`, `wget … | bash`, including a `sudo` variant. Requires a
 * network-fetch command (`curl`/`wget`) before the pipe — the brief's intent
 * is network-sourced code, so `cat file.txt | sh` (a local file, no network)
 * is deliberately excluded. See docs/rules/SKILL004.md.
 */
const PIPE_TO_SHELL_RE = /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b/g;

/** `iwr … | iex`, `Invoke-WebRequest … | Invoke-Expression` — the PowerShell equivalent. */
const PIPE_TO_POWERSHELL_RE = /\b(?:iwr|Invoke-WebRequest)\b[^\n|]*\|\s*(?:iex|Invoke-Expression)\b/gi;

/**
 * A `raw.githubusercontent.com` URL, trailing sentence punctuation stripped.
 *
 * The backtick is excluded along with the quote characters because SKILL.md is
 * markdown: a URL written inline is almost always inside `code span` markers,
 * and swallowing the closing backtick put it into the finding's own evidence
 * and message (`…README.md``), which reads as a malformed URL.
 */
const RAW_GITHUB_RE = /https?:\/\/raw\.githubusercontent\.com\/[^\s'"`()<>]+/g;

const FULL_SHA_RE = /^[0-9a-f]{40}$/i;

/**
 * Extensions that make the fetched thing documentation rather than code.
 *
 * This rule is `remote-code-fetch`: the risk it names is a skill running code
 * whose content can change after review. A `.md` file is read, not run. The
 * regression corpus (docs/SPEC.md §8.2) found this the hard way — the official
 * `mcp-builder` skill produced four `high` findings, all of them the SDK's own
 * `README.md` fetched from `main` for the model to read.
 *
 * Remote *text* pulled into a model's context is its own risk, but it is a
 * prompt-injection risk, which is SKILL001 and SKILL002's subject, not a
 * supply-chain one. Filed under this rule it was simply wrong.
 */
const DOC_EXTENSION_RE = /\.(?:md|markdown|txt|rst|adoc)$/i;

/** `owner/repo/ref/path...` — the third path segment is the ref. */
function extractRef(url: string): string | undefined {
  const path = url.replace(/^https?:\/\/raw\.githubusercontent\.com\//, '');
  return path.split('/')[2];
}

/** True when the URL points at a document, ignoring any query string or fragment. */
function isDocumentUrl(url: string): boolean {
  const withoutSuffix = url.split('#')[0]!.split('?')[0]!;
  return DOC_EXTENSION_RE.test(withoutSuffix);
}

export const SKILL004 = {
  id: 'SKILL004',
  title: 'Skill downloads and executes remote code',
  severity: 'high',
  confidence: 'high',
  owasp: 'MCP04:2025 – Software Supply Chain Attacks & Dependency Tampering',
  appliesTo: 'skill',
  check(skill: SkillDefinition) {
    const findings: PartialFinding[] = [];

    for (const m of skill.body.matchAll(PIPE_TO_SHELL_RE)) {
      if (m.index === undefined) continue;
      findings.push({
        location: locateInBody(skill, m.index, m[0].length),
        message:
          `Skill "${skill.name}" downloads content and pipes it directly into a shell: ` +
          `\`${truncate(m[0])}\`. Whatever the remote host serves at run time gets executed verbatim, ` +
          'and it need not be what it served when the skill was reviewed.',
        remediation:
          'Download the script to a file, review it, pin it by commit SHA, and execute the verified ' +
          'copy. For releases, check the published checksum.',
        evidence: truncate(m[0]),
      });
    }

    for (const m of skill.body.matchAll(PIPE_TO_POWERSHELL_RE)) {
      if (m.index === undefined) continue;
      findings.push({
        location: locateInBody(skill, m.index, m[0].length),
        message:
          `Skill "${skill.name}" downloads content and pipes it directly into PowerShell: ` +
          `\`${truncate(m[0])}\`. Whatever the remote host serves at run time gets executed verbatim, ` +
          'and it need not be what it served when the skill was reviewed.',
        remediation:
          'Download the script to a file, review it, pin it by commit SHA, and execute the verified ' +
          'copy. For releases, check the published checksum.',
        evidence: truncate(m[0]),
      });
    }

    for (const m of skill.body.matchAll(RAW_GITHUB_RE)) {
      if (m.index === undefined) continue;
      const trimmed = m[0].replace(/[).,;:]+$/, '');
      const ref = extractRef(trimmed);
      if (ref !== undefined && FULL_SHA_RE.test(ref)) continue;
      if (isDocumentUrl(trimmed)) continue;

      findings.push({
        location: locateInBody(skill, m.index, trimmed.length),
        message:
          `Skill "${skill.name}" fetches source from raw.githubusercontent.com pinned to a mutable ` +
          `ref ("${ref ?? '?'}") instead of a commit SHA: \`${truncate(trimmed)}\`. Content behind a ` +
          'branch name or tag can change at any time after the skill was reviewed.',
        remediation:
          'Pin the URL to a full 40-character commit SHA, or download to a file, review it, and ' +
          'execute the verified copy.',
        evidence: truncate(trimmed),
      });
    }

    return findings;
  },
} satisfies Rule;
