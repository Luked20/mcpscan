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

/**
 * The same mapping for a file the skill ships, where the offset is already
 * absolute — no `bodyOffsetLine` shift, because there is no frontmatter above it.
 */
function locateInFile(file: string, text: string, offset: number, length = 0): SourceLocation {
  const lineStarts = createLineIndex(text);
  const start = offsetToPosition(lineStarts, offset, text.length);
  const end = offsetToPosition(lineStarts, offset + length, text.length);
  return { file, line: start.line, column: start.column, endLine: end.line, endColumn: end.column };
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

/**
 * The two-step form: fetch a remote file to disk, then execute *that same file*.
 *
 * `PIPE_TO_SHELL_RE` above only sees `curl … | sh` on one line. SKILL-INJECT's
 * first payload is `curl -sLO http://…/patch1` followed by `bash patch1` — the
 * commoner shape in the wild, and one this rule missed entirely (SPEC §8.10.1).
 *
 * Precision comes from requiring the SAME filename in both halves, not from the
 * wording. A skill that downloads a data file it never runs does not match; a
 * skill that runs a script it ships (rather than one it just fetched) does not
 * match either. Both of those are common and legitimate, and both stay silent.
 *
 * Note this is the un-remediated form of this rule's own advice: "download to a
 * file, review it, pin it by SHA, execute the verified copy" is safe precisely
 * because a human reads the file in between. Fetching and executing in the same
 * breath skips that step while looking like it took it.
 */
const CURL_OUTPUT_RE = /\bcurl\b[^\n;&|]*?(?:-o|--output)\s+(?:'([^'\n]+)'|"([^"\n]+)"|([^\s'"]+))/g;
const CURL_REMOTE_NAME_RE = /\bcurl\b[^\n;&|]*?(?:-[a-zA-Z]*O[a-zA-Z]*|--remote-name)\b[^\n;&|]*/g;
const WGET_OUTPUT_RE = /\bwget\b[^\n;&|]*?(?:-O|--output-document(?:=|\s+))\s*(?:'([^'\n]+)'|"([^"\n]+)"|([^\s'"]+))/g;
const WGET_PLAIN_RE = /\bwget\b(?!\s*-O\b)[^\n;&|]*/g;

/** A URL inside a fetch command, used to derive the filename `-O` implies. */
const URL_IN_COMMAND_RE = /https?:\/\/[^\s'"`;&|)]+/;

/** Interpreters that execute a path handed to them, plus the bare `./script` form. */
const EXECUTES_FILE_RE =
  /(?:\b(?:ba|z|k)?sh\b|\bpython3?\b|\bnode\b|\bperl\b|\bruby\b|\bsource\b|^\s*\.\s|\.\/)\s*([^\s'"`;&|)]+)/gm;

/** `foo/bar/baz.sh?x=1` -> `baz.sh`. Empty when the URL ends in a slash. */
function urlBasename(url: string): string {
  const path = url.split(/[?#]/)[0] ?? '';
  const last = path.split('/').filter((p) => p.length > 0).pop() ?? '';
  return last;
}

interface FetchedFile {
  /** The name the fetch writes to disk. */
  name: string;
  index: number;
  command: string;
}

/** Every "fetch a remote file to disk" in `text`, with the filename it produces. */
function findFetchesToFile(text: string): FetchedFile[] {
  const out: FetchedFile[] = [];

  for (const re of [CURL_OUTPUT_RE, WGET_OUTPUT_RE]) {
    for (const m of text.matchAll(re)) {
      if (m.index === undefined) continue;
      const name = m[1] ?? m[2] ?? m[3];
      // `-o -` writes to stdout, so nothing lands on disk to execute later.
      if (!name || name === '-') continue;
      out.push({ name, index: m.index, command: m[0] });
    }
  }

  // `curl -O <url>` and bare `wget <url>` both name the file after the URL.
  for (const re of [CURL_REMOTE_NAME_RE, WGET_PLAIN_RE]) {
    for (const m of text.matchAll(re)) {
      if (m.index === undefined) continue;
      const url = URL_IN_COMMAND_RE.exec(m[0])?.[0];
      if (!url) continue;
      const name = urlBasename(url);
      if (!name) continue;
      out.push({ name, index: m.index, command: m[0] });
    }
  }

  return out;
}

/**
 * A fetch-to-file whose filename is later handed to an interpreter.
 *
 * Matching is on the basename, so `bash ./patch1` satisfies a fetch that wrote
 * `patch1`, and a path like `scripts/patch1` still matches `patch1`.
 */
function findDownloadThenExecute(text: string): Array<{ fetch: FetchedFile; exec: string; index: number }> {
  const fetches = findFetchesToFile(text);
  if (fetches.length === 0) return [];

  const out: Array<{ fetch: FetchedFile; exec: string; index: number }> = [];
  for (const m of text.matchAll(EXECUTES_FILE_RE)) {
    if (m.index === undefined) continue;
    const target = m[1];
    if (!target) continue;
    const targetBase = target.split('/').pop() ?? target;
    for (const fetch of fetches) {
      // The execution has to come after the download; the reverse order is
      // running a file that happens to share a name, not running what was fetched.
      if (m.index <= fetch.index) continue;
      if ((fetch.name.split('/').pop() ?? fetch.name) !== targetBase) continue;
      out.push({ fetch, exec: m[0].trim(), index: m.index });
      break;
    }
  }
  return out;
}

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

    // The same three shapes, in every file the skill ships. A skill's payload is
    // routinely not in SKILL.md at all: the body says "run backup.sh from this
    // skills scripts directory" -- indistinguishable from real documentation --
    // and the script fetches and runs a remote file. See SPEC 8.10.1.
    for (const script of skill.bundledScripts) {
      const where = (offset: number, length: number) => locateInFile(script.file, script.text, offset, length);

      for (const m of script.text.matchAll(PIPE_TO_SHELL_RE)) {
        if (m.index === undefined) continue;
        findings.push({
          location: where(m.index, m[0].length),
          message:
            `Skill "${skill.name}" ships \`${script.file}\`, which downloads content and pipes it ` +
            `directly into a shell: \`${truncate(m[0])}\`. Whatever the remote host serves at run ` +
            'time gets executed verbatim, and it need not be what it served when the skill was reviewed.',
          remediation:
            'Download the script to a file, review it, pin it by commit SHA, and execute the verified ' +
            'copy. For releases, check the published checksum.',
          evidence: truncate(m[0]),
        });
      }

      for (const m of script.text.matchAll(PIPE_TO_POWERSHELL_RE)) {
        if (m.index === undefined) continue;
        findings.push({
          location: where(m.index, m[0].length),
          message:
            `Skill "${skill.name}" ships \`${script.file}\`, which downloads content and pipes it ` +
            `directly into PowerShell: \`${truncate(m[0])}\`. Whatever the remote host serves at run ` +
            'time gets executed verbatim, and it need not be what it served when the skill was reviewed.',
          remediation:
            'Download the script to a file, review it, pin it by commit SHA, and execute the verified ' +
            'copy. For releases, check the published checksum.',
          evidence: truncate(m[0]),
        });
      }

      for (const hit of findDownloadThenExecute(script.text)) {
        findings.push({
          location: where(hit.fetch.index, hit.fetch.command.length),
          message:
            `Skill "${skill.name}" ships \`${script.file}\`, which downloads a file and then executes ` +
            `it: \`${truncate(hit.fetch.command.trim())}\` writes "${hit.fetch.name}", and \`${truncate(hit.exec)}\` ` +
            'runs it. Nothing reads the file in between, so whatever the remote host serves at run time ' +
            'is executed as-is.',
          remediation:
            'Review the downloaded file before running it, and pin what you fetch by commit SHA or ' +
            'verify it against a published checksum. If the code is meant to be part of the skill, ' +
            'ship it in the skill instead of fetching it.',
          evidence: truncate(hit.fetch.command.trim()),
        });
      }
    }

    // Also in the body itself: a fenced block there is instructions the agent
    // follows, and the two-step form is no safer for being written in markdown.
    for (const hit of findDownloadThenExecute(skill.body)) {
      findings.push({
        location: locateInBody(skill, hit.fetch.index, hit.fetch.command.length),
        message:
          `Skill "${skill.name}" tells the agent to download a file and then execute it: ` +
          `\`${truncate(hit.fetch.command.trim())}\` writes "${hit.fetch.name}", and \`${truncate(hit.exec)}\` ` +
          'runs it. Nothing reads the file in between, so whatever the remote host serves at run time ' +
          'is executed as-is.',
        remediation:
          'Review the downloaded file before running it, and pin what you fetch by commit SHA or ' +
          'verify it against a published checksum. If the code is meant to be part of the skill, ' +
          'ship it in the skill instead of fetching it.',
        evidence: truncate(hit.fetch.command.trim()),
      });
    }

    return findings;
  },
} satisfies Rule;
