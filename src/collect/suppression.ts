import type { Suppression } from '../core/types.js';

/**
 * Suppression comments — mechanism 3 of false-positive control (docs/SPEC.md §8.3).
 *
 *     // mcpscan-disable-next-line MCP004 -- path is validated in validatePath()
 *
 * A security scanner that a developer cannot silence, case by case, gets
 * silenced wholesale instead: `--disable MCP004` turns the rule off for the
 * entire repository, and removing the CI step turns everything off. Both are a
 * total loss compared to one annotated line. So the escape hatch has to exist.
 *
 * **The reason is mandatory**, and that is the whole design. Without the `--`
 * and a justification the suppression does not take effect and is reported
 * instead (see `defect`). A suppression with no written reason is
 * indistinguishable, six months later, from a finding someone silenced because
 * they did not want to deal with it — which is exactly how a scanner's output
 * decays into noise everyone ignores.
 */

export const SUPPRESSION_MARKER = 'mcpscan-disable-next-line';
const MARKER = SUPPRESSION_MARKER;

/** Closing delimiters of the comment syntaxes this marker can appear inside. */
const COMMENT_TERMINATOR_RE = /(?:-->|\*\/)\s*$/;

const RULE_ID_SEPARATOR_RE = /[\s,]+/;

/**
 * What may appear on the line *before* the marker: whitespace and the opening
 * punctuation of the comment syntaxes above (`//`, `#`, block comments and
 * their ` * ` continuations, `<!--`). Anything else means the marker is not
 * starting a comment — it is inside code or prose that merely talks about it.
 *
 * This is what stops the scanner from flagging its own source. `suppression.ts`
 * and `core/suppress.ts` necessarily contain the marker in string literals and
 * doc comments, and without this every one of those lines parsed as a
 * (malformed) suppression, producing three `info` findings on a self-scan.
 * The same guard removes the common false case in scanned code: a JSON string
 * value is preceded by `": "`, and a quote is not in this set.
 */
const COMMENT_PREFIX_RE = /^[\s/*#<!-]*$/;

/**
 * `collectSuppressions(file, text)` — same no-I/O contract as the other
 * collectors: text in, structure out.
 *
 * Deliberately carrier-agnostic: it looks for the marker anywhere on a line,
 * whatever comment syntax surrounds it. Manifests are read as JSONC (`//`),
 * `SKILL.md` is markdown (`<!-- -->`), server source is TS/JS (line or block
 * comments), and each would otherwise need its own scanner for no gain.
 *
 * What keeps that from matching every mention of the marker is
 * `COMMENT_PREFIX_RE` below: the marker has to *start* a comment, with nothing
 * but whitespace and comment punctuation before it on the line. A real
 * suppression always looks like that, and prose or code that merely names the
 * marker never does.
 */
export function collectSuppressions(file: string, text: string): Suppression[] {
  const out: Suppression[] = [];
  const lines = text.split('\n');

  for (const [index, rawLine] of lines.entries()) {
    const line = rawLine.replace(/\r$/, '');
    const at = line.indexOf(MARKER);
    if (at < 0) continue;
    if (!COMMENT_PREFIX_RE.test(line.slice(0, at))) continue;

    // Strip the closing delimiter *before* looking for the `--` separator:
    // `<!-- mcpscan-disable-next-line MCP004 -->` would otherwise split on the
    // `--` of `-->` and report a reason of `>`.
    const body = line.slice(at + MARKER.length).replace(COMMENT_TERMINATOR_RE, '').trim();

    const base = {
      file, line: index + 1, column: at + 1, targetLine: index + 2, raw: line.trim(),
    };
    const separator = body.indexOf('--');

    if (separator < 0) {
      out.push({ ...base, ruleIds: parseRuleIds(body), defect: 'missing-reason' });
      continue;
    }

    const ruleIds = parseRuleIds(body.slice(0, separator));
    const reason = body.slice(separator + 2).trim();

    if (reason.length === 0) {
      out.push({ ...base, ruleIds, defect: 'missing-reason' });
      continue;
    }
    if (ruleIds.length === 0) {
      // `mcpscan-disable-next-line -- reason` would suppress every rule on the
      // line. That is broader than SPEC §8.3 defines and broader than anyone
      // needs: silencing one rule should not silence the next one to be
      // written. Treated as a defect rather than quietly given the wide
      // meaning.
      out.push({ ...base, ruleIds, reason, defect: 'missing-rule-id' });
      continue;
    }

    out.push({ ...base, ruleIds, reason });
  }

  return out;
}

function parseRuleIds(text: string): string[] {
  return text.trim().split(RULE_ID_SEPARATOR_RE).filter((s) => s.length > 0);
}
