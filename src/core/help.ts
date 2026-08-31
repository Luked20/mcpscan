/**
 * Where a finding sends the reader.
 *
 * A base ending in `/` is treated as a directory of per-rule pages and gets
 * `<ID>.md` appended; anything else is used verbatim for every rule. Only
 * `docs/rules/` is published — the design record (`docs/SPEC.md`,
 * `docs/ARCHITECTURE.md`) is gitignored — so the pages this points at do exist.
 *
 * This lives in its own module rather than in `scan.ts` so that `core/engine`
 * and `report/sarif` can use it without importing `scan.ts`, which imports them.
 */
export const HELP_BASE_URI = 'https://github.com/Luked20/mcpscan/blob/main/docs/rules/';

/** See `HELP_BASE_URI`. */
export function helpUriFor(ruleId: string, base: string = HELP_BASE_URI): string {
  return base.endsWith('/') ? `${base}${ruleId}.md` : base;
}
