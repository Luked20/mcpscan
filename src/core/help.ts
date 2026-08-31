/**
 * Where a finding sends the reader.
 *
 * A base ending in `/` is treated as a directory of per-rule pages and gets
 * `<ID>.md` appended; anything else is used verbatim for every rule.
 *
 * The per-rule pages exist in this repository but are **not published** —
 * `docs/` is gitignored — so the base points at the README's rules table
 * instead. Putting the per-rule links back is one line: end this string with a
 * `/` and publish `docs/rules/`.
 *
 * This lives in its own module rather than in `scan.ts` so that `core/engine`
 * and `report/sarif` can use it without importing `scan.ts`, which imports them.
 */
export const HELP_BASE_URI = 'https://github.com/Luked20/mcpscan#rules';

/** See `HELP_BASE_URI`. */
export function helpUriFor(ruleId: string, base: string = HELP_BASE_URI): string {
  return base.endsWith('/') ? `${base}${ruleId}.md` : base;
}
