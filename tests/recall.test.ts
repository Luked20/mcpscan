/**
 * The recall harness — docs/SPEC.md §8.4.
 *
 * `anti-fp.test.ts` answers one question: how much noise does this scanner make
 * on code that is fine? This file answers the other one: when an attack is
 * actually present, is it found?
 *
 * ## Why these cases and not fixtures
 *
 * Every rule already has a `tests/fixtures/<ID>/vulnerable/` that it detects,
 * and the anti-fp harness already enforces that. But a vulnerable fixture is
 * written by whoever wrote the rule, in the same sitting — it proves the rule
 * fires on the attack its author imagined, which is very nearly a tautology.
 * The same blind spot the clean fixtures had before `tests/corpus/clean/`
 * existed.
 *
 * So none of the payloads here were written for this project. They are
 * captured, verbatim, from published proof-of-concept attacks:
 *
 *  - `invariantlabs-ai/mcp-injection-experiments` — the PoCs from the research
 *    that named tool poisoning in the first place.
 *  - `harishsg993010/damn-vulnerable-MCP-server` — a deliberately vulnerable
 *    server built as a teaching corpus.
 *
 * ## Why a captured tools/list and not the server
 *
 * Each case is the `tools/list` response the real attack serves, obtained once
 * with `--connect` and committed. The test therefore installs nothing,
 * downloads nothing, executes no third-party code, and does not depend on the
 * Python SDK's API staying still — while still measuring the actual payload
 * rather than a paraphrase of it.
 *
 * That the payload only exists at run time is itself the finding: a static scan
 * of every repository here produces **zero**, because the poisoned text lives in
 * a Python docstring and only becomes a tool `description` once the server runs.
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { scan } from '../src/scan.js';

const MALICIOUS_ROOT = 'tests/corpus/malicious';

interface Expectation {
  attack: string;
  expect: Array<{ ruleId: string; severity: string }>;
}

/** Discovered from the filesystem, so a new case is covered the moment it lands. */
function discoverCases(): string[] {
  return readdirSync(MALICIOUS_ROOT, { withFileTypes: true })
    .filter((e) => e.isDirectory() && existsSync(join(MALICIOUS_ROOT, e.name, 'EXPECTED.json')))
    .map((e) => e.name)
    .sort();
}

const cases = discoverCases();

describe('recall harness — captured attacks (SPEC §8.4)', () => {
  it('found the captured attacks', () => {
    expect(cases.length).toBeGreaterThanOrEqual(5);
  });

  for (const name of cases) {
    const dir = join(MALICIOUS_ROOT, name);
    const expected = JSON.parse(readFileSync(join(dir, 'EXPECTED.json'), 'utf8')) as Expectation;

    describe(name, () => {
      it('is documented — what the attack does, and where it came from', () => {
        expect(expected.attack.length).toBeGreaterThan(40);
        expect(existsSync(join(dir, 'PROVENANCE.txt'))).toBe(true);
      });

      it(
        expected.expect.length > 0
          ? `is detected as ${expected.expect.map((e) => `${e.ruleId}/${e.severity}`).join(', ')}`
          : 'produces nothing, and the reason is written down',
        async () => {
          const result = await scan({ path: dir, failOn: 'none' });
          expect(result.error).toBeUndefined();

          // Rule *and* severity, not merely "something fired". Without the pair,
          // a future change that detects something else entirely — or downgrades
          // a critical to info — would leave this test green.
          //
          // Compared as SETS, not multisets. Recall asks "was this attack caught
          // by rule X at severity Y", and a rule firing twice on one capture
          // answers that no differently than firing once — a payload that trips
          // two patterns at once is corroboration, not a second attack. Counting
          // duplicates made the harness report a *strengthened* detection as a
          // regression, which is the one thing it must never do.
          const key = (e: { ruleId: string; severity: string }) => `${e.ruleId}/${e.severity}`;
          const uniq = (es: ReadonlyArray<{ ruleId: string; severity: string }>) =>
            [...new Set(es.map(key))].sort();

          const actual = uniq(result.findings);
          const wanted = uniq(expected.expect);

          if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
            const missing = wanted.filter((k) => !actual.includes(k));
            const extra = actual.filter((k) => !wanted.includes(k));
            throw new Error(
              `${name} — ${expected.attack}\n` +
              `  expected: ${JSON.stringify(wanted)}\n` +
              `  actual:   ${JSON.stringify(actual)}\n` +
              (missing.length > 0
                ? `  Recall regression — no longer caught: ${missing.join(', ')}.\n` +
                  '  An attack this scanner used to catch now gets past it.'
                : wanted.length === 0
                  ? '  This case is recorded as a known miss. If the scanner now detects it, that is\n' +
                    '  progress — update EXPECTED.json to lock the detection in.'
                  : `  Detection improved — newly caught: ${extra.join(', ')}.\n` +
                    '  Nothing was lost. Update EXPECTED.json to lock the new detection in.'),
            );
          }
          expect(actual).toEqual(wanted);
        },
      );
    });
  }
});

describe('recall harness — the shape of the result', () => {
  it('every case carries a captured artifact, never a hand-written one', () => {
    // The point worth preserving: nothing in this corpus was authored here.
    // A case is either a server's `tools/list` as it actually served it — a
    // static scan of those repositories finds nothing, because the payload is a
    // Python docstring until the server runs — or a `SKILL.md` composed from a
    // third-party payload by that project's own injection procedure.
    for (const name of cases) {
      const dir = join(MALICIOUS_ROOT, name);
      const manifest = join(dir, 'tools.json');
      if (existsSync(manifest)) {
        expect(JSON.parse(readFileSync(manifest, 'utf8'))).toHaveProperty('tools');
        continue;
      }
      // A skill case: the captured artifact is the skill itself.
      expect(existsSync(join(dir, 'SKILL.md'))).toBe(true);
      expect(readFileSync(join(dir, 'SKILL.md'), 'utf8').startsWith('---')).toBe(true);
    }
  });

  it('the rug pull is held as two snapshots of one server', async () => {
    // `--connect` answers "what is this server exposing right now", never "what
    // will it expose tomorrow". The same server, scanned twice, gives two
    // different answers -- and both are correct reports of what it served.
    const benign = await scan({ path: `${MALICIOUS_ROOT}/invariant-rug-pull-benign`, failOn: 'none' });
    const poisoned = await scan({ path: `${MALICIOUS_ROOT}/invariant-rug-pull-poisoned`, failOn: 'none' });

    expect(benign.findings).toEqual([]);
    expect(poisoned.findings).toHaveLength(1);
    expect(poisoned.findings[0]!.severity).toBe('critical');
  });
});
