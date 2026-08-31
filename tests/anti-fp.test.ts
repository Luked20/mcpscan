/**
 * The anti-false-positive harness — docs/SPEC.md §8.
 *
 * Pulled forward from what was originally a later phase: with ten more rules
 * coming, this needs to exist before rule #3, not after rule #12. Everything
 * here discovers its subjects from RULES or the filesystem — never a
 * hardcoded rule-id list — so a new rule is automatically covered the moment
 * its fixtures land, with no edit to this file.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { join } from 'node:path';
import { RULES } from '../src/rules/index.js';
import { CONFIDENCE_CEILING } from '../src/core/types.js';
import { rank } from '../src/core/severity.js';
import { scan } from '../src/scan.js';

const FIXTURES_ROOT = 'tests/fixtures';
const RULE_ID_RE = /^(MCP|SKILL)\d{3}$/;

function isNonEmptyDir(path: string): boolean {
  if (!existsSync(path)) return false;
  if (!statSync(path).isDirectory()) return false;
  return readdirSync(path).length > 0;
}

/** Every subdirectory of tests/fixtures/ that has a `vulnerable/` child — discovered, not listed. */
function discoverFixtureRuleIds(): string[] {
  return readdirSync(FIXTURES_ROOT, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .filter((name) => existsSync(join(FIXTURES_ROOT, name, 'vulnerable')))
    .sort();
}

describe('anti-false-positive harness — registry discipline (SPEC §8.1)', () => {
  for (const rule of RULES) {
    describe(rule.id, () => {
      it('has a non-empty vulnerable fixture directory', () => {
        expect(isNonEmptyDir(`${FIXTURES_ROOT}/${rule.id}/vulnerable`)).toBe(true);
      });

      it('has a non-empty clean fixture directory', () => {
        expect(isNonEmptyDir(`${FIXTURES_ROOT}/${rule.id}/clean`)).toBe(true);
      });

      // `docs/` is gitignored, so a CI checkout has no rule pages to check. This
      // SKIPS rather than passes: a skipped test is visible in the run output,
      // where a silently-true assertion would quietly stop guarding anything.
      it.skipIf(!existsSync('docs/rules'))('has documentation at docs/rules/<ID>.md', () => {
        expect(existsSync(`docs/rules/${rule.id}.md`)).toBe(true);
      });

      it('declares a severity within its own confidence ceiling', () => {
        const ceiling = CONFIDENCE_CEILING[rule.confidence];
        expect(
          rank(rule.severity),
          `${rule.id} declares severity "${rule.severity}" with confidence "${rule.confidence}", ` +
            `whose ceiling is "${ceiling}"`,
        ).toBeLessThanOrEqual(rank(ceiling));
      });

      it('has an id matching MCP### or SKILL###', () => {
        expect(rule.id).toMatch(RULE_ID_RE);
      });

      it('has a non-empty title that does not end with a period', () => {
        expect(rule.title.length).toBeGreaterThan(0);
        expect(rule.title.endsWith('.')).toBe(false);
      });
    });
  }
});

describe('anti-false-positive harness — self-detection (SPEC §8.1)', () => {
  const ruleIds = discoverFixtureRuleIds();

  it('discovered at least one fixture directory', () => {
    expect(ruleIds.length).toBeGreaterThan(0);
  });

  for (const id of ruleIds) {
    it(`${id} detects at least one finding in its own vulnerable fixture`, async () => {
      const result = await scan({
        path: `${FIXTURES_ROOT}/${id}/vulnerable`,
        failOn: 'none',
        rules: [id],
      });
      expect(
        result.error,
        `scan of ${FIXTURES_ROOT}/${id}/vulnerable restricted to rule ${id} failed: ${result.error ?? ''}`,
      ).toBeUndefined();
      expect(result.findings.length).toBeGreaterThan(0);
    });
  }
});

describe('anti-false-positive harness — cross-fixture precision (SPEC §8.2)', () => {
  const ruleIds = discoverFixtureRuleIds();

  // The important check: every OTHER rule's clean fixture must also stay
  // clean under every registered rule. This is what catches a new rule
  // firing on another rule's clean fixture — the most common way a false
  // positive enters unnoticed.
  for (const id of ruleIds) {
    it(`${FIXTURES_ROOT}/${id}/clean triggers zero findings from any registered rule`, async () => {
      const path = `${FIXTURES_ROOT}/${id}/clean`;
      const result = await scan({ path, failOn: 'none' }); // every registered rule, no --rules/--disable filter

      if (result.findings.length > 0) {
        const detail = result.findings
          .map((f) => {
            const loc = `${f.location.file}:${f.location.line}:${f.location.column}` +
              (f.location.jsonPath ? ` (${f.location.jsonPath})` : '');
            return `  - rule ${f.ruleId} at ${loc} — evidence: ${JSON.stringify(f.evidence ?? '<none>')}`;
          })
          .join('\n');
        throw new Error(
          `${path} is supposed to be a CLEAN fixture for ${id}, but triggered ` +
            `${result.findings.length} finding(s) when scanned with every registered rule:\n${detail}\n` +
            `Either the offending rule is over-broad, or this fixture belongs under a different rule's directory.`,
        );
      }

      expect(result.findings).toEqual([]);
    });
  }
});

describe('anti-false-positive harness — regression corpus (SPEC §8.2)', () => {
  // Mechanism 2. Everything under tests/corpus/ is real, third-party, and
  // known-clean: `tools/list` output captured from the official MCP reference
  // servers, and SKILL.md files taken verbatim from anthropics/skills. See
  // tests/corpus/README.md for what is in it and scripts/capture-corpus.mjs
  // for how it got there. Nothing is downloaded or executed at test time.
  //
  // Why this exists on top of the clean fixtures above: a fixture I wrote is
  // shaped by the rule I was writing at the time, so it cannot tell me the
  // rule is over-broad in a way I did not think of. Real manifests can, and
  // did — on its first run this corpus produced 13 `high` findings, all of
  // them false, and both are recorded in docs/SPEC.md §7.4.
  // `clean/` only: tests/corpus/malicious/ holds captured attacks and is measured
  // by the recall harness in tests/recall.test.ts, which asserts the opposite.
  const CORPUS_ROOT = 'tests/corpus/clean';

  /**
   * One scan per *deployment*, not one scan of the whole tree.
   *
   * Each captured server is scanned on its own, because that is what a real
   * scan looks like: a user points mcpscan at one server, never at a bag of
   * nine unrelated ones. Scanning them together asserted they are co-loaded,
   * which is false -- and it manufactured a finding to match. `search_nodes` is
   * declared by both `memory-server` and n8n's server, so MCP006 correctly
   * reported a collision between two servers that only ever met inside this
   * directory. The rule was right; the target misrepresented reality.
   *
   * `skills/`, `source/` and `configs/` stay whole-tree scans: those genuinely
   * do coexist in a repository, which is the shape they were taken from.
   */
  function scanTargets(): string[] {
    const captures = ['servers', 'live'].flatMap((group) => {
      const dir = join(CORPUS_ROOT, group);
      if (!existsSync(dir)) return [];
      return readdirSync(dir, { withFileTypes: true })
        .filter((e) => e.isDirectory())
        .map((e) => join(dir, e.name));
    });
    return [...captures, ...['skills', 'source', 'configs'].map((d) => join(CORPUS_ROOT, d))];
  }

  const targets = scanTargets();
  const results = new Map<string, Awaited<ReturnType<typeof scan>>>();

  beforeAll(async () => {
    for (const target of targets) {
      results.set(target, await scan({ path: target, failOn: 'none' })); // every registered rule
    }
  });

  const totals = () => {
    const sum = { tools: 0, skills: 0, sourceFiles: 0, servers: 0, resources: 0, prompts: 0 };
    for (const r of results.values()) {
      sum.tools += r.stats.tools;
      sum.skills += r.stats.skills;
      sum.sourceFiles += r.stats.sourceFiles;
      sum.servers += r.stats.servers;
      sum.resources += r.stats.resources;
      sum.prompts += r.stats.prompts;
    }
    return sum;
  };

  it('found something to scan in every part of the corpus', () => {
    expect(targets.length).toBeGreaterThanOrEqual(8);
  });

  it('parses cleanly — a corpus the scanner cannot read proves nothing', () => {
    for (const [target, r] of results) {
      expect(r.error, `${target}: ${r.error ?? ''}`).toBeUndefined();
      expect(r.stats.unreadable, target).toBe(0);
    }
  });

  it('actually contains subjects — an empty corpus would pass silently', () => {
    // Hard floors, not the exact current counts: this catches a corpus that got
    // deleted, moved, or excluded by a glob change, without failing every time
    // someone adds a server to it.
    //
    // One floor per subject kind, because a rule is only measured by the kind it
    // consumes: without `sourceFiles` MCP008 has no real input, without
    // `servers` neither do MCP007 and MCP009, and the zero-high/critical
    // assertion below would pass for those three by never running them.
    const sum = totals();
    expect(sum.tools).toBeGreaterThanOrEqual(100);
    expect(sum.skills).toBeGreaterThanOrEqual(10);
    expect(sum.sourceFiles).toBeGreaterThanOrEqual(8);
    expect(sum.servers).toBeGreaterThanOrEqual(5);
    // Phase 2 collects these; nothing consumes them yet (SPEC 8.6). The floor is
    // here so the day a rule does, it has real input rather than none.
    expect(sum.resources).toBeGreaterThanOrEqual(9);
    expect(sum.prompts).toBeGreaterThanOrEqual(4);
  });

  it('produces zero high/critical findings from any registered rule', () => {
    const serious = [...results].flatMap(([target, r]) =>
      r.findings
        .filter((f) => f.severity === 'high' || f.severity === 'critical')
        .map((f) => ({ target, f })));

    if (serious.length > 0) {
      const detail = serious
        .map(({ target, f }) => {
          const loc = `${f.location.file}:${f.location.line}:${f.location.column}` +
            (f.location.jsonPath ? ` (${f.location.jsonPath})` : '');
          return `  - [${target}] ${f.ruleId} [${f.severity}] at ${loc} — ${f.message}`;
        })
        .join('\n');
      throw new Error(
        `${serious.length} high/critical finding(s) against the known-clean regression corpus:\n${detail}\n\n` +
          'This is real third-party code that is not vulnerable. Either the rule is over-broad and ' +
          'needs narrowing, or this corpus entry genuinely is not clean and does not belong here — ' +
          'decide which, and record the reasoning in docs/SPEC.md §7.4. Do not add an exception here.',
      );
    }

    expect(serious).toEqual([]);
  });
});

describe('anti-false-positive harness — no invisible characters in .ts source (SPEC §8)', () => {
  // Codepoint ranges from docs/SPEC.md §7.2 / the MCP002 policy: the classes
  // with no legitimate use in machine-read text. `.json` fixtures are exempt
  // — they are where these characters legitimately live, on purpose, for
  // MCP002's own tests.
  const INVISIBLE_RANGES: ReadonlyArray<readonly [number, number]> = [
    [0x200b, 0x200d], // ZWSP, ZWNJ, ZWJ
    [0x2060, 0x2060], // word joiner
    [0xfeff, 0xfeff], // BOM
    [0x202a, 0x202e], // bidi embeddings/overrides
    [0x2066, 0x2069], // bidi isolates
    [0xe0000, 0xe007f], // tag characters
  ];

  function isInvisible(cp: number): boolean {
    return INVISIBLE_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi);
  }

  const files = execSync('git ls-files', { encoding: 'utf8' })
    .split('\n')
    .map((s) => s.trim())
    // tests/corpus/ is third-party code captured verbatim as regression data,
    // not this project's source. Holding someone else's file to this project's
    // source hygiene would be both wrong and unfixable — the only remedy would
    // be editing the corpus, which destroys the one property that makes it
    // worth having.
    .filter((f) => f.length > 0 && f.endsWith('.ts') && !f.startsWith('tests/corpus/'));

  it('found at least one tracked .ts file to check', () => {
    expect(files.length).toBeGreaterThan(0);
  });

  for (const file of files) {
    it(`${file} contains no invisible codepoints`, () => {
      const text = readFileSync(file, 'utf8');
      const hits: string[] = [];
      let cpIndex = 0;
      for (const ch of text) {
        const cp = ch.codePointAt(0)!;
        if (isInvisible(cp)) hits.push(`U+${cp.toString(16).toUpperCase()} at codepoint ${cpIndex}`);
        cpIndex += 1;
      }
      expect(hits, `${file} contains invisible character(s): ${hits.join(', ')}`).toEqual([]);
    });
  }
});
