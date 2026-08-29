/**
 * The anti-false-positive harness — docs/SPEC.md §8.
 *
 * Pulled forward from what was originally a later phase: with ten more rules
 * coming, this needs to exist before rule #3, not after rule #12. Everything
 * here discovers its subjects from RULES or the filesystem — never a
 * hardcoded rule-id list — so a new rule is automatically covered the moment
 * its fixtures land, with no edit to this file.
 */
import { describe, it, expect } from 'vitest';
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

      it('has documentation at docs/rules/<ID>.md', () => {
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
    .filter((f) => f.length > 0 && f.endsWith('.ts'));

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
