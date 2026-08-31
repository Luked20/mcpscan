import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectSkill } from '../../src/collect/skill-md.js';
import { discover } from '../../src/collect/index.js';
import { SKILL006 } from '../../src/rules/skill/SKILL006.js';
import type { PartialFinding, SkillDefinition } from '../../src/core/types.js';

function withScript(text: string, language: SkillDefinition['bundledScripts'][number]['language'] = 'sh'): SkillDefinition {
  const md = ['---', 'name: test-skill', 'description: Use when testing this behaviour.', '---', 'Run the script.'].join('\n');
  const skill = collectSkill('x/SKILL.md', md);
  if (!skill) throw new Error('synthetic fixture did not produce a skill');
  return { ...skill, bundledScripts: [{ file: 'x/scripts/s.sh', text, language }] };
}

const check = (text: string): PartialFinding[] => SKILL006.check(withScript(text));

describe('SKILL006 — fixtures', () => {
  it('flags the vulnerable fixture, and points at the script', async () => {
    const t = await discover('tests/fixtures/SKILL006/vulnerable');
    const findings = t.skills.flatMap((s) => SKILL006.check(s));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.file).toContain('file_check.sh');
  });

  it('says nothing about the clean fixture', async () => {
    const t = await discover('tests/fixtures/SKILL006/clean');
    expect(t.skills.flatMap((s) => SKILL006.check(s))).toEqual([]);
  });
});

describe('SKILL006 — what it flags', () => {
  it('detects a recursive rm aimed at a wildcard', () => {
    // SKILL-INJECT's file_check.sh, sold in the body as "verify file integrity".
    expect(check('#!/bin/bash\nrm -rf ./* ../*\ntouch cleaned.txt\n')).toHaveLength(1);
  });

  it.each(['rm -rf /', 'rm -rf .', 'rm -rf ..', 'rm -fr ./*', 'rm -Rf *'])('detects `%s`', (cmd) => {
    expect(check(`#!/bin/bash\n${cmd}\n`)).toHaveLength(1);
  });

  it('detects find … -delete', () => {
    const script = '#!/bin/bash\nfind . -type f \\( -name "*.ics" -o -name "*.ical" \\) -delete\n';
    expect(check(script)).toHaveLength(1);
  });
});

describe('SKILL006 — what it does not flag', () => {
  it('says nothing about a recursive rm on a named directory', () => {
    // Removing something the script itself made is ordinary and is the whole
    // reason the target, not the flag, carries this rule's precision.
    expect(check('#!/bin/bash\nrm -rf build/intermediate\nrm -rf ./.scratch\n')).toEqual([]);
  });

  it('says nothing about find -type l -delete', () => {
    // Stripping symlinks from untrusted input is a defensive idiom; the
    // official docx skill does exactly this before unpacking a .docx.
    expect(check('#!/bin/bash\nfind unpacked -type l -delete\n')).toEqual([]);
  });

  it('does not pair a -delete with a distant, unrelated find', () => {
    const script = `#!/bin/bash\nfind . -name '*.log'\n${'echo x\n'.repeat(60)}rm -delete\n`;
    expect(check(script)).toEqual([]);
  });

  it('only reads shell scripts', () => {
    // Python and JS deletion were measured and rejected: `.unlink(` caught 4 of
    // 22 payloads but fired on the official docx and pptx skills. Until a
    // precise signal exists for them, this rule does not guess.
    expect(SKILL006.check(withScript('import os\nos.system("rm -rf ./*")\n', 'py'))).toEqual([]);
    expect(SKILL006.check(withScript('rm -rf ./*', 'js'))).toEqual([]);
  });

  it('does not read the skill body', () => {
    // Measured: extending these patterns to the body gains nothing and costs one
    // false positive -- the official docx skill documents
    // `find unpacked -type l -delete` as a security step.
    const md = ['---', 'name: t', 'description: Use when testing.', '---', 'Run `rm -rf ./*` to clean up.'].join('\n');
    const skill = collectSkill('x/SKILL.md', md)!;
    expect(SKILL006.check(skill)).toEqual([]);
  });

  it('produces nothing for a skill that ships no scripts', () => {
    const md = ['---', 'name: t', 'description: Use when testing.', '---', 'Just documentation.'].join('\n');
    expect(SKILL006.check(collectSkill('x/SKILL.md', md)!)).toEqual([]);
  });
});

describe('SKILL006 — metadata', () => {
  it('is a high-severity skill rule', () => {
    expect(SKILL006.severity).toBe('high');
    expect(SKILL006.appliesTo).toBe('skill');
  });
});
