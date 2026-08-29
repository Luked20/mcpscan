import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectSkill } from '../../src/collect/skill-md.js';

const BASIC = 'tests/fixtures/skill-md/basic/SKILL.md';
const basicText = readFileSync(BASIC, 'utf8');

describe('collectSkill — fields', () => {
  it('extracts name, description, and allowed-tools from a YAML-list frontmatter', () => {
    const skill = collectSkill(BASIC, basicText);
    expect(skill).not.toBeNull();
    expect(skill!.name).toBe('git-commit-helper');
    expect(skill!.description).toBe('Helps craft conventional commit messages from staged changes.');
    expect(skill!.allowedTools).toEqual(['Bash(git *)', 'Read']);
  });

  it('preserves scope-qualified allowed-tools entries verbatim', () => {
    const skill = collectSkill(BASIC, basicText)!;
    expect(skill.allowedTools).toContain('Bash(git *)');
  });

  it('keeps the raw frontmatter object', () => {
    const skill = collectSkill(BASIC, basicText)!;
    expect(skill.frontmatter['name']).toBe('git-commit-helper');
  });

  it('captures the body text after the closing fence', () => {
    const skill = collectSkill(BASIC, basicText)!;
    expect(skill.body.startsWith('# Git Commit Helper')).toBe(true);
    expect(skill.body).not.toContain('allowed-tools');
  });

  it('finds referenced relative markdown links', () => {
    const text = [
      '---',
      'name: with-links',
      'description: A skill that references sibling files.',
      '---',
      '# Body',
      '',
      'See [the helper script](./helper.sh) and [docs](../docs/readme.md).',
      'Also an [external link](https://example.com/x) and an [anchor](#usage).',
      '',
    ].join('\n');
    const skill = collectSkill('with-links/SKILL.md', text)!;
    expect(skill.referencedFiles).toEqual(['./helper.sh', '../docs/readme.md']);
  });
});

describe('collectSkill — name fallback', () => {
  it('falls back to the containing directory name when frontmatter has no name', () => {
    const file = 'tests/fixtures/skill-md/dir-fallback/SKILL.md';
    const skill = collectSkill(file, readFileSync(file, 'utf8'));
    expect(skill).not.toBeNull();
    expect(skill!.name).toBe('dir-fallback');
  });
});

describe('collectSkill — bodyOffsetLine', () => {
  it('points at the exact real line where the body starts', () => {
    const skill = collectSkill(BASIC, basicText)!;
    // Fixture: line 7 is the closing `---`, so the body starts on line 8.
    expect(skill.bodyOffsetLine).toBe(8);
  });
});

describe('collectSkill — frontmatterLoc', () => {
  it("returns the real line of the 'description' key", () => {
    const skill = collectSkill(BASIC, basicText)!;
    expect(skill.frontmatterLoc('description').line).toBe(3);
  });

  it("returns the real line of the 'name' key", () => {
    const skill = collectSkill(BASIC, basicText)!;
    expect(skill.frontmatterLoc('name').line).toBe(2);
  });

  it("returns the real line of the 'allowed-tools' key", () => {
    const skill = collectSkill(BASIC, basicText)!;
    expect(skill.frontmatterLoc('allowed-tools').line).toBe(4);
  });

  it('falls back to origin when the key is absent', () => {
    const skill = collectSkill(BASIC, basicText)!;
    expect(skill.frontmatterLoc('nonexistent-key')).toEqual(skill.origin);
  });

  it('does not match a key name that only appears inside another value', () => {
    const text = [
      '---',
      'name: my-skill',
      'description: "Please do not say name: out loud"',
      '---',
      '# Body',
      '',
    ].join('\n');
    const skill = collectSkill('x/SKILL.md', text)!;
    // The real 'name:' key is on line 2 — the occurrence of "name:" inside the
    // description string on line 3 must not be mistaken for it.
    expect(skill.frontmatterLoc('name').line).toBe(2);
  });
});

describe('collectSkill — allowed-tools formats', () => {
  it('parses a comma-separated string', () => {
    const text = [
      '---',
      'name: s',
      'description: d',
      'allowed-tools: Bash(git *), Read, Agent(reviewer)',
      '---',
      '# Body',
      '',
    ].join('\n');
    const skill = collectSkill('x/SKILL.md', text)!;
    expect(skill.allowedTools).toEqual(['Bash(git *)', 'Read', 'Agent(reviewer)']);
  });

  it('is absent when the frontmatter has no allowed-tools key', () => {
    const text = ['---', 'name: s', 'description: d', '---', '# Body', ''].join('\n');
    const skill = collectSkill('x/SKILL.md', text)!;
    expect(skill.allowedTools).toBeUndefined();
  });
});

describe('collectSkill — returns null rather than throwing', () => {
  it('no frontmatter at all', () => {
    expect(collectSkill('x/SKILL.md', '# Just a body\n')).toBeNull();
  });

  it('invalid YAML in the frontmatter', () => {
    const text = '---\nname: [unterminated\n---\n# Body\n';
    expect(collectSkill('x/SKILL.md', text)).toBeNull();
  });

  it('frontmatter that parses to a YAML list, not a mapping', () => {
    const text = '---\n- a\n- b\n---\n# Body\n';
    expect(collectSkill('x/SKILL.md', text)).toBeNull();
  });

  it('frontmatter that parses to a scalar, not a mapping', () => {
    const text = '---\njust a plain scalar string\n---\n# Body\n';
    expect(collectSkill('x/SKILL.md', text)).toBeNull();
  });

  it('opening fence with no closing fence', () => {
    expect(collectSkill('x/SKILL.md', '---\nname: s\n# Body without a close\n')).toBeNull();
  });
});

describe('collectSkill — CRLF line endings', () => {
  it('parses frontmatter and computes bodyOffsetLine correctly under CRLF', () => {
    const text = ['---', 'name: crlf-skill', 'description: d', '---', '# Body', '', 'More text.', ''].join(
      '\r\n',
    );
    const skill = collectSkill('crlf/SKILL.md', text)!;
    expect(skill).not.toBeNull();
    expect(skill.name).toBe('crlf-skill');
    expect(skill.body.startsWith('# Body')).toBe(true);
    expect(skill.bodyOffsetLine).toBe(5);
    expect(skill.frontmatterLoc('description').line).toBe(3);
  });
});
