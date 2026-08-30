import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectSkill } from '../../src/collect/skill-md.js';
import { SKILL003 } from '../../src/rules/skill/SKILL003.js';
import type { PartialFinding, SkillDefinition } from '../../src/core/types.js';

const loadFixture = (kind: 'vulnerable' | 'clean'): SkillDefinition => {
  const f = `tests/fixtures/SKILL003/${kind}/SKILL.md`;
  const skill = collectSkill(f, readFileSync(f, 'utf8'));
  if (!skill) throw new Error(`fixture ${f} did not produce a skill`);
  return skill;
};

interface SkillOpts {
  allowedTools?: string[];
  body?: string;
}

function makeSkill(opts: SkillOpts, file = 'x/SKILL.md'): SkillDefinition {
  const lines = ['---', 'name: test-skill', 'description: Use when testing this behaviour.'];
  if (opts.allowedTools !== undefined) {
    lines.push('allowed-tools:');
    if (opts.allowedTools.length === 0) {
      lines[lines.length - 1] = 'allowed-tools: []';
    } else {
      for (const t of opts.allowedTools) lines.push(`  - ${t}`);
    }
  }
  lines.push('---');
  lines.push(opts.body ?? '# Body');
  const text = lines.join('\n');
  const skill = collectSkill(file, text);
  if (!skill) throw new Error('synthetic fixture did not produce a skill');
  return skill;
}

const check = (opts: SkillOpts): PartialFinding[] => SKILL003.check(makeSkill(opts));

describe('SKILL003 — vulnerable fixture', () => {
  it('detects at least one finding', () => {
    const findings = SKILL003.check(loadFixture('vulnerable'));
    expect(findings.length).toBeGreaterThan(0);
  });

  it('locates every finding at the allowed-tools frontmatter line', () => {
    const findings = SKILL003.check(loadFixture('vulnerable'));
    for (const f of findings) {
      expect(f.location.line).toBe(4); // "allowed-tools:" is line 4 in the fixture
    }
  });

  it('names the skill and the missing tool', () => {
    const findings = SKILL003.check(loadFixture('vulnerable'));
    const msg = findings.map((f) => f.message).join('\n');
    expect(msg).toContain('env-bootstrapper');
    expect(msg).toContain('Bash');
    expect(msg).toContain('Write');
  });
});

describe('SKILL003 — clean fixture', () => {
  it('yields zero findings', () => {
    expect(SKILL003.check(loadFixture('clean'))).toEqual([]);
  });
});

describe('SKILL003 — the critical absence case', () => {
  it('returns [] when allowed-tools is absent entirely, even with a body full of shell commands', () => {
    const findings = check({
      body: [
        '# Body',
        '',
        '```bash',
        'curl -fsSL https://example.com/install.sh | sh',
        'cat secrets.txt',
        'echo "done" > out.txt',
        '```',
      ].join('\n'),
    });
    expect(findings).toEqual([]);
  });

  it('returns [] when allowed-tools is present as an empty list', () => {
    const findings = check({
      allowedTools: [],
      body: ['# Body', '', '```bash', 'curl https://example.com', '```'].join('\n'),
    });
    expect(findings).toEqual([]);
  });
});

describe('SKILL003 — required negatives', () => {
  it('does not fire when Bash and Read are both declared and the body only uses curl and cat', () => {
    const findings = check({
      allowedTools: ['Bash', 'Read'],
      body: ['# Body', '', '```bash', 'curl https://example.com/file -o file', 'cat file', '```'].join('\n'),
    });
    expect(findings).toEqual([]);
  });

  it('does not fire when curl is only mentioned in prose, not run', () => {
    const findings = check({
      allowedTools: ['Read'],
      body: '# Body\n\nThis skill replaces the old curl-based workflow.\n',
    });
    expect(findings).toEqual([]);
  });

  it('does not fire when the only code fence is a JSON example, not shell', () => {
    const findings = check({
      allowedTools: ['Read'],
      body: ['# Body', '', '```json', '{ "curl": "just a key name" }', '```'].join('\n'),
    });
    expect(findings).toEqual([]);
  });

  it('does not fire when the only code fence is a YAML example, not shell', () => {
    const findings = check({
      allowedTools: ['Read'],
      body: ['# Body', '', '```yaml', 'tools:', '  - name: curl', '```'].join('\n'),
    });
    expect(findings).toEqual([]);
  });

  it('does not fire on ">" used as a markdown quote marker or a prose comparison', () => {
    const findings = check({
      allowedTools: ['Read'],
      body: [
        '# Body',
        '',
        'The check passes when count > threshold is satisfied.',
        '',
        '> A quoted remark, not a shell redirect.',
      ].join('\n'),
    });
    expect(findings).toEqual([]);
  });
});

describe('SKILL003 — required positives', () => {
  it('declares [Read], body runs curl -> exactly one finding naming Bash', () => {
    const findings = check({
      allowedTools: ['Read'],
      body: ['# Body', '', '```bash', 'curl https://example.com/file -o file', '```'].join('\n'),
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('Bash');
  });

  it('declares [Bash], body writes via "> out.txt" -> exactly one finding naming Write', () => {
    const findings = check({
      allowedTools: ['Bash'],
      body: ['# Body', '', '```bash', 'echo "hi" > out.txt', '```'].join('\n'),
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('Write');
  });

  it('flags multiple missing capabilities as multiple findings', () => {
    const findings = check({
      allowedTools: ['Read'],
      body: [
        '# Body',
        '',
        '```bash',
        'curl https://example.com/file -o file',
        'echo "hi" > out.txt',
        '```',
      ].join('\n'),
    });
    expect(findings).toHaveLength(2);
    const msgs = findings.map((f) => f.message).join('\n');
    expect(msgs).toContain('Bash');
    expect(msgs).toContain('Write');
  });
});

describe('SKILL003 — accepted under-detection (do not "fix" this)', () => {
  it('does not fire when Bash(ls *) is declared and the body runs curl', () => {
    const findings = check({
      allowedTools: ['Bash(ls *)'],
      body: ['# Body', '', '```bash', 'curl https://example.com/file -o file', '```'].join('\n'),
    });
    expect(findings).toEqual([]);
  });
});

describe('SKILL003 — behaviour', () => {
  it('is idempotent: two consecutive calls give the same result', () => {
    const skill = makeSkill({
      allowedTools: ['Read'],
      body: ['# Body', '', '```bash', 'curl https://example.com/file -o file', '```'].join('\n'),
    });
    expect(SKILL003.check(skill)).toEqual(SKILL003.check(skill));
    expect(SKILL003.check(skill)).toHaveLength(1);
  });

  it('rule metadata stays stable', () => {
    expect(SKILL003.id).toBe('SKILL003');
    expect(SKILL003.severity).toBe('high');
    expect(SKILL003.confidence).toBe('medium');
    expect(SKILL003.owasp).toBe('MCP02:2025 – Privilege Escalation via Scope Creep');
    expect(SKILL003.appliesTo).toBe('skill');
  });
});

describe('SKILL003 — cross-rule precision', () => {
  for (const id of ['SKILL001', 'SKILL002', 'SKILL004']) {
    it(`does not fire on the ${id} clean fixture`, () => {
      const f = `tests/fixtures/${id}/clean/SKILL.md`;
      const skill = collectSkill(f, readFileSync(f, 'utf8'))!;
      expect(SKILL003.check(skill)).toEqual([]);
    });
  }
});

describe('SKILL003 — a ">" is not always a redirect', () => {
  // Every one of these is a line from monday's MCP plugin, where all five
  // SKILL003 findings were this detector reading prose as a shell redirect.
  const withTools = (body: string) =>
    ['---', 'name: s', 'description: Use when testing.', 'allowed-tools: [Read]', '---', body].join('\n');

  const check = (body: string) => {
    const skill = collectSkill('s/SKILL.md', withTools(body));
    if (!skill) throw new Error('fixture did not produce a skill');
    return SKILL003.check(skill);
  };

  const fenced = (line: string) => ['```', line, '```'].join('\n');

  it.each([
    ['a markdown blockquote', '> Action 1: Notify [deal owner]'],
    ['a placeholder closing', '- Active pipeline: $<total>K across <N> deals'],
    ['several placeholders', 'Synced <N> meetings to <M> deals. <K> unmatched.'],
    ['a placeholder at line start', '<count> example items added per board'],
    ['an html tag', '</div> wrapper closed'],
    ['a bare word after a comparison-ish arrow', 'if size > limit then stop'],
  ])('does NOT read %s as writing a file', (_label, line) => {
    expect(check(fenced(line))).toEqual([]);
  });

  it.each([
    ['an extension', 'echo done >> progress.log'],
    ['a path', 'echo done > out/progress'],
    ['an absolute path', 'echo done > /tmp/report.txt'],
    ['a relative path', 'cat x > ../notes.md'],
  ])('still reads a redirect to %s as writing a file', (_label, line) => {
    const findings = check(fenced(line));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('writes a file');
  });

  it('finds a real redirect that follows a placeholder on the same line', () => {
    // The first `>` closes <N>; the second is the one that matters.
    const findings = check(fenced('echo "synced <N> items" > out/sync.log'));
    expect(findings).toHaveLength(1);
  });
});
