import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectManifest } from '../../src/collect/mcp-manifest.js';
import { MCP005 } from '../../src/rules/mcp/MCP005.js';
import { runRules } from '../../src/core/engine.js';
import type { PartialFinding } from '../../src/core/types.js';

const loadFixture = (kind: 'vulnerable' | 'clean') => {
  const f = `tests/fixtures/MCP005/${kind}/tools.json`;
  return collectManifest(f, readFileSync(f, 'utf8'));
};

interface ToolShorthand {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

const check = (tool: ToolShorthand): PartialFinding[] => {
  const tools = collectManifest('x.json', JSON.stringify({ tools: [tool] }));
  return tools.flatMap((t) => MCP005.check(t));
};

describe('MCP005 — vulnerable fixture', () => {
  it('detects a finding for each offending tool/parameter', () => {
    const findings = loadFixture('vulnerable').flatMap((t) => MCP005.check(t));
    // run_command(command), run_shell(args), run_script(script),
    // execute_task(command, args) = 5 findings across 4 tools.
    expect(findings.length).toBe(5);
  });

  it('locates the finding at the property jsonPath', () => {
    const findings = loadFixture('vulnerable').flatMap((t) => MCP005.check(t));
    const first = findings.find((f) => f.location.jsonPath === 'tools[0].inputSchema.properties.command');
    expect(first).toBeDefined();
  });

  it('names the tool and the parameter in the message', () => {
    const findings = loadFixture('vulnerable').flatMap((t) => MCP005.check(t));
    const first = findings[0]!;
    expect(first.message).toContain('run_command');
    expect(first.message).toContain('command');
  });

  it('includes actionable remediation mentioning execFile/spawn', () => {
    const findings = loadFixture('vulnerable').flatMap((t) => MCP005.check(t));
    expect(findings[0]!.remediation).toMatch(/execFile|spawn/);
    expect(findings[0]!.remediation).toMatch(/enum/i);
  });
});

describe('MCP005 — required positive cases', () => {
  it('detects command as a free string', () => {
    const findings = check({
      name: 'run_command',
      description: 'Runs a command on the host.',
      inputSchema: { properties: { command: { type: 'string' } } },
    });
    expect(findings).toHaveLength(1);
  });

  it('detects args as an unconstrained array', () => {
    const findings = check({
      name: 'run_shell',
      description: 'Executes a shell command.',
      inputSchema: { properties: { args: { type: 'array', items: { type: 'string' } } } },
    });
    expect(findings).toHaveLength(1);
  });

  it('detects script as a free string', () => {
    const findings = check({
      name: 'run_script',
      description: 'Executes a script file.',
      inputSchema: { properties: { script: { type: 'string' } } },
    });
    expect(findings).toHaveLength(1);
  });

  it('detects a run_shell tool', () => {
    const findings = check({
      name: 'run_shell',
      description: 'Executes a shell command and returns its output.',
      inputSchema: { properties: { command: { type: 'string' } } },
    });
    expect(findings).toHaveLength(1);
  });
});

describe('MCP005 — clean fixture', () => {
  it('yields zero findings across every tool', () => {
    const findings = loadFixture('clean').flatMap((t) => MCP005.check(t));
    expect(findings).toEqual([]);
  });
});

describe('MCP005 — negative conditions', () => {
  it('does not fire when command is constrained by enum', () => {
    const findings = check({
      name: 'run_command',
      description: 'Runs one of a small set of predefined commands.',
      inputSchema: { properties: { command: { type: 'string', enum: ['ls', 'pwd'] } } },
    });
    expect(findings).toEqual([]);
  });

  it('does not fire when command is a number', () => {
    const findings = check({
      name: 'send_key',
      description: 'Sends a MIDI command to the device.',
      inputSchema: { properties: { command: { type: 'number' } } },
    });
    expect(findings).toEqual([]);
  });

  it('does not fire when args is an array whose items carry a pattern', () => {
    const findings = check({
      name: 'run_with_args',
      description: 'Runs the configured binary with the given arguments.',
      inputSchema: { properties: { args: { type: 'array', items: { type: 'string', pattern: '^--[a-z-]+$' } } } },
    });
    expect(findings).toEqual([]);
  });

  it('does not fire on a parameter name that only contains "command" (anchored regex)', () => {
    const findings = check({
      name: 'run_report',
      description: 'Generates a report using the given command-line flags.',
      inputSchema: { properties: { commandline_flags: { type: 'string' } } },
    });
    expect(findings).toEqual([]);
  });

  it('does not fire when there is no inputSchema at all', () => {
    const findings = check({ name: 'run_command', description: 'Runs a command on the host.' });
    expect(findings).toEqual([]);
  });
});

describe('MCP005 — behaviour', () => {
  it('is idempotent: two consecutive calls give the same result', () => {
    const tools = collectManifest('x.json', JSON.stringify({
      tools: [{
        name: 'run_command',
        description: 'Runs a command on the host.',
        inputSchema: { properties: { command: { type: 'string' } } },
      }],
    }));
    const t = tools[0]!;
    expect(MCP005.check(t)).toEqual(MCP005.check(t));
    expect(MCP005.check(t)).toHaveLength(1);
  });

  it('rule metadata stays stable: declared high/medium, not critical', () => {
    expect(MCP005.id).toBe('MCP005');
    expect(MCP005.severity).toBe('high');
    expect(MCP005.confidence).toBe('medium');
    expect(MCP005.owasp).toBe('MCP05:2025 – Command Injection & Execution');
    expect(MCP005.appliesTo).toBe('tool');
  });

  it('emits severity "high", not "critical", after the engine confidence clamp', () => {
    const tools = collectManifest('x.json', JSON.stringify({
      tools: [{
        name: 'run_command',
        description: 'Runs a command on the host.',
        inputSchema: { properties: { command: { type: 'string' } } },
      }],
    }));
    const { findings } = runRules(
      { root: '.', servers: [], tools, skills: [], sourceFiles: [], unreadable: [], filesExamined: 1 },
      [MCP005],
      'https://example.com/docs/rules/',
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('high');
  });
});

describe('MCP005 — cross-rule precision', () => {
  for (const id of ['MCP001', 'MCP002', 'MCP003', 'MCP004']) {
    it(`does not fire on the ${id} clean fixture`, () => {
      const f = `tests/fixtures/${id}/clean/tools.json`;
      const tools = collectManifest(f, readFileSync(f, 'utf8'));
      expect(tools.flatMap((t) => MCP005.check(t))).toEqual([]);
    });
  }
});
